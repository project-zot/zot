package meta

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	testimage "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errHookInternal = errors.New("hook internal test error")

func TestPriorTagManifestsFromMetaDB(t *testing.T) {
	Convey("priorTagManifestsFromMetaDB", t, func() {
		ctx := context.Background()

		Convey("empty tags", func() {
			out, err := priorTagManifestsFromMetaDB(ctx, mocks.MetaDBMock{}, "repo", nil)
			So(err, ShouldBeNil)
			So(len(out), ShouldEqual, 0)
		})

		Convey("repo meta not found yields empty map", func() {
			db := mocks.MetaDBMock{
				GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{}, zerr.ErrRepoMetaNotFound
				},
			}

			out, err := priorTagManifestsFromMetaDB(ctx, db, "repo", []string{"t"})
			So(err, ShouldBeNil)
			So(len(out), ShouldEqual, 0)
		})

		Convey("get repo meta error propagates", func() {
			db := mocks.MetaDBMock{
				GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{}, errHookInternal
				},
			}

			_, err := priorTagManifestsFromMetaDB(ctx, db, "repo", []string{"t"})
			So(errors.Is(err, errHookInternal), ShouldBeTrue)
		})

		Convey("empty tag map in repo meta", func() {
			db := mocks.MetaDBMock{
				GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{Tags: map[mTypes.Tag]mTypes.Descriptor{}}, nil
				},
			}

			out, err := priorTagManifestsFromMetaDB(ctx, db, "repo", []string{"t"})
			So(err, ShouldBeNil)
			So(len(out), ShouldEqual, 0)
		})

		Convey("skips unknown tag empty digest invalid digest", func() {
			good := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

			db := mocks.MetaDBMock{
				GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"only-good": {Digest: good, MediaType: ispec.MediaTypeImageManifest},
							"empty-dig": {Digest: "", MediaType: ispec.MediaTypeImageManifest},
							"bad-dig":   {Digest: "not-a-digest", MediaType: ispec.MediaTypeImageManifest},
						},
					}, nil
				},
			}

			tags := []string{"missing", "only-good", "empty-dig", "bad-dig"}
			out, err := priorTagManifestsFromMetaDB(ctx, db, "repo", tags)
			So(err, ShouldBeNil)
			So(len(out), ShouldEqual, 1)

			pm, ok := out["only-good"]
			So(ok, ShouldBeTrue)
			So(pm.digest.String(), ShouldEqual, good)
			So(pm.mediaType, ShouldEqual, ispec.MediaTypeImageManifest)
		})

		Convey("default media type when descriptor empty", func() {
			good := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

			db := mocks.MetaDBMock{
				GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
					return mTypes.RepoMeta{
						Tags: map[mTypes.Tag]mTypes.Descriptor{
							"t": {Digest: good, MediaType: ""},
						},
					}, nil
				},
			}

			out, err := priorTagManifestsFromMetaDB(ctx, db, "repo", []string{"t"})
			So(err, ShouldBeNil)
			So(out["t"].mediaType, ShouldEqual, ispec.MediaTypeImageManifest)
		})
	})
}

func TestRollbackDigestManifestTags(t *testing.T) {
	Convey("rollbackDigestManifestTags", t, func() {
		ctx := context.Background()
		testLog := log.NewTestLogger()

		img := testimage.CreateDefaultImage()
		mediaType := img.ManifestDescriptor.MediaType
		if mediaType == "" {
			mediaType = ispec.MediaTypeImageManifest
		}

		body := img.ManifestDescriptor.Data
		dgst := img.Digest()

		Convey("delete manifest error is logged path", func() {
			var deleteCalls int

			is := mocks.MockedImageStore{
				DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error {
					deleteCalls++

					return errors.New("delete failed")
				},
			}

			sc := storage.StoreController{DefaultStore: &is}
			rollbackDigestManifestTags(ctx, "repo", []string{"a"}, nil, mediaType, dgst, body, sc,
				mocks.MetaDBMock{}, testLog, nil)

			So(deleteCalls, ShouldEqual, 1)
		})

		Convey("delete manifest not found is ignored", func() {
			is := mocks.MockedImageStore{
				DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error {
					return zerr.ErrManifestNotFound
				},
			}

			sc := storage.StoreController{DefaultStore: &is}
			rollbackDigestManifestTags(ctx, "repo", []string{"a"}, nil, mediaType, dgst, body, sc,
				mocks.MetaDBMock{}, testLog, nil)
		})

		Convey("on delete manifest failure is logged", func() {
			is := mocks.MockedImageStore{}

			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(string, string, godigest.Digest) error {
					return errors.New("remove failed")
				},
			}

			sc := storage.StoreController{DefaultStore: &is}
			rollbackDigestManifestTags(ctx, "repo", []string{"t"}, []string{"t"}, mediaType, dgst, body, sc,
				metaDB, testLog, nil)
		})

		Convey("prior restore get blob fails", func() {
			other := testimage.CreateRandomImage()
			priorD := (&other).Digest()
			prior := map[string]priorTagManifest{
				"t": {digest: priorD, mediaType: mediaType},
			}

			is := mocks.MockedImageStore{
				DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error { return nil },
				GetBlobContentFn: func(string, godigest.Digest) ([]byte, error) {
					return nil, errors.New("blob missing")
				},
			}

			sc := storage.StoreController{DefaultStore: &is}
			rollbackDigestManifestTags(ctx, "repo", []string{"t"}, []string{"t"}, mediaType, dgst, body, sc,
				mocks.MetaDBMock{}, testLog, prior)
		})

		Convey("prior restore put manifest fails", func() {
			priorBody := body
			priorD := dgst
			prior := map[string]priorTagManifest{
				"t": {digest: priorD, mediaType: mediaType},
			}

			is := mocks.MockedImageStore{
				DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error { return nil },
				GetBlobContentFn: func(_ string, blobDigest godigest.Digest) ([]byte, error) {
					So(blobDigest, ShouldResemble, priorD)

					return priorBody, nil
				},
				PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string, body []byte, extraTags []string) (godigest.Digest, godigest.Digest, error) {
					return "", "", errors.New("put failed")
				},
			}

			sc := storage.StoreController{DefaultStore: &is}
			rollbackDigestManifestTags(ctx, "repo", []string{"t"}, []string{"t"}, mediaType, dgst, body, sc,
				mocks.MetaDBMock{}, testLog, prior)
		})

		Convey("prior restore metadb update fails", func() {
			priorBody := body
			priorD := dgst
			prior := map[string]priorTagManifest{
				"t": {digest: priorD, mediaType: mediaType},
			}

			var manifest ispec.Manifest
			err := json.Unmarshal(priorBody, &manifest)
			So(err, ShouldBeNil)

			configBytes, err := json.Marshal(img.Config)
			So(err, ShouldBeNil)

			metaDB := mocks.MetaDBMock{
				SetRepoReferenceFn: func(context.Context, string, string, mTypes.ImageMeta) error {
					return errors.New("set ref failed")
				},
			}

			is := mocks.MockedImageStore{
				DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error { return nil },
				GetBlobContentFn: func(_ string, blobDigest godigest.Digest) ([]byte, error) {
					switch {
					case blobDigest == priorD:
						return priorBody, nil
					case blobDigest == manifest.Config.Digest:
						return configBytes, nil
					default:
						So(blobDigest.String(), ShouldBeIn,
							[]string{priorD.String(), manifest.Config.Digest.String()})
					}

					return nil, nil
				},
				PutImageManifestFn: func(ctx context.Context, _, _, _ string, blob []byte, _ []string) (godigest.Digest, godigest.Digest, error) {
					d := godigest.FromBytes(blob)

					return d, d, nil
				},
			}

			sc := storage.StoreController{DefaultStore: &is}
			rollbackDigestManifestTags(ctx, "repo", []string{"t"}, []string{"t"}, mediaType, dgst, body, sc,
				metaDB, testLog, prior)
		})
	})
}
