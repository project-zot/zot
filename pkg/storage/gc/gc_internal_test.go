package gc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/go-viper/mapstructure/v2"
	godigest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var (
	errGC    = errors.New("gc error")
	repoName = "test" //nolint: gochecknoglobals
)

type retentionPolicyMock struct {
	retainedUntagged []string
}

func (rpm retentionPolicyMock) HasDeleteReferrer(repo string) bool {
	return false
}

func (rpm retentionPolicyMock) HasDeleteUntagged(repo string) bool {
	return true
}

func (rpm retentionPolicyMock) HasUntaggedRetention(repo string) bool {
	return true
}

func (rpm retentionPolicyMock) HasTagRetention(repo string) bool {
	return false
}

func (rpm retentionPolicyMock) GetRetainedTagsFromIndex(ctx context.Context, repo string, index ispec.Index) []string {
	return nil
}

func (rpm retentionPolicyMock) GetRetainedTagsFromMetaDB(ctx context.Context, repoMeta types.RepoMeta,
	index ispec.Index,
) []string {
	return nil
}

func (rpm retentionPolicyMock) GetRetainedUntaggedFromMetaDB(ctx context.Context, repoMeta types.RepoMeta,
	index ispec.Index,
) []string {
	return rpm.retainedUntagged
}

func TestRemoveUntaggedManifestsWithRetention(t *testing.T) {
	Convey("removeUntaggedManifests keeps untagged manifests retained by policy", t, func() {
		digest := godigest.FromString("retained")
		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					Digest:    digest,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		gc := GarbageCollect{
			metaDB: mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
					return types.RepoMeta{Name: repo}, nil
				},
			},
			policyMgr: retentionPolicyMock{
				retainedUntagged: []string{digest.String()},
			},
			log: zlog.NewTestLogger(),
		}

		gced, err := gc.removeUntaggedManifests(context.Background(), repoName, &index, map[godigest.Digest]bool{})

		So(err, ShouldBeNil)
		So(gced, ShouldBeFalse)
		So(index.Manifests, ShouldHaveLength, 1)
		So(index.Manifests[0].Digest, ShouldEqual, digest)
	})
}

func TestGarbageCollectWithMockedImageStore(t *testing.T) {
	trueVal := true

	ctx := context.Background()

	Convey("Cover gc error paths", t, func(c C) {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")
		metrics := monitoring.NewNopMetricServer()

		gcOptions := Options{
			Delay: storageConstants.DefaultGCDelay,
			ImageRetention: config.ImageRetention{
				Delay: storageConstants.DefaultGCDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			},
		}

		Convey("Error on GetIndex in gc.cleanRepo()", func() {
			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
					return types.RepoMeta{}, errGC
				},
			}, gcOptions, audit, log, metrics)

			err := gc.cleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on RemoveIdleRepository in gc.cleanRepo()", func() {
			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte(`{"schemaVersion":2,"manifests":[]}`), nil
				},
				RemoveIdleRepositoryFn: func(repo string, maxBlobAge time.Duration) (bool, error) {
					return false, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err := gc.cleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Meta delete failure after idle repo removal is logged, not returned", func() {
			metaCalled := false

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte(`{"schemaVersion":2,"manifests":[]}`), nil
				},
				RemoveIdleRepositoryFn: func(repo string, maxBlobAge time.Duration) (bool, error) {
					return true, nil
				},
			}

			metaDB := mocks.MetaDBMock{
				DeleteRepoMetaFn: func(repo string) error {
					metaCalled = true

					return errGC
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			err := gc.cleanRepo(ctx, repoName)
			So(err, ShouldBeNil)
			So(metaCalled, ShouldBeTrue)
		})

		Convey("Error on GetIndex in gc.deleteUnreferencedBlobs()", func() {
			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
					return types.RepoMeta{}, errGC
				},
			}, gcOptions, audit, log, metrics)

			_, err := gc.deleteUnreferencedBlobs("repo", time.Hour, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.removeManifest()", func() {
			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					return errGC
				},
			}
			gc := NewGarbageCollect(mocks.MockedImageStore{}, metaDB, gcOptions, audit, log, metrics)

			desc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromString("digest"),
			}
			index := &ispec.Index{Manifests: []ispec.Descriptor{desc}}
			_, err := gc.removeManifest(repoName, index, desc, desc.Digest.String(), "", "")
			So(err, ShouldNotBeNil)
		})

		Convey("Error on metaDB in gc.cleanRepo()", func() {
			gcOptions := Options{
				Delay: storageConstants.DefaultGCDelay,
				ImageRetention: config.ImageRetention{
					Delay: storageConstants.DefaultGCDelay,
					Policies: []config.RetentionPolicy{
						{
							Repositories: []string{"**"},
							KeepTags: []config.KeepTagsPolicy{
								{
									Patterns: []string{".*"},
								},
							},
						},
					},
				},
			}

			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
					return types.RepoMeta{}, errGC
				},
			}, gcOptions, audit, log, metrics)

			err := gc.removeTagsPerRetentionPolicy(ctx, "name", &ispec.Index{})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on context done in removeTags...", func() {
			gcOptions := Options{
				Delay: storageConstants.DefaultGCDelay,
				ImageRetention: config.ImageRetention{
					Delay: storageConstants.DefaultGCDelay,
					Policies: []config.RetentionPolicy{
						{
							Repositories: []string{"**"},
							KeepTags: []config.KeepTagsPolicy{
								{
									Patterns: []string{".*"},
								},
							},
						},
					},
				},
			}

			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			ctx, cancel := context.WithCancel(ctx)
			cancel()

			err := gc.removeTagsPerRetentionPolicy(ctx, "name", &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("digest")),
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on PutIndexContent in gc.cleanRepo()", func() {
			returnedIndexJSON := ispec.Index{}

			returnedIndexJSONBuf, err := json.Marshal(returnedIndexJSON)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				PutIndexContentFn: func(repo string, index ispec.Index) error {
					return errGC
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexJSONBuf, nil
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.cleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.cleanBlobs() in gc.cleanRepo()", func() {
			returnedIndexJSON := ispec.Index{}

			returnedIndexJSONBuf, err := json.Marshal(returnedIndexJSON)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				PutIndexContentFn: func(repo string, index ispec.Index) error {
					return nil
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexJSONBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{}, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.cleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("False on imgStore.DirExists() in gc.cleanRepo()", func() {
			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return false
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err := gc.cleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.identifyManifestsReferencedInIndex in gc.cleanManifests() with multiarch image", func() {
			indexImageDigest := godigest.FromBytes([]byte("digest"))

			returnedIndexImage := ispec.Index{
				Subject: &ispec.DescriptorEmptyJSON,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    godigest.FromBytes([]byte("digest2")),
					},
				},
			}

			returnedIndexImageBuf, err := json.Marshal(returnedIndexImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == indexImageDigest {
						return returnedIndexImageBuf, nil
					} else {
						return nil, errGC
					}
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &trueVal,
					},
				},
			}
			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.removeManifestsPerRepoPolicy(ctx, repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    indexImageDigest,
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.identifyManifestsReferencedInIndex in gc.cleanManifests() with image", func() {
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, errGC
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &trueVal,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err := gc.removeManifestsPerRepoPolicy(ctx, repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("digest")),
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on context done in removeManifests...", func() {
			imgStore := mocks.MockedImageStore{}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &trueVal,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			ctx, cancel := context.WithCancel(ctx)
			cancel()

			err := gc.removeManifestsPerRepoPolicy(ctx, repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("digest")),
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.removeManifestIfOlderThan() in gc.cleanManifests() with image", func() {
			returnedImage := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
			}

			returnedImageBuf, err := json.Marshal(returnedImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedImageBuf, nil
				},
			}

			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					return errGC
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &trueVal,
					},
				},
			}
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			err = gc.removeManifestsPerRepoPolicy(ctx, repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("digest")),
					},
				},
			})
			So(err, ShouldNotBeNil)
		})
		Convey("Error on gc.removeManifestIfOlderThan() in gc.cleanManifests() with signature", func() {
			returnedImage := ispec.Manifest{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: zcommon.NotationSignature,
			}

			returnedImageBuf, err := json.Marshal(returnedImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedImageBuf, nil
				},
			}

			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					return errGC
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{}
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			desc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromBytes([]byte("digest")),
			}

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{desc},
			}
			_, err = gc.removeManifest(repoName, index, desc, desc.Digest.String(), storage.NotationType,
				godigest.FromBytes([]byte("digest2")))

			So(err, ShouldNotBeNil)
		})

		Convey("removeManifest treats DeleteSignature ErrImageMetaNotFound as already cleaned", func() {
			imgStore := mocks.MockedImageStore{}
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					return zerr.ErrImageMetaNotFound
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{}
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			desc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromBytes([]byte("sig-digest")),
			}
			index := &ispec.Index{Manifests: []ispec.Descriptor{desc}}

			gced, err := gc.removeManifest(repoName, index, desc, desc.Digest.String(), storage.NotationType,
				godigest.FromBytes([]byte("subject-digest")))
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
		})

		Convey("StatBlob failure in gcReferrer skips age check and continues (image index)", func() {
			manifestDesc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    godigest.FromBytes([]byte("digest")),
			}

			returnedIndexImage := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Subject: &ispec.Descriptor{
					Digest: godigest.FromBytes([]byte("digest2")),
				},
				Manifests: []ispec.Descriptor{
					manifestDesc,
				},
			}

			returnedIndexImageBuf, err := json.Marshal(returnedIndexImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedIndexImageBuf, nil
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.removeManifestsPerRepoPolicy(ctx, repoName, &returnedIndexImage)
			So(err, ShouldBeNil)
			So(len(returnedIndexImage.Manifests), ShouldEqual, 1)
		})

		Convey("StatBlob failure in gcReferrer skips age check and continues (image)", func() {
			manifestDesc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromBytes([]byte("digest")),
			}

			returnedImage := ispec.Manifest{
				Subject: &ispec.Descriptor{
					Digest: godigest.FromBytes([]byte("digest2")),
				},
				MediaType: ispec.MediaTypeImageManifest,
			}

			returnedImageBuf, err := json.Marshal(returnedImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedImageBuf, nil
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, errGC
				},
			}

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					manifestDesc,
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.removeManifestsPerRepoPolicy(ctx, repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 1)
		})

		Convey("Missing nested index blob in removeReferrersWithMissingSubject is skipped gracefully", func() {
			// Create a top-level index that contains a nested index
			// The nested index blob will be missing
			topLevelIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    godigest.FromString("missing-nested-index"),
						Size:      100,
					},
				},
			}

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					// Return ErrBlobNotFound for the missing nested index
					return nil, zerr.ErrBlobNotFound
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			// removeReferrersWithMissingSubject should skip the missing nested index and continue
			gced, err := gc.removeReferrersWithMissingSubject(repoName, &topLevelIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
		})

		Convey("removeReferrersWithMissingSubject skips unknown media types", func() {
			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: "application/vnd.unknown.manifest.v1+json",
						Digest:    godigest.FromString("unknown-media"),
						Size:      10,
					},
				},
			}

			readCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					readCount++

					return nil, zerr.ErrBlobNotFound
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(readCount, ShouldEqual, 0)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
		})

		Convey("removeReferrersWithMissingSubject continues when index blob read fails", func() {
			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    godigest.FromString("bad-index"),
						Size:      10,
					},
				},
			}

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, errGC
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
		})

		Convey("removeReferrersWithMissingSubject continues when manifest blob read fails", func() {
			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromString("bad-manifest"),
						Size:      10,
					},
				},
			}

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, errGC
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
		})

		Convey("removeReferrer GCs orphaned notation signature via subject path", func() {
			missingSubject := godigest.FromString("missing-subject")

			desc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromString("notation-sig"),
				Size:      10,
			}
			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{desc},
			}

			imgStore := mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 10, time.Now().Add(-24 * time.Hour), nil
				},
			}

			deletedSig := false
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deletedSig = signedManifestDigest == missingSubject &&
						sm.SignatureDigest == desc.Digest.String() &&
						sm.SignatureType == storage.NotationType

					return nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{Delay: 0}
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			subject := &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    missingSubject,
				Size:      1,
			}
			gced, err := gc.removeReferrer(repoName, &parentIndex, desc, subject, zcommon.ArtifactTypeNotation, nil)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deletedSig, ShouldBeTrue)
			So(len(parentIndex.Manifests), ShouldEqual, 0)
		})

		Convey("removeReferrer skips cosign row when StatBlob fails (fail-closed age check)", func() {
			missingSubject := godigest.FromString("missing-subject")
			cosignTag := "sha256-" + missingSubject.Encoded() + ".sig"

			desc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromString("cosign-sig"),
				Size:      10,
				Annotations: map[string]string{
					ispec.AnnotationRefName: cosignTag,
				},
			}
			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{desc},
			}

			imgStore := mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, 0, time.Time{}, errGC
				},
			}

			gcOptions.Delay = 0
			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrer(repoName, &parentIndex, desc, nil, "", nil)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
		})

		Convey("Missing nested index blob in identifyManifestsReferencedInIndex is skipped gracefully", func() {
			// Create a top-level index that contains a nested index
			// The nested index blob will be missing
			topLevelIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    godigest.FromString("missing-nested-index"),
						Size:      100,
					},
				},
			}

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					// Return ErrBlobNotFound for the missing nested index
					return nil, zerr.ErrBlobNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			// identifyManifestsReferencedInIndex should skip the missing nested index and continue
			referenced := make(map[godigest.Digest]bool)
			err := gc.identifyManifestsReferencedInIndex(topLevelIndex, repoName, referenced,
				map[godigest.Digest]struct{}{})
			So(err, ShouldBeNil)
			// No manifests should be marked as referenced since the nested index is missing
			So(len(referenced), ShouldEqual, 0)
		})

		Convey("identifyManifestsReferencedInIndex reads a shared nested index once", func() {
			childManifestDigest := godigest.FromString("leaf-manifest")
			subjectDigest := godigest.FromString("referrer-subject")

			sharedIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    subjectDigest,
					Size:      1,
				},
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    childManifestDigest,
						Size:      10,
					},
				},
			}
			sharedIndexBuf, err := json.Marshal(sharedIndex)
			So(err, ShouldBeNil)
			sharedIndexDigest := godigest.FromBytes(sharedIndexBuf)

			// Parent index names the same nested index digest twice (duplicate sibling refs).
			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    sharedIndexDigest,
						Size:      int64(len(sharedIndexBuf)),
					},
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    sharedIndexDigest,
						Size:      int64(len(sharedIndexBuf)),
					},
				},
			}

			readCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == sharedIndexDigest {
						readCount++

						return sharedIndexBuf, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			referenced := make(map[godigest.Digest]bool)
			err = gc.identifyManifestsReferencedInIndex(parentIndex, repoName, referenced,
				map[godigest.Digest]struct{}{})
			So(err, ShouldBeNil)
			So(readCount, ShouldEqual, 1)
			So(referenced[childManifestDigest], ShouldBeTrue)
			// Nested index with a subject is itself marked as referenced (referrer).
			So(referenced[sharedIndexDigest], ShouldBeTrue)
		})

		Convey("removeReferrersWithMissingSubject keeps a shared referrer whose subject is present", func() {
			subjectDigest := godigest.FromString("present-subject")

			sharedIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    subjectDigest,
					Size:      1,
				},
				Manifests: []ispec.Descriptor{},
			}
			sharedIndexBuf, err := json.Marshal(sharedIndex)
			So(err, ShouldBeNil)
			sharedIndexDigest := godigest.FromBytes(sharedIndexBuf)

			// rootIndex / parent lists the subject and duplicate refs to the shared referrer index.
			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    subjectDigest,
						Size:      1,
					},
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    sharedIndexDigest,
						Size:      int64(len(sharedIndexBuf)),
					},
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    sharedIndexDigest,
						Size:      int64(len(sharedIndexBuf)),
					},
				},
			}

			readCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == sharedIndexDigest {
						readCount++

						return sharedIndexBuf, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(readCount, ShouldEqual, 1)
			So(len(parentIndex.Manifests), ShouldEqual, 3)
		})

		Convey("removeReferrersWithMissingSubject GCs an orphaned referrer with missing subject", func() {
			missingSubject := godigest.FromString("missing-subject")

			orphanedReferrer := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    missingSubject,
					Size:      1,
				},
				Manifests: []ispec.Descriptor{},
			}
			orphanedBuf, err := json.Marshal(orphanedReferrer)
			So(err, ShouldBeNil)
			orphanedDigest := godigest.FromBytes(orphanedBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    orphanedDigest,
						Size:      int64(len(orphanedBuf)),
					},
				},
			}

			readCount := 0
			statCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == orphanedDigest {
						readCount++

						return orphanedBuf, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					if digest == orphanedDigest {
						statCount++
					}

					// Old enough to pass the retention delay check.
					return true, int64(len(orphanedBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(readCount, ShouldEqual, 1)
			So(statCount, ShouldEqual, 1)
			So(len(parentIndex.Manifests), ShouldEqual, 0)
		})

		Convey("removeReferrer removes cosign .sig by tag when digest is also listed untagged", func() {
			missingSubject := godigest.FromString("missing-subject")
			cosignTag := "sha256-" + missingSubject.Encoded() + ".sig"

			sharedManifest := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config:    ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
			}
			sharedBuf, err := json.Marshal(sharedManifest)
			So(err, ShouldBeNil)
			sharedDigest := godigest.FromBytes(sharedBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    sharedDigest,
						Size:      int64(len(sharedBuf)),
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    sharedDigest,
						Size:      int64(len(sharedBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}
			cosignDesc := parentIndex.Manifests[1]

			imgStore := mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, int64(len(sharedBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			deletedSig := false
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deletedSig = signedManifestDigest == missingSubject &&
						sm.SignatureDigest == sharedDigest.String() &&
						sm.SignatureType == storage.CosignType

					return nil
				},
			}

			gcOptions.Delay = 0
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrer(repoName, &parentIndex, cosignDesc, nil, "", nil)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deletedSig, ShouldBeTrue)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
			_, hasTag := parentIndex.Manifests[0].Annotations[ispec.AnnotationRefName]
			So(hasTag, ShouldBeFalse)
		})

		Convey("removeReferrer skips legacy cosign tag prune when subject digest is malformed", func() {
			malformedCosignTag := "sha256-not-a-valid-digest.sig"

			sharedManifest := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config:    ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
			}
			sharedBuf, err := json.Marshal(sharedManifest)
			So(err, ShouldBeNil)
			sharedDigest := godigest.FromBytes(sharedBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    sharedDigest,
						Size:      int64(len(sharedBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: malformedCosignTag,
						},
					},
				},
			}
			cosignDesc := parentIndex.Manifests[0]

			statCalled := false
			imgStore := mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					statCalled = true

					return true, int64(len(sharedBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			deletedSig := false
			removedRef := false
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deletedSig = true

					return nil
				},
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					removedRef = true

					return nil
				},
			}

			gcOptions.Delay = 0
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrer(repoName, &parentIndex, cosignDesc, nil, "", nil)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(statCalled, ShouldBeFalse)
			So(deletedSig, ShouldBeFalse)
			So(removedRef, ShouldBeFalse)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
			So(parentIndex.Manifests[0].Annotations[ispec.AnnotationRefName], ShouldEqual, malformedCosignTag)
		})

		Convey("removeReferrersWithMissingSubject GCs cosign .sig when digest is also listed untagged", func() {
			missingSubject := godigest.FromString("missing-subject")
			cosignTag := "sha256-" + missingSubject.Encoded() + ".sig"

			sharedManifest := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config:    ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
			}
			sharedBuf, err := json.Marshal(sharedManifest)
			So(err, ShouldBeNil)
			sharedDigest := godigest.FromBytes(sharedBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    sharedDigest,
						Size:      int64(len(sharedBuf)),
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    sharedDigest,
						Size:      int64(len(sharedBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}

			readCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == sharedDigest {
						readCount++

						return sharedBuf, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, int64(len(sharedBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			deletedSig := false
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deletedSig = signedManifestDigest == missingSubject &&
						sm.SignatureDigest == sharedDigest.String() &&
						sm.SignatureType == storage.CosignType

					return nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deletedSig, ShouldBeTrue)
			So(readCount, ShouldEqual, 1)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
			_, hasTag := parentIndex.Manifests[0].Annotations[ispec.AnnotationRefName]
			So(hasTag, ShouldBeFalse)
		})

		Convey("removeReferrer removes a cosign bundle attestation with a missing subject as a referrer", func() {
			missingSubject := godigest.FromString("missing-subject")
			annotations := map[string]string{zcommon.CosignBundlePredicateTypeAnnotation: "https://spdx.dev/Document"}

			referrer := ispec.Manifest{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: zcommon.ArtifactTypeCosignBundle,
				Config:       ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    missingSubject,
					Size:      1,
				},
				Annotations: annotations,
			}
			referrerBuf, err := json.Marshal(referrer)
			So(err, ShouldBeNil)
			referrerDigest := godigest.FromBytes(referrerBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
					},
				},
			}
			attestationDesc := parentIndex.Manifests[0]

			imgStore := mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, int64(len(referrerBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			removedReferences := 0
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					So("an attestation is not a signature", ShouldBeEmpty)

					return nil
				},
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					removedReferences++
					So(manifestDigest, ShouldEqual, referrerDigest)

					return nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{Delay: 0}
			gcOptions.Delay = 0
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrer(repoName, &parentIndex, attestationDesc, referrer.Subject,
				zcommon.ArtifactTypeCosignBundle, annotations)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(removedReferences, ShouldEqual, 1)
			So(parentIndex.Manifests, ShouldBeEmpty)
		})

		Convey("removeReferrer skips cosign path after subject path already GCd the row", func() {
			// OCI cosign referrer: subject in blob AND legacy .sig tag on the descriptor.
			// Subject path removes by tag first; cosign path must not retry the same tag
			// (ErrManifestNotFound would abort GC).
			missingSubject := godigest.FromString("missing-subject")
			cosignTag := "sha256-" + missingSubject.Encoded() + ".sig"

			referrer := ispec.Manifest{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: zcommon.ArtifactTypeCosign,
				Config:       ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    missingSubject,
					Size:      1,
				},
			}
			referrerBuf, err := json.Marshal(referrer)
			So(err, ShouldBeNil)
			referrerDigest := godigest.FromBytes(referrerBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}
			cosignDesc := parentIndex.Manifests[0]

			imgStore := mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, int64(len(referrerBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			deleteSignatureCalls := 0
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deleteSignatureCalls++
					So(signedManifestDigest, ShouldEqual, missingSubject)
					So(sm.SignatureDigest, ShouldEqual, referrerDigest.String())
					So(sm.SignatureType, ShouldEqual, storage.CosignType)

					return nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{Delay: 0}
			gcOptions.Delay = 0
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrer(repoName, &parentIndex, cosignDesc, referrer.Subject, zcommon.ArtifactTypeCosign, nil)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deleteSignatureCalls, ShouldEqual, 1)
			// Last-tag delete re-adds an untagged row.
			So(len(parentIndex.Manifests), ShouldEqual, 1)
			_, hasTag := parentIndex.Manifests[0].Annotations[ispec.AnnotationRefName]
			So(hasTag, ShouldBeFalse)
		})

		Convey("removeReferrersWithMissingSubject GCs OCI cosign referrer that also has a .sig tag", func() {
			missingSubject := godigest.FromString("missing-subject")
			cosignTag := "sha256-" + missingSubject.Encoded() + ".sig"

			referrer := ispec.Manifest{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: zcommon.ArtifactTypeCosign,
				Config:       ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    missingSubject,
					Size:      1,
				},
			}
			referrerBuf, err := json.Marshal(referrer)
			So(err, ShouldBeNil)
			referrerDigest := godigest.FromBytes(referrerBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == referrerDigest {
						return referrerBuf, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, int64(len(referrerBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			deleteSignatureCalls := 0
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deleteSignatureCalls++

					return nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}
			gcOptions.Delay = 0

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deleteSignatureCalls, ShouldBeGreaterThan, 0)
			// Untagged sibling remains; tagged .sig row is gone.
			So(len(parentIndex.Manifests), ShouldEqual, 1)
			_, hasTag := parentIndex.Manifests[0].Annotations[ispec.AnnotationRefName]
			So(hasTag, ShouldBeFalse)
		})

		Convey("removeManifestsPerRepoPolicy GCs both tags when orphaned referrer shares a digest", func() {
			// Last-tag delete re-adds an untagged row (RemoveManifestDescByReference).
			// A single removeReferrersWithMissingSubject pass leaves that row; the outer
			// removeManifestsPerRepoPolicy loop clears it on a later referrer pass.
			missingSubject := godigest.FromString("missing-subject")

			referrer := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config:    ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    missingSubject,
					Size:      1,
				},
			}
			referrerBuf, err := json.Marshal(referrer)
			So(err, ShouldBeNil)
			referrerDigest := godigest.FromBytes(referrerBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: "referrer-v1",
						},
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: "referrer-v2",
						},
					},
				},
			}

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == referrerDigest {
						return referrerBuf, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, int64(len(referrerBuf)), time.Now().Add(-24 * time.Hour), nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.removeManifestsPerRepoPolicy(context.Background(), repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(len(parentIndex.Manifests), ShouldEqual, 0)
		})

		Convey("removeReferrersWithMissingSubject keeps both tags when subject is present", func() {
			subjectDigest := godigest.FromString("present-subject")

			referrer := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config:    ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    subjectDigest,
					Size:      1,
				},
			}
			referrerBuf, err := json.Marshal(referrer)
			So(err, ShouldBeNil)
			referrerDigest := godigest.FromBytes(referrerBuf)

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    subjectDigest,
						Size:      1,
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: "referrer-v1",
						},
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    referrerDigest,
						Size:      int64(len(referrerBuf)),
						Annotations: map[string]string{
							ispec.AnnotationRefName: "referrer-v2",
						},
					},
				},
			}

			readCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == referrerDigest {
						readCount++

						return referrerBuf, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(readCount, ShouldEqual, 1)
			So(len(parentIndex.Manifests), ShouldEqual, 3)

			tags := map[string]bool{}
			for _, desc := range parentIndex.Manifests {
				if tag, ok := desc.Annotations[ispec.AnnotationRefName]; ok {
					tags[tag] = true
				}
			}
			So(tags["referrer-v1"], ShouldBeTrue)
			So(tags["referrer-v2"], ShouldBeTrue)
		})

		Convey("removeReferrersWithMissingSubject skips duplicate missing index blobs once", func() {
			missingDigest := godigest.FromString("missing-nested-index")

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    missingDigest,
						Size:      100,
					},
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    missingDigest,
						Size:      100,
					},
				},
			}

			readCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == missingDigest {
						readCount++
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(readCount, ShouldEqual, 1)
			So(len(parentIndex.Manifests), ShouldEqual, 2)
		})

		Convey("removeReferrersWithMissingSubject GCs cosign .sig after a sibling missing blob miss", func() {
			missingSubject := godigest.FromString("missing-subject")
			cosignTag := "sha256-" + missingSubject.Encoded() + ".sig"
			missingDigest := godigest.FromString("missing-shared-manifest")

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    missingDigest,
						Size:      10,
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    missingDigest,
						Size:      10,
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}

			readCount := 0
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == missingDigest {
						readCount++
					}

					return nil, zerr.ErrBlobNotFound
				},
				// Age check is independent of GetBlobContent: mock Stat success so this
				// case covers missing-cache + cosign sibling GC, not StatBlob fail-closed.
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 10, time.Now().Add(-24 * time.Hour), nil
				},
			}

			deletedSig := false
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deletedSig = signedManifestDigest == missingSubject &&
						sm.SignatureDigest == missingDigest.String() &&
						sm.SignatureType == storage.CosignType

					return nil
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}
			gcOptions.Delay = 0

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deletedSig, ShouldBeTrue)
			So(readCount, ShouldEqual, 1)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
			_, hasTag := parentIndex.Manifests[0].Annotations[ispec.AnnotationRefName]
			So(hasTag, ShouldBeFalse)
		})

		Convey("removeReferrersWithMissingSubject continues when StatBlob reports missing", func() {
			// StatBlob errors fail closed for age eligibility (do not delete the row here);
			// CleanRepo must not abort so removeStaleManifestEntries can still run later.
			missingSubject := godigest.FromString("missing-subject")
			cosignTag := "sha256-" + missingSubject.Encoded() + ".sig"
			missingDigest := godigest.FromString("missing-cosign-blob")

			parentIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    missingDigest,
						Size:      10,
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, errclass.MarkMissing(driver.PathNotFoundError{Path: digest.String(), DriverName: "local"})
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, errclass.MarkMissing(
						driver.PathNotFoundError{Path: digest.String(), DriverName: "local"})
				},
			}

			gcOptions.ImageRetention = config.ImageRetention{
				Delay: 0,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
					},
				},
			}
			gcOptions.Delay = 0

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			gced, err := gc.removeReferrersWithMissingSubject(repoName, &parentIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
		})

		Convey("identifyManifestsReferencedInIndex walks a diamond DAG once per node", func() {
			leafDigest := godigest.FromString("diamond-leaf")
			subjectDigest := godigest.FromString("leaf-subject")

			midLeft := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    leafDigest,
					Size:      1,
				}},
			}
			midLeftBuf, err := json.Marshal(midLeft)
			So(err, ShouldBeNil)
			midLeftDigest := godigest.FromBytes(midLeftBuf)

			midRight := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{{
					MediaType:   ispec.MediaTypeImageManifest,
					Digest:      leafDigest,
					Size:        1,
					Annotations: map[string]string{"branch": "right"},
				}},
			}
			midRightBuf, err := json.Marshal(midRight)
			So(err, ShouldBeNil)
			midRightDigest := godigest.FromBytes(midRightBuf)

			root := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    midLeftDigest,
						Size:      int64(len(midLeftBuf)),
					},
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    midRightDigest,
						Size:      int64(len(midRightBuf)),
					},
				},
			}

			leafManifest := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config:    ispec.Descriptor{Digest: godigest.FromString("cfg"), Size: 1},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    subjectDigest,
					Size:      1,
				},
			}
			leafBuf, err := json.Marshal(leafManifest)
			So(err, ShouldBeNil)

			reads := map[godigest.Digest]int{}
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					reads[digest]++

					switch digest {
					case midLeftDigest:
						return midLeftBuf, nil
					case midRightDigest:
						return midRightBuf, nil
					case leafDigest:
						return leafBuf, nil
					default:
						return nil, zerr.ErrBlobNotFound
					}
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			referenced := make(map[godigest.Digest]bool)
			err = gc.identifyManifestsReferencedInIndex(root, repoName, referenced,
				map[godigest.Digest]struct{}{})
			So(err, ShouldBeNil)
			So(midLeftDigest, ShouldNotEqual, midRightDigest)
			So(reads[midLeftDigest], ShouldEqual, 1)
			So(reads[midRightDigest], ShouldEqual, 1)
			So(reads[leafDigest], ShouldEqual, 1)
			// Leaf is referenced both as a nested manifest and as a referrer (has subject).
			So(referenced[leafDigest], ShouldBeTrue)
		})

		Convey("Error on ListBlobUploads in deleteBlobUploads", func() {
			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return true
				},
				ListBlobUploadsFn: func(repo string) ([]string, error) {
					return nil, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteBlobUploads(repoName, time.Hour)
			So(err, ShouldNotBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("Error on GetReferencedBlobs in deleteUnreferencedBlobs", func() {
			returnedIndex := ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("manifest-content")),
					},
				},
			}
			returnedIndexBuf, err := json.Marshal(returnedIndex)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteUnreferencedBlobs(repoName, time.Hour, log)
			So(err, ShouldNotBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("ErrStorageMissing on GetAllBlobs in deleteUnreferencedBlobs", func() {
			returnedIndex := ispec.Index{}
			returnedIndexBuf, err := json.Marshal(returnedIndex)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, errclass.MarkMissing(
						driver.PathNotFoundError{Path: "/blobs/sha256", DriverName: "local"})
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteUnreferencedBlobs(repoName, time.Hour, log)
			So(err, ShouldBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("Error on GetAllBlobs in deleteUnreferencedBlobs", func() {
			returnedIndex := ispec.Index{}
			returnedIndexBuf, err := json.Marshal(returnedIndex)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteUnreferencedBlobs(repoName, time.Hour, log)
			So(err, ShouldNotBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("StatBlobUpload error in deleteBlobUploads", func() {
			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return true
				},
				ListBlobUploadsFn: func(repo string) ([]string, error) {
					return []string{"upload-1"}, nil
				},
				StatBlobUploadFn: func(repo string, uuid string) (bool, int64, time.Time, error) {
					return false, 0, time.Time{}, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteBlobUploads(repoName, time.Hour)
			So(err, ShouldNotBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("Invalid digest from GetAllBlobs in deleteUnreferencedBlobs", func() {
			returnedIndex := ispec.Index{}
			returnedIndexBuf, err := json.Marshal(returnedIndex)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{godigest.Digest("invalid")}, nil
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteUnreferencedBlobs(repoName, time.Hour, log)
			So(err, ShouldNotBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("StatBlob error in deleteUnreferencedBlobs skips candidate and continues", func() {
			blobDigest := godigest.FromBytes([]byte("blob-content"))

			returnedIndex := ispec.Index{}
			returnedIndexBuf, err := json.Marshal(returnedIndex)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{blobDigest}, nil
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, 0, time.Time{}, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteUnreferencedBlobs(repoName, time.Hour, log)
			So(err, ShouldBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("CleanupRepo error in deleteUnreferencedBlobs", func() {
			blobDigest := godigest.FromBytes([]byte("blob-content"))

			returnedIndex := ispec.Index{}
			returnedIndexBuf, err := json.Marshal(returnedIndex)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{blobDigest}, nil
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return true, 100, time.Now().Add(-2 * time.Hour), nil
				},
				CleanupRepoFn: func(repo string, blobs []godigest.Digest) (int, error) {
					return 0, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			deleted, err := gc.deleteUnreferencedBlobs(repoName, time.Hour, log)
			So(err, ShouldNotBeNil)
			So(deleted, ShouldEqual, 0)
		})

		Convey("CleanRepo records error metrics when cleanRepo fails", func() {
			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return false
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err := gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeTrue)
		})

		Convey("removeStaleManifestEntries removes entries whose blobs are missing", func() {
			existingDigest := godigest.FromString("existing-blob")
			missingDigest := godigest.FromString("missing-blob")

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{existingDigest}, nil
				},
			}

			removedRef := ""
			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					removedRef = reference

					return nil
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    existingDigest,
						MediaType: ispec.MediaTypeImageManifest,
					},
					{
						Digest:    missingDigest,
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 1)
			So(index.Manifests[0].Digest, ShouldEqual, existingDigest)
			So(removedRef, ShouldEqual, missingDigest.String())
		})

		Convey("removeStaleManifestEntries uses tag as reference when available", func() {
			missingDigest := godigest.FromString("missing-blob")

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, nil
				},
			}

			removedRef := ""
			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					removedRef = reference

					return nil
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    missingDigest,
						MediaType: ispec.MediaTypeImageManifest,
						Annotations: map[string]string{
							ispec.AnnotationRefName: "v1.0",
						},
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
			So(removedRef, ShouldEqual, "v1.0")
		})

		Convey("removeStaleManifestEntries removes cosign signature via DeleteSignature when blob is missing", func() {
			subjectDigest := godigest.FromString("signed-manifest")
			missingSigDigest := godigest.FromString("missing-sig")
			cosignTag := "sha256-" + subjectDigest.Encoded() + ".sig"

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, nil
				},
			}

			deletedSig := false
			removedRef := false
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deletedSig = signedManifestDigest == subjectDigest &&
						sm.SignatureDigest == missingSigDigest.String() &&
						sm.SignatureType == storage.CosignType

					return nil
				},
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					removedRef = true

					return nil
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    missingSigDigest,
						MediaType: ispec.MediaTypeImageManifest,
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
			So(deletedSig, ShouldBeTrue)
			So(removedRef, ShouldBeFalse)
		})

		Convey("removeStaleManifestEntries falls back to RemoveRepoReference for malformed cosign tag", func() {
			missingSigDigest := godigest.FromString("missing-sig")
			malformedCosignTag := "sha256-not-a-valid-digest.sig"

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, nil
				},
			}

			deletedSig := false
			removedRef := ""
			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					deletedSig = true

					return nil
				},
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					removedRef = reference

					return nil
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    missingSigDigest,
						MediaType: ispec.MediaTypeImageManifest,
						Annotations: map[string]string{
							ispec.AnnotationRefName: malformedCosignTag,
						},
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
			So(deletedSig, ShouldBeFalse)
			So(removedRef, ShouldEqual, malformedCosignTag)
		})

		Convey("removeStaleManifestEntries skips in DryRun mode", func() {
			dryRunOptions := Options{
				Delay: storageConstants.DefaultGCDelay,
				ImageRetention: config.ImageRetention{
					DryRun: true,
					Delay:  storageConstants.DefaultGCDelay,
				},
			}

			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{}, dryRunOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("whatever"),
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 1)
		})

		Convey("removeStaleManifestEntries treats GetAllBlobs Missing as empty storage", func() {
			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, errclass.MarkMissing(driver.PathNotFoundError{})
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("blob"),
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
		})

		Convey("removeStaleManifestEntries aborts on GetAllBlobs Transient without pruning", func() {
			transient := errclass.MarkTransient(errors.New("list blip")) //nolint:err113 // test

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, transient
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			keptDigest := godigest.FromString("still-present")
			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    keptDigest,
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(len(index.Manifests), ShouldEqual, 1)
			So(index.Manifests[0].Digest, ShouldEqual, keptDigest)
		})

		Convey("removeStaleManifestEntries continues despite metaDB errors", func() {
			missingDigest := godigest.FromString("missing-blob")

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, nil
				},
			}

			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					return errGC
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    missingDigest,
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
		})

		Convey("removeStaleManifestEntries keeps sparse image index when some nested manifests exist", func() {
			indexDigest := godigest.FromString("image-index-blob")
			existingNested := godigest.FromString("existing-nested")
			missingNested := godigest.FromString("missing-nested")

			indexBlob, err := json.Marshal(ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{Digest: existingNested, MediaType: ispec.MediaTypeImageManifest},
					{Digest: missingNested, MediaType: ispec.MediaTypeImageManifest},
				},
			})
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{indexDigest, existingNested}, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == indexDigest {
						return indexBlob, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    indexDigest,
						MediaType: ispec.MediaTypeImageIndex,
						Size:      int64(len(indexBlob)),
					},
				},
			}

			err = gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 1)
			So(index.Manifests[0].Digest, ShouldEqual, indexDigest)
		})

		Convey("removeStaleManifestEntries drops image index when all nested manifests are missing", func() {
			indexDigest := godigest.FromString("image-index-blob")
			missingNested := godigest.FromString("missing-nested")

			indexBlob, err := json.Marshal(ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{Digest: missingNested, MediaType: ispec.MediaTypeImageManifest},
				},
			})
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{indexDigest}, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == indexDigest {
						return indexBlob, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    indexDigest,
						MediaType: ispec.MediaTypeImageIndex,
						Size:      int64(len(indexBlob)),
					},
				},
			}

			err = gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
		})

		Convey("removeStaleManifestEntries skips metaDB sync when metaDB is nil", func() {
			missingDigest := godigest.FromString("missing-blob")

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, nil
				},
			}

			gc := NewGarbageCollect(imgStore, nil, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    missingDigest,
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
		})

		Convey("removeStaleManifestEntries propagates image index read errors", func() {
			indexDigest := godigest.FromString("image-index-blob")

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{indexDigest}, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    indexDigest,
						MediaType: ispec.MediaTypeImageIndex,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldNotBeNil)
			So(len(index.Manifests), ShouldEqual, 1)
		})

		Convey("removeStaleManifestEntries drops image index when index blob is missing at read time", func() {
			indexDigest := godigest.FromString("image-index-blob")

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{indexDigest}, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, zerr.ErrBlobNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    indexDigest,
						MediaType: ispec.MediaTypeImageIndex,
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
		})

		Convey("removeStaleManifestEntries keeps image index when nested list is empty", func() {
			indexDigest := godigest.FromString("image-index-blob")

			indexBlob, err := json.Marshal(ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{},
			})
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{indexDigest}, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == indexDigest {
						return indexBlob, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    indexDigest,
						MediaType: ispec.MediaTypeImageIndex,
						Size:      int64(len(indexBlob)),
					},
				},
			}

			err = gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 1)
			So(index.Manifests[0].Digest, ShouldEqual, indexDigest)
		})

		Convey("removeStaleManifestEntries continues when cosign signature metadata is missing", func() {
			subjectDigest := godigest.FromString("signed-manifest")
			missingSigDigest := godigest.FromString("missing-sig")
			cosignTag := "sha256-" + subjectDigest.Encoded() + ".sig"

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, nil
				},
			}

			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					return zerr.ErrImageMetaNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    missingSigDigest,
						MediaType: ispec.MediaTypeImageManifest,
						Annotations: map[string]string{
							ispec.AnnotationRefName: cosignTag,
						},
					},
				},
			}

			err := gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
		})

		Convey("removeStaleManifestEntries syncs metaDB when dropping stale image index", func() {
			indexDigest := godigest.FromString("image-index-blob")
			missingNested := godigest.FromString("missing-nested")

			indexBlob, err := json.Marshal(ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{Digest: missingNested, MediaType: ispec.MediaTypeImageManifest},
				},
			})
			So(err, ShouldBeNil)

			removed := false
			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					if manifestDigest == indexDigest {
						removed = true
					}

					return nil
				},
			}

			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return []godigest.Digest{indexDigest}, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == indexDigest {
						return indexBlob, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log, metrics)

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    indexDigest,
						MediaType: ispec.MediaTypeImageIndex,
						Size:      int64(len(indexBlob)),
					},
				},
			}

			err = gc.removeStaleManifestEntries(repoName, index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 0)
			So(removed, ShouldBeTrue)
		})
	})
}

func TestCleanRepoWithStaleManifestEntries(t *testing.T) {
	ctx := context.Background()

	Convey("cleanRepo end-to-end prunes stale manifest entries", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")
		metrics := monitoring.NewNopMetricServer()

		existingDigest := godigest.FromString("existing-blob")
		missingDigest := godigest.FromString("missing-blob")

		returnedIndex := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					Digest:    existingDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
				{
					Digest:    missingDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		returnedIndexBuf, err := json.Marshal(returnedIndex)
		So(err, ShouldBeNil)

		var savedIndex ispec.Index

		imgStore := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return returnedIndexBuf, nil
			},
			GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
				return []godigest.Digest{existingDigest}, nil
			},
			PutIndexContentFn: func(repo string, index ispec.Index) error {
				savedIndex = index

				return nil
			},
			CleanupRepoFn: func(repo string, blobs []godigest.Digest) (int, error) {
				return 0, nil
			},
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				if digest == existingDigest {
					m := ispec.Manifest{
						SchemaVersion: 2,
					}
					b, _ := json.Marshal(m)

					return b, nil
				}

				return nil, zerr.ErrBlobNotFound
			},
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				if digest == existingDigest {
					return true, 100, time.Now().Add(-time.Hour), nil
				}

				return false, 0, time.Time{}, zerr.ErrBlobNotFound
			},
			ListBlobUploadsFn: func(repo string) ([]string, error) {
				return nil, nil
			},
		}

		falseVal := false
		gcOptions := Options{
			Delay: storageConstants.DefaultGCDelay,
			ImageRetention: config.ImageRetention{
				Delay: storageConstants.DefaultGCDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &falseVal,
					},
				},
			},
		}

		gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

		err = gc.cleanRepo(ctx, repoName)
		So(err, ShouldBeNil)
		So(len(savedIndex.Manifests), ShouldEqual, 1)
		So(savedIndex.Manifests[0].Digest, ShouldEqual, existingDigest)
	})

	Convey("cleanRepo aborts on GetAllBlobs Transient before PutIndexContent", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")
		metrics := monitoring.NewNopMetricServer()

		existingDigest := godigest.FromString("existing-blob")

		returnedIndex := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					Digest:    existingDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		returnedIndexBuf, err := json.Marshal(returnedIndex)
		So(err, ShouldBeNil)

		putIndexCalled := false
		cleanupCalled := false
		transient := errclass.MarkTransient(errors.New("list blip")) //nolint:err113 // test

		imgStore := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return returnedIndexBuf, nil
			},
			GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
				return nil, transient
			},
			PutIndexContentFn: func(repo string, index ispec.Index) error {
				putIndexCalled = true

				return nil
			},
			CleanupRepoFn: func(repo string, blobs []godigest.Digest) (int, error) {
				cleanupCalled = true

				return 0, nil
			},
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				m := ispec.Manifest{SchemaVersion: 2}
				b, _ := json.Marshal(m)

				return b, nil
			},
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				return true, 100, time.Now().Add(-time.Hour), nil
			},
			ListBlobUploadsFn: func(repo string) ([]string, error) {
				return nil, nil
			},
		}

		falseVal := false
		gcOptions := Options{
			Delay: storageConstants.DefaultGCDelay,
			ImageRetention: config.ImageRetention{
				Delay: storageConstants.DefaultGCDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &falseVal,
					},
				},
			},
		}

		gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

		err = gc.cleanRepo(ctx, repoName)
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		So(putIndexCalled, ShouldBeFalse)
		So(cleanupCalled, ShouldBeFalse)
	})
}

func TestGetSubjectFromCosignTag(t *testing.T) {
	Convey("cosign tag subject digests are parsed for both .sig and .sbom", t, func() {
		subjectDigest := godigest.FromString("app:v1")

		index := &ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					Digest:    subjectDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		Convey("signature tag resolves to the subject and stays referenced", func() {
			sigTag := "sha256-" + subjectDigest.Encoded() + ".sig"

			So(zcommon.IsCosignTag(sigTag), ShouldBeTrue)
			So(getSubjectFromCosignTag(sigTag), ShouldEqual, subjectDigest)
			So(isManifestReferencedInIndex(index, getSubjectFromCosignTag(sigTag)), ShouldBeTrue)
		})

		Convey("SBOM tag resolves to the subject and stays referenced", func() {
			sbomTag := "sha256-" + subjectDigest.Encoded() + ".sbom"

			So(zcommon.IsCosignTag(sbomTag), ShouldBeTrue)
			So(getSubjectFromCosignTag(sbomTag), ShouldEqual, subjectDigest)
			So(isManifestReferencedInIndex(index, getSubjectFromCosignTag(sbomTag)), ShouldBeTrue)
		})
	})
}

func TestCleanupRepoMissingBlob(t *testing.T) {
	Convey("CleanupRepo skips blobs that are already absent", t, func() {
		dir := t.TempDir()

		log := zlog.NewTestLogger()

		metrics := monitoring.NewNopMetricServer()

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		content := []byte("disappearing blob")
		digest := godigest.FromBytes(content)

		_, _, err := imgStore.FullBlobUpload(context.Background(), repoName, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		blobPath := path.Join(dir, repoName, "blobs", "sha256", digest.Encoded())
		err = os.Remove(blobPath)
		So(err, ShouldBeNil)

		count, err := imgStore.CleanupRepo(repoName, []godigest.Digest{digest})
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 1)
	})
}

// decodeGCTimeWindow runs the real config.GCTimeWindowDecodeHook used at config-unmarshal
// time, so these fixtures exercise the same path production config loading does; gc no
// longer parses or validates time windows itself (see config.GCTimeWindow).
func decodeGCTimeWindow(t *testing.T, window string) config.GCTimeWindow {
	t.Helper()

	var result config.GCTimeWindow

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: config.GCTimeWindowDecodeHook(),
		Result:     &result,
	})
	if err != nil {
		t.Fatalf("failed to create decoder: %v", err)
	}

	if err := decoder.Decode(window); err != nil {
		t.Fatalf("failed to decode gc time window %q: %v", window, err)
	}

	return result
}

func normalizeHour(hour int) int {
	return ((hour % 24) + 24) % 24
}

// windowAfter returns a one-hour "HH:MM-HH:MM" window starting an hour after hour:minute,
// so it never contains hour:minute.
func windowAfter(hour, minute int) string {
	return fmt.Sprintf("%02d:%02d-%02d:%02d", normalizeHour(hour+1), minute, normalizeHour(hour+2), minute)
}

// windowContaining returns a two-hour "HH:MM-HH:MM" window centered on hour:minute, with
// an hour of margin on each side so it safely contains hour:minute.
func windowContaining(hour, minute int) string {
	return fmt.Sprintf("%02d:%02d-%02d:%02d", normalizeHour(hour-1), minute, normalizeHour(hour+1), minute)
}

func TestGCTaskGeneratorTimeWindow(t *testing.T) {
	Convey("GCTaskGenerator.IsReady respects the configured time window", t, func() {
		now := time.Now().UTC()

		Convey("outside the window, generator is not ready", func() {
			outsideWindow := decodeGCTimeWindow(t, windowAfter(now.Hour(), now.Minute()))

			gen := &GCTaskGenerator{timeWindow: outsideWindow}
			So(gen.IsReady(), ShouldBeFalse)
		})

		Convey("inside the window, generator is ready", func() {
			insideWindow := decodeGCTimeWindow(t, windowContaining(now.Hour(), now.Minute()))

			gen := &GCTaskGenerator{timeWindow: insideWindow}
			So(gen.IsReady(), ShouldBeTrue)
		})

		Convey("no window configured, generator is ready", func() {
			gen := &GCTaskGenerator{}
			So(gen.IsReady(), ShouldBeTrue)
		})

		Convey("nextRun in the future, generator is not ready regardless of window", func() {
			gen := &GCTaskGenerator{nextRun: now.Add(time.Hour)}
			So(gen.IsReady(), ShouldBeFalse)
		})

		Convey("a sweep already in progress stays ready outside the window", func() {
			outsideWindow := decodeGCTimeWindow(t, windowAfter(now.Hour(), now.Minute()))

			gen := &GCTaskGenerator{
				timeWindow:     outsideWindow,
				processedRepos: map[string]struct{}{"repo1": {}},
				nextRun:        now.Add(-time.Second),
			}
			So(gen.IsReady(), ShouldBeTrue)
		})

		Convey("deferral outside the window is only logged once", func() {
			outsideWindow := decodeGCTimeWindow(t, windowAfter(now.Hour(), now.Minute()))

			gen := &GCTaskGenerator{
				gc:         GarbageCollect{log: zlog.NewTestLogger()},
				timeWindow: outsideWindow,
			}

			So(gen.IsReady(), ShouldBeFalse)
			So(gen.loggedWindowDefer, ShouldBeTrue)

			// stays deferred without logging again (no panic, flag stays set)
			So(gen.IsReady(), ShouldBeFalse)
			So(gen.loggedWindowDefer, ShouldBeTrue)

			// once the sweep is allowed to proceed, the flag resets for the next deferral episode
			gen.timeWindow = config.GCTimeWindow{}
			So(gen.IsReady(), ShouldBeTrue)
			So(gen.loggedWindowDefer, ShouldBeFalse)
		})
	})
}

func TestRemoveTagsPerRetentionPolicyMissingRepoMeta(t *testing.T) {
	Convey("tag retention keeps every tag when the repo record is missing", t, func() {
		oldDigest := godigest.FromString("old-matching-tag")
		newDigest := godigest.FromString("new-matching-tag")
		otherDigest := godigest.FromString("unmatched-tag")

		pushedWithin := 24 * time.Hour
		gcOptions := Options{
			Delay: time.Hour,
			ImageRetention: config.ImageRetention{
				Delay: time.Hour,
				Policies: []config.RetentionPolicy{
					{
						Repositories: []string{"**"},
						KeepTags: []config.KeepTagsPolicy{
							{
								Patterns:                []string{"^v[0-9]+$"},
								MostRecentlyPushedCount: 1,
								PushedWithin:            &pushedWithin,
							},
						},
					},
				},
			},
		}

		now := time.Now()
		repoMeta := types.RepoMeta{
			Name: repoName,
			Tags: map[types.Tag]types.Descriptor{
				"v1":    {Digest: oldDigest.String(), MediaType: ispec.MediaTypeImageManifest},
				"v2":    {Digest: newDigest.String(), MediaType: ispec.MediaTypeImageManifest},
				"other": {Digest: otherDigest.String(), MediaType: ispec.MediaTypeImageManifest},
			},
			Statistics: map[types.ImageDigest]types.DescriptorStatistics{
				oldDigest.String(): {
					PushTimestamp:     now.Add(-48 * time.Hour),
					LastPullTimestamp: now.Add(-48 * time.Hour),
				},
				newDigest.String(): {
					PushTimestamp:     now,
					LastPullTimestamp: now,
				},
				otherDigest.String(): {
					PushTimestamp:     now,
					LastPullTimestamp: now,
				},
			},
		}

		// Count and pushedWithin both drop v1 when statistics exist. A nil metaDB keeps every
		// tag matching the name pattern, including v1, and drops "other". A missing repo
		// record keeps every tag because count and time rules cannot be evaluated.
		testCases := []struct {
			name     string
			nilMeta  bool
			getErr   error
			wantErr  bool
			wantTags []string
		}{
			{name: "successful metadata trims by count and time", wantTags: []string{"v2"}},
			{name: "nil metadata keeps pattern matches", nilMeta: true, wantTags: []string{"v1", "v2"}},
			{
				name:     "direct ErrRepoMetaNotFound keeps every tag",
				getErr:   zerr.ErrRepoMetaNotFound,
				wantTags: []string{"other", "v1", "v2"},
			},
			{
				name:     "wrapped ErrRepoMetaNotFound keeps every tag",
				getErr:   fmt.Errorf("lookup repo: %w", zerr.ErrRepoMetaNotFound),
				wantTags: []string{"other", "v1", "v2"},
			},
			{
				name:     "unrelated metadata error is returned",
				getErr:   errGC,
				wantErr:  true,
				wantTags: []string{"other", "v1", "v2"},
			},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				index := tagRetentionIndex(oldDigest, newDigest, otherDigest)

				var metaDB types.MetaDB
				if !testCase.nilMeta {
					metaDB = mocks.MetaDBMock{
						GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
							if testCase.getErr != nil {
								return types.RepoMeta{}, testCase.getErr
							}

							return repoMeta, nil
						},
					}
				}

				gc := NewGarbageCollect(mocks.MockedImageStore{}, metaDB, gcOptions,
					zlog.NewAuditLogger("debug", ""), zlog.NewTestLogger(), monitoring.NewNopMetricServer())

				err := gc.removeTagsPerRetentionPolicy(context.Background(), repoName, &index)
				if testCase.wantErr {
					So(err, ShouldNotBeNil)
					So(errors.Is(err, errGC), ShouldBeTrue)
				} else {
					So(err, ShouldBeNil)
				}

				So(descriptorTags(index), ShouldResemble, testCase.wantTags)
			})
		}
	})
}

func TestRemoveUntaggedManifestsMissingRepoMeta(t *testing.T) {
	Convey("untagged retention keeps every manifest when the repo record is missing", t, func() {
		oldDrop := godigest.FromString("untagged-old-drop")
		oldKeep := godigest.FromString("untagged-old-keep")
		young := godigest.FromString("untagged-young")
		child := godigest.FromString("multiarch-child")

		manifestBlob, err := json.Marshal(ispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageManifest,
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    godigest.FromString("config"),
				Size:      2,
			},
			Layers: []ispec.Descriptor{},
		})
		So(err, ShouldBeNil)

		indexBlob, err := json.Marshal(ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageManifest, Digest: child, Size: 1},
			},
		})
		So(err, ShouldBeNil)

		indexDigest := godigest.FromBytes(indexBlob)
		retainedByPolicy := []string{indexDigest.String(), child.String(), oldKeep.String(), young.String()}
		retainedByDelay := []string{indexDigest.String(), child.String(), young.String()}
		allDigests := []string{
			indexDigest.String(), child.String(), oldDrop.String(), oldKeep.String(), young.String(),
		}

		slices.Sort(retainedByPolicy)
		slices.Sort(retainedByDelay)
		slices.Sort(allDigests)

		now := time.Now()
		repoMeta := types.RepoMeta{
			Name: repoName,
			Statistics: map[types.ImageDigest]types.DescriptorStatistics{
				oldDrop.String(): {PushTimestamp: now.Add(-48 * time.Hour), LastPullTimestamp: now.Add(-48 * time.Hour)},
				oldKeep.String(): {PushTimestamp: now.Add(-2 * time.Hour), LastPullTimestamp: now.Add(-2 * time.Hour)},
				young.String():   {PushTimestamp: now, LastPullTimestamp: now},
				child.String():   {PushTimestamp: now.Add(-48 * time.Hour), LastPullTimestamp: now.Add(-48 * time.Hour)},
			},
		}

		deleteUntagged := true
		gcOptions := Options{
			Delay: time.Hour,
			ImageRetention: config.ImageRetention{
				Delay: time.Hour,
				Policies: []config.RetentionPolicy{
					{
						Repositories:   []string{"**"},
						DeleteUntagged: &deleteUntagged,
						KeepUntagged: &config.KeepUntaggedPolicy{
							MostRecentlyPushedCount: 2,
						},
					},
				},
			},
		}

		imgStore := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				if digest == indexDigest {
					return indexBlob, nil
				}

				return manifestBlob, nil
			},
			StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
				if digest == young {
					return true, 1, time.Now(), nil
				}

				return true, 1, now.Add(-2 * time.Hour), nil
			},
		}

		testCases := []struct {
			name        string
			nilMeta     bool
			getErr      error
			wantErr     bool
			wantDigests []string
		}{
			{name: "metadata applies keepUntagged", wantDigests: retainedByPolicy},
			{name: "nil metadata uses retention delay", nilMeta: true, wantDigests: retainedByDelay},
			{
				name:        "direct ErrRepoMetaNotFound retains untagged",
				getErr:      zerr.ErrRepoMetaNotFound,
				wantDigests: allDigests,
			},
			{
				name:        "wrapped ErrRepoMetaNotFound retains untagged",
				getErr:      fmt.Errorf("lookup repo: %w", zerr.ErrRepoMetaNotFound),
				wantDigests: allDigests,
			},
			{name: "unrelated metadata error aborts", getErr: errGC, wantErr: true, wantDigests: allDigests},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				index := untaggedRetentionIndex(oldDrop, oldKeep, young, child, indexDigest)

				var metaDB types.MetaDB
				if !testCase.nilMeta {
					metaDB = mocks.MetaDBMock{
						GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
							if testCase.getErr != nil {
								return types.RepoMeta{}, testCase.getErr
							}

							return repoMeta, nil
						},
					}
				}

				gc := NewGarbageCollect(imgStore, metaDB, gcOptions,
					zlog.NewAuditLogger("debug", ""), zlog.NewTestLogger(), monitoring.NewNopMetricServer())

				err := gc.removeManifestsPerRepoPolicy(context.Background(), repoName, &index)
				if testCase.wantErr {
					So(err, ShouldNotBeNil)
					So(errors.Is(err, errGC), ShouldBeTrue)
				} else {
					So(err, ShouldBeNil)
				}

				So(sortedDigestStrings(index), ShouldResemble, testCase.wantDigests)
			})
		}
	})
}

func TestRemoveManifestDeleteSignatureMetadataErrors(t *testing.T) {
	Convey("removeManifest treats missing signature metadata as already cleaned", t, func() {
		testCases := []struct {
			name      string
			withMeta  bool
			deleteErr error
			wantErr   bool
		}{
			{name: "nil metadb permits removal"},
			{name: "nil delete error permits removal", withMeta: true},
			{name: "ErrImageMetaNotFound permits removal", withMeta: true, deleteErr: zerr.ErrImageMetaNotFound},
			{name: "ErrRepoMetaNotFound permits removal", withMeta: true, deleteErr: zerr.ErrRepoMetaNotFound},
			{
				name:      "wrapped ErrImageMetaNotFound permits removal",
				withMeta:  true,
				deleteErr: fmt.Errorf("delete signature: %w", zerr.ErrImageMetaNotFound),
			},
			{
				name:      "wrapped ErrRepoMetaNotFound permits removal",
				withMeta:  true,
				deleteErr: fmt.Errorf("delete signature: %w", zerr.ErrRepoMetaNotFound),
			},
			{name: "unrelated database error is returned", withMeta: true, deleteErr: errGC, wantErr: true},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				desc := ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    godigest.FromString("signature-manifest"),
				}
				index := &ispec.Index{Manifests: []ispec.Descriptor{desc}}

				var metaDB types.MetaDB
				if testCase.withMeta {
					metaDB = mocks.MetaDBMock{
						DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest,
							sm types.SignatureMetadata,
						) error {
							return testCase.deleteErr
						},
					}
				}

				gc := NewGarbageCollect(mocks.MockedImageStore{}, metaDB, Options{},
					zlog.NewAuditLogger("debug", ""), zlog.NewTestLogger(), monitoring.NewNopMetricServer())

				gced, err := gc.removeManifest(repoName, index, desc, desc.Digest.String(), storage.CosignType,
					godigest.FromString("signed-subject"))
				if testCase.wantErr {
					So(err, ShouldNotBeNil)
					So(errors.Is(err, errGC), ShouldBeTrue)
					So(gced, ShouldBeFalse)

					return
				}

				So(err, ShouldBeNil)
				So(gced, ShouldBeTrue)
				So(index.Manifests, ShouldBeEmpty)
			})
		}
	})
}

func TestRemoveUntaggedManifestsProgress(t *testing.T) {
	delay := time.Hour

	newGC := func(oldDigest godigest.Digest) (GarbageCollect, *bytes.Buffer, *bytes.Buffer) {
		var logBuf, auditBuf bytes.Buffer

		log := zlog.NewLoggerWithWriter("debug", &logBuf)
		audit := zlog.NewLoggerWithWriter("debug", &auditBuf)

		gc := GarbageCollect{
			imgStore: mocks.MockedImageStore{
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					if digest == oldDigest {
						return true, 1, time.Now().Add(-2 * delay), nil
					}

					return true, 1, time.Now(), nil
				},
			},
			opts:      Options{ImageRetention: config.ImageRetention{Delay: delay}},
			policyMgr: retentionPolicyMock{},
			log:       log,
			auditLog:  &audit,
		}

		return gc, &logBuf, &auditBuf
	}

	Convey("an eligible untagged manifest before a younger one still reports progress", t, func() {
		eligible := godigest.FromString("eligible-untagged")
		young := godigest.FromString("younger-untagged")
		index := &ispec.Index{
			Manifests: []ispec.Descriptor{
				{Digest: eligible, MediaType: ispec.MediaTypeImageManifest},
				{Digest: young, MediaType: ispec.MediaTypeImageManifest},
			},
		}

		gc, logBuf, auditBuf := newGC(eligible)
		gced, err := gc.removeUntaggedManifests(context.Background(), repoName, index, map[godigest.Digest]bool{})

		So(err, ShouldBeNil)
		So(gced, ShouldBeTrue)
		So(index.Manifests, ShouldHaveLength, 1)
		So(index.Manifests[0].Digest, ShouldEqual, young)
		So(untaggedDeletionLogs(logBuf.String(), eligible.String()), ShouldEqual, 1)
		So(untaggedDeletionLogs(logBuf.String(), young.String()), ShouldEqual, 0)
		So(untaggedDeletionLogs(auditBuf.String(), eligible.String()), ShouldEqual, 1)
		So(untaggedDeletionLogs(auditBuf.String(), young.String()), ShouldEqual, 0)
	})

	Convey("an untagged pass that removes nothing reports no progress", t, func() {
		first := godigest.FromString("young-first")
		second := godigest.FromString("young-second")
		index := &ispec.Index{
			Manifests: []ispec.Descriptor{
				{Digest: first, MediaType: ispec.MediaTypeImageManifest},
				{Digest: second, MediaType: ispec.MediaTypeImageManifest},
			},
		}

		// Neither descriptor is the old digest, so the age check keeps both.
		gc, logBuf, auditBuf := newGC(godigest.FromString("neither"))
		gced, err := gc.removeUntaggedManifests(context.Background(), repoName, index, map[godigest.Digest]bool{})

		So(err, ShouldBeNil)
		So(gced, ShouldBeFalse)
		So(index.Manifests, ShouldHaveLength, 2)
		So(logBuf.String(), ShouldNotContainSubstring, "removed untagged manifest")
		So(auditBuf.String(), ShouldNotContainSubstring, "removed untagged manifest")
	})
}

func TestCleanRepoCompletesWhenSignatureMetadataIsMissing(t *testing.T) {
	ctx := context.Background()
	repo := "gc-missing-meta"
	gcDelay := time.Hour

	Convey("cleanRepo finishes referrer and untagged GC when signature metadata is already gone", t, func() {
		harness := newMissingMetaCleanRepo(t, repo, gcDelay, zerr.ErrRepoMetaNotFound, false)

		err := harness.gc.cleanRepo(ctx, repo)
		So(err, ShouldBeNil)
		So(harness.calls.deleteCalls, ShouldEqual, 1)
		So(harness.calls.subject, ShouldEqual, harness.subject.manifest)
		So(harness.calls.meta.SignatureDigest, ShouldEqual, harness.signature.manifest.String())
		So(harness.calls.meta.SignatureType, ShouldEqual, storage.CosignType)
		So(slices.Contains(harness.calls.removed, harness.subject.manifest), ShouldBeTrue)
		So(slices.Contains(harness.calls.removed, harness.signature.manifest), ShouldBeTrue)

		indexBytes, err := harness.imgStore.GetIndexContent(repo)
		So(err, ShouldBeNil)

		var saved ispec.Index
		err = json.Unmarshal(indexBytes, &saved)
		So(err, ShouldBeNil)
		So(saved.Manifests, ShouldHaveLength, 1)
		So(saved.Manifests[0].Digest, ShouldEqual, harness.young.manifest)
		_, tagged := saved.Manifests[0].Annotations[ispec.AnnotationRefName]
		So(tagged, ShouldBeFalse)

		assertGCBlobs(harness.rootDir, repo, harness.subject, false)
		assertGCBlobs(harness.rootDir, repo, harness.signature, false)
		assertGCBlobs(harness.rootDir, repo, harness.young, true)

		remaining, err := harness.imgStore.GetAllBlobs(repo)
		So(err, ShouldBeNil)
		So(sortedDigests(remaining), ShouldResemble, sortedDigests([]godigest.Digest{
			harness.young.manifest, harness.young.config, harness.young.layer,
		}))
	})

	Convey("a genuine signature metadata failure does not persist the index or delete blobs", t, func() {
		harness := newMissingMetaCleanRepo(t, repo, gcDelay, errGC, false)

		err := harness.gc.cleanRepo(ctx, repo)
		So(err, ShouldNotBeNil)
		So(errors.Is(err, errGC), ShouldBeTrue)
		So(harness.calls.deleteCalls, ShouldEqual, 1)

		indexBytes, err := harness.imgStore.GetIndexContent(repo)
		So(err, ShouldBeNil)
		So(indexBytes, ShouldResemble, harness.indexBefore)

		assertGCBlobs(harness.rootDir, repo, harness.subject, true)
		assertGCBlobs(harness.rootDir, repo, harness.signature, true)
		assertGCBlobs(harness.rootDir, repo, harness.young, true)
	})

	Convey("dry-run leaves persisted storage and metadata untouched", t, func() {
		harness := newMissingMetaCleanRepo(t, repo, gcDelay, zerr.ErrRepoMetaNotFound, true)

		err := harness.gc.cleanRepo(ctx, repo)
		So(err, ShouldBeNil)
		So(harness.calls.deleteCalls, ShouldEqual, 0)
		So(harness.calls.removed, ShouldBeEmpty)

		indexBytes, err := harness.imgStore.GetIndexContent(repo)
		So(err, ShouldBeNil)
		So(indexBytes, ShouldResemble, harness.indexBefore)

		assertGCBlobs(harness.rootDir, repo, harness.subject, true)
		assertGCBlobs(harness.rootDir, repo, harness.signature, true)
		assertGCBlobs(harness.rootDir, repo, harness.young, true)
	})
}

type gcBlobSet struct {
	manifest     godigest.Digest
	config       godigest.Digest
	layer        godigest.Digest
	manifestSize int64
}

type signatureMetaCalls struct {
	deleteCalls int
	subject     godigest.Digest
	meta        types.SignatureMetadata
	removed     []godigest.Digest
}

type missingMetaCleanRepo struct {
	rootDir     string
	imgStore    storageTypes.ImageStore
	gc          GarbageCollect
	subject     gcBlobSet
	signature   gcBlobSet
	young       gcBlobSet
	indexBefore []byte
	calls       *signatureMetaCalls
}

func newMissingMetaCleanRepo(t *testing.T, repo string, gcDelay time.Duration, deleteErr error, dryRun bool,
) missingMetaCleanRepo {
	t.Helper()

	rootDir := t.TempDir()
	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()
	imgStore := local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)

	ctx := context.Background()
	subject := uploadGCManifest(ctx, imgStore, repo, "subject", []byte("subject-layer"))
	signature := uploadGCManifest(ctx, imgStore, repo, "signature", []byte("signature-layer"))
	young := uploadGCManifest(ctx, imgStore, repo, "young", []byte("young-layer"))

	// Eligible subject, then its legacy cosign tag, then a younger untagged manifest.
	// The young descriptor follows the subject so a sweep that forgets earlier progress
	// would stop before the orphaned signature can be removed.
	index := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    subject.manifest,
				Size:      subject.manifestSize,
			},
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    signature.manifest,
				Size:      signature.manifestSize,
				Annotations: map[string]string{
					ispec.AnnotationRefName: "sha256-" + subject.manifest.Encoded() + ".sig",
				},
			},
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    young.manifest,
				Size:      young.manifestSize,
			},
		},
	}

	err := imgStore.PutIndexContent(repo, index)
	So(err, ShouldBeNil)

	indexBefore, err := imgStore.GetIndexContent(repo)
	So(err, ShouldBeNil)

	err = backdateGCBlobs(rootDir, repo, subject, 2*gcDelay)
	So(err, ShouldBeNil)
	err = backdateGCBlobs(rootDir, repo, signature, 2*gcDelay)
	So(err, ShouldBeNil)

	calls := &signatureMetaCalls{}
	deleteUntagged := true
	gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{
		DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
			calls.deleteCalls++
			calls.subject = signedManifestDigest
			calls.meta = sm

			return deleteErr
		},
		RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
			calls.removed = append(calls.removed, manifestDigest)

			return nil
		},
	}, Options{
		Delay: gcDelay,
		ImageRetention: config.ImageRetention{
			Delay:  gcDelay,
			DryRun: dryRun,
			Policies: []config.RetentionPolicy{
				{
					Repositories:    []string{"**"},
					DeleteReferrers: true,
					DeleteUntagged:  &deleteUntagged,
				},
			},
		},
	}, zlog.NewAuditLogger("debug", ""), log, metrics)

	return missingMetaCleanRepo{
		rootDir:     rootDir,
		imgStore:    imgStore,
		gc:          gc,
		subject:     subject,
		signature:   signature,
		young:       young,
		indexBefore: indexBefore,
		calls:       calls,
	}
}

func uploadGCManifest(ctx context.Context, imgStore storageTypes.ImageStore, repo, author string, layer []byte,
) gcBlobSet {
	configBlob, err := json.Marshal(ispec.Image{
		Author: author,
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{godigest.FromBytes(layer)},
		},
	})
	So(err, ShouldBeNil)

	configDigest := godigest.FromBytes(configBlob)
	_, _, err = imgStore.FullBlobUpload(ctx, repo, bytes.NewReader(configBlob), configDigest)
	So(err, ShouldBeNil)

	layerDigest := godigest.FromBytes(layer)
	_, _, err = imgStore.FullBlobUpload(ctx, repo, bytes.NewReader(layer), layerDigest)
	So(err, ShouldBeNil)

	manifest := ispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageManifest,
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
				Size:      int64(len(layer)),
			},
		},
	}

	manifestBlob, err := json.Marshal(manifest)
	So(err, ShouldBeNil)

	manifestDigest := godigest.FromBytes(manifestBlob)
	_, _, err = imgStore.FullBlobUpload(ctx, repo, bytes.NewReader(manifestBlob), manifestDigest)
	So(err, ShouldBeNil)

	return gcBlobSet{
		manifest:     manifestDigest,
		config:       configDigest,
		layer:        layerDigest,
		manifestSize: int64(len(manifestBlob)),
	}
}

func backdateGCBlobs(rootDir, repo string, blobs gcBlobSet, age time.Duration) error {
	old := time.Now().Add(-age)

	for _, digest := range []godigest.Digest{blobs.manifest, blobs.config, blobs.layer} {
		blobPath := path.Join(rootDir, repo, "blobs", digest.Algorithm().String(), digest.Encoded())
		if err := os.Chtimes(blobPath, old, old); err != nil {
			return err
		}
	}

	return nil
}

func assertGCBlobs(rootDir, repo string, blobs gcBlobSet, present bool) {
	for _, digest := range []godigest.Digest{blobs.manifest, blobs.config, blobs.layer} {
		_, err := os.Stat(path.Join(rootDir, repo, "blobs", digest.Algorithm().String(), digest.Encoded()))
		So(err == nil, ShouldEqual, present)
	}
}

func tagRetentionIndex(oldDigest, newDigest, otherDigest godigest.Digest) ispec.Index {
	return ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{
			taggedManifestDesc(oldDigest, "v1"),
			taggedManifestDesc(newDigest, "v2"),
			taggedManifestDesc(otherDigest, "other"),
		},
	}
}

func taggedManifestDesc(digest godigest.Digest, tag string) ispec.Descriptor {
	return ispec.Descriptor{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    digest,
		Size:      1,
		Annotations: map[string]string{
			ispec.AnnotationRefName: tag,
		},
	}
}

func untaggedRetentionIndex(oldDrop, oldKeep, young, child, indexDigest godigest.Digest) ispec.Index {
	return ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{
			{MediaType: ispec.MediaTypeImageManifest, Digest: oldDrop, Size: 1},
			{MediaType: ispec.MediaTypeImageManifest, Digest: oldKeep, Size: 1},
			{MediaType: ispec.MediaTypeImageManifest, Digest: young, Size: 1},
			{MediaType: ispec.MediaTypeImageManifest, Digest: child, Size: 1},
			{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    indexDigest,
				Size:      1,
				Annotations: map[string]string{
					ispec.AnnotationRefName: "multi",
				},
			},
		},
	}
}

func descriptorTags(index ispec.Index) []string {
	tags := make([]string, 0)

	for _, desc := range index.Manifests {
		tag, ok := getDescriptorTag(desc)
		if ok {
			tags = append(tags, tag)
		}
	}

	slices.Sort(tags)

	return tags
}

func sortedDigestStrings(index ispec.Index) []string {
	digests := make([]string, 0, len(index.Manifests))

	for _, desc := range index.Manifests {
		digests = append(digests, desc.Digest.String())
	}

	slices.Sort(digests)

	return digests
}

func sortedDigests(digests []godigest.Digest) []string {
	sorted := make([]string, 0, len(digests))

	for _, digest := range digests {
		sorted = append(sorted, digest.String())
	}

	slices.Sort(sorted)

	return sorted
}

func untaggedDeletionLogs(logs, digest string) int {
	count := 0

	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "removed untagged manifest") && strings.Contains(line, digest) {
			count++
		}
	}

	return count
}
