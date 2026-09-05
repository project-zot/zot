package gc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/go-viper/mapstructure/v2"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
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

		Convey("Error on gc.gcReferrer() in gc.cleanManifests() with image index", func() {
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
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.gcReferrer() in gc.cleanManifests() with image", func() {
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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.removeManifestsPerRepoPolicy(ctx, repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					manifestDesc,
				},
			})
			So(err, ShouldNotBeNil)
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
			gced, err := gc.removeReferrer(repoName, &parentIndex, desc, subject, zcommon.ArtifactTypeNotation)
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deletedSig, ShouldBeTrue)
			So(len(parentIndex.Manifests), ShouldEqual, 0)
		})

		Convey("removeReferrer returns error when cosign path cannot stat blob", func() {
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

			gced, err := gc.removeReferrer(repoName, &parentIndex, desc, nil, "")
			So(err, ShouldNotBeNil)
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

			gced, err := gc.removeReferrer(repoName, &parentIndex, cosignDesc, nil, "")
			So(err, ShouldBeNil)
			So(gced, ShouldBeTrue)
			So(deletedSig, ShouldBeTrue)
			So(len(parentIndex.Manifests), ShouldEqual, 1)
			_, hasTag := parentIndex.Manifests[0].Annotations[ispec.AnnotationRefName]
			So(hasTag, ShouldBeFalse)
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

			gced, err := gc.removeReferrer(repoName, &parentIndex, cosignDesc, referrer.Subject, zcommon.ArtifactTypeCosign)
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

		Convey("removeReferrersWithMissingSubject aborts when StatBlob reports missing", func() {
			// Match main: StatBlob errors (including ErrBlobNotFound from ImageStore's
			// error collapsing) fail closed in isBlobOlderThan.
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
					return nil, driver.PathNotFoundError{Path: digest.String(), DriverName: "local"}
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, driver.PathNotFoundError{Path: digest.String(), DriverName: "local"}
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
			So(err, ShouldNotBeNil)
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

		Convey("PathNotFoundError on GetAllBlobs in deleteUnreferencedBlobs", func() {
			returnedIndex := ispec.Index{}
			returnedIndexBuf, err := json.Marshal(returnedIndex)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, driver.PathNotFoundError{Path: "/blobs/sha256", DriverName: "local"}
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

		Convey("StatBlob error in deleteUnreferencedBlobs", func() {
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
			So(err, ShouldNotBeNil)
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

		Convey("CleanRepo fails when the repo lock is unavailable", func() {
			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return true
				},
				LockRepoFn: func(ctx context.Context, repo string) (storageTypes.RepoLock, error) {
					return nil, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err := gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, errGC), ShouldBeTrue)
		})

		Convey("CleanRepo fails before the index write when the repo lock was lost mid-sweep", func() {
			indexWritten := false
			emptyIndex, err := json.Marshal(ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}})
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return true
				},
				LockRepoFn: func(ctx context.Context, repo string) (storageTypes.RepoLock, error) {
					return mocks.RepoLockMock{StillHeldFn: func(context.Context) bool { return false }}, nil
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return emptyIndex, nil
				},
				PutIndexContentFn: func(repo string, index ispec.Index) error {
					indexWritten = true

					return nil
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log, metrics)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrRepoLockUnavailable), ShouldBeTrue)
			So(indexWritten, ShouldBeFalse)
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

		Convey("removeStaleManifestEntries treats GetAllBlobs PathNotFound as empty storage", func() {
			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, driver.PathNotFoundError{}
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
					m := ispec.Manifest{}
					m.SchemaVersion = 2
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
