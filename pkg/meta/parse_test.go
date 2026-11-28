package meta_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	dockerList "github.com/distribution/distribution/v3/manifest/manifestlist"
	docker "github.com/distribution/distribution/v3/manifest/schema2"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	rediscfg "zotregistry.dev/zot/v2/pkg/api/config/redis"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	"zotregistry.dev/zot/v2/pkg/meta/dynamodb"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	"zotregistry.dev/zot/v2/pkg/meta/redis"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	tcommon "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
	"zotregistry.dev/zot/v2/pkg/test/signature"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

const repo = "repo"

// errMetaTestInjected is returned from mocks in this file to assert error paths in ParseStorage and related tests.
var errMetaTestInjected = errors.New("injected error for parse_test mocks")

func TestParseStorageErrors(t *testing.T) {
	ctx := context.Background()

	Convey("ParseStorage", t, func() {
		imageStore := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return nil, errMetaTestInjected
			},
			GetRepositoriesFn: func() ([]string, error) {
				return []string{"repo1", "repo2"}, nil
			},
		}
		storeController := storage.StoreController{DefaultStore: imageStore}
		metaDB := mocks.MetaDBMock{}

		// sync repo fail
		err := meta.ParseStorage(metaDB, storeController, log.NewTestLogger())
		So(err, ShouldBeNil)

		Convey("getAllRepos errors", func() {
			imageStore1 := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{"repo1", "repo2"}, nil
				},
			}
			imageStore2 := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return nil, errMetaTestInjected
				},
			}
			storeController := storage.StoreController{
				DefaultStore: imageStore1,
				SubStore: map[string]storageTypes.ImageStore{
					"a": imageStore2,
				},
			}

			err := meta.ParseStorage(metaDB, storeController, log.NewTestLogger())
			So(err, ShouldNotBeNil)
		})

		Convey("metaDB.GetAllRepoNames errors", func() {
			metaDB.GetAllRepoNamesFn = func() ([]string, error) { return nil, errMetaTestInjected }

			err := meta.ParseStorage(metaDB, storeController, log.NewTestLogger())
			So(err, ShouldNotBeNil)
		})

		Convey("metaDB.DeleteRepoMeta errors", func() {
			imageStore1 := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) { return []string{"repo1", "repo2"}, nil },
			}
			storeController := storage.StoreController{DefaultStore: imageStore1}

			metaDB.GetAllRepoNamesFn = func() ([]string, error) { return []string{"deleted"}, nil }
			metaDB.DeleteRepoMetaFn = func(repo string) error { return errMetaTestInjected }

			err := meta.ParseStorage(metaDB, storeController, log.NewTestLogger())
			So(err, ShouldNotBeNil)
		})

		Convey("StatIndex errors", func() {
			imageStore1 := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) { return []string{"repo1", "repo2"}, nil },
			}
			imageStore1.StatIndexFn = func(repo string) (bool, int64, time.Time, error) {
				return false, 0, time.Time{}, errMetaTestInjected
			}

			storeController := storage.StoreController{DefaultStore: imageStore1}

			err := meta.ParseStorage(metaDB, storeController, log.NewTestLogger())
			So(err, ShouldBeNil)
		})
	})

	Convey("Parse Repo", t, func() {
		imageStore := mocks.MockedImageStore{}
		storeController := storage.StoreController{DefaultStore: &imageStore}
		metaDB := mocks.MetaDBMock{}
		log := log.NewTestLogger()

		Convey("imageStore.GetIndexContent errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return nil, errMetaTestInjected
			}

			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("json.Unmarshal errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return []byte("Invalid JSON"), nil
			}

			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("resetRepoReferences errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return []byte("{}"), nil
			}
			metaDB.ResetRepoReferencesFn = func(repo string, tagsToKeep map[string]bool) error { return errMetaTestInjected }
			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("zcommon.IsReferrersTag", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return getIndexBlob(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromString("digest"),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							},
						},
					},
				}), nil
			}
			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldBeNil)
		})

		Convey("imageStore.GetBlobContent non-missing error", func() {
			manifestDigest := godigest.FromString("digest")
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return getIndexBlob(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    manifestDigest,
							Annotations: map[string]string{
								ispec.AnnotationRefName: "tag",
							},
						},
					},
				}), nil
			}
			imageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
				// Return a non-missing error (not ErrBlobNotFound or PathNotFoundError)
				return nil, errMetaTestInjected
			}
			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, errMetaTestInjected)
		})

		Convey("imageStore.GetImageManifest missing blob - graceful handling", func() {
			digest1 := godigest.FromString("digest1")
			digest2 := godigest.FromString("digest2")
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return getIndexBlob(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    digest1,
							Annotations: map[string]string{
								ispec.AnnotationRefName: "tag1",
							},
						},
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    digest2,
							Annotations: map[string]string{
								ispec.AnnotationRefName: "tag2",
							},
						},
					},
				}), nil
			}
			callCount := 0
			setRepoRefCount := 0
			// Create a valid image for the second manifest
			validImage := CreateRandomImage()
			manifestBlob, _ := json.Marshal(validImage.Manifest)
			configBlob, _ := json.Marshal(validImage.Config)
			imageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
				callCount++
				// First manifest is missing, second one succeeds
				if digest == digest1 {
					return nil, zerr.ErrBlobNotFound
				}

				if digest == digest2 {
					// Return valid manifest for second one
					return manifestBlob, nil
				}
				// Return config blob when requested
				if digest == validImage.ConfigDescriptor.Digest {
					return configBlob, nil
				}

				return nil, zerr.ErrBlobNotFound
			}
			metaDB.SetRepoReferenceFn = func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
				setRepoRefCount++
				// Verify it's only called for tag2 (the second manifest)
				So(reference, ShouldEqual, "tag2")

				return nil
			}
			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldBeNil)
			// Should have called GetBlobContent for both manifests (and config)
			So(callCount, ShouldEqual, 3)
			// Should have called SetRepoReference only once for the second manifest (first was skipped)
			So(setRepoRefCount, ShouldEqual, 1)
		})

		Convey("manifestMetaIsPresent true", func() {
			indexContent := ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("manifest1"),
						MediaType: ispec.MediaTypeImageManifest,
						Annotations: map[string]string{
							ispec.AnnotationRefName: "tag1",
						},
					},
				},
			}
			indexBlob, err := json.Marshal(indexContent)
			So(err, ShouldBeNil)

			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return indexBlob, nil
			}

			Convey("metaDB.SetRepoReference", func() {
				metaDB.SetRepoReferenceFn = func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					return errMetaTestInjected
				}

				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
		})
	})

	image := CreateRandomImage()

	Convey("SetImageMetaFromInput errors", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		mockedMetaDB := mocks.MetaDBMock{}
		log := log.NewTestLogger()

		Convey("Image Manifest errors", func() {
			Convey("Get Config blob error", func() {
				mockImageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, errMetaTestInjected
				}

				err := meta.SetImageMetaFromInput(ctx, "repo", "tag", ispec.MediaTypeImageManifest, image.Digest(),
					image.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
				So(err, ShouldNotBeNil)
			})
			Convey("Unmarshal config blob error", func() {
				mockImageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte("bad-blob"), nil
				}

				err := meta.SetImageMetaFromInput(ctx, "repo", "tag", ispec.MediaTypeImageManifest, image.Digest(),
					image.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
				So(err, ShouldNotBeNil)
			})
			Convey("Is Signature", func() {
				image := CreateDefaultImage()
				mediaType := ispec.MediaTypeImageManifest
				// it has more than 1 layer
				badNotationSignature := CreateImageWith().RandomLayers(2, 10).EmptyConfig().Subject(image.DescriptorRef()).
					ArtifactType(zcommon.ArtifactTypeNotation).Build()
				goodNotationSignature := CreateMockNotationSignature(image.DescriptorRef())

				Convey("GetSignatureLayersInfo errors", func() {
					err := meta.SetImageMetaFromInput(ctx, "repo", "tag", mediaType, badNotationSignature.Digest(),
						badNotationSignature.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
					So(err, ShouldNotBeNil)
				})
				Convey("UpdateSignaturesValidity errors", func() {
					mockedMetaDB.UpdateSignaturesValidityFn = func(ctx context.Context, repo string,
						manifestDigest godigest.Digest,
					) error {
						return errMetaTestInjected
					}
					err := meta.SetImageMetaFromInput(ctx, "repo", "tag", mediaType, goodNotationSignature.Digest(),
						goodNotationSignature.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
					So(err, ShouldNotBeNil)
				})
			})
		})
		Convey("Image Index errors", func() {
			Convey("Unmarshal error", func() {
				err := meta.SetImageMetaFromInput(ctx, "repo", "tag", ispec.MediaTypeImageIndex, "",
					[]byte("bad-json"), mockImageStore, mockedMetaDB, log)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestSetImageMetaFromInputPreservesDescriptorMediaType(t *testing.T) {
	ctx := context.Background()
	logger := log.NewTestLogger()

	Convey("Docker manifest media type", t, func() {
		image := CreateRandomImage().AsDockerImage()
		configBlob, err := json.Marshal(image.Config)
		So(err, ShouldBeNil)

		var storedImageMeta mTypes.ImageMeta

		imageStore := mocks.MockedImageStore{
			GetBlobContentFn: func(string, godigest.Digest) ([]byte, error) {
				return configBlob, nil
			},
		}
		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(_ context.Context, _, _ string, imageMeta mTypes.ImageMeta) error {
				storedImageMeta = imageMeta

				return nil
			},
		}

		err = meta.SetImageMetaFromInput(ctx, "repo", "tag", docker.MediaTypeManifest, image.Digest(),
			image.ManifestDescriptor.Data, imageStore, metaDB, logger)
		So(err, ShouldBeNil)
		So(storedImageMeta.MediaType, ShouldEqual, docker.MediaTypeManifest)
	})

	Convey("Docker manifest-list media type", t, func() {
		multiarch := CreateRandomMultiarch().AsDockerImage()

		var storedImageMeta mTypes.ImageMeta

		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(_ context.Context, _, _ string, imageMeta mTypes.ImageMeta) error {
				storedImageMeta = imageMeta

				return nil
			},
		}

		err := meta.SetImageMetaFromInput(ctx, "repo", "tag", dockerList.MediaTypeManifestList,
			multiarch.Digest(), multiarch.IndexDescriptor.Data, mocks.MockedImageStore{}, metaDB, logger)
		So(err, ShouldBeNil)
		So(storedImageMeta.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
		So(storedImageMeta.Index.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
	})
}

func getIndexBlob(index ispec.Index) []byte {
	index.MediaType = ispec.MediaTypeImageIndex

	blob, err := json.Marshal(index)
	if err != nil {
		panic("image index should always be marshable")
	}

	return blob
}

func TestParseStorageWithBoltDB(t *testing.T) {
	Convey("Boltdb", t, func() {
		rootDir := t.TempDir()
		log := log.NewLogger("debug", "/dev/null")

		boltDB, err := boltdb.GetBoltDriver(boltdb.DBParameters{
			RootDir: rootDir,
		})
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDB, log)
		So(err, ShouldBeNil)

		RunParseStorageTests(rootDir, metaDB, log)
	})
}

func TestParseStorageWithRedisDB(t *testing.T) {
	Convey("Redis", t, func() {
		miniRedis := miniredis.RunT(t)

		rootDir := t.TempDir()
		log := log.NewTestLogger()

		params := redis.DBDriverParameters{KeyPrefix: "zot"}
		driverConfig := map[string]any{"url": "redis://" + miniRedis.Addr()}

		redisDriver, err := rediscfg.GetRedisClient(driverConfig, log)
		So(err, ShouldBeNil)

		metaDB, err := redis.New(redisDriver, params, log)
		So(metaDB, ShouldNotBeNil)
		So(err, ShouldBeNil)

		RunParseStorageTests(rootDir, metaDB, log)
	})
}

func TestParseStoragePullRetention(t *testing.T) {
	Convey("pulledWithin retains an old tag after Redis loses its pull history", t, func() {
		ctx := context.Background()
		miniRedis := miniredis.RunT(t)
		logger := log.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		imageStore := local.NewImageStore(t.TempDir(), false, false, logger, metrics, nil, nil, nil, nil)
		storeController := storage.StoreController{DefaultStore: imageStore}
		client, err := rediscfg.GetRedisClient(map[string]any{"url": "redis://" + miniRedis.Addr()}, logger)
		So(err, ShouldBeNil)
		metaDB, err := redis.New(client, redis.DBDriverParameters{KeyPrefix: "zot"}, logger)
		So(err, ShouldBeNil)

		const tag = "old"
		image := CreateRandomImage()
		So(WriteImageToFileSystem(image, repo, tag, storeController), ShouldBeNil)
		body, digest, mediaType, err := imageStore.GetImageManifest(repo, tag)
		So(err, ShouldBeNil)
		So(meta.OnUpdateManifest(ctx, repo, tag, mediaType, digest, body, storeController, metaDB, logger), ShouldBeNil)
		repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		unpulled := repoMeta.Statistics[digest.String()]
		So(unpulled.LastPullTimestamp.Equal(time.Unix(0, 0)), ShouldBeTrue)
		So(meta.ParseRepo(repo, metaDB, storeController, logger), ShouldBeNil)
		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		So(repoMeta.Statistics[digest.String()], ShouldResemble, unpulled)

		pulledWithin := 7 * 24 * time.Hour
		pushedAt := time.Now().Add(-2 * pulledWithin)
		So(os.Chtimes(imageStore.BlobPath(repo, digest), pushedAt, pushedAt), ShouldBeNil)
		So(meta.OnGetManifest(repo, tag, mediaType, body, storeController, metaDB, logger), ShouldBeNil)
		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		So(repoMeta.Statistics[digest.String()].DownloadCount, ShouldEqual, 1)

		miniRedis.FlushAll()
		_, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldEqual, zerr.ErrRepoMetaNotFound)
		parseStarted := time.Now()
		So(meta.MaybeParseStorage(metaDB, storeController, true, "v1", logger), ShouldBeNil)
		parseFinished := time.Now()
		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		recovered := repoMeta.Statistics[digest.String()]
		So(recovered.PushTimestamp, ShouldHappenWithin, time.Minute, pushedAt)
		So(recovered.DownloadCount, ShouldEqual, 0)
		So(repoMeta.DownloadCount, ShouldEqual, 0)

		collector := gc.NewGarbageCollect(imageStore, metaDB, gc.Options{
			ImageRetention: config.ImageRetention{
				Policies: []config.RetentionPolicy{{
					Repositories: []string{repo},
					KeepTags:     []config.KeepTagsPolicy{{Patterns: []string{".*"}, PulledWithin: &pulledWithin}},
				}},
			},
		}, &logger, logger, metrics)
		So(collector.CleanRepo(ctx, repo), ShouldBeNil)
		_, retainedDigest, _, err := imageStore.GetImageManifest(repo, tag)
		So(err, ShouldBeNil)
		So(retainedDigest, ShouldEqual, digest)
		So(recovered.LastPullTimestamp.Before(parseStarted), ShouldBeFalse)
		So(recovered.LastPullTimestamp.After(parseFinished), ShouldBeFalse)

		So(meta.ParseRepo(repo, metaDB, storeController, logger), ShouldBeNil)
		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		So(repoMeta.Statistics[digest.String()], ShouldResemble, recovered)

		So(meta.OnGetManifest(repo, tag, mediaType, body, storeController, metaDB, logger), ShouldBeNil)
		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		pulled := repoMeta.Statistics[digest.String()]
		So(pulled.DownloadCount, ShouldEqual, 1)
		So(pulled.LastPullTimestamp, ShouldHappenAfter, recovered.LastPullTimestamp)
		So(meta.ParseRepo(repo, metaDB, storeController, logger), ShouldBeNil)
		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		So(repoMeta.Statistics[digest.String()], ShouldResemble, pulled)
	})
}

func TestParseStorageDynamoWrapper(t *testing.T) {
	tskip.SkipDynamo(t)

	// Unique table names once per test: ResetTable deletes tables; shared fixed names race
	// with other packages (e.g. pkg/api TestObjectStorageController) under `go test ./...`.
	// Keep the UUID outside the outer Convey so GoConvey re-runs for nested cases in
	// RunParseStorageTests reuse one table set instead of creating a new one each time.
	tableSuffix, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	Convey("Dynamodb", t, func() {
		rootDir := t.TempDir()
		log := log.NewLogger("debug", "/dev/null")

		params := dynamodb.DBDriverParameters{
			Endpoint:               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			Region:                 "us-east-2",
			RepoMetaTablename:      "RepoMetadataTable" + tableSuffix.String(),
			RepoBlobsInfoTablename: "RepoBlobsInfoTablename" + tableSuffix.String(),
			ImageMetaTablename:     "ImageMetaTablename" + tableSuffix.String(),
			UserDataTablename:      "UserDataTable" + tableSuffix.String(),
			APIKeyTablename:        "ApiKeyTable" + tableSuffix.String(),
			VersionTablename:       "Version" + tableSuffix.String(),
		}

		dynamoClient, err := dynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := dynamodb.New(dynamoClient, params, log)
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename)
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetTable(dynamoWrapper.RepoBlobsTablename)
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetTable(dynamoWrapper.ImageMetaTablename)
		So(err, ShouldBeNil)

		RunParseStorageTests(rootDir, dynamoWrapper, log)
	})
}

func RunParseStorageTests(rootDir string, metaDB mTypes.MetaDB, log log.Logger) {
	ctx := context.Background()

	Convey("Push timestamp falls back to the manifest blob storage mod time", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		image := CreateRandomImage() //nolint:staticcheck

		err := WriteImageToFileSystem(image, repo, "tag1", storeController)
		So(err, ShouldBeNil)

		// Backdate the manifest blob: after a metaDB loss the real push time is gone,
		// so the storage mod time is the only remaining record of when it was pushed.
		manifestDigest := image.ManifestDescriptor.Digest
		blobPath := imageStore.BlobPath(repo, manifestDigest)
		pushedAt := time.Now().Add(-72 * time.Hour)

		err = os.Chtimes(blobPath, pushedAt, pushedAt)
		So(err, ShouldBeNil)

		parseStarted := time.Now()
		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)

		stats, ok := repoMeta.Statistics[manifestDigest.String()]
		So(ok, ShouldBeTrue)
		So(stats.PushTimestamp, ShouldHappenWithin, time.Minute, pushedAt)
		So(stats.LastPullTimestamp, ShouldHappenWithin, time.Minute, parseStarted)
		So(stats.DownloadCount, ShouldEqual, 0)
		So(repoMeta.Tags["tag1"].TaggedTimestamp.IsZero(), ShouldBeTrue)
	})

	Convey("Test with simple case", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		manifests := []ispec.Manifest{}

		for i := range 3 {
			image := CreateRandomImage() //nolint:staticcheck

			manifests = append(manifests, image.Manifest)

			err := WriteImageToFileSystem(
				image, repo, fmt.Sprintf("tag%d", i), storeController)
			So(err, ShouldBeNil)
		}

		// add fake signature for tag1
		signatureTag, err := signature.GetCosignSignatureTagForManifest(manifests[1])
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifests[1])
		So(err, ShouldBeNil)

		signedManifestDigest := godigest.FromBytes(manifestBlob)

		image := CreateRandomImage()

		err = WriteImageToFileSystem(image, repo, signatureTag, storeController)
		So(err, ShouldBeNil)

		// remove tag2 from index.json
		indexPath := path.Join(rootDir, repo, "index.json")
		indexFile, err := os.Open(indexPath)
		So(err, ShouldBeNil)
		buf, err := io.ReadAll(indexFile)
		So(err, ShouldBeNil)

		var index ispec.Index
		if err = json.Unmarshal(buf, &index); err == nil {
			for _, manifest := range index.Manifests {
				if val, ok := manifest.Annotations[ispec.AnnotationRefName]; ok && val == "tag2" {
					delete(manifest.Annotations, ispec.AnnotationRefName)

					break
				}
			}
		}

		buf, err = json.Marshal(index)
		So(err, ShouldBeNil)

		err = os.WriteFile(indexPath, buf, 0o600)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repos, err := metaDB.GetMultipleRepoMeta(ctx,
			func(repoMeta mTypes.RepoMeta) bool { return true })
		So(err, ShouldBeNil)

		So(len(repos), ShouldEqual, 1)
		So(len(repos[0].Tags), ShouldEqual, 2)

		for tag, descriptor := range repos[0].Tags {
			imageManifestData, err := metaDB.GetFullImageMeta(ctx, repo, tag)
			So(err, ShouldBeNil)

			if descriptor.Digest == signedManifestDigest.String() {
				So(imageManifestData.Signatures, ShouldNotBeEmpty)
			}
		}
	})

	Convey("Accept orphan signatures", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		// add an image
		image := CreateRandomImage()

		err := WriteImageToFileSystem(image, repo, "tag1", storeController)
		So(err, ShouldBeNil)

		// add mock cosign signature without pushing the signed image
		image = CreateRandomImage()

		So(err, ShouldBeNil)

		signatureTag, err := signature.GetCosignSignatureTagForManifest(image.Manifest)
		So(err, ShouldBeNil)

		missingImageDigest := image.ManifestDescriptor.Digest

		// get the body of the signature
		signature := CreateRandomImage()

		err = WriteImageToFileSystem(signature, repo, signatureTag, storeController)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repos, err := metaDB.GetMultipleRepoMeta(ctx,
			func(repoMeta mTypes.RepoMeta) bool { return true })
		So(err, ShouldBeNil)

		for _, desc := range repos[0].Tags {
			So(desc.Digest, ShouldNotResemble, missingImageDigest.String())
		}

		So(len(repos), ShouldEqual, 1)
		So(repos[0].Tags, ShouldContainKey, "tag1")
		So(repos[0].Tags, ShouldNotContainKey, signatureTag)
		So(repos[0].Signatures, ShouldContainKey, missingImageDigest.String())
	})

	Convey("Detect cosign bundle signatures by artifact type and subject", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		signedImage := CreateRandomImage()
		err := WriteImageToFileSystem(signedImage, repo, "signed", storeController)
		So(err, ShouldBeNil)

		bundleSig := CreateMockCosignBundleSignature(signedImage.DescriptorRef())
		err = WriteImageToFileSystem(bundleSig, repo, "bundle-sig", storeController)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repos, err := metaDB.GetMultipleRepoMeta(ctx,
			func(repoMeta mTypes.RepoMeta) bool { return true })
		So(err, ShouldBeNil)
		So(repos, ShouldNotBeEmpty)

		repoMeta := repos[0]
		subjectDigest := signedImage.DigestStr()
		So(repoMeta.Signatures, ShouldContainKey, subjectDigest)
		So(repoMeta.Signatures[subjectDigest], ShouldContainKey, zcommon.CosignSignature)
		So(len(repoMeta.Signatures[subjectDigest][zcommon.CosignSignature]), ShouldBeGreaterThan, 0)
	})

	Convey("Index cosign bundle attestations as referrers, not signatures", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		signedImage := CreateRandomImage()
		err := WriteImageToFileSystem(signedImage, repo, "signed", storeController)
		So(err, ShouldBeNil)

		bundleSig := CreateMockCosignBundleSignature(signedImage.DescriptorRef())
		err = WriteImageToFileSystem(bundleSig, repo, bundleSig.DigestStr(), storeController)
		So(err, ShouldBeNil)

		attestation := CreateMockCosignBundleAttestation(signedImage.DescriptorRef(), "https://spdx.dev/Document")
		err = WriteImageToFileSystem(attestation, repo, attestation.DigestStr(), storeController)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)

		subjectDigest := signedImage.DigestStr()

		// slot 0 of the list is reserved for a legacy .sig signature and stays empty here
		signatureDigests := []string{}

		for _, sigInfo := range repoMeta.Signatures[subjectDigest][zcommon.CosignSignature] {
			if sigInfo.SignatureManifestDigest != "" {
				signatureDigests = append(signatureDigests, sigInfo.SignatureManifestDigest)
			}
		}

		So(signatureDigests, ShouldResemble, []string{bundleSig.DigestStr()})

		So(repoMeta.Referrers[subjectDigest], ShouldHaveLength, 1)
		referrer := repoMeta.Referrers[subjectDigest][0]
		So(referrer.Digest, ShouldEqual, attestation.DigestStr())
		So(referrer.ArtifactType, ShouldEqual, zcommon.ArtifactTypeCosignBundle)
		So(referrer.Annotations[zcommon.CosignBundlePredicateTypeAnnotation], ShouldEqual, "https://spdx.dev/Document")
	})

	Convey("Check statistics after load", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		image := CreateRandomImage() //nolint:staticcheck

		err := WriteImageToFileSystem(image, repo, "tag", storeController)
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(ctx, repo, "tag", image.AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.IncrementRepoStars(repo)
		So(err, ShouldBeNil)
		err = metaDB.UpdateStatsOnDownload(repo, "tag")
		So(err, ShouldBeNil)
		err = metaDB.UpdateStatsOnDownload(repo, "tag")
		So(err, ShouldBeNil)
		err = metaDB.UpdateStatsOnDownload(repo, "tag")
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[image.DigestStr()].DownloadCount, ShouldEqual, 3)
		So(repoMeta.StarCount, ShouldEqual, 1)
		So(time.Now(), ShouldHappenAfter, repoMeta.Statistics[image.DigestStr()].LastPullTimestamp)

		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[image.DigestStr()].DownloadCount, ShouldEqual, 3)
		So(repoMeta.StarCount, ShouldEqual, 1)
	})

	Convey("preserve TaggedTimestamp during ParseRepo", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		// Create images with tags
		for i := range 2 {
			image := CreateRandomImage() //nolint:staticcheck

			err := WriteImageToFileSystem(
				image, repo, fmt.Sprintf("tag%d", i), storeController)
			So(err, ShouldBeNil)

			// a tag first seen by a re-parse has no TaggedTimestamp, so record a live push
			err = metaDB.SetRepoReference(ctx, repo, fmt.Sprintf("tag%d", i), image.AsImageMeta())
			So(err, ShouldBeNil)
		}

		// Initial parse to set up metadata
		err := meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		// Get initial TaggedTimestamp values
		repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		So(repoMeta.Tags, ShouldContainKey, "tag0")
		So(repoMeta.Tags, ShouldContainKey, "tag1")

		tag0Timestamp := repoMeta.Tags["tag0"].TaggedTimestamp
		tag1Timestamp := repoMeta.Tags["tag1"].TaggedTimestamp

		// Verify timestamps are not zero
		So(tag0Timestamp.IsZero(), ShouldBeFalse)
		So(tag1Timestamp.IsZero(), ShouldBeFalse)

		// Re-parse the storage (simulating service restart)
		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		// Verify TaggedTimestamp values are preserved
		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)
		So(repoMeta.Tags, ShouldContainKey, "tag0")
		So(repoMeta.Tags, ShouldContainKey, "tag1")
		So(repoMeta.Tags["tag0"].TaggedTimestamp, ShouldEqual, tag0Timestamp)
		So(repoMeta.Tags["tag1"].TaggedTimestamp, ShouldEqual, tag1Timestamp)
	})

	// make sure pushTimestamp is always populated to not interfere with retention logic
	Convey("Always update pushTimestamp if its value is 0(time.Time{})", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		image := CreateRandomImage() //nolint:staticcheck

		err := WriteImageToFileSystem(image, repo, "tag", storeController)
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(ctx, repo, "tag", image.AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.UpdateStatsOnDownload(repo, "tag")
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[image.DigestStr()].DownloadCount, ShouldEqual, 1)
		So(time.Now(), ShouldHappenAfter, repoMeta.Statistics[image.DigestStr()].LastPullTimestamp)
		So(time.Now(), ShouldHappenAfter, repoMeta.Statistics[image.DigestStr()].PushTimestamp)

		// update statistics (simulate that a metaDB has statistics, but pushTimestamp is 0)
		stats := repoMeta.Statistics[image.DigestStr()]
		oldPushTimestamp := stats.PushTimestamp
		stats.PushTimestamp = time.Time{}
		repoMeta.Statistics[image.DigestStr()] = stats

		err = metaDB.SetRepoMeta(repo, repoMeta)
		So(err, ShouldBeNil)

		// metaDB should detect that pushTimestamp is 0 and repopulate it
		// (from the manifest blob's storage mod time, so close to the original push).
		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repoMeta, err = metaDB.GetRepoMeta(ctx, repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[image.DigestStr()].DownloadCount, ShouldEqual, 1)
		So(repoMeta.DownloadCount, ShouldEqual, 1)
		So(repoMeta.Statistics[image.DigestStr()].PushTimestamp, ShouldHappenWithin, time.Minute, oldPushTimestamp)
	})

	Convey("Parse 2 times and check correct update of the metaDB for modified and deleted repos", func() {
		storeController := ociutils.GetDefaultStoreController(rootDir, log)

		notModifiedRepo := "not-modified-repo"
		modifiedAddImageRepo := "modified-add-image-repo"
		modifiedRemoveImageRepo := "modified-remove-image-repo"
		deletedRepo := "deleted-repo"
		addedRepo := "added-repo"
		tag := "tag"
		tag2 := "tag2"
		newTag := "newTag"

		image := CreateRandomImage()

		err := WriteImageToFileSystem(image, notModifiedRepo, tag, storeController)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(image, modifiedAddImageRepo, tag, storeController)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(image, modifiedRemoveImageRepo, tag, storeController)
		So(err, ShouldBeNil)
		err = WriteImageToFileSystem(image, modifiedRemoveImageRepo, tag2, storeController)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(image, deletedRepo, tag, storeController)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repoMetaList, err := metaDB.SearchRepos(ctx, "")
		So(err, ShouldBeNil)
		So(len(repoMetaList), ShouldEqual, 4)

		repoNames := tcommon.AccumulateField(repoMetaList, func(rm mTypes.RepoMeta) string { return rm.Name })
		So(repoNames, ShouldContain, notModifiedRepo)
		So(repoNames, ShouldContain, modifiedAddImageRepo)
		So(repoNames, ShouldContain, modifiedRemoveImageRepo)
		So(repoNames, ShouldContain, deletedRepo)

		time.Sleep(time.Second)

		// Update the storage

		err = WriteImageToFileSystem(image, modifiedAddImageRepo, newTag, storeController)
		So(err, ShouldBeNil)

		err = storeController.GetDefaultImageStore().DeleteImageManifest(
			context.Background(), modifiedRemoveImageRepo, tag2, false)
		So(err, ShouldBeNil)

		err = os.RemoveAll(filepath.Join(rootDir, deletedRepo))
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(image, addedRepo, tag, storeController)
		So(err, ShouldBeNil)

		// Parse again
		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		repoMetaList, err = metaDB.SearchRepos(ctx, "")
		So(err, ShouldBeNil)
		So(len(repoMetaList), ShouldEqual, 4)

		repoNames = tcommon.AccumulateField(repoMetaList, func(rm mTypes.RepoMeta) string { return rm.Name })
		So(repoNames, ShouldContain, notModifiedRepo)
		So(repoNames, ShouldContain, modifiedAddImageRepo)
		So(repoNames, ShouldContain, modifiedRemoveImageRepo)
		So(repoNames, ShouldNotContain, deletedRepo)
		So(repoNames, ShouldContain, addedRepo)

		repoMeta, err := metaDB.GetRepoMeta(ctx, modifiedAddImageRepo)
		So(err, ShouldBeNil)

		So(repoMeta.Tags, ShouldContainKey, tag)
		So(repoMeta.Tags, ShouldContainKey, newTag)

		repoMeta, err = metaDB.GetRepoMeta(ctx, modifiedRemoveImageRepo)
		So(err, ShouldBeNil)

		So(repoMeta.Tags, ShouldContainKey, tag)
		So(repoMeta.Tags, ShouldNotContainKey, tag2)
	})

	Convey("Test no duplicate repos with substores and nested repo names", func() {
		// Create nested directories - substore is a subdirectory of default store
		defaultStoreDir := rootDir
		substoreDir := filepath.Join(rootDir, "a")

		defaultStore := local.NewImageStore(defaultStoreDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		substore := local.NewImageStore(substoreDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{
			DefaultStore: defaultStore,
			SubStore: map[string]storageTypes.ImageStore{
				"/a": substore,
			},
		}

		// Create a repo in default store (regular repo name, no route prefix)
		defaultRepo := "repo-in-default"
		image1 := CreateRandomImage()
		err := WriteImageToFileSystem(image1, defaultRepo, "tag1", storeController)
		So(err, ShouldBeNil)

		// Create repos in substore (these will be returned by substore.GetRepositories())
		// Repos in substore should have the "a" prefix to match the substore route
		substoreRepo1 := "a/repo-in-substore-1"
		substoreRepo2 := "a/repo-in-substore-2"
		image2 := CreateRandomImage()
		err = WriteImageToFileSystem(image2, substoreRepo1, "tag1", storeController)
		So(err, ShouldBeNil)
		image3 := CreateRandomImage()
		err = WriteImageToFileSystem(image3, substoreRepo2, "tag1", storeController)
		So(err, ShouldBeNil)

		// Parse storage
		err = meta.ParseStorage(metaDB, storeController, log)
		So(err, ShouldBeNil)

		// Get all repos from metaDB
		repoMetaList, err := metaDB.SearchRepos(ctx, "")
		So(err, ShouldBeNil)

		// Collect all repo names and count occurrences
		repoNames := make(map[string]int)
		for _, repoMeta := range repoMetaList {
			repoNames[repoMeta.Name]++
		}

		// Verify expected repos are present
		// Substore repos are processed first (with "a/" prefix), then default store repos
		expectedRepos := []string{substoreRepo1, substoreRepo2, defaultRepo}
		for _, expectedRepo := range expectedRepos {
			So(repoNames, ShouldContainKey, expectedRepo)
		}

		// Verify no duplicates - each repo should appear exactly once
		for _, count := range repoNames {
			So(count, ShouldEqual, 1)
		}

		// Verify total count - should be 3 repos:
		// - substoreRepo1, substoreRepo2 (from substore with "a/" prefix)
		// - defaultRepo (from default store, no prefix)
		So(len(repoMetaList), ShouldEqual, 3)
	})

	Convey("ParseStorage should parse repos without metadata", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log, monitoring.NewNopMetricServer(), nil, nil, nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		// Create a repo in storage
		testRepo := "repo-without-metadata"

		// Ensure repo doesn't exist in metadata (clean up from previous test runs if needed)
		err := metaDB.DeleteRepoMeta(testRepo)
		So(err, ShouldBeNil)

		// Verify GetRepoLastUpdated returns zero (repo doesn't exist in metadata)
		metaLastUpdated := metaDB.GetRepoLastUpdated(testRepo)
		So(metaLastUpdated.IsZero(), ShouldBeTrue)

		image := CreateRandomImage()

		err = WriteImageToFileSystem(image, testRepo, "tag1", storeController)
		So(err, ShouldBeNil)

		// Verify repo still doesn't exist in metadata (GetRepoMeta should return ErrRepoMetaNotFound)
		_, err = metaDB.GetRepoMeta(ctx, testRepo)
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrRepoMetaNotFound), ShouldBeTrue)

		// Verify GetRepoLastUpdated still returns zero
		metaLastUpdated = metaDB.GetRepoLastUpdated(testRepo)
		So(metaLastUpdated.IsZero(), ShouldBeTrue)

		// Parse storage - repos without metadata (zero time) are always parsed
		// Note: This behavior is the same with or without the !metaLastUpdated.IsZero() guard
		// because storageLastUpdated.Before(time.Time{}) is always false for valid timestamps
		err = meta.ParseStorage(metaDB, storeController, log) //nolint: contextcheck
		So(err, ShouldBeNil)

		// Verify repo metadata was created
		repoMeta, err := metaDB.GetRepoMeta(ctx, testRepo)
		So(err, ShouldBeNil)
		So(repoMeta.Name, ShouldEqual, testRepo)
		So(repoMeta.Tags, ShouldContainKey, "tag1")

		// Verify GetRepoLastUpdated now returns a non-zero time
		metaLastUpdated = metaDB.GetRepoLastUpdated(testRepo)
		So(metaLastUpdated.IsZero(), ShouldBeFalse)
	})
}

func TestGetSignatureLayersInfo(t *testing.T) {
	Convey("wrong signature type", t, func() {
		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", "wrong signature type", []byte{},
			nil, log.NewTestLogger())
		So(err, ShouldBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("notation index", t, func() {
		notationIndex := ispec.Index{
			MediaType: ispec.MediaTypeImageIndex,
		}

		notationIndexBlob, err := json.Marshal(notationIndex)
		So(err, ShouldBeNil)
		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature, notationIndexBlob,
			nil, log.NewTestLogger())
		So(err, ShouldBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("signature layer missing from storage", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		mockImageStore.StatBlobFn = func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
			return false, -1, time.Time{}, errMetaTestInjected
		}
		image := CreateRandomImage()

		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.CosignSignature,
			image.ManifestDescriptor.Data, mockImageStore, log.NewTestLogger())
		So(err, ShouldNotBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("notation len(manifestContent.Layers) != 1", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		image := CreateImageWith().RandomLayers(3, 10).RandomConfig().Build()

		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature,
			image.ManifestDescriptor.Data, mockImageStore, log.NewTestLogger())
		So(err, ShouldNotBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("notation signature layer missing from storage", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		mockImageStore.StatBlobFn = func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
			return false, -1, time.Time{}, errMetaTestInjected
		}
		image := CreateImageWith().RandomLayers(1, 10).RandomConfig().Build()

		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature,
			image.ManifestDescriptor.Data, mockImageStore, log.NewTestLogger())
		So(err, ShouldNotBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("signature layers are recorded by digest, their content stays in storage", t, func() {
		mockImageStore := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return nil, errMetaTestInjected
			},
		}
		image := CreateImageWith().RandomLayers(1, 10).RandomConfig().Build()

		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.CosignSignature,
			image.ManifestDescriptor.Data, mockImageStore, log.NewTestLogger())
		So(err, ShouldBeNil)
		So(layers, ShouldHaveLength, 1)
		So(layers[0].LayerDigest, ShouldEqual, image.Manifest.Layers[0].Digest.String())
	})

	Convey("error while unmarshaling manifest content", t, func() {
		_, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.CosignSignature, []byte("bad manifest"),
			nil, log.NewTestLogger())
		So(err, ShouldNotBeNil)

		_, err = meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature, []byte("bad manifest"),
			nil, log.NewTestLogger())
		So(err, ShouldNotBeNil)
	})
}

// parseTestDB is a metaDB whose stored protos can be read raw and which can be cloned raw.
type parseTestDB struct {
	metaDB    mTypes.MetaDB
	repoMeta  func() *proto_go.RepoMeta
	repoBlobs func() *proto_go.RepoBlobs
	clone     func() parseTestDB
}

func newBoltParseTestDB(t *testing.T, rootDir string) parseTestDB {
	t.Helper()

	boltDB, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: rootDir})
	So(err, ShouldBeNil)
	t.Cleanup(func() { _ = boltDB.Close() })

	metaDB, err := boltdb.New(boltDB, log.NewTestLogger())
	So(err, ShouldBeNil)

	rawRead := func(bucket string, message proto.Message) {
		err := boltDB.View(func(tx *bolt.Tx) error {
			return proto.Unmarshal(tx.Bucket([]byte(bucket)).Get([]byte(repo)), message)
		})
		So(err, ShouldBeNil)
	}

	return parseTestDB{
		metaDB: metaDB,
		repoMeta: func() *proto_go.RepoMeta {
			repoMeta := &proto_go.RepoMeta{}
			rawRead(boltdb.RepoMetaBuck, repoMeta)

			return repoMeta
		},
		repoBlobs: func() *proto_go.RepoBlobs {
			repoBlobs := &proto_go.RepoBlobs{}
			rawRead(boltdb.RepoBlobsBuck, repoBlobs)

			return repoBlobs
		},
		clone: func() parseTestDB {
			cloneDir := t.TempDir()

			err := boltDB.View(func(tx *bolt.Tx) error {
				return tx.CopyFile(path.Join(cloneDir, "meta.db"), 0o600)
			})
			So(err, ShouldBeNil)

			return newBoltParseTestDB(t, cloneDir)
		},
	}
}

func copyMiniRedis(t *testing.T, source, target *miniredis.Miniredis) {
	t.Helper()

	for _, key := range source.Keys() {
		switch source.Type(key) {
		case "hash":
			fields, err := source.HKeys(key)
			So(err, ShouldBeNil)

			for _, field := range fields {
				target.HSet(key, field, source.HGet(key, field))
			}
		case "string":
			value, err := source.Get(key)
			So(err, ShouldBeNil)
			So(target.Set(key, value), ShouldBeNil)
		case "zset":
			members, err := source.SortedSet(key)
			So(err, ShouldBeNil)

			for member, score := range members {
				_, err := target.ZAdd(key, score, member)
				So(err, ShouldBeNil)
			}
		default:
			t.Fatalf("cannot clone redis key %q of type %s", key, source.Type(key))
		}
	}
}

func newRedisParseTestDB(t *testing.T, source *miniredis.Miniredis) parseTestDB {
	t.Helper()

	miniRedis := miniredis.RunT(t)
	if source != nil {
		copyMiniRedis(t, source, miniRedis)
	}

	logger := log.NewTestLogger()

	redisClient, err := rediscfg.GetRedisClient(map[string]any{"url": "redis://" + miniRedis.Addr()}, logger)
	So(err, ShouldBeNil)

	redisDB, err := redis.New(redisClient, redis.DBDriverParameters{KeyPrefix: "zot"}, logger)
	So(err, ShouldBeNil)

	rawRead := func(key string, message proto.Message) {
		So(proto.Unmarshal([]byte(miniRedis.HGet(key, repo)), message), ShouldBeNil)
	}

	return parseTestDB{
		metaDB: redisDB,
		repoMeta: func() *proto_go.RepoMeta {
			repoMeta := &proto_go.RepoMeta{}
			rawRead(redisDB.RepoMetaKey, repoMeta)

			return repoMeta
		},
		repoBlobs: func() *proto_go.RepoBlobs {
			repoBlobs := &proto_go.RepoBlobs{}
			rawRead(redisDB.RepoBlobsKey, repoBlobs)

			return repoBlobs
		},
		clone: func() parseTestDB { return newRedisParseTestDB(t, miniRedis) },
	}
}

// parseTestBackends lists the metaDB flavours the parse equivalence tests run on, each as a constructor.
func parseTestBackends(t *testing.T) map[string]func() parseTestDB {
	t.Helper()

	return map[string]func() parseTestDB{
		"boltdb":    func() parseTestDB { return newBoltParseTestDB(t, t.TempDir()) },
		"miniredis": func() parseTestDB { return newRedisParseTestDB(t, nil) },
	}
}

type parseFixtureRepo struct {
	controller storage.StoreController
	images     map[string]Image
}

// writeParseFixtureRepo fills a local repo with tags, a retag, an untagged manifest, a multi-arch index after its
// children, and a cosign tag signature, a notation signature and an SBOM referrer, each after its subject.
func writeParseFixtureRepo(t *testing.T) parseFixtureRepo {
	t.Helper()

	logger := log.NewTestLogger()
	imageStore := local.NewImageStore(t.TempDir(), false, false,
		logger, monitoring.NewNopMetricServer(), nil, nil, nil, nil)
	controller := storage.StoreController{DefaultStore: imageStore}
	images := map[string]Image{}

	write := func(image Image, ref string) {
		So(WriteImageToFileSystem(image, repo, ref, controller), ShouldBeNil)
	}

	for _, tag := range []string{"tagA", "tagB", "tagC"} {
		images[tag] = CreateRandomImage()
		write(images[tag], tag)
	}

	write(images["tagA"], "tagA-retag")

	untagged := CreateRandomImage()
	write(untagged, untagged.DigestStr())

	multiarch := CreateRandomMultiarch()
	So(WriteMultiArchImageToFileSystem(multiarch, repo, "multi", controller), ShouldBeNil)

	cosignTag, err := signature.GetCosignSignatureTagForManifest(images["tagA"].Manifest)
	So(err, ShouldBeNil)
	write(CreateRandomImage(), cosignTag)

	// an empty config blob would have to exist already, so the referrers carry a real config
	config := ispec.Image{}
	config.Architecture, config.OS = "amd64", "linux"

	notation := CreateImageWith().RandomLayers(1, 10).ImageConfig(config).Subject(images["tagB"].DescriptorRef()).
		ArtifactType(zcommon.ArtifactTypeNotation).Build()
	write(notation, notation.DigestStr())

	sbom := CreateImageWith().RandomLayers(1, 10).ImageConfig(config).Subject(images["tagC"].DescriptorRef()).
		ArtifactType("application/spdx+json").Build()
	write(sbom, sbom.DigestStr())

	return parseFixtureRepo{controller: controller, images: images}
}

// parseRepoSequentially is the per-entry parse loop that parseRepo replaced, kept as the reference result.
func parseRepoSequentially(metaDB mTypes.MetaDB, controller storage.StoreController) {
	logger := log.NewTestLogger()
	imageStore := controller.GetImageStore(repo)

	err := imageStore.WithRepoReadLock(repo, func() error {
		indexBlob, err := imageStore.GetIndexContent(repo)
		So(err, ShouldBeNil)

		var index ispec.Index
		So(json.Unmarshal(indexBlob, &index), ShouldBeNil)

		tagsToKeep := map[string]bool{}

		for _, manifest := range index.Manifests {
			tag := manifest.Annotations[ispec.AnnotationRefName]
			if tag != "" && !zcommon.IsReferrersTag(tag) {
				tagsToKeep[tag] = true
			}
		}

		err = metaDB.ResetRepoReferences(repo, tagsToKeep)
		if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return err
		}

		initialPullTimestamp := mTypes.WithInitialPullTimestamp(time.Now())

		for _, manifest := range index.Manifests {
			tag := manifest.Annotations[ispec.AnnotationRefName]
			if zcommon.IsReferrersTag(tag) {
				continue
			}

			manifestBlob, err := imageStore.GetBlobContent(repo, manifest.Digest)
			So(err, ShouldBeNil)

			reference := tag
			if tag == "" {
				reference = manifest.Digest.String()
			}

			setOpts := []mTypes.SetRepoReferenceOption{initialPullTimestamp}
			if found, _, modTime, err := imageStore.StatBlob(repo, manifest.Digest); err == nil && found {
				setOpts = append(setOpts, mTypes.WithPushTimestamp(modTime))
			}

			err = meta.SetImageMetaFromInput(context.Background(), repo, reference, manifest.MediaType,
				manifest.Digest, manifestBlob, imageStore, metaDB, logger, setOpts...)
			So(err, ShouldBeNil)
		}

		return nil
	})
	So(err, ShouldBeNil)
}

func sortedProtoText(messages []*proto_go.Platform) []string {
	texts := make([]string, 0, len(messages))
	for _, message := range messages {
		texts = append(texts, prototext.Format(message))
	}

	sort.Strings(texts)

	return texts
}

// assertSameRepoState compares RepoMeta and RepoBlobs as stored, with Vendors and Platforms sorted because they are
// built from map iteration, and the ImageMeta of every digest the repo knows.
func assertSameRepoState(actual, expected parseTestDB) {
	actualMeta, expectedMeta := actual.repoMeta(), expected.repoMeta()

	sort.Strings(actualMeta.Vendors)
	sort.Strings(expectedMeta.Vendors)

	So(sortedProtoText(actualMeta.Platforms), ShouldResemble, sortedProtoText(expectedMeta.Platforms))

	actualMeta.Platforms, expectedMeta.Platforms = nil, nil

	// Each parse stamps the statistics it creates with its own time.Now() as the first pull time.
	for digest, expectedStats := range expectedMeta.Statistics {
		actualStats := actualMeta.Statistics[digest]

		actualPull, expectedPull := actualStats.GetLastPullTimestamp().AsTime(), expectedStats.GetLastPullTimestamp().AsTime()
		if actualStats == nil || actualPull.Equal(expectedPull) {
			continue
		}

		So(actualPull, ShouldHappenWithin, time.Minute, expectedPull)

		actualStats.LastPullTimestamp = expectedStats.LastPullTimestamp
	}

	So(prototext.Format(actualMeta), ShouldEqual, prototext.Format(expectedMeta))
	So(prototext.Format(actual.repoBlobs()), ShouldEqual, prototext.Format(expected.repoBlobs()))

	digests := map[string]struct{}{}
	for _, descriptor := range expectedMeta.Tags {
		digests[descriptor.Digest] = struct{}{}
	}

	for digest := range expectedMeta.Statistics {
		digests[digest] = struct{}{}
	}

	So(len(digests), ShouldBeGreaterThan, 3)

	for digest := range digests {
		if digest == "" {
			continue
		}

		actualImage, actualErr := actual.metaDB.GetImageMeta(godigest.Digest(digest))
		expectedImage, expectedErr := expected.metaDB.GetImageMeta(godigest.Digest(digest))

		So(actualErr == nil, ShouldEqual, expectedErr == nil)
		So(actualImage, ShouldResemble, expectedImage)
	}
}

func TestParseRepoEqualsSequentialPath(t *testing.T) {
	logger := log.NewTestLogger()

	for name, newDB := range parseTestBackends(t) {
		Convey("parsing into an empty "+name+" gives what the per-entry loop gives", t, func() {
			fixture := writeParseFixtureRepo(t)
			parsed, sequential := newDB(), newDB()

			So(meta.ParseRepo(repo, parsed.metaDB, fixture.controller, logger), ShouldBeNil)
			parseRepoSequentially(sequential.metaDB, fixture.controller)

			assertSameRepoState(parsed, sequential)
		})

		Convey("parsing into a populated "+name+" gives what the per-entry loop gives", t, func() {
			fixture := writeParseFixtureRepo(t)
			parsed := newDB()

			So(meta.ParseRepo(repo, parsed.metaDB, fixture.controller, logger), ShouldBeNil)
			So(parsed.metaDB.UpdateStatsOnDownload(repo, "tagA"), ShouldBeNil)
			So(parsed.metaDB.SetRepoReference(context.Background(), repo, "absent-from-storage",
				CreateRandomImage().AsImageMeta()), ShouldBeNil)

			tagC := fixture.images["tagC"]
			So(parsed.metaDB.RemoveRepoReference(repo, "tagC", tagC.Digest()), ShouldBeNil)
			So(parsed.metaDB.SetRepoReference(context.Background(), repo, "tagC", tagC.AsImageMeta()), ShouldBeNil)

			sequential := parsed.clone()

			So(meta.ParseRepo(repo, parsed.metaDB, fixture.controller, logger), ShouldBeNil)
			parseRepoSequentially(sequential.metaDB, fixture.controller)

			So(parsed.repoMeta().Tags, ShouldNotContainKey, "absent-from-storage")
			assertSameRepoState(parsed, sequential)
		})
	}
}

func TestParseRepoUsesBlobModTimeAsPushTimestamp(t *testing.T) {
	Convey("the push timestamp of a parsed image is the mod time of its manifest blob", t, func() {
		fixture := writeParseFixtureRepo(t)
		imageStore := fixture.controller.GetImageStore(repo)
		image := fixture.images["tagB"]

		pushedAt := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
		So(os.Chtimes(imageStore.BlobPath(repo, image.Digest()), pushedAt, pushedAt), ShouldBeNil)

		db := newBoltParseTestDB(t, t.TempDir())
		So(meta.ParseRepo(repo, db.metaDB, fixture.controller, log.NewTestLogger()), ShouldBeNil)

		repoMeta, err := db.metaDB.GetRepoMeta(context.Background(), repo)
		So(err, ShouldBeNil)

		_, _, modTime, err := imageStore.StatBlob(repo, image.Digest())
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[image.DigestStr()].PushTimestamp.UnixNano(), ShouldEqual, modTime.UnixNano())
		So(modTime.UnixNano(), ShouldEqual, pushedAt.UnixNano())
		So(repoMeta.Tags["tagB"].TaggedTimestamp.IsZero(), ShouldBeTrue)
	})
}

func TestParseRepoAppliesSignatureListedBeforeItsSubject(t *testing.T) {
	Convey("a cosign signature listed before its subject ends up on the subject", t, func() {
		imageStore := local.NewImageStore(t.TempDir(), false, false,
			log.NewTestLogger(), monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		controller := storage.StoreController{DefaultStore: imageStore}

		subject := CreateRandomImage()
		signatureTag, err := signature.GetCosignSignatureTagForManifest(subject.Manifest)
		So(err, ShouldBeNil)

		So(WriteImageToFileSystem(CreateRandomImage(), repo, signatureTag, controller), ShouldBeNil)
		So(WriteImageToFileSystem(subject, repo, "subject", controller), ShouldBeNil)

		db := newBoltParseTestDB(t, t.TempDir())
		So(meta.ParseRepo(repo, db.metaDB, controller, log.NewTestLogger()), ShouldBeNil)

		repoMeta, err := db.metaDB.GetRepoMeta(context.Background(), repo)
		So(err, ShouldBeNil)
		So(repoMeta.Signatures[subject.DigestStr()][zcommon.CosignSignature], ShouldHaveLength, 1)
	})
}

func TestParseRepoAppliesConfigDerivedFields(t *testing.T) {
	const vendor = "acme"

	config := ispec.Image{}
	config.Architecture, config.OS = "riscv64", "plan9"
	config.Config.Labels = map[string]string{"config-label": "config-value"}

	image := CreateImageWith().RandomLayers(1, 10).ImageConfig(config).
		Annotations(map[string]string{ispec.AnnotationVendor: vendor}).Build()

	assertConfigDerived := func(metaDB mTypes.MetaDB) {
		imageMeta, err := metaDB.GetImageMeta(image.Digest())
		So(err, ShouldBeNil)
		So(imageMeta.Manifests[0].Config.Architecture, ShouldEqual, "riscv64")
		So(imageMeta.Manifests[0].Config.OS, ShouldEqual, "plan9")
		So(imageMeta.Manifests[0].Config.Config.Labels["config-label"], ShouldEqual, "config-value")

		repoMeta, err := metaDB.GetRepoMeta(context.Background(), repo)
		So(err, ShouldBeNil)
		So(repoMeta.Platforms, ShouldHaveLength, 1)
		So(repoMeta.Platforms[0].Architecture, ShouldEqual, "riscv64")
		So(repoMeta.Platforms[0].OS, ShouldEqual, "plan9")
		So(repoMeta.Vendors, ShouldResemble, []string{vendor})
	}

	Convey("parseRepo stores the platform and vendor of the image config", t, func() {
		imageStore := local.NewImageStore(t.TempDir(), false, false,
			log.NewTestLogger(), monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		controller := storage.StoreController{DefaultStore: imageStore}

		So(WriteImageToFileSystem(image, repo, "tag", controller), ShouldBeNil)

		db := newBoltParseTestDB(t, t.TempDir())
		So(meta.ParseRepo(repo, db.metaDB, controller, log.NewTestLogger()), ShouldBeNil)

		assertConfigDerived(db.metaDB)
	})

	Convey("SetImageMetaFromInput stores the platform and vendor of the image config", t, func() {
		imageStore := local.NewImageStore(t.TempDir(), false, false,
			log.NewTestLogger(), monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		controller := storage.StoreController{DefaultStore: imageStore}

		So(WriteImageToFileSystem(image, repo, "tag", controller), ShouldBeNil)

		manifestBlob, err := imageStore.GetBlobContent(repo, image.Digest())
		So(err, ShouldBeNil)

		db := newBoltParseTestDB(t, t.TempDir())
		err = meta.SetImageMetaFromInput(context.Background(), repo, "tag", ispec.MediaTypeImageManifest,
			image.Digest(), manifestBlob, imageStore, db.metaDB, log.NewTestLogger())
		So(err, ShouldBeNil)

		assertConfigDerived(db.metaDB)
	})
}
