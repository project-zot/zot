package gc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
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
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var (
	errGC    = errors.New("gc error")
	repoName = "test" //nolint: gochecknoglobals
)

func TestGarbageCollectManifestErrors(t *testing.T) {
	Convey("Make imagestore and upload manifest", t, func(c C) {
		dir := t.TempDir()

		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")

		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop() // Clean up metrics server to prevent resource leaks

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
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
		}, audit, log)

		Convey("trigger missing blob in addImageIndexBlobsToReferences()", func() {
			// GC should continue when blobs are missing (not found), not return an error
			err := gc.addIndexBlobsToReferences(repoName, ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("miss"),
						MediaType: ispec.MediaTypeImageIndex,
					},
				},
			}, map[string]bool{})
			So(err, ShouldBeNil)
		})

		Convey("trigger missing blob in addImageManifestBlobsToReferences()", func() {
			// GC should continue when blobs are missing (not found), not return an error
			err := gc.addIndexBlobsToReferences(repoName, ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("miss"),
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}, map[string]bool{})
			So(err, ShouldBeNil)
		})

		content := []byte("this is a blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		_, blen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    digest,
					Size:      int64(len(content)),
				},
			},
		}

		manifest.SchemaVersion = 2

		body, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(body)

		_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, body)
		So(err, ShouldBeNil)

		Convey("trigger GetIndex error in GetReferencedBlobs", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o755)
				So(err, ShouldBeNil)
			}()

			// Note: Permission denied from Stat() is converted to ErrBlobNotFound in originalBlobInfo,
			// so we can't distinguish it from missing blobs. GC treats missing blobs gracefully,
			// so permission denied from Stat() will also be treated as missing (return nil).
			// Permission denied from ReadFile() will still return an error.
			err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
			So(err, ShouldBeNil)
		})

		Convey("trigger GetImageManifest error in AddIndexBlobsToReferences", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", manifestDigest.Encoded()), 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", manifestDigest.Encoded()), 0o755)
				So(err, ShouldBeNil)
			}()

			err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
			So(err, ShouldNotBeNil)
		})
	})
}

func TestGarbageCollectIndexErrors(t *testing.T) {
	Convey("Make imagestore and upload manifest", t, func(c C) {
		dir := t.TempDir()

		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")

		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
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
		}, audit, log)

		content := []byte("this is a blob")
		bdgst := godigest.FromBytes(content)
		So(bdgst, ShouldNotBeNil)

		_, bsize, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), bdgst)
		So(err, ShouldBeNil)
		So(bsize, ShouldEqual, len(content))

		var index ispec.Index
		index.SchemaVersion = 2
		index.MediaType = ispec.MediaTypeImageIndex

		var digest godigest.Digest

		for i := 0; i < 4; i++ {
			// upload image config blob
			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := GetRandomImageConfig()
			buf := bytes.NewBuffer(cblob)
			buflen := buf.Len()
			blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    bdgst,
						Size:      bsize,
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)

			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			index.Manifests = append(index.Manifests, ispec.Descriptor{
				Digest:    digest,
				MediaType: ispec.MediaTypeImageManifest,
				Size:      int64(len(content)),
			})
		}

		// upload index image
		indexContent, err := json.Marshal(index)
		So(err, ShouldBeNil)

		indexDigest := godigest.FromBytes(indexContent)
		So(indexDigest, ShouldNotBeNil)

		_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageIndex, indexContent)
		So(err, ShouldBeNil)

		index, err = common.GetIndex(imgStore, repoName, log)
		So(err, ShouldBeNil)

		err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
		So(err, ShouldBeNil)

		Convey("trigger GetImageIndex error in GetReferencedBlobsInImageIndex", func() {
			err := os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", indexDigest.Encoded()), 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", indexDigest.Encoded()), 0o755)
				So(err, ShouldBeNil)
			}()

			err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
			So(err, ShouldNotBeNil)
		})
	})
}

func TestGarbageCollectWithMockedImageStore(t *testing.T) {
	trueVal := true

	ctx := context.Background()

	Convey("Cover gc error paths", t, func(c C) {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")

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
			}, gcOptions, audit, log)

			err := gc.cleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on GetIndex in gc.removeUnreferencedBlobs()", func() {
			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
					return types.RepoMeta{}, errGC
				},
			}, gcOptions, audit, log)

			err := gc.removeUnreferencedBlobs("repo", time.Hour, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.removeManifest()", func() {
			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{
				GetRepoMetaFn: func(ctx context.Context, repo string) (types.RepoMeta, error) {
					return types.RepoMeta{}, errGC
				},
			}, gcOptions, audit, log)

			_, err := gc.removeManifest("", &ispec.Index{}, ispec.DescriptorEmptyJSON, "tag", "", "")
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
			}, gcOptions, audit, log)

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

			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{}, gcOptions, audit, log)

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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

			err = gc.cleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("False on imgStore.DirExists() in gc.cleanRepo()", func() {
			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return false
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

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
			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

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

		Convey("Error on gc.gcManifest() in gc.cleanManifests() with image", func() {
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
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log)

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
		Convey("Error on gc.gcManifest() in gc.cleanManifests() with signature", func() {
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
			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log)

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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

			err = gc.removeManifestsPerRepoPolicy(ctx, repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					manifestDesc,
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Missing nested index blob in removeIndexReferrers is skipped gracefully", func() {
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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

			// removeIndexReferrers should skip the missing nested index and continue
			gced, err := gc.removeIndexReferrers(repoName, &topLevelIndex, topLevelIndex)
			So(err, ShouldBeNil)
			So(gced, ShouldBeFalse)
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

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

			// identifyManifestsReferencedInIndex should skip the missing nested index and continue
			referenced := make(map[godigest.Digest]bool)
			err := gc.identifyManifestsReferencedInIndex(topLevelIndex, repoName, referenced)
			So(err, ShouldBeNil)
			// No manifests should be marked as referenced since the nested index is missing
			So(len(referenced), ShouldEqual, 0)
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

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log)

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

			gc := NewGarbageCollect(imgStore, metaDB, gcOptions, audit, log)

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

		Convey("removeStaleManifestEntries skips in DryRun mode", func() {
			dryRunOptions := Options{
				Delay: storageConstants.DefaultGCDelay,
				ImageRetention: config.ImageRetention{
					DryRun: true,
					Delay:  storageConstants.DefaultGCDelay,
				},
			}

			gc := NewGarbageCollect(mocks.MockedImageStore{}, mocks.MetaDBMock{}, dryRunOptions, audit, log)

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

		Convey("removeStaleManifestEntries handles GetAllBlobs PathNotFound gracefully", func() {
			imgStore := mocks.MockedImageStore{
				GetAllBlobsFn: func(repo string) ([]godigest.Digest, error) {
					return nil, driver.PathNotFoundError{}
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

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
			// index should be unchanged — we couldn't check, so don't prune
			So(len(index.Manifests), ShouldEqual, 1)
		})

	})
}

func TestCleanRepoWithStaleManifestEntries(t *testing.T) {
	ctx := context.Background()

	Convey("cleanRepo end-to-end prunes stale manifest entries", t, func() {
		log := zlog.NewTestLogger()
		audit := zlog.NewAuditLogger("debug", "")

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
			CleanupRepoFn: func(repo string, blobs []godigest.Digest, removeRepo bool) (int, error) {
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

		// Disable untagged cleanup so removeManifestsPerRepoPolicy doesn't try
		// to stat missing blobs before removeStaleManifestEntries can prune them.
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

		gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gcOptions, audit, log)

		err = gc.cleanRepo(ctx, repoName)
		So(err, ShouldBeNil)
		// The stale manifest entry should have been pruned
		So(len(savedIndex.Manifests), ShouldEqual, 1)
		So(savedIndex.Manifests[0].Digest, ShouldEqual, existingDigest)
	})
}

func TestCleanupRepoMissingBlob(t *testing.T) {
	Convey("CleanupRepo skips blobs that are already absent", t, func() {
		dir := t.TempDir()

		log := zlog.NewTestLogger()

		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		// Create a repo with a blob, then remove the blob file to simulate S3 disappearance
		content := []byte("disappearing blob")
		digest := godigest.FromBytes(content)

		_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		// Remove the blob file directly to simulate it being missing on S3
		blobPath := path.Join(dir, repoName, "blobs", "sha256", digest.Encoded())
		err = os.Remove(blobPath)
		So(err, ShouldBeNil)

		// CleanupRepo should skip the missing blob without error
		count, err := imgStore.CleanupRepo(repoName, []godigest.Digest{digest}, false)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 1)
	})
}
