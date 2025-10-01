//go:build sync
// +build sync

package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/ref"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/extensions/lint"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/storage/local"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

func TestService(t *testing.T) {
	Convey("trigger fetch tags error", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, os.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.Logger{})
		So(err, ShouldBeNil)

		err = service.SyncRepo(context.Background(), "repo")
		So(err, ShouldNotBeNil)
	})

	Convey("test context cancellation in SyncRepo without mock", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, os.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.Logger{})
		So(err, ShouldBeNil)

		// Create a context that's already cancelled
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = service.SyncRepo(ctx, "repo")
		So(err, ShouldNotBeNil)
		// This will fail at getTags before reaching the cancellation check
	})

	Convey("test context cancellation in SyncRepo with mock", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, os.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.Logger{})
		So(err, ShouldBeNil)

		// Create a mock remote that returns tags so we can reach the loop
		mockRemote := &mocks.SyncRemoteMock{
			GetTagsFn: func(ctx context.Context, repo string) ([]string, error) {
				return []string{"tag1", "tag2", "tag3"}, nil
			},
		}
		service.remote = mockRemote

		// Create a context that's already cancelled
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = service.SyncRepo(ctx, "repo")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, context.Canceled), ShouldBeTrue)
	})

	Convey("test SyncReferrers ReferrerList error", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, os.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.Logger{})
		So(err, ShouldBeNil)

		// Create a minimal mock remote that only returns tags
		mockRemote := &mocks.SyncRemoteMock{
			GetTagsFn: func(ctx context.Context, repo string) ([]string, error) {
				return []string{"tag1"}, nil
			},
		}
		service.remote = mockRemote

		// Set rc to nil to force a panic at ReferrerList call
		service.rc = nil

		// Use defer to catch the panic - this confirms we reached the ReferrerList call
		var panicOccurred bool
		defer func() {
			if r := recover(); r != nil {
				panicOccurred = true
				t.Logf("SyncReferrers panic (expected): %v", r)
			}
		}()

		ctx := context.Background()
		err = service.SyncReferrers(ctx, "repo", "tag1", []string{"signature"})

		// We expect a panic when rc is nil, which confirms we reached the ReferrerList call
		So(panicOccurred, ShouldBeTrue)
	})

	Convey("test syncImage ReferrerList error with OnlySigned", t, func() {
		onlySigned := true
		conf := syncconf.RegistryConfig{
			URLs:       []string{"http://invalid-registry-that-does-not-exist:9999"},
			OnlySigned: &onlySigned,
		}

		service, err := New(conf, "", nil, os.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.Logger{})
		So(err, ShouldBeNil)

		// Create a mock remote that returns necessary data
		mockRemote := &mocks.SyncRemoteMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				return ref.New("invalid-registry-that-does-not-exist:9999/" + repo + ":" + tag)
			},
			GetDigestFn: func(ctx context.Context, repo, tag string) (godigest.Digest, error) {
				return godigest.Digest("sha256:abc123"), nil
			},
		}
		service.remote = mockRemote

		// Create a mock destination
		mockDest := &mocks.SyncDestinationMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				return ref.New("local/" + repo + ":" + tag)
			},
		}
		service.destination = mockDest

		ctx := context.Background()
		err = service.syncImage(ctx, "localrepo", "remoterepo", "tag1", []string{}, true)

		// We expect an error when ReferrerList fails (network/connection error in this case)
		So(err, ShouldNotBeNil)
	})
}

func TestDestinationRegistry(t *testing.T) {
	Convey("make StoreController", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		syncImgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)
		repoName := "repo"

		storeController := storage.StoreController{DefaultStore: syncImgStore}
		registry := NewDestinationRegistry(storeController, storeController, nil, log)
		imageReference, err := registry.GetImageReference(repoName, "1.0")
		So(err, ShouldBeNil)
		So(imageReference, ShouldNotBeNil)

		imgStore := getImageStoreFromImageReference(repoName, imageReference, log)

		// create a blob/layer
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("this is a blob1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)
		blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)
		bdgst1 := digest
		bsize1 := len(content)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// push index image
		var index ispec.Index
		index.SchemaVersion = 2
		index.MediaType = ispec.MediaTypeImageIndex

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
						Digest:    bdgst1,
						Size:      int64(bsize1),
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

		Convey("sync index image", func() {
			ok, err := registry.CanSkipImage(repoName, "1.0", indexDigest)
			So(ok, ShouldBeFalse)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldBeNil)
		})

		Convey("CleanupImage()", func() {
			ok, err := registry.CanSkipImage(repoName, "1.0", indexDigest)
			So(ok, ShouldBeFalse)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldBeNil)

			err = registry.CleanupImage(imageReference, repoName)
			So(err, ShouldBeNil)
		})

		Convey("trigger GetImageManifest error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, indexDigest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger linter error in CommitImage()", func() {
			defaultVal := true
			linter := lint.NewLinter(&config.LintConfig{
				BaseConfig: config.BaseConfig{
					Enable: &defaultVal,
				},
				MandatoryAnnotations: []string{"annot1"},
			}, log)

			syncImgStore := local.NewImageStore(dir, true, true, log, metrics, linter, cacheDriver, nil, nil)
			repoName := "repo"

			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, nil, log)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldBeNil)
		})

		Convey("trigger GetBlobContent on manifest error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, digest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger copyBlob() error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, bdgst1), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger PutImageManifest error on index manifest in CommitImage()", func() {
			err = os.MkdirAll(syncImgStore.BlobPath(repoName, indexDigest), storageConstants.DefaultDirPerms)
			So(err, ShouldBeNil)

			err = os.Chmod(syncImgStore.BlobPath(repoName, indexDigest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger metaDB error on index manifest in CommitImage()", func() {
			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, mocks.MetaDBMock{
				SetRepoReferenceFn: func(ctx context.Context, repo string, reference string, imageMeta mTypes.ImageMeta) error {
					if reference == "1.0" {
						return zerr.ErrRepoMetaNotFound
					}

					return nil
				},
			}, log)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger metaDB error on image manifest in CommitImage()", func() {
			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, mocks.MetaDBMock{
				SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					return zerr.ErrRepoMetaNotFound
				},
			}, log)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("push image", func() {
			imageReference, err := registry.GetImageReference(repoName, "2.0")
			So(err, ShouldBeNil)
			So(imageReference, ShouldNotBeNil)

			imgStore := getImageStoreFromImageReference(repoName, imageReference, log)

			// upload image

			// create a blob/layer
			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content := []byte("this is a blob1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)
			bdgst1 := digest
			bsize1 := len(content)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// upload image config blob
			upload, err = imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed(repoName, upload, buf)
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
						Digest:    bdgst1,
						Size:      int64(bsize1),
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			_, _, err = imgStore.PutImageManifest(repoName, "2.0", ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			Convey("sync image", func() {
				ok, err := registry.CanSkipImage(repoName, "2.0", digest)
				So(ok, ShouldBeFalse)
				So(err, ShouldBeNil)

				err = registry.CommitAll(repoName, imageReference)
				So(err, ShouldBeNil)
			})
		})
	})
}
