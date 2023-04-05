//go:build sync
// +build sync

package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/lint"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	client "zotregistry.io/zot/pkg/extensions/sync/httpclient"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/inject"
	"zotregistry.io/zot/pkg/test/mocks"
)

const (
	testImage    = "zot-test"
	testImageTag = "0.0.1"

	host = "127.0.0.1:45117"
)

var ErrTestError = fmt.Errorf("testError")

func TestInjectSyncUtils(t *testing.T) {
	Convey("Inject errors in utils functions", t, func() {
		repositoryReference := fmt.Sprintf("%s/%s", host, testImage)
		ref, err := parseRepositoryReference(repositoryReference)
		So(err, ShouldBeNil)
		So(ref.Name(), ShouldEqual, repositoryReference)

		injected := inject.InjectFailure(0)
		if injected {
			_, err = getRepoTags(context.Background(), &types.SystemContext{}, host, testImage)
			So(err, ShouldNotBeNil)
		}

		injected = inject.InjectFailure(0)
		_, err = getPolicyContext(log.NewLogger("debug", ""))
		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imageStore := local.NewImageStore(t.TempDir(), false, storageConstants.DefaultGCDelay,
			false, false, log, metrics, nil, nil,
		)
		injected = inject.InjectFailure(0)

		ols := NewOciLayoutStorage(storage.StoreController{DefaultStore: imageStore})
		_, err = ols.GetImageReference(testImage, testImageTag)
		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}
	})
}

func TestSyncInternal(t *testing.T) {
	Convey("Verify parseRepositoryReference func", t, func() {
		repositoryReference := fmt.Sprintf("%s/%s", host, testImage)
		ref, err := parseRepositoryReference(repositoryReference)
		So(err, ShouldBeNil)
		So(ref.Name(), ShouldEqual, repositoryReference)

		repositoryReference = fmt.Sprintf("%s/%s:tagged", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldEqual, errors.ErrInvalidRepositoryName)

		repositoryReference = fmt.Sprintf("http://%s/%s", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldNotBeNil)

		repositoryReference = fmt.Sprintf("docker://%s/%s", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldNotBeNil)

		_, err = getFileCredentials("/path/to/inexistent/file")
		So(err, ShouldNotBeNil)

		tempFile, err := os.CreateTemp("", "sync-credentials-")
		if err != nil {
			panic(err)
		}

		content := []byte(`{`)
		if err := os.WriteFile(tempFile.Name(), content, 0o600); err != nil {
			panic(err)
		}

		_, err = getFileCredentials(tempFile.Name())
		So(err, ShouldNotBeNil)

		srcCtx := &types.SystemContext{}
		_, err = getRepoTags(context.Background(), srcCtx, host, testImage)
		So(err, ShouldNotBeNil)

		_, err = getRepoTags(context.Background(), srcCtx, host, testImage)
		So(err, ShouldNotBeNil)

		_, err = getFileCredentials("/invalid/path/to/file")
		So(err, ShouldNotBeNil)

		ok := isSupportedMediaType("unknown")
		So(ok, ShouldBeFalse)
	})
}

func TestRemoteRegistry(t *testing.T) {
	Convey("test remote registry", t, func() {
		logger := log.NewLogger("debug", "")
		cfg := client.Config{
			URL:       "url",
			TLSVerify: false,
		}

		client, err := client.New(cfg, logger)
		So(err, ShouldBeNil)

		remote := NewRemoteRegistry(client, logger)
		imageRef, err := layout.NewReference("dir", "image")
		So(err, ShouldBeNil)
		_, _, _, err = remote.GetManifestContent(imageRef)
		So(err, ShouldNotBeNil)

		tags, err := remote.GetRepoTags("repo")
		So(tags, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
	})
}

func TestLocalRegistry(t *testing.T) {
	Convey("make StoreController", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		syncImgStore := local.NewImageStore(dir, true, storageConstants.DefaultGCDelay,
			true, true, log, metrics, nil, cacheDriver)
		repoName := "repo"

		registry := NewLocalRegistry(storage.StoreController{DefaultStore: syncImgStore}, nil, log)
		imageReference, err := registry.GetImageReference(repoName, "1.0")
		So(err, ShouldBeNil)
		So(imageReference, ShouldNotBeNil)

		imgStore := getImageStoreFromImageReference(imageReference, repoName, "1.0")

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

			cblob, cdigest := test.GetRandomImageConfig()
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

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldBeNil)
		})

		Convey("trigger GetImageManifest error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, indexDigest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitImage(imageReference, repoName, "1.0")
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

			syncImgStore := local.NewImageStore(dir, true, storageConstants.DefaultGCDelay,
				true, true, log, metrics, linter, cacheDriver)
			repoName := "repo"

			registry := NewLocalRegistry(storage.StoreController{DefaultStore: syncImgStore}, nil, log)

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldBeNil)
		})

		Convey("trigger GetBlobContent on manifest error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, digest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldNotBeNil)
		})

		Convey("trigger copyBlob() error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, bdgst1), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldNotBeNil)
		})

		Convey("trigger PutImageManifest error on index manifest in CommitImage()", func() {
			err = os.MkdirAll(syncImgStore.BlobPath(repoName, indexDigest), storageConstants.DefaultDirPerms)
			So(err, ShouldBeNil)

			err = os.Chmod(syncImgStore.BlobPath(repoName, indexDigest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldNotBeNil)
		})

		Convey("trigger repoDB error on index manifest in CommitImage()", func() {
			registry := NewLocalRegistry(storage.StoreController{DefaultStore: syncImgStore}, mocks.RepoDBMock{
				SetRepoReferenceFn: func(repo, Reference string, manifestDigest godigest.Digest, mediaType string) error {
					if Reference == "1.0" {
						return errors.ErrRepoMetaNotFound
					}

					return nil
				},
			}, log)

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldNotBeNil)
		})

		Convey("trigger repoDB error on image manifest in CommitImage()", func() {
			registry := NewLocalRegistry(storage.StoreController{DefaultStore: syncImgStore}, mocks.RepoDBMock{
				SetRepoReferenceFn: func(repo, Reference string, manifestDigest godigest.Digest, mediaType string) error {
					return errors.ErrRepoMetaNotFound
				},
			}, log)

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldNotBeNil)
		})

		Convey("push image", func() {
			imageReference, err := registry.GetImageReference(repoName, "2.0")
			So(err, ShouldBeNil)
			So(imageReference, ShouldNotBeNil)

			imgStore := getImageStoreFromImageReference(imageReference, repoName, "2.0")

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

			cblob, cdigest := test.GetRandomImageConfig()
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

				err = registry.CommitImage(imageReference, repoName, "2.0")
				So(err, ShouldBeNil)
			})
		})
	})
}
