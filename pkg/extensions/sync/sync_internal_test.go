//go:build sync
// +build sync

package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"

	dockerManifest "github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/oci/layout"
	"github.com/containers/image/v5/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/extensions/lint"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	client "zotregistry.dev/zot/pkg/extensions/sync/httpclient"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/storage/local"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/inject"
	"zotregistry.dev/zot/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
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
		imageStore := local.NewImageStore(t.TempDir(), false, false, log, metrics, nil, nil)
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
		So(err, ShouldEqual, zerr.ErrInvalidRepositoryName)

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

func TestService(t *testing.T) {
	Convey("trigger fetch tags error", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", os.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.Logger{})
		So(err, ShouldBeNil)

		err = service.SyncRepo(context.Background(), "repo")
		So(err, ShouldNotBeNil)
	})
}

func TestSyncRepo(t *testing.T) {
	Convey("trigger context error", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", os.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.Logger{})
		So(err, ShouldBeNil)

		service.remote = mocks.SyncRemote{
			GetRepoTagsFn: func(repo string) ([]string, error) {
				return []string{"repo1", "repo2"}, nil
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err = service.SyncRepo(ctx, "repo")
		So(err, ShouldEqual, ctx.Err())
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

		syncImgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
		repoName := "repo"

		storeController := storage.StoreController{DefaultStore: syncImgStore}
		registry := NewDestinationRegistry(storeController, storeController, nil, log)
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

			syncImgStore := local.NewImageStore(dir, true, true, log, metrics, linter, cacheDriver)
			repoName := "repo"

			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, nil, log)

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

			err = registry.CommitImage(imageReference, repoName, "1.0")
			So(err, ShouldNotBeNil)
		})

		Convey("trigger metaDB error on image manifest in CommitImage()", func() {
			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, mocks.MetaDBMock{
				SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					return zerr.ErrRepoMetaNotFound
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

				err = registry.CommitImage(imageReference, repoName, "2.0")
				So(err, ShouldBeNil)
			})
		})
	})
}

func TestConvertDockerToOCI(t *testing.T) {
	Convey("test converting docker to oci functions", t, func() {
		dir := t.TempDir()

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, log.NewLogger("debug", ""))

		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		imageRef, err := layout.NewReference(path.Join(dir, "zot-test"), "0.0.1")
		So(err, ShouldBeNil)

		imageSource, err := imageRef.NewImageSource(context.Background(), &types.SystemContext{})
		So(err, ShouldBeNil)

		defer imageSource.Close()

		Convey("trigger Unmarshal manifest error", func() {
			_, err = convertDockerManifestToOCI(imageSource, []byte{})
			So(err, ShouldNotBeNil)
		})

		Convey("trigger getImageConfigContent() error", func() {
			manifestBuf, _, err := imageSource.GetManifest(context.Background(), nil)
			So(err, ShouldBeNil)

			var manifest ispec.Manifest

			err = json.Unmarshal(manifestBuf, &manifest)
			So(err, ShouldBeNil)

			err = os.Chmod(path.Join(dir, "zot-test", "blobs/sha256", manifest.Config.Digest.Encoded()), 0o000)
			So(err, ShouldBeNil)

			_, err = convertDockerManifestToOCI(imageSource, manifestBuf)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger Unmarshal config error", func() {
			manifestBuf, _, err := imageSource.GetManifest(context.Background(), nil)
			So(err, ShouldBeNil)

			var manifest ispec.Manifest

			err = json.Unmarshal(manifestBuf, &manifest)
			So(err, ShouldBeNil)

			err = os.WriteFile(path.Join(dir, "zot-test", "blobs/sha256", manifest.Config.Digest.Encoded()),
				[]byte{}, storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			_, err = convertDockerManifestToOCI(imageSource, manifestBuf)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger convertDockerLayersToOCI error", func() {
			manifestBuf, _, err := imageSource.GetManifest(context.Background(), nil)
			So(err, ShouldBeNil)

			var manifest ispec.Manifest

			err = json.Unmarshal(manifestBuf, &manifest)
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBuf)

			manifest.Layers[0].MediaType = "unknown"

			newManifest, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			err = os.WriteFile(path.Join(dir, "zot-test", "blobs/sha256", manifestDigest.Encoded()),
				newManifest, storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			_, err = convertDockerManifestToOCI(imageSource, manifestBuf)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger convertDockerIndexToOCI error", func() {
			manifestBuf, _, err := imageSource.GetManifest(context.Background(), nil)
			So(err, ShouldBeNil)

			_, err = convertDockerIndexToOCI(imageSource, manifestBuf)
			So(err, ShouldNotBeNil)

			// make zot-test image an index image

			var manifest ispec.Manifest

			err = json.Unmarshal(manifestBuf, &manifest)
			So(err, ShouldBeNil)

			dockerNewManifest := ispec.Manifest{
				MediaType: dockerManifest.DockerV2Schema2MediaType,
				Config:    manifest.Config,
				Layers:    manifest.Layers,
			}

			dockerNewManifestBuf, err := json.Marshal(dockerNewManifest)
			So(err, ShouldBeNil)

			dockerManifestDigest := godigest.FromBytes(manifestBuf)

			err = os.WriteFile(path.Join(dir, "zot-test", "blobs/sha256", dockerManifestDigest.Encoded()),
				dockerNewManifestBuf, storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			var index ispec.Index

			index.Manifests = append(index.Manifests, ispec.Descriptor{
				Digest:    dockerManifestDigest,
				Size:      int64(len(dockerNewManifestBuf)),
				MediaType: dockerManifest.DockerV2Schema2MediaType,
			})

			index.MediaType = dockerManifest.DockerV2ListMediaType

			dockerIndexBuf, err := json.Marshal(index)
			So(err, ShouldBeNil)

			dockerIndexDigest := godigest.FromBytes(dockerIndexBuf)

			err = os.WriteFile(path.Join(dir, "zot-test", "blobs/sha256", dockerIndexDigest.Encoded()),
				dockerIndexBuf, storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			// write index.json

			var indexJSON ispec.Index

			indexJSONBuf, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
			So(err, ShouldBeNil)

			err = json.Unmarshal(indexJSONBuf, &indexJSON)
			So(err, ShouldBeNil)

			indexJSON.Manifests = append(indexJSON.Manifests, ispec.Descriptor{
				Digest:    dockerIndexDigest,
				Size:      int64(len(dockerIndexBuf)),
				MediaType: ispec.MediaTypeImageIndex,
				Annotations: map[string]string{
					ispec.AnnotationRefName: "0.0.2",
				},
			})

			indexJSONBuf, err = json.Marshal(indexJSON)
			So(err, ShouldBeNil)

			err = os.WriteFile(path.Join(dir, "zot-test", "index.json"), indexJSONBuf, storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			imageRef, err := layout.NewReference(path.Join(dir, "zot-test"), "0.0.2")
			So(err, ShouldBeNil)

			imageSource, err := imageRef.NewImageSource(context.Background(), &types.SystemContext{})
			So(err, ShouldBeNil)

			_, err = convertDockerIndexToOCI(imageSource, dockerIndexBuf)
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(dir, "zot-test", "blobs/sha256", dockerManifestDigest.Encoded()), 0o000)
			So(err, ShouldBeNil)

			_, err = convertDockerIndexToOCI(imageSource, dockerIndexBuf)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestConvertDockerLayersToOCI(t *testing.T) {
	Convey("test converting docker to oci functions", t, func() {
		dockerLayers := []ispec.Descriptor{
			{
				MediaType: dockerManifest.DockerV2Schema2ForeignLayerMediaType,
			},
			{
				MediaType: dockerManifest.DockerV2Schema2ForeignLayerMediaTypeGzip,
			},
			{
				MediaType: dockerManifest.DockerV2SchemaLayerMediaTypeUncompressed,
			},
			{
				MediaType: dockerManifest.DockerV2Schema2LayerMediaType,
			},
		}

		err := convertDockerLayersToOCI(dockerLayers)
		So(err, ShouldBeNil)

		So(dockerLayers[0].MediaType, ShouldEqual, ispec.MediaTypeImageLayerNonDistributable)     //nolint: staticcheck
		So(dockerLayers[1].MediaType, ShouldEqual, ispec.MediaTypeImageLayerNonDistributableGzip) //nolint: staticcheck
		So(dockerLayers[2].MediaType, ShouldEqual, ispec.MediaTypeImageLayer)
		So(dockerLayers[3].MediaType, ShouldEqual, ispec.MediaTypeImageLayerGzip)
	})
}
