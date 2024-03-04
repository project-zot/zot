package storage_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	common "zotregistry.dev/zot/pkg/storage/common"
	"zotregistry.dev/zot/pkg/storage/imagestore"
	"zotregistry.dev/zot/pkg/storage/local"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestValidateManifest(t *testing.T) {
	Convey("Make manifest", t, func(c C) {
		dir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		content := []byte("this is a blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		_, blen, err := imgStore.FullBlobUpload("test", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		Convey("bad manifest schema version", func() {
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

			manifest.SchemaVersion = 999

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldNotBeNil)
			var internalErr *zerr.Error
			So(errors.As(err, &internalErr), ShouldBeTrue)
			So(internalErr.GetDetails(), ShouldContainKey, "jsonSchemaValidation")
			So(internalErr.GetDetails()["jsonSchemaValidation"], ShouldEqual, "[schemaVersion: Must be less than or equal to 2]")
		})

		Convey("bad config blob", func() {
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

			configBlobPath := imgStore.BlobPath("test", cdigest)

			err := os.WriteFile(configBlobPath, []byte("bad config blob"), 0o000)
			So(err, ShouldBeNil)

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			// this was actually an umoci error on config blob
			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldBeNil)
		})

		Convey("manifest with non-distributable layers", func() {
			content := []byte("this blob doesn't exist")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayerNonDistributable, //nolint:staticcheck
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}

			manifest.SchemaVersion = 2

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldBeNil)
		})
	})
}

func TestGetReferrersErrors(t *testing.T) {
	Convey("make storage", t, func(c C) {
		dir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, false, true, log, metrics, nil, cacheDriver)

		artifactType := "application/vnd.example.icecream.v1"
		validDigest := godigest.FromBytes([]byte("blob"))

		Convey("Trigger invalid digest error", func(c C) {
			_, err := common.GetReferrers(imgStore, "zot-test", "invalidDigest",
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger repo not found error", func(c C) {
			_, err := common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		storageCtlr := storage.StoreController{DefaultStore: imgStore}
		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", storageCtlr)
		So(err, ShouldBeNil)

		digest := godigest.FromBytes([]byte("{}"))

		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: "application/vnd.example.invalid.v1",
					Digest:    digest,
				},
			},
		}

		indexBuf, err := json.Marshal(index)
		So(err, ShouldBeNil)

		Convey("Trigger GetBlobContent() not found", func(c C) {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, zerr.ErrBlobNotFound
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger GetBlobContent() generic error", func(c C) {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, zerr.ErrBadBlob
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger unmarshal error on manifest image mediaType", func(c C) {
			index = ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
					},
				},
			}

			indexBuf, err = json.Marshal(index)
			So(err, ShouldBeNil)

			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, nil
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger nil subject", func(c C) {
			index = ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
					},
				},
			}

			indexBuf, err = json.Marshal(index)
			So(err, ShouldBeNil)

			ociManifest := ispec.Manifest{
				Subject: nil,
			}

			ociManifestBuf, err := json.Marshal(ociManifest)
			So(err, ShouldBeNil)

			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return ociManifestBuf, nil
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldBeNil)
		})

		Convey("Index bad blob", func() {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte(`{
						"manifests": [{
							"digest": "digest",
							"mediaType": "application/vnd.oci.image.index.v1+json"
						}]
					}`), nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte("bad blob"), nil
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Index bad artifac type", func() {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte(`{
						"manifests": [{
							"digest": "digest",
							"mediaType": "application/vnd.oci.image.index.v1+json"
						}]
					}`), nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte(`{ 
						"subject": {"digest": "` + validDigest.String() + `"}
						}`), nil
				},
			}

			ref, err := common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{"art.type"}, log)
			So(err, ShouldBeNil)
			So(len(ref.Manifests), ShouldEqual, 0)
		})
	})
}

func TestGetImageIndexErrors(t *testing.T) {
	log := log.Logger{Logger: zerolog.New(os.Stdout)}

	Convey("Trigger invalid digest error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{}

		_, err := common.GetImageIndex(imgStore, "zot-test", "invalidDigest", log)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger GetBlobContent error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, zerr.ErrBlobNotFound
			},
		}

		validDigest := godigest.FromBytes([]byte("blob"))

		_, err := common.GetImageIndex(imgStore, "zot-test", validDigest, log)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger unmarshal error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, nil
			},
		}

		validDigest := godigest.FromBytes([]byte("blob"))

		_, err := common.GetImageIndex(imgStore, "zot-test", validDigest, log)
		So(err, ShouldNotBeNil)
	})
}

func TestGetBlobDescriptorFromRepo(t *testing.T) {
	log := log.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)

	tdir := t.TempDir()
	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     tdir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)

	driver := local.New(true)
	imgStore := imagestore.NewImageStore(tdir, tdir, true,
		true, log, metrics, nil, driver, cacheDriver)

	repoName := "zot-test"

	Convey("Test error paths", t, func() {
		storeController := storage.StoreController{DefaultStore: imgStore}

		image := CreateRandomMultiarch()

		tag := "index"

		err := WriteMultiArchImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		blob := image.Images[0].Layers[0]
		blobDigest := godigest.FromBytes(blob)
		blobSize := len(blob)

		desc, err := common.GetBlobDescriptorFromIndex(imgStore, ispec.Index{Manifests: []ispec.Descriptor{
			{
				Digest:    image.Digest(),
				MediaType: ispec.MediaTypeImageIndex,
			},
		}}, repoName, blobDigest, log)
		So(err, ShouldBeNil)
		So(desc.Digest, ShouldEqual, blobDigest)
		So(desc.Size, ShouldEqual, blobSize)

		desc, err = common.GetBlobDescriptorFromRepo(imgStore, repoName, blobDigest, log)
		So(err, ShouldBeNil)
		So(desc.Digest, ShouldEqual, blobDigest)
		So(desc.Size, ShouldEqual, blobSize)

		indexBlobPath := imgStore.BlobPath(repoName, image.Digest())
		err = os.Chmod(indexBlobPath, 0o000)
		So(err, ShouldBeNil)

		defer func() {
			err = os.Chmod(indexBlobPath, 0o644)
			So(err, ShouldBeNil)
		}()

		_, err = common.GetBlobDescriptorFromIndex(imgStore, ispec.Index{Manifests: []ispec.Descriptor{
			{
				Digest:    image.Digest(),
				MediaType: ispec.MediaTypeImageIndex,
			},
		}}, repoName, blobDigest, log)
		So(err, ShouldNotBeNil)

		manifestDigest := image.Images[0].Digest()
		manifestBlobPath := imgStore.BlobPath(repoName, manifestDigest)
		err = os.Chmod(manifestBlobPath, 0o000)
		So(err, ShouldBeNil)

		defer func() {
			err = os.Chmod(manifestBlobPath, 0o644)
			So(err, ShouldBeNil)
		}()

		_, err = common.GetBlobDescriptorFromRepo(imgStore, repoName, blobDigest, log)
		So(err, ShouldNotBeNil)

		_, err = common.GetBlobDescriptorFromRepo(imgStore, repoName, manifestDigest, log)
		So(err, ShouldBeNil)
	})
}

func TestIsSignature(t *testing.T) {
	Convey("Unknown media type", t, func(c C) {
		isSingature := common.IsSignature(ispec.Descriptor{
			MediaType: "unknown media type",
		})
		So(isSingature, ShouldBeFalse)
	})
}

func TestDedupeGeneratorErrors(t *testing.T) {
	log := log.Logger{Logger: zerolog.New(os.Stdout)}

	// Ideally this would be covered by the end-to-end test,
	// but the coverage for the error is unpredictable, prone to race conditions
	Convey("GetNextDigestWithBlobPaths errors", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{"repo1", "repo2"}, nil
			},
			GetNextDigestWithBlobPathsFn: func(repos []string, lastDigests []godigest.Digest) (
				godigest.Digest, []string, error,
			) {
				return "sha256:123", []string{}, ErrTestError
			},
		}

		generator := &common.DedupeTaskGenerator{
			ImgStore: imgStore,
			Dedupe:   true,
			Log:      log,
		}

		task, err := generator.Next()
		So(err, ShouldNotBeNil)
		So(task, ShouldBeNil)
	})
}
