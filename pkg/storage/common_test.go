package storage_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

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
		imgStore := local.NewImageStore(dir, true, storage.DefaultGCDelay, true,
			true, log, metrics, nil, cacheDriver)

		content := []byte("this is a blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		_, blen, err := imgStore.FullBlobUpload("test", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		cblob, cdigest := test.GetRandomImageConfig()
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

			_, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldNotBeNil)
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

			_, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldNotBeNil)
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

		imgStore := local.NewImageStore(dir, true, storage.DefaultGCDelay, false,
			true, log, metrics, nil, cacheDriver)

		artifactType := "application/vnd.example.icecream.v1"
		validDigest := godigest.FromBytes([]byte("blob"))

		Convey("Trigger invalid digest error", func(c C) {
			_, err := storage.GetReferrers(imgStore, "zot-test", "invalidDigest",
				[]string{artifactType}, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)

			_, err = storage.GetOrasReferrers(imgStore, "zot-test", "invalidDigest",
				artifactType, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger repo not found error", func(c C) {
			_, err := storage.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)

			_, err = storage.GetOrasReferrers(imgStore, "zot-test", validDigest,
				artifactType, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)
		})

		err := test.CopyFiles("../../test/data/zot-test", path.Join(dir, "zot-test"))
		So(err, ShouldBeNil)

		digest := godigest.FromBytes([]byte("{}"))

		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: artifactspec.MediaTypeArtifactManifest,
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
					return []byte{}, errors.ErrBlobNotFound
				},
			}

			_, err = storage.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)

			_, err = storage.GetOrasReferrers(imgStore, "zot-test", validDigest,
				artifactType, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger GetBlobContent() generic error", func(c C) {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, errors.ErrBadBlob
				},
			}

			_, err = storage.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)

			_, err = storage.GetOrasReferrers(imgStore, "zot-test", validDigest,
				artifactType, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger continue on different artifactType", func(c C) {
			orasManifest := artifactspec.Manifest{
				Subject: &artifactspec.Descriptor{
					Digest:       digest,
					ArtifactType: "unknown",
				},
			}

			orasBuf, err := json.Marshal(orasManifest)
			So(err, ShouldBeNil)

			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return orasBuf, nil
				},
			}

			_, err = storage.GetOrasReferrers(imgStore, "zot-test", validDigest,
				artifactType, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)

			_, err = storage.GetOrasReferrers(imgStore, "zot-test", digest,
				artifactType, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)
		})

		Convey("Unmarshal oras artifact error", func(c C) {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte("wrong content"), nil
				},
			}

			_, err = storage.GetOrasReferrers(imgStore, "zot-test", validDigest, artifactType, log.With().Caller().Logger())
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

			_, err = storage.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger unmarshal error on artifact mediaType", func(c C) {
			index = ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeArtifactManifest,
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

			_, err = storage.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log.With().Caller().Logger())
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger nil subject", func(c C) {
			index = ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeArtifactManifest,
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

			_, err = storage.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log.With().Caller().Logger())
			So(err, ShouldBeNil)
		})
	})
}

func TestGetImageIndexErrors(t *testing.T) {
	log := zerolog.New(os.Stdout)

	Convey("Trigger invalid digest error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{}

		_, err := storage.GetImageIndex(imgStore, "zot-test", "invalidDigest", log)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger GetBlobContent error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, errors.ErrBlobNotFound
			},
		}

		validDigest := godigest.FromBytes([]byte("blob"))

		_, err := storage.GetImageIndex(imgStore, "zot-test", validDigest, log)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger unmarshal error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, nil
			},
		}

		validDigest := godigest.FromBytes([]byte("blob"))

		_, err := storage.GetImageIndex(imgStore, "zot-test", validDigest, log)
		So(err, ShouldNotBeNil)
	})
}
