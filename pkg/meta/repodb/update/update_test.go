package update_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	bolt_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	repoDBUpdate "zotregistry.io/zot/pkg/meta/repodb/update"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("test error")

func TestOnUpdateManifest(t *testing.T) {
	Convey("On UpdateManifest", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)
		storeController.DefaultStore = local.NewImageStore(rootDir, true, 1*time.Second,
			true, true, log, metrics, nil, nil,
		)

		repoDB, err := bolt_wrapper.NewBoltDBWrapper(bolt_wrapper.DBParameters{
			RootDir: rootDir,
		})
		So(err, ShouldBeNil)

		config, layers, manifest, err := test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(test.Image{Config: config, Manifest: manifest, Layers: layers, Tag: "tag1"},
			"repo", storeController)
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		digest := godigest.FromBytes(manifestBlob)

		err = repoDBUpdate.OnUpdateManifest("repo", "tag1", "", digest, manifestBlob, storeController, repoDB, log)
		So(err, ShouldBeNil)

		repoMeta, err := repoDB.GetRepoMeta("repo")
		So(err, ShouldBeNil)

		So(repoMeta.Tags, ShouldContainKey, "tag1")
	})
}

func TestUpdateErrors(t *testing.T) {
	Convey("Update operations", t, func() {
		Convey("On UpdateManifest", func() {
			imageStore := mocks.MockedImageStore{}
			storeController := storage.StoreController{DefaultStore: &imageStore}
			repoDB := mocks.RepoDBMock{}
			log := log.NewLogger("debug", "")

			Convey("zerr.ErrOrphanSignature", func() {
				manifestContent := oras.Manifest{
					Subject: &oras.Descriptor{
						Digest: "123",
					},
				}
				manifestBlob, err := json.Marshal(manifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte{}, "", "", zerr.ErrManifestNotFound
				}

				err = repoDBUpdate.OnUpdateManifest("repo", "tag1", "", "digest", manifestBlob,
					storeController, repoDB, log)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("On DeleteManifest", func() {
			imageStore := mocks.MockedImageStore{}
			storeController := storage.StoreController{DefaultStore: &imageStore}
			repoDB := mocks.RepoDBMock{}
			log := log.NewLogger("debug", "")

			Convey("CheckIsImageSignature errors", func() {
				manifestContent := oras.Manifest{
					Subject: &oras.Descriptor{
						Digest: "123",
					},
				}
				manifestBlob, err := json.Marshal(manifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte{}, "", "", zerr.ErrManifestNotFound
				}

				err = repoDBUpdate.OnDeleteManifest("repo", "tag1", "digest", "media", manifestBlob,
					storeController, repoDB, log)
				So(err, ShouldNotBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte{}, "", "", ErrTestError
				}

				err = repoDBUpdate.OnDeleteManifest("repo", "tag1", "digest", "media", manifestBlob,
					storeController, repoDB, log)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("On GetManifest", func() {
			imageStore := mocks.MockedImageStore{}
			storeController := storage.StoreController{DefaultStore: &imageStore}
			repoDB := mocks.RepoDBMock{}
			log := log.NewLogger("debug", "")

			Convey("CheckIsImageSignature errors", func() {
				manifestContent := oras.Manifest{
					Subject: &oras.Descriptor{
						Digest: "123",
					},
				}
				manifestBlob, err := json.Marshal(manifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte{}, "", "", zerr.ErrManifestNotFound
				}

				err = repoDBUpdate.OnGetManifest("repo", "tag1", "digest", manifestBlob,
					storeController, repoDB, log)
				So(err, ShouldNotBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte{}, "", "", ErrTestError
				}

				err = repoDBUpdate.OnGetManifest("repo", "tag1", "media", manifestBlob,
					storeController, repoDB, log)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SetMetadataFromInput", func() {
			imageStore := mocks.MockedImageStore{}
			storeController := storage.StoreController{DefaultStore: &imageStore}
			repoDB := mocks.RepoDBMock{}
			log := log.NewLogger("debug", "")

			err := repoDBUpdate.SetMetadataFromInput("repo", "ref", "digest", "", []byte("BadManifestBlob"),
				storeController, repoDB, log)
			So(err, ShouldNotBeNil)

			// reference is digest

			manifestContent := ispec.Manifest{}
			manifestBlob, err := json.Marshal(manifestContent)
			So(err, ShouldBeNil)

			imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				return manifestBlob, "", "", nil
			}
			imageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte("{}"), nil
			}

			err = repoDBUpdate.SetMetadataFromInput("repo", string(godigest.FromString("reference")), "", "digest",
				manifestBlob, storeController, repoDB, log)
			So(err, ShouldBeNil)
		})
	})
}
