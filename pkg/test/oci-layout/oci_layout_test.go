//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package ocilayout_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	. "zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
	ocilayout "zotregistry.io/zot/pkg/test/oci-layout"
)

var ErrTestError = fmt.Errorf("testError")

func TestBaseOciLayoutUtils(t *testing.T) {
	manifestDigest := GetTestBlobDigest("zot-test", "config").String()

	Convey("GetImageManifestSize fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		size := olu.GetImageManifestSize("", "")
		So(size, ShouldBeZeroValue)
	})

	Convey("GetImageConfigSize: fail GetImageBlobManifest", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		size := olu.GetImageConfigSize("", "")
		So(size, ShouldBeZeroValue)
	})

	Convey("GetImageConfigSize: config GetBlobContent fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				if digest.String() == manifestDigest {
					return []byte{}, ErrTestError
				}

				return []byte(
					`
				{
					"schemaVersion": 2,
					"mediaType": "application/vnd.oci.image.manifest.v1+json",
					"config": {
						"mediaType": "application/vnd.oci.image.config.v1+json",
						"digest": manifestDigest,
						"size": 1476
					},
					"layers": [
						{
							"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
							"digest": "` + GetTestBlobDigest("zot-test", "layer").String() + `",
							"size": 76097157
						}
					]
				}`), nil
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		size := olu.GetImageConfigSize("", "")
		So(size, ShouldBeZeroValue)
	})

	Convey("GetRepoLastUpdated: config GetBlobContent fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err := olu.GetRepoLastUpdated("")
		So(err, ShouldNotBeNil)
	})

	Convey("GetImageTagsWithTimestamp: GetImageBlobManifest fails", t, func() {
		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{Annotations: map[string]string{ispec.AnnotationRefName: "w"}}, {},
			},
		}

		indexBlob, err := json.Marshal(index)
		So(err, ShouldBeNil)

		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return nil, ErrTestError
			},
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return indexBlob, nil
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err = olu.GetImageTagsWithTimestamp("rep")
		So(err, ShouldNotBeNil)
	})

	Convey("GetImageTagsWithTimestamp: GetImageInfo fails", t, func() {
		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{Annotations: map[string]string{ispec.AnnotationRefName: "w"}}, {},
			},
		}

		indexBlob, err := json.Marshal(index)
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    "configDigest",
			},
			Layers: []ispec.Descriptor{
				{},
				{},
			},
		}

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				if digest.String() == "configDigest" {
					return nil, ErrTestError
				}

				return manifestBlob, nil
			},
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return indexBlob, nil
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err = olu.GetImageTagsWithTimestamp("repo")
		So(err, ShouldNotBeNil)
	})

	Convey("GetExpandedRepoInfo: fails", t, func() {
		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{},
				{
					Annotations: map[string]string{
						ispec.AnnotationRefName: "w",
						ispec.AnnotationVendor:  "vend",
					},
				},
			},
		}

		indexBlob, err := json.Marshal(index)
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{
			Annotations: map[string]string{
				ispec.AnnotationRefName: "w",
				ispec.AnnotationVendor:  "vend",
			},
			Layers: []ispec.Descriptor{
				{},
				{},
			},
		}

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		mockStoreController := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return nil, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err = olu.GetExpandedRepoInfo("rep")
		So(err, ShouldNotBeNil)

		// GetRepoLastUpdated fails
		mockStoreController = mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return indexBlob, nil
			},
		}

		storeController = storage.StoreController{DefaultStore: mockStoreController}
		olu = ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err = olu.GetExpandedRepoInfo("rep")
		So(err, ShouldNotBeNil)

		// anotations

		mockStoreController = mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return indexBlob, nil
			},
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return manifestBlob, nil
			},
		}

		storeController = storage.StoreController{DefaultStore: mockStoreController}
		olu = ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err = olu.GetExpandedRepoInfo("rep")
		So(err, ShouldBeNil)
	})

	Convey("GetImageInfo fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err := olu.GetImageInfo("", "")
		So(err, ShouldNotBeNil)
	})

	Convey("CheckManifestSignature: notation", t, func() {
		// GetReferrers - fails => checkNotarySignature returns false
		mockStoreController := mocks.MockedImageStore{
			GetImageManifestFn: func(name, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "", "", zerr.ErrRepoNotFound
			},
			GetReferrersFn: func(name string, digest godigest.Digest, mediaTypes []string) (ispec.Index, error) {
				return ispec.Index{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ocilayout.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		check := olu.CheckManifestSignature("rep", godigest.FromString(""))
		So(check, ShouldBeFalse)

		// checkNotarySignature -> true
		dir := t.TempDir()

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// push test image to repo
		config, layers, manifest, err := GetImageComponents(100)
		So(err, ShouldBeNil)

		layersSize1 := 0
		for _, l := range layers {
			layersSize1 += len(l)
		}

		repo := "repo"
		tag := "1.0.1"
		err = UploadImage(
			Image{
				Manifest:  manifest,
				Config:    config,
				Layers:    layers,
				Reference: tag,
			},
			baseURL,
			repo,
		)
		So(err, ShouldBeNil)

		olu = ocilayout.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewLogger("debug", ""))
		manifestList, err := olu.GetImageManifests(repo)
		So(err, ShouldBeNil)
		So(len(manifestList), ShouldEqual, 1)

		isSigned := olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeFalse)

		err = SignImageUsingNotary(fmt.Sprintf("%s:%s", repo, tag), port)
		So(err, ShouldBeNil)

		isSigned = olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeTrue)
	})
}

func TestExtractImageDetails(t *testing.T) {
	Convey("extractImageDetails good workflow", t, func() {
		dir := t.TempDir()
		testLogger := log.NewLogger("debug", "")
		imageStore := local.NewImageStore(dir, false, 0, false, false,
			testLogger, monitoring.NewMetricsServer(false, testLogger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		num := 10
		config, layers, manifest, err := GetImageComponents(num)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(
			Image{
				Manifest:  manifest,
				Layers:    layers,
				Config:    config,
				Reference: "latest",
			}, "zot-test", storeController,
		)
		So(err, ShouldBeNil)

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)
		configDigest := godigest.FromBytes(configBlob)

		olu := ocilayout.NewBaseOciLayoutUtils(storeController, testLogger)
		resDigest, resManifest, resIspecImage, resErr := olu.ExtractImageDetails("zot-test", "latest", testLogger)
		So(string(resDigest), ShouldContainSubstring, "sha256:8492645f16")
		So(resManifest.Config.Digest.String(), ShouldContainSubstring, configDigest.Encoded())

		So(resIspecImage.Architecture, ShouldContainSubstring, "amd64")
		So(resErr, ShouldBeNil)
	})

	Convey("extractImageDetails bad ispec.ImageManifest", t, func() {
		dir := t.TempDir()
		testLogger := log.NewLogger("debug", "")
		imageStore := local.NewImageStore(dir, false, 0, false, false,
			testLogger, monitoring.NewMetricsServer(false, testLogger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		olu := ocilayout.NewBaseOciLayoutUtils(storeController, testLogger)
		resDigest, resManifest, resIspecImage, resErr := olu.ExtractImageDetails("zot-test",
			"latest", testLogger)
		So(resErr, ShouldEqual, zerr.ErrRepoNotFound)
		So(string(resDigest), ShouldEqual, "")
		So(resManifest, ShouldBeNil)

		So(resIspecImage, ShouldBeNil)
	})

	Convey("extractImageDetails bad imageConfig", t, func() {
		dir := t.TempDir()
		testLogger := log.NewLogger("debug", "")
		imageStore := local.NewImageStore(dir, false, 0, false, false,
			testLogger, monitoring.NewMetricsServer(false, testLogger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		num := 10
		config, layers, manifest, err := GetImageComponents(num)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(
			Image{
				Manifest:  manifest,
				Layers:    layers,
				Config:    config,
				Reference: "latest",
			}, "zot-test", storeController,
		)
		So(err, ShouldBeNil)

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)
		configDigest := godigest.FromBytes(configBlob)

		err = os.Remove(path.Join(dir, "zot-test/blobs/sha256", configDigest.Encoded()))
		if err != nil {
			panic(err)
		}

		olu := ocilayout.NewBaseOciLayoutUtils(storeController, testLogger)
		resDigest, resManifest, resIspecImage, resErr := olu.ExtractImageDetails("zot-test", "latest", testLogger)
		So(resErr, ShouldEqual, zerr.ErrBlobNotFound)
		So(string(resDigest), ShouldEqual, "")
		So(resManifest, ShouldBeNil)
		So(resIspecImage, ShouldBeNil)
	})
}

func TestTagsInfo(t *testing.T) {
	Convey("Test tags info", t, func() {
		allTags := make([]cvemodel.TagInfo, 0)

		firstTag := cvemodel.TagInfo{
			Name: "1.0.0",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}
		secondTag := cvemodel.TagInfo{
			Name: "1.0.1",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a179362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}
		thirdTag := cvemodel.TagInfo{
			Name: "1.0.2",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a170362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}
		fourthTag := cvemodel.TagInfo{
			Name: "1.0.3",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a171362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}

		allTags = append(allTags, firstTag, secondTag, thirdTag, fourthTag)

		latestTag := ocilayout.GetLatestTag(allTags)
		So(latestTag.Name, ShouldEqual, "1.0.3")
	})
}
