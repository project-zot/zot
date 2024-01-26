//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package ociutils_test

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

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/local"
	tcommon "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
	signature "zotregistry.dev/zot/pkg/test/signature"
)

var ErrTestError = fmt.Errorf("testError")

func TestBaseOciLayoutUtils(t *testing.T) {
	Convey("GetImageManifestSize fail", t, func() {
		mockStoreController := mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, ErrTestError
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		size := olu.GetImageConfigSize("", "")
		So(size, ShouldBeZeroValue)
	})

	Convey("GetImageConfigSize: config GetBlobContent fail", t, func() {
		image := CreateRandomImage()
		manifestDigest := image.ConfigDescriptor.Digest.String()

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
							"digest": "` + image.Manifest.Layers[0].Digest.String() + `",
							"size": 76097157
						}
					]
				}`), nil
			},
		}

		storeController := storage.StoreController{DefaultStore: mockStoreController}
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		_, err = olu.GetExpandedRepoInfo("rep")
		So(err, ShouldNotBeNil)

		// GetRepoLastUpdated fails
		mockStoreController = mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return indexBlob, nil
			},
		}

		storeController = storage.StoreController{DefaultStore: mockStoreController}
		olu = ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu = ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

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
		olu := ociutils.NewBaseOciLayoutUtils(storeController, log.NewLogger("debug", ""))

		check := olu.CheckManifestSignature("rep", godigest.FromString(""))
		So(check, ShouldBeFalse)

		// checkNotarySignature -> true
		dir := t.TempDir()

		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// push test image to repo
		image := CreateRandomImage()

		repo := "repo"
		tag := "1.0.1"
		err := UploadImage(image, baseURL, repo, tag)
		So(err, ShouldBeNil)

		olu = ociutils.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewLogger("debug", ""))
		manifestList, err := olu.GetImageManifests(repo)
		So(err, ShouldBeNil)
		So(len(manifestList), ShouldEqual, 1)

		isSigned := olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeFalse)

		err = signature.SignImageUsingNotary(fmt.Sprintf("%s:%s", repo, tag), port, true)
		So(err, ShouldBeNil)

		isSigned = olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeTrue)
	})

	//nolint: dupl
	Convey("CheckManifestSignature: cosign(tag)", t, func() {
		// checkCosignSignature -> true (tag)
		dir := t.TempDir()

		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// push test image to repo
		image := CreateRandomImage()

		repo := "repo2"
		tag := "1.0.2"
		err := UploadImage(image, baseURL, repo, tag)
		So(err, ShouldBeNil)

		olu := ociutils.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewLogger("debug", ""))
		manifestList, err := olu.GetImageManifests(repo)
		So(err, ShouldBeNil)
		So(len(manifestList), ShouldEqual, 1)

		isSigned := olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeFalse)

		// checkCosignSignature -> true (tag)
		err = signature.SignImageUsingCosign(fmt.Sprintf("%s:%s", repo, tag), port, false)
		So(err, ShouldBeNil)

		isSigned = olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeTrue)
	})

	//nolint: dupl
	Convey("CheckManifestSignature: cosign(with referrers)", t, func() {
		// checkCosignSignature -> true (referrers)
		dir := t.TempDir()

		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		conf.Extensions.Search.CVE = nil

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		// push test image to repo
		image := CreateRandomImage()

		repo := "repo3"
		tag := "1.0.3"
		err := UploadImage(image, baseURL, repo, tag)
		So(err, ShouldBeNil)

		olu := ociutils.NewBaseOciLayoutUtils(ctlr.StoreController, log.NewLogger("debug", ""))
		manifestList, err := olu.GetImageManifests(repo)
		So(err, ShouldBeNil)
		So(len(manifestList), ShouldEqual, 1)

		isSigned := olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeFalse)

		// checkCosignSignature -> true (referrers)
		err = signature.SignImageUsingCosign(fmt.Sprintf("%s:%s", repo, tag), port, true)
		So(err, ShouldBeNil)

		isSigned = olu.CheckManifestSignature(repo, manifestList[0].Digest)
		So(isSigned, ShouldBeTrue)
	})
}

func TestExtractImageDetails(t *testing.T) {
	Convey("extractImageDetails good workflow", t, func() {
		dir := t.TempDir()
		testLogger := log.NewLogger("debug", "")
		imageStore := local.NewImageStore(dir, false, false,
			testLogger, monitoring.NewMetricsServer(false, testLogger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		image := CreateRandomImage()

		err := WriteImageToFileSystem(image, "zot-test", "latest", storeController)
		So(err, ShouldBeNil)

		olu := ociutils.NewBaseOciLayoutUtils(storeController, testLogger)
		resDigest, resManifest, resIspecImage, resErr := olu.ExtractImageDetails("zot-test", "latest", testLogger)
		So(string(resDigest), ShouldEqual, image.ManifestDescriptor.Digest.String())
		So(resManifest.Config.Digest.String(), ShouldEqual, image.ConfigDescriptor.Digest.String())

		So(resIspecImage.Architecture, ShouldContainSubstring, "amd64")
		So(resErr, ShouldBeNil)
	})

	Convey("extractImageDetails bad ispec.ImageManifest", t, func() {
		dir := t.TempDir()
		testLogger := log.NewLogger("debug", "")
		imageStore := local.NewImageStore(dir, false, false,
			testLogger, monitoring.NewMetricsServer(false, testLogger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		olu := ociutils.NewBaseOciLayoutUtils(storeController, testLogger)
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
		imageStore := local.NewImageStore(dir, false, false,
			testLogger, monitoring.NewMetricsServer(false, testLogger), nil, nil)

		storeController := storage.StoreController{
			DefaultStore: imageStore,
		}

		image := CreateRandomImage()

		err := WriteImageToFileSystem(image, "zot-test", "latest", storeController)
		So(err, ShouldBeNil)

		err = os.Remove(path.Join(dir, "zot-test/blobs/sha256", image.ConfigDescriptor.Digest.Encoded()))
		if err != nil {
			panic(err)
		}

		olu := ociutils.NewBaseOciLayoutUtils(storeController, testLogger)
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
			Tag: "1.0.0",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a178362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}
		secondTag := cvemodel.TagInfo{
			Tag: "1.0.1",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a179362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}
		thirdTag := cvemodel.TagInfo{
			Tag: "1.0.2",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a170362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}
		fourthTag := cvemodel.TagInfo{
			Tag: "1.0.3",
			Descriptor: cvemodel.Descriptor{
				Digest:    "sha256:eca04f027f414362596f2632746d8a171362170b9ac9af772011fedcc3877ebb",
				MediaType: ispec.MediaTypeImageManifest,
			},
			Timestamp: time.Now(),
		}

		allTags = append(allTags, firstTag, secondTag, thirdTag, fourthTag)

		latestTag := ociutils.GetLatestTag(allTags)
		So(latestTag.Tag, ShouldEqual, "1.0.3")
	})
}
