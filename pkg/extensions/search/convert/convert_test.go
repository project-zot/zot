package convert_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/extensions/search/convert"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	. "zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestConvertErrors(t *testing.T) {
	Convey("", t, func() {
		repoDB, err := bolt.NewBoltDBWrapper(bolt.DBParameters{
			RootDir: t.TempDir(),
		})
		So(err, ShouldBeNil)

		configBlob, err := json.Marshal(ispec.Image{})
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(ispec.Manifest{
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayerGzip,
					Size:      0,
					Digest:    godigest.NewDigestFromEncoded(godigest.SHA256, "digest"),
				},
			},
		})
		So(err, ShouldBeNil)

		repoMeta11 := repodb.ManifestMetadata{
			ManifestBlob: manifestBlob,
			ConfigBlob:   configBlob,
		}

		digest11 := godigest.FromString("abc1")
		err = repoDB.SetManifestMeta("repo1", digest11, repoMeta11)
		So(err, ShouldBeNil)
		err = repoDB.SetRepoTag("repo1", "0.1.0", digest11, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		repoMetas, manifestMetaMap, _, err := repoDB.SearchRepos(context.Background(), "", repodb.Filter{},
			repodb.PageInput{})
		So(err, ShouldBeNil)

		ctx := graphql.WithResponseContext(context.Background(),
			graphql.DefaultErrorPresenter, graphql.DefaultRecover)

		_ = convert.RepoMeta2RepoSummary(
			ctx,
			repoMetas[0],
			manifestMetaMap,
			convert.SkipQGLField{},
			mocks.CveInfoMock{
				GetCVESummaryForImageFn: func(image string) (cveinfo.ImageCVESummary, error) {
					return cveinfo.ImageCVESummary{}, ErrTestError
				},
			},
		)

		So(graphql.GetErrors(ctx).Error(), ShouldContainSubstring, "unable to run vulnerability scan on tag")
	})
}

func TestBuildImageInfo(t *testing.T) {
	rootDir := t.TempDir()

	port := GetFreePort()
	baseURL := GetBaseURL(port)

	conf := config.New()
	conf.HTTP.Port = port
	conf.Storage.RootDirectory = rootDir
	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}

	conf.Extensions.Search.CVE = nil

	ctlr := api.NewController(conf)
	ctlrManager := NewControllerManager(ctlr)

	ctlrManager.StartAndWait(port)
	defer ctlrManager.StopServer()

	olu := &common.BaseOciLayoutUtils{
		StoreController: ctlr.StoreController,
		Log:             ctlr.Log,
	}

	Convey("Check image summary when the image has no history", t, func() {
		imageName := "nohistory"

		config := ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author: "ZotUser",
		}

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)
		layerDigest := godigest.FromString(imageName)
		layerblob := []byte(imageName)
		schemaVersion := 2
		ispecManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: schemaVersion,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{ // just 1 layer in manifest
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len(layerblob)),
				},
			},
		}
		manifestLayersSize := ispecManifest.Layers[0].Size
		manifestBlob, err := json.Marshal(ispecManifest)
		So(err, ShouldBeNil)
		manifestDigest := godigest.FromBytes(manifestBlob)
		err = UploadImage(
			Image{
				Manifest: ispecManifest,
				Config:   config,
				Layers: [][]byte{
					layerblob,
				},
				Tag: "0.0.1",
			},
			baseURL,
			imageName,
		)
		So(err, ShouldBeNil)

		imageConfig, err := olu.GetImageConfigInfo(imageName, manifestDigest)
		So(err, ShouldBeNil)

		isSigned := false

		imageSummary := convert.BuildImageInfo(imageName, imageName, manifestDigest, ispecManifest,
			imageConfig, isSigned)

		So(len(imageSummary.Layers), ShouldEqual, len(ispecManifest.Layers))
		imageSummaryLayerSize, err := strconv.Atoi(*imageSummary.Size)
		So(err, ShouldBeNil)
		So(imageSummaryLayerSize, ShouldEqual, manifestLayersSize)
	})

	Convey("Check image summary when layer count matche history entries", t, func() {
		imageName := "valid"

		config := ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author: "ZotUser",
			History: []ispec.History{ // should contain 3 elements, 2 of which corresponding to layers
				{
					EmptyLayer: false,
				},
				{
					EmptyLayer: false,
				},
				{
					EmptyLayer: true,
				},
			},
		}

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)
		layerDigest := godigest.FromString("layer1")
		layerblob := []byte("layer1")
		layerDigest2 := godigest.FromString("layer2")
		layerblob2 := []byte("layer2")
		schemaVersion := 2
		ispecManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: schemaVersion,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{ // just 1 layer in manifest
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len(layerblob)),
				},
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest2,
					Size:      int64(len(layerblob2)),
				},
			},
		}
		manifestLayersSize := ispecManifest.Layers[0].Size + ispecManifest.Layers[1].Size
		manifestBlob, err := json.Marshal(ispecManifest)
		So(err, ShouldBeNil)
		manifestDigest := godigest.FromBytes(manifestBlob)
		err = UploadImage(
			Image{
				Manifest: ispecManifest,
				Config:   config,
				Layers: [][]byte{
					layerblob,
					layerblob2,
				},
				Tag: "0.0.1",
			},
			baseURL,
			imageName,
		)
		So(err, ShouldBeNil)

		imageConfig, err := olu.GetImageConfigInfo(imageName, manifestDigest)
		So(err, ShouldBeNil)

		isSigned := false

		imageSummary := convert.BuildImageInfo(imageName, imageName, manifestDigest, ispecManifest,
			imageConfig, isSigned)

		So(len(imageSummary.Layers), ShouldEqual, len(ispecManifest.Layers))
		imageSummaryLayerSize, err := strconv.Atoi(*imageSummary.Size)
		So(err, ShouldBeNil)
		So(imageSummaryLayerSize, ShouldEqual, manifestLayersSize)
	})

	Convey("Check image summary when layer count does not match history", t, func() {
		imageName := "invalid"

		config := ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			RootFS: ispec.RootFS{
				Type:    "layers",
				DiffIDs: []godigest.Digest{},
			},
			Author: "ZotUser",
			History: []ispec.History{ // should contain 3 elements, 2 of which corresponding to layers
				{
					EmptyLayer: false,
				},
				{
					EmptyLayer: false,
				},
				{
					EmptyLayer: true,
				},
			},
		}

		configBlob, err := json.Marshal(config)
		So(err, ShouldBeNil)

		configDigest := godigest.FromBytes(configBlob)
		layerDigest := godigest.FromString(imageName)
		layerblob := []byte(imageName)
		schemaVersion := 2
		ispecManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: schemaVersion,
			},
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configBlob)),
			},
			Layers: []ispec.Descriptor{ // just 1 layer in manifest
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len(layerblob)),
				},
			},
		}
		manifestLayersSize := ispecManifest.Layers[0].Size
		manifestBlob, err := json.Marshal(ispecManifest)
		So(err, ShouldBeNil)
		manifestDigest := godigest.FromBytes(manifestBlob)
		err = UploadImage(
			Image{
				Manifest: ispecManifest,
				Config:   config,
				Layers: [][]byte{
					layerblob,
				},
				Tag: "0.0.1",
			},
			baseURL,
			imageName,
		)
		So(err, ShouldBeNil)

		imageConfig, err := olu.GetImageConfigInfo(imageName, manifestDigest)
		So(err, ShouldBeNil)

		isSigned := false

		imageSummary := convert.BuildImageInfo(imageName, imageName, manifestDigest, ispecManifest,
			imageConfig, isSigned)

		So(len(imageSummary.Layers), ShouldEqual, len(ispecManifest.Layers))
		imageSummaryLayerSize, err := strconv.Atoi(*imageSummary.Size)
		So(err, ShouldBeNil)
		So(imageSummaryLayerSize, ShouldEqual, manifestLayersSize)
	})
}
