package image_test

import (
	"encoding/json"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
)

func TestImageBuilder(t *testing.T) {
	vulnLayer, err := GetLayerWithVulnerability()
	if err != nil {
		t.FailNow()
	}

	Convey("Signature images", t, func() {
		image := CreateDefaultImage()
		cosign := CreateMockCosignSignature(image.DescriptorRef())
		So(cosign.Manifest.ArtifactType, ShouldResemble, common.ArtifactTypeCosign)

		notation := CreateMockNotationSignature(image.DescriptorRef())
		So(notation.Manifest.ArtifactType, ShouldResemble, common.ArtifactTypeNotation)
	})

	Convey("Test Layer Builders", t, func() {
		layerBuilder := CreateImageWith()

		Convey("LayerBlobs", func() {
			layerBlobs := [][]byte{{11, 11, 11}, {22, 22, 22}}

			image := layerBuilder.
				LayerBlobs(layerBlobs).
				DefaultConfig().
				Build()

			So(image.Layers, ShouldResemble, layerBlobs)
			So(image.Config, ShouldResemble, GetDefaultConfig())
		})

		Convey("DefaultLayers", func() {
			image := layerBuilder.
				DefaultLayers().
				DefaultConfig().
				Build()

			So(image.Layers, ShouldResemble, GetDefaultLayersBlobs())
			So(image.Config, ShouldResemble, GetDefaultConfig())
		})

		Convey("Layers", func() {
			blob1, blob2 := []byte{10, 10, 10}, []byte{20, 20, 20}

			layers := []Layer{
				{
					Blob:      blob1,
					MediaType: ispec.MediaTypeImageLayerGzip,
					Digest:    godigest.FromBytes(blob1),
				},
				{
					Blob:      blob2,
					MediaType: ispec.MediaTypeImageLayerGzip,
					Digest:    godigest.FromBytes(blob2),
				},
			}
			image := layerBuilder.
				Layers(layers).
				DefaultConfig().
				Build()

			So(image.Layers, ShouldResemble, [][]byte{blob1, blob2})
			So(image.Config, ShouldResemble, GetDefaultConfig())
		})

		Convey("Empty Layer", func() {
			image := layerBuilder.
				EmptyLayer().
				DefaultConfig().
				Build()

			So(image.Layers, ShouldResemble, [][]byte{ispec.DescriptorEmptyJSON.Data})
		})
	})

	Convey("Config builder", t, func() {
		configBuilder := CreateImageWith().DefaultLayers()

		Convey("Empty Config", func() {
			img := configBuilder.EmptyConfig().Build()
			So(img.Manifest.Config.Size, ShouldEqual, ispec.DescriptorEmptyJSON.Size)
			So(img.Manifest.Config.Digest, ShouldResemble, ispec.DescriptorEmptyJSON.Digest)
		})
	})

	Convey("Vulnerable config builder", t, func() {
		configBuilder := CreateImageWith().VulnerableLayers()

		Convey("VulnerableConfig", func() {
			platform := ispec.Platform{OS: "os", Architecture: "arch"}

			img := configBuilder.VulnerableConfig(ispec.Image{
				Platform: ispec.Platform{OS: "os", Architecture: "arch"},
			}).Build()

			So(img.Layers[0], ShouldEqual, vulnLayer)
			So(img.Config.Platform, ShouldResemble, platform)
		})

		Convey("Random VulnerableConfig", func() {
			img := configBuilder.RandomVulnConfig().Build()

			So(img.Layers[0], ShouldEqual, vulnLayer)
		})
	})

	Convey("Manifest builder", t, func() {
		manifestBuilder := CreateImageWith().DefaultLayers().DefaultConfig()

		subject := ispec.Descriptor{
			Digest:    godigest.FromString("digest"),
			MediaType: ispec.MediaTypeImageManifest,
		}

		image := manifestBuilder.
			Subject(&subject).
			ArtifactType("art.type").
			Annotations(map[string]string{"key": "val"}).
			Build()

		So(image.Layers, ShouldResemble, GetDefaultLayersBlobs())
		So(image.Config, ShouldResemble, GetDefaultConfig())
		So(image.Manifest.Subject, ShouldResemble, &subject)
		So(image.Manifest.ArtifactType, ShouldResemble, "art.type")
		So(image.Manifest.Annotations, ShouldResemble, map[string]string{"key": "val"})
	})
}

func TestMultiarchImageBuilder(t *testing.T) {
	Convey("Multiarch", t, func() {
		multiArch := CreateMultiarchWith().
			Images([]Image{
				CreateRandomImage(),
				CreateRandomImage(),
			}).
			Annotations(map[string]string{"a": "b"}).
			ArtifactType("art.type").
			Subject(&ispec.Descriptor{}).
			Build()

		So(len(multiArch.Images), ShouldEqual, 2)
		So(multiArch.Index.ArtifactType, ShouldResemble, "art.type")
		So(multiArch.Index.Subject, ShouldNotBeNil)
		So(multiArch.Index.Annotations, ShouldNotBeNil)
		So(multiArch.Index.Annotations, ShouldContainKey, "a")
	})
}

func TestPredefinedImages(t *testing.T) {
	Convey("Predefined Images", t, func() {
		img := CreateDefaultImage()
		So(img.Layers, ShouldResemble, GetDefaultLayersBlobs())

		img = CreateDefaultImageWith().ArtifactType("art.type").Build()
		So(img.Manifest.ArtifactType, ShouldEqual, "art.type")

		img = CreateRandomImageWith().ArtifactType("art.type").Build()
		So(img.Manifest.ArtifactType, ShouldEqual, "art.type")

		img = CreateRandomVulnerableImage()
		So(img.Layers, ShouldNotResemble, GetDefaultLayersBlobs())

		img = CreateRandomVulnerableImageWith().ArtifactType("art.type").Build()
		So(img.Manifest.ArtifactType, ShouldEqual, "art.type")
	})
}

func TestImageMethods(t *testing.T) {
	img := CreateDefaultImage()

	Convey("Image", t, func() {
		manifestBlob, err := json.Marshal(img.Manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBlob)
		manifestSize := int64(len(manifestBlob))

		Convey("img descriptor", func() {
			descriptor := img.Descriptor()

			So(manifestDigest, ShouldResemble, descriptor.Digest)
			So(manifestSize, ShouldEqual, descriptor.Size)
			So(ispec.MediaTypeImageManifest, ShouldResemble, descriptor.MediaType)
		})
	})
}
