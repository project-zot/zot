package image

import (
	"crypto/rand"
	"encoding/json"
	mathRand "math/rand"
	"strconv"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/pkg/common"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
)

const (
	TestFakeSignatureArtType = "application/test.fake.signature"
)

// LayerBuilder abstracts the first step in creating an OCI image, specifying the layers of the image.
type LayerBuilder interface {
	// LayerBlobs sets the image layers from the gives blobs array, adding a default zipped layer media type.
	LayerBlobs(layers [][]byte) ConfigBuilder
	// Layers sets the given layers to the built image
	Layers(layers []Layer) ConfigBuilder
	// RandomLayers generates `count` layers with the given size and initialises them with random values
	// and a default zipped layer media type.
	RandomLayers(count, size int) ConfigBuilder
	// EmptyLayer adds a single empty json layer semnifying no layers.
	EmptyLayer() ConfigBuilder
	// DefaultLayers adds predefined default layers.
	DefaultLayers() ConfigBuilder
	// VulnerableLayers adds layers that contains known CVE's.
	VulnerableLayers() VulnerableConfigBuilder
}

// ConfigBuilder abstracts the second step in creating an OCI image, specifying the config content of the image.
type ConfigBuilder interface {
	// ImageConfig sets the given image config. It updates the "config" field of the image manifest with
	// values corresponding to the given image.
	ImageConfig(config ispec.Image) ManifestBuilder
	// ImageConfig sets an empty json as the images config. It updates the "config" field of the image manifest with
	// values corresponding to the empty descriptor.
	EmptyConfig() ManifestBuilder
	// ArtifactConfig sets an empty json as the content of the image config and sets it's media type (described by
	// the Config field of the image manifest) to the given artifact type. This will make the created image
	// an OCI artifact.
	// (see: https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidelines-for-artifact-usage)
	ArtifactConfig(artifactType string) ManifestBuilder
	// PlatformConfig is used when we're interesting in specifying only the platform of a manifest.
	// Other fields of the config are random.
	PlatformConfig(architecture, os string) ManifestBuilder
	// DefaultConfig sets the default config, platform linux/amd64.
	DefaultConfig() ManifestBuilder
	// CustomConfigBlob will set a custom blob as the image config without other checks.
	CustomConfigBlob(configBlob []byte, mediaType string) ManifestBuilder
	// RandomConfig sets a randomly generated config.
	RandomConfig() ManifestBuilder
}

// VulnerableConfigBuilder abstracts specifying the config of an vulnerable OCI image.
// Keeping the RootFS field consistent with the vulnerable layers.
type VulnerableConfigBuilder interface {
	// VulnerableConfig sets the given config while keeping the correct RootFS values for the
	// vulnerable layer set earlier. This allows scan tools to find CVE's
	VulnerableConfig(config ispec.Image) ManifestBuilder
	// DefaultVulnConfig sets default config of the vulnerable image
	DefaultVulnConfig() ManifestBuilder
	// RandomVulnConfig sets the keeping the correct RootFS values for the
	// vulnerable layer set earlier. This allows scan tools to find CVE's
	RandomVulnConfig() ManifestBuilder
}

// ManifestBuilder abstracts creating the manifest of the image.
type ManifestBuilder interface {
	// Subject sets the subject of the image manifest.
	Subject(subject *ispec.Descriptor) ManifestBuilder
	// ArtifactType sets the artifact type field on the image manifest,
	// (see: https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidelines-for-artifact-usage)
	ArtifactType(artifactType string) ManifestBuilder
	// Annotations sets the annotations field on the image manifest.
	Annotations(annotations map[string]string) ManifestBuilder

	Build() Image
}

type Image struct {
	Manifest ispec.Manifest
	Config   ispec.Image
	Layers   [][]byte

	ConfigDescriptor   ispec.Descriptor
	ManifestDescriptor ispec.Descriptor
}

func (img *Image) Digest() godigest.Digest {
	if img.ManifestDescriptor.Digest != "" {
		return img.ManifestDescriptor.Digest
	}

	// when we'll migrate all code to the new format of creating images we can replace this with
	// the value from manifestDescriptor
	blob, err := json.Marshal(img.Manifest)
	if err != nil {
		panic("unreachable: ispec.Manifest should always be marshable")
	}

	return godigest.FromBytes(blob)
}

func (img *Image) DigestStr() string {
	return img.Digest().String()
}

func (img *Image) Size() int {
	size := img.ConfigDescriptor.Size + img.ManifestDescriptor.Size

	for _, layer := range img.Manifest.Layers {
		size += layer.Size
	}

	return int(size)
}

func (img Image) Descriptor() ispec.Descriptor {
	return ispec.Descriptor{
		MediaType: img.ManifestDescriptor.MediaType,
		Digest:    img.ManifestDescriptor.Digest,
		Size:      img.ManifestDescriptor.Size,
	}
}

func (img Image) DescriptorRef() *ispec.Descriptor {
	return &ispec.Descriptor{
		MediaType: img.ManifestDescriptor.MediaType,
		Digest:    img.ManifestDescriptor.Digest,
		Size:      img.ManifestDescriptor.Size,
	}
}

func (img Image) AsImageMeta() mTypes.ImageMeta {
	return mTypes.ImageMeta{
		MediaType: img.Manifest.MediaType,
		Digest:    img.ManifestDescriptor.Digest,
		Size:      img.ManifestDescriptor.Size,
		Manifests: []mTypes.ManifestMeta{
			{
				Size:     img.ManifestDescriptor.Size,
				Digest:   img.ManifestDescriptor.Digest,
				Manifest: img.Manifest,
				Config:   img.Config,
			},
		},
	}
}

type Layer struct {
	Blob      []byte
	MediaType string
	Digest    godigest.Digest
}

// CreateImageWith initiates the creation of an OCI image. The creation process starts with
// specifying the layers of the image.
func CreateImageWith() LayerBuilder {
	// set default values here
	return &BaseImageBuilder{}
}

func CreateDefaultImage() Image {
	return CreateImageWith().DefaultLayers().DefaultConfig().Build()
}

func CreateDefaultImageWith() ManifestBuilder {
	return CreateImageWith().DefaultLayers().DefaultConfig()
}

const (
	layerCount = 1
	layerSize  = 10
)

func CreateRandomImage() Image {
	return CreateImageWith().RandomLayers(layerCount, layerSize).RandomConfig().Build()
}

func CreateRandomImageWith() ManifestBuilder {
	return CreateImageWith().RandomLayers(layerCount, layerSize).RandomConfig()
}

// CreateDefaultVulnerableImage creates a vulnerable image with the default config.
func CreateDefaultVulnerableImage() Image {
	return CreateImageWith().VulnerableLayers().DefaultVulnConfig().Build()
}

func CreateRandomVulnerableImage() Image {
	return CreateImageWith().VulnerableLayers().RandomVulnConfig().Build()
}

func CreateRandomVulnerableImageWith() ManifestBuilder {
	return CreateImageWith().VulnerableLayers().RandomVulnConfig()
}

func CreateMockNotationSignature(subject *ispec.Descriptor) Image {
	return CreateImageWith().RandomLayers(1, 10).EmptyConfig().Subject(subject).
		ArtifactType(common.ArtifactTypeNotation).Build()
}

func CreateMockCosignSignature(subject *ispec.Descriptor) Image {
	return CreateImageWith().RandomLayers(1, 10).EmptyConfig().Subject(subject).
		ArtifactType(common.ArtifactTypeCosign).Build()
}

type BaseImageBuilder struct {
	layers []Layer

	config           ispec.Image
	configDescriptor ispec.Descriptor

	annotations  map[string]string
	subject      *ispec.Descriptor
	artifactType string
}

func (ib *BaseImageBuilder) Layers(layers []Layer) ConfigBuilder {
	ib.layers = layers

	return ib
}

func (ib *BaseImageBuilder) LayerBlobs(layers [][]byte) ConfigBuilder {
	for _, layer := range layers {
		ib.layers = append(ib.layers, Layer{
			Blob:      layer,
			MediaType: ispec.MediaTypeImageLayerGzip,
			Digest:    godigest.FromBytes(layer),
		})
	}

	return ib
}

func (ib *BaseImageBuilder) EmptyLayer() ConfigBuilder {
	ib.layers = []Layer{
		{
			Blob:      ispec.DescriptorEmptyJSON.Data,
			MediaType: ispec.DescriptorEmptyJSON.MediaType,
			Digest:    ispec.DescriptorEmptyJSON.Digest,
		},
	}

	return ib
}

func (ib *BaseImageBuilder) RandomLayers(count, size int) ConfigBuilder {
	for i := 0; i < count; i++ {
		layer := make([]byte, size)

		_, err := rand.Read(layer)
		if err != nil {
			panic("unexpected error while reading random bytes")
		}

		ib.layers = append(ib.layers, Layer{
			Blob:      layer,
			MediaType: ispec.MediaTypeImageLayerGzip,
			Digest:    godigest.FromBytes(layer),
		})
	}

	return ib
}

func (ib *BaseImageBuilder) DefaultLayers() ConfigBuilder {
	ib.layers = GetDefaultLayers()

	return ib
}

func (ib *BaseImageBuilder) VulnerableLayers() VulnerableConfigBuilder {
	layer, err := GetLayerWithVulnerability()
	if err != nil {
		panic("unable to read vulnerable layers from test data: " + err.Error())
	}

	ib.layers = []Layer{
		{
			Blob:      layer,
			MediaType: ispec.MediaTypeImageLayerGzip,
			Digest:    godigest.FromBytes(layer),
		},
	}

	return ib
}

func (ib *BaseImageBuilder) ImageConfig(config ispec.Image) ManifestBuilder {
	ib.config = config

	configBlob, err := json.Marshal(config)
	if err != nil {
		panic("unreachable: ispec.Image should always be marshable")
	}

	ib.configDescriptor = ispec.Descriptor{
		MediaType: ispec.MediaTypeImageConfig,
		Size:      int64(len(configBlob)),
		Data:      configBlob,
		Digest:    godigest.FromBytes(configBlob),
	}

	return ib
}

func (ib *BaseImageBuilder) DefaultConfig() ManifestBuilder {
	return ib.ImageConfig(GetDefaultConfig())
}

func (ib *BaseImageBuilder) PlatformConfig(arch, os string) ManifestBuilder {
	conf := GetDefaultConfig()

	conf.Created = RandomDateRef(time.UTC)
	conf.Author = getRandomAuthor()
	conf.Platform = ispec.Platform{Architecture: arch, OS: os}

	return ib.ImageConfig(conf)
}

func (ib *BaseImageBuilder) EmptyConfig() ManifestBuilder {
	ib.configDescriptor = ispec.DescriptorEmptyJSON

	return ib
}

func (ib *BaseImageBuilder) ArtifactConfig(artifactType string) ManifestBuilder {
	configDescriptor := ispec.DescriptorEmptyJSON
	configDescriptor.MediaType = artifactType

	ib.configDescriptor = configDescriptor

	return ib
}

func (ib *BaseImageBuilder) CustomConfigBlob(configBlob []byte, mediaType string) ManifestBuilder {
	ib.config = ispec.Image{}

	ib.configDescriptor = ispec.Descriptor{
		MediaType: mediaType,
		Size:      int64(len(configBlob)),
		Data:      configBlob,
		Digest:    godigest.FromBytes(configBlob),
	}

	return ib
}

func (ib *BaseImageBuilder) RandomConfig() ManifestBuilder {
	config := GetDefaultConfig()
	config.Author = getRandomAuthor()
	config.Platform = getRandomPlatform()
	config.Created = RandomDateRef(time.UTC)

	ib.config = config

	configBlob, err := json.Marshal(config)
	if err != nil {
		panic("unreachable: ispec.Image should always be marshable")
	}

	ib.configDescriptor = ispec.Descriptor{
		MediaType: ispec.MediaTypeImageConfig,
		Digest:    godigest.FromBytes(configBlob),
		Size:      int64(len(configBlob)),
		Data:      configBlob,
	}

	return ib
}

func (ib *BaseImageBuilder) DefaultVulnConfig() ManifestBuilder {
	vulnerableConfig := GetDefaultVulnConfig()

	configBlob, err := json.Marshal(vulnerableConfig)
	if err != nil {
		panic("unreachable: ispec.Image should always be marshable")
	}

	vulnConfigDescriptor := ispec.Descriptor{
		MediaType: ispec.MediaTypeImageConfig,
		Digest:    godigest.FromBytes(configBlob),
		Size:      int64(len(configBlob)),
		Data:      configBlob,
	}

	ib.config = vulnerableConfig
	ib.configDescriptor = vulnConfigDescriptor

	return ib
}

func (ib *BaseImageBuilder) VulnerableConfig(config ispec.Image) ManifestBuilder {
	vulnerableConfig := ispec.Image{
		Created:  config.Created,
		Platform: config.Platform,
		Config:   config.Config,
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{"sha256:f1417ff83b319fbdae6dd9cd6d8c9c88002dcd75ecf6ec201c8c6894681cf2b5"},
		},
		Author:  config.Author,
		History: config.History,
	}

	configBlob, err := json.Marshal(vulnerableConfig)
	if err != nil {
		panic("unreachable: ispec.Image should always be marshable")
	}

	vulnConfigDescriptor := ispec.Descriptor{
		MediaType: ispec.MediaTypeImageConfig,
		Digest:    godigest.FromBytes(configBlob),
		Size:      int64(len(configBlob)),
		Data:      configBlob,
	}

	ib.config = vulnerableConfig
	ib.configDescriptor = vulnConfigDescriptor

	return ib
}

func (ib *BaseImageBuilder) RandomVulnConfig() ManifestBuilder {
	vulnerableConfig := GetDefaultVulnConfig()

	vulnerableConfig.Author = getRandomAuthor()
	vulnerableConfig.Platform = getRandomPlatform()
	vulnerableConfig.Created = RandomDateRef(time.UTC)

	configBlob, err := json.Marshal(vulnerableConfig)
	if err != nil {
		panic("unreachable: ispec.Image should always be marshable")
	}

	vulnConfigDescriptor := ispec.Descriptor{
		MediaType: ispec.MediaTypeImageConfig,
		Digest:    godigest.FromBytes(configBlob),
		Size:      int64(len(configBlob)),
		Data:      configBlob,
	}

	ib.config = vulnerableConfig
	ib.configDescriptor = vulnConfigDescriptor

	return ib
}

func (ib *BaseImageBuilder) Subject(subject *ispec.Descriptor) ManifestBuilder {
	ib.subject = subject

	return ib
}

func (ib *BaseImageBuilder) ArtifactType(artifactType string) ManifestBuilder {
	ib.artifactType = artifactType

	return ib
}

func (ib *BaseImageBuilder) Annotations(annotations map[string]string) ManifestBuilder {
	ib.annotations = annotations

	return ib
}

func (ib *BaseImageBuilder) Build() Image {
	img := Image{
		Layers:           getLayerBlobs(ib.layers),
		Config:           ib.config,
		ConfigDescriptor: ib.configDescriptor,
		Manifest: ispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: storageConstants.SchemaVersion},
			MediaType: ispec.MediaTypeImageManifest,
			Config: ispec.Descriptor{
				MediaType: ib.configDescriptor.MediaType,
				Digest:    ib.configDescriptor.Digest,
				Size:      ib.configDescriptor.Size,
			},
			Layers:       getLayersDescriptors(ib.layers),
			ArtifactType: ib.artifactType,
			Subject:      ib.subject,
			Annotations:  ib.annotations,
		},
	}

	manifestBlob, err := json.Marshal(img.Manifest)
	if err != nil {
		panic("unreachable: ispec.Manifest should always be marshable")
	}

	img.ManifestDescriptor = ispec.Descriptor{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    godigest.FromBytes(manifestBlob),
		Size:      int64(len(manifestBlob)),
		Data:      manifestBlob,
	}

	return img
}

func getRandomAuthor() string {
	const n = 100000

	return "ZotUser-" + strconv.Itoa(mathRand.Intn(n)) //nolint: gosec
}

func getRandomPlatform() ispec.Platform {
	const n = 100000

	return ispec.Platform{
		OS:           "linux-" + strconv.Itoa(mathRand.Intn(n)), //nolint: gosec
		Architecture: "amd64-" + strconv.Itoa(mathRand.Intn(n)), //nolint: gosec
	}
}

func getLayerBlobs(layers []Layer) [][]byte {
	blobs := make([][]byte, len(layers))

	for i := range layers {
		blobs[i] = layers[i].Blob
	}

	return blobs
}

func getLayersDescriptors(layers []Layer) []ispec.Descriptor {
	descriptors := make([]ispec.Descriptor, len(layers))

	for i := range layers {
		descriptors[i] = ispec.Descriptor{
			Digest:    layers[i].Digest,
			MediaType: layers[i].MediaType,
			Size:      int64(len(layers[i].Blob)),
		}
	}

	return descriptors
}
