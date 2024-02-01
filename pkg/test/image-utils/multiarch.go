package image

import (
	"encoding/json"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	mTypes "zotregistry.dev/zot/pkg/meta/types"
)

type MultiarchImage struct {
	Index  ispec.Index
	Images []Image

	IndexDescriptor ispec.Descriptor
}

func (mi *MultiarchImage) Digest() godigest.Digest {
	indexBlob, err := json.Marshal(mi.Index)
	if err != nil {
		panic("unreachable: ispec.Index should always be marshable")
	}

	return godigest.FromBytes(indexBlob)
}

func (mi *MultiarchImage) DigestStr() string {
	return mi.Digest().String()
}

func (mi MultiarchImage) AsImageMeta() mTypes.ImageMeta {
	index := mi.Index

	manifests := make([]mTypes.ManifestMeta, 0, len(index.Manifests))

	for _, image := range mi.Images {
		manifests = append(manifests, image.AsImageMeta().Manifests...)
	}

	return mTypes.ImageMeta{
		MediaType: ispec.MediaTypeImageIndex,
		Digest:    mi.IndexDescriptor.Digest,
		Size:      mi.IndexDescriptor.Size,
		Index:     &index,
		Manifests: manifests,
	}
}

type ImagesBuilder interface {
	Images(images []Image) MultiarchBuilder
	RandomImages(count int) MultiarchBuilder
}

type MultiarchBuilder interface {
	Subject(subject *ispec.Descriptor) MultiarchBuilder
	ArtifactType(artifactType string) MultiarchBuilder
	Annotations(annotations map[string]string) MultiarchBuilder
	Build() MultiarchImage
}

func CreateMultiarchWith() ImagesBuilder {
	return &BaseMultiarchBuilder{}
}

func CreateRandomMultiarch() MultiarchImage {
	return CreateMultiarchWith().
		Images([]Image{
			CreateRandomImage(),
			CreateRandomImage(),
			CreateRandomImage(),
		}).
		Build()
}

func CreateVulnerableMultiarch() MultiarchImage {
	return CreateMultiarchWith().
		Images([]Image{
			CreateRandomImage(),
			CreateRandomVulnerableImage(),
			CreateRandomImage(),
		}).
		Build()
}

type BaseMultiarchBuilder struct {
	images       []Image
	subject      *ispec.Descriptor
	artifactType string
	annotations  map[string]string
}

func (mb *BaseMultiarchBuilder) Images(images []Image) MultiarchBuilder {
	mb.images = images

	return mb
}

func (mb *BaseMultiarchBuilder) RandomImages(count int) MultiarchBuilder {
	images := make([]Image, count)

	for i := range images {
		images[i] = CreateRandomImage()
	}

	mb.images = images

	return mb
}

func (mb *BaseMultiarchBuilder) Subject(subject *ispec.Descriptor) MultiarchBuilder {
	mb.subject = subject

	return mb
}

func (mb *BaseMultiarchBuilder) ArtifactType(artifactType string) MultiarchBuilder {
	mb.artifactType = artifactType

	return mb
}

func (mb *BaseMultiarchBuilder) Annotations(annotations map[string]string) MultiarchBuilder {
	mb.annotations = annotations

	return mb
}

func (mb *BaseMultiarchBuilder) Build() MultiarchImage {
	manifests := make([]ispec.Descriptor, len(mb.images))

	for i := range manifests {
		manifests[i] = ispec.Descriptor{
			Digest:    mb.images[i].ManifestDescriptor.Digest,
			Size:      mb.images[i].ManifestDescriptor.Size,
			MediaType: ispec.MediaTypeImageManifest,
		}
	}

	version := 2

	index := ispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: version},
		MediaType:    ispec.MediaTypeImageIndex,
		Manifests:    manifests,
		Annotations:  mb.annotations,
		Subject:      mb.subject,
		ArtifactType: mb.artifactType,
	}

	indexBlob, err := json.Marshal(index)
	if err != nil {
		panic("unreachable: ispec.Index should always be marshable")
	}

	indexDigest := godigest.FromBytes(indexBlob)

	return MultiarchImage{
		Index:  index,
		Images: mb.images,

		IndexDescriptor: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Size:      int64(len(indexBlob)),
			Digest:    indexDigest,
			Data:      indexBlob,
		},
	}
}
