package test

import (
	"encoding/json"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	mTypes "zotregistry.io/zot/pkg/meta/types"
)

type MultiarchImage struct {
	Index     ispec.Index
	Images    []Image
	Reference string

	indexDescriptor ispec.Descriptor
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

func (mi *MultiarchImage) IndexData() mTypes.IndexData {
	indexBlob, err := json.Marshal(mi.Index)
	if err != nil {
		panic("unreachable: ispec.Index should always be marshable")
	}

	return mTypes.IndexData{IndexBlob: indexBlob}
}

type ImagesBuilder interface {
	Images(images []Image) MultiarchBuilder
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

	ref := indexDigest.String()

	return MultiarchImage{
		Index:     index,
		Images:    mb.images,
		Reference: ref,

		indexDescriptor: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Size:      int64(len(indexBlob)),
			Digest:    indexDigest,
			Data:      indexBlob,
		},
	}
}
