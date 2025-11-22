package compat

import (
	"slices"

	dockerList "github.com/distribution/distribution/v3/manifest/manifestlist"
	docker "github.com/distribution/distribution/v3/manifest/schema2"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/v2/errors"
)

// MediaCompatibility determines non-OCI media-compatilibility.
type MediaCompatibility string

const (
	DockerManifestV2SchemaV2 = "docker2s2"
)

// docker

func CompatibleManifestMediaTypes() []string {
	return []string{docker.MediaTypeManifest}
}

func IsCompatibleManifestMediaType(mediatype string) bool {
	return slices.Contains(CompatibleManifestMediaTypes(), mediatype)
}

func CompatibleManifestListMediaTypes() []string {
	return []string{dockerList.MediaTypeManifestList}
}

func IsCompatibleManifestListMediaType(mediatype string) bool {
	return slices.Contains(CompatibleManifestListMediaTypes(), mediatype)
}

func CompatibleConfigMediaTypes() []string {
	return []string{docker.MediaTypeImageConfig}
}

func IsCompatibleConfigMediaType(mediatype string) bool {
	return slices.Contains(CompatibleConfigMediaTypes(), mediatype)
}

func Validate(body []byte, mediaType string) ([]v1.Descriptor, error) {
	switch mediaType {
	case docker.MediaTypeManifest:
		var desm docker.DeserializedManifest

		if err := desm.UnmarshalJSON(body); err != nil {
			return nil, err
		}

		return desm.References(), nil
	case dockerList.MediaTypeManifestList:
		var desm dockerList.DeserializedManifestList

		if err := desm.UnmarshalJSON(body); err != nil {
			return nil, err
		}

		return desm.References(), nil
	}

	return nil, errors.ErrMediaTypeNotSupported
}
