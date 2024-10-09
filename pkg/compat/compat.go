package compat

import (
	dockerList "github.com/distribution/distribution/v3/manifest/manifestlist"
	docker "github.com/distribution/distribution/v3/manifest/schema2"
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
	for _, mt := range CompatibleManifestMediaTypes() {
		if mt == mediatype {
			return true
		}
	}

	return false
}

func CompatibleManifestListMediaTypes() []string {
	return []string{dockerList.MediaTypeManifestList}
}

func IsCompatibleManifestListMediaType(mediatype string) bool {
	for _, mt := range CompatibleManifestListMediaTypes() {
		if mt == mediatype {
			return true
		}
	}

	return false
}
