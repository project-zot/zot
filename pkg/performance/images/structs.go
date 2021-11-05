package main

const (
	pathFormat       = "%s/blobs/sha256/%s"
	digestFormat     = "sha256:%s"
	layoutFormat     = "%s/oci-layout"
	filename         = "file"
	tarName          = "file.tar.gz"
	configFileName   = "configFile"
	manifestFileName = "manifestFile"
)

var imageNameList = []string{
	"zot-tests-single-images-dummy",
	"zot-tests-parallel-images-dummy-1",
	"zot-tests-parallel-images-dummy-2",
	"zot-tests-parallel-images-dummy-3",
	"zot-tests-parallel-images-dummy-4",
	"zot-tests-parallel-images-dummy-5",
	"zot-tests-dummy-push",
}

type ManifestConfig struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

type Manifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	Config        ManifestConfig   `json:"config"`
	Layers        []ManifestConfig `json:layers`
}

type RootFs struct {
	Type     string   `json:"type"`
	Diff_ids []string `json:"diff_ids"`
}

type Config struct {
	Architecture string `json:"architecture"`
	Os           string `json:"os"`
	Rootfs       RootFs `json:"rootfs"`
}

type Index struct {
	SchemaVersion int              `json:"schemaversion"`
	Manifests     []ManifestConfig `json:"manifests"`
}

type Layout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}
