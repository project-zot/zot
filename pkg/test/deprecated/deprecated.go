package deprecated

import (
	"crypto/rand"
	"encoding/json"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/inject"
)

// Deprecated: Should use the new functions starting with "Create".
func GetImageComponents(layerSize int) (ispec.Image, [][]byte, ispec.Manifest, error) {
	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	if err = inject.Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layers := [][]byte{
		make([]byte, layerSize),
	}

	schemaVersion := 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	return config, layers, manifest, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomImageComponents(layerSize int) (ispec.Image, [][]byte, ispec.Manifest, error) {
	config := ispec.Image{
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "ZotUser",
	}

	configBlob, err := json.Marshal(config)
	if err = inject.Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layers := [][]byte{
		GetRandomLayer(layerSize),
	}

	schemaVersion := 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	return config, layers, manifest, nil
}

func GetRandomLayer(size int) []byte {
	layer := make([]byte, size)

	_, err := rand.Read(layer)
	if err != nil {
		return layer
	}

	return layer
}

// Deprecated: Should use the new functions starting with "Create".
func GetVulnImageWithConfig(config ispec.Image) (image.Image, error) {
	vulnerableLayer, err := image.GetLayerWithVulnerability()
	if err != nil {
		return image.Image{}, err
	}

	vulnerableConfig := ispec.Image{
		Platform: config.Platform,
		Config:   config.Config,
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{"sha256:f1417ff83b319fbdae6dd9cd6d8c9c88002dcd75ecf6ec201c8c6894681cf2b5"},
		},
		Created: config.Created,
		History: config.History,
	}

	img, err := GetImageWithComponents(
		vulnerableConfig,
		[][]byte{
			vulnerableLayer,
		})
	if err != nil {
		return image.Image{}, err
	}

	return img, err
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomImage() (image.Image, error) {
	const layerSize = 20

	config, layers, manifest, err := GetRandomImageComponents(layerSize)
	if err != nil {
		return image.Image{}, err
	}

	return image.Image{
		Manifest: manifest,
		Layers:   layers,
		Config:   config,
	}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageComponentsWithConfig(conf ispec.Image) (ispec.Image, [][]byte, ispec.Manifest, error) {
	configBlob, err := json.Marshal(conf)
	if err = inject.Error(err); err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	configDigest := godigest.FromBytes(configBlob)

	layerSize := 100
	layer := make([]byte, layerSize)

	_, err = rand.Read(layer)
	if err != nil {
		return ispec.Image{}, [][]byte{}, ispec.Manifest{}, err
	}

	layers := [][]byte{
		layer,
	}

	schemaVersion := 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    configDigest,
			Size:      int64(len(configBlob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    godigest.FromBytes(layers[0]),
				Size:      int64(len(layers[0])),
			},
		},
	}

	return conf, layers, manifest, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageWithConfig(conf ispec.Image) (image.Image, error) {
	config, layers, manifest, err := GetImageComponentsWithConfig(conf)
	if err != nil {
		return image.Image{}, err
	}

	return image.Image{
		Manifest: manifest,
		Config:   config,
		Layers:   layers,
	}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageWithComponents(config ispec.Image, layers [][]byte) (image.Image, error) {
	configBlob, err := json.Marshal(config)
	if err != nil {
		return image.Image{}, err
	}

	manifestLayers := make([]ispec.Descriptor, 0, len(layers))

	for _, layer := range layers {
		manifestLayers = append(manifestLayers, ispec.Descriptor{
			MediaType: "application/vnd.oci.image.layer.v1.tar",
			Digest:    godigest.FromBytes(layer),
			Size:      int64(len(layer)),
		})
	}

	const schemaVersion = 2

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Versioned: specs.Versioned{
			SchemaVersion: schemaVersion,
		},
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    godigest.FromBytes(configBlob),
			Size:      int64(len(configBlob)),
		},
		Layers: manifestLayers,
	}

	return image.Image{
		Manifest: manifest,
		Config:   config,
		Layers:   layers,
	}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetImageWithSubject(subjectDigest godigest.Digest, mediaType string) (image.Image, error) {
	num := 100

	conf, layers, manifest, err := GetRandomImageComponents(num)
	if err != nil {
		return image.Image{}, err
	}

	manifest.Subject = &ispec.Descriptor{
		Digest:    subjectDigest,
		MediaType: mediaType,
	}

	return image.Image{
		Manifest: manifest,
		Config:   conf,
		Layers:   layers,
	}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomMultiarchImageComponents() (ispec.Index, []image.Image, error) {
	const layerSize = 100

	randomLayer1 := make([]byte, layerSize)

	_, err := rand.Read(randomLayer1)
	if err != nil {
		return ispec.Index{}, []image.Image{}, err
	}

	image1, err := GetImageWithComponents(
		ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		},
		[][]byte{
			randomLayer1,
		})
	if err != nil {
		return ispec.Index{}, []image.Image{}, err
	}

	randomLayer2 := make([]byte, layerSize)

	_, err = rand.Read(randomLayer2)
	if err != nil {
		return ispec.Index{}, []image.Image{}, err
	}

	image2, err := GetImageWithComponents(
		ispec.Image{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "386",
			},
		},
		[][]byte{
			randomLayer2,
		})
	if err != nil {
		return ispec.Index{}, []image.Image{}, err
	}

	randomLayer3 := make([]byte, layerSize)

	_, err = rand.Read(randomLayer3)
	if err != nil {
		return ispec.Index{}, []image.Image{}, err
	}

	image3, err := GetImageWithComponents(
		ispec.Image{
			Platform: ispec.Platform{
				OS:           "windows",
				Architecture: "amd64",
			},
		},
		[][]byte{
			randomLayer3,
		})
	if err != nil {
		return ispec.Index{}, []image.Image{}, err
	}

	index := ispec.Index{
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    getManifestDigest(image1.Manifest),
				Size:      getManifestSize(image1.Manifest),
			},
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    getManifestDigest(image2.Manifest),
				Size:      getManifestSize(image2.Manifest),
			},
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    getManifestDigest(image3.Manifest),
				Size:      getManifestSize(image3.Manifest),
			},
		},
	}

	return index, []image.Image{image1, image2, image3}, nil
}

// Deprecated: Should use the new functions starting with "Create".
func GetRandomMultiarchImage(reference string) (image.MultiarchImage, error) {
	index, images, err := GetRandomMultiarchImageComponents()
	if err != nil {
		return image.MultiarchImage{}, err
	}

	index.SchemaVersion = 2

	return image.MultiarchImage{
		Index: index, Images: images, Reference: reference,
	}, err
}

// Deprecated: Should use the new functions starting with "Create".
func GetMultiarchImageForImages(images []image.Image) image.MultiarchImage {
	var index ispec.Index

	for _, image := range images {
		index.Manifests = append(index.Manifests, ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    getManifestDigest(image.Manifest),
			Size:      getManifestSize(image.Manifest),
		})
	}

	index.SchemaVersion = 2

	return image.MultiarchImage{Index: index, Images: images}
}

func getManifestSize(manifest ispec.Manifest) int64 {
	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return 0
	}

	return int64(len(manifestBlob))
}

func getManifestDigest(manifest ispec.Manifest) godigest.Digest {
	manifestBlob, err := json.Marshal(manifest)
	if err != nil {
		return ""
	}

	return godigest.FromBytes(manifestBlob)
}
