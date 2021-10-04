// Package common ...
package common

import (
	"encoding/json"
	"os"
	"path"
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// OciLayoutInfo ...
type OciLayoutUtils struct {
	Log log.Logger
}

// NewOciLayoutUtils initializes a new OciLayoutUtils object.
func NewOciLayoutUtils(log log.Logger) *OciLayoutUtils {
	return &OciLayoutUtils{Log: log}
}

func (olu OciLayoutUtils) GetImageManifests(storeController storage.StoreController,
	image string) ([]ispec.Descriptor, error) {
	imageStore := storeController.GetImageStore(image)
	buf, err := imageStore.GetIndexContent(image)

	if err != nil {
		if os.IsNotExist(err) {
			olu.Log.Error().Err(err).Msg("index.json doesn't exist")

			return nil, errors.ErrRepoNotFound
		}

		olu.Log.Error().Err(err).Msg("unable to open index.json")

		return nil, errors.ErrRepoNotFound
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		olu.Log.Error().Err(err).Str("dir", path.Join(imageStore.RootDir(), image)).Msg("invalid JSON")
		return nil, errors.ErrRepoNotFound
	}

	return index.Manifests, nil
}

func (olu OciLayoutUtils) GetImageBlobManifest(storeController storage.StoreController, imageDir string,
	digest string) (v1.Manifest, error) {
	var blobIndex v1.Manifest

	imageStore := storeController.GetImageStore(imageDir)
	blobBuf, err := imageStore.GetBlobContent(imageDir, digest)

	if err != nil {
		olu.Log.Error().Err(err).Msg("unable to open image metadata file")

		return blobIndex, err
	}

	if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
		olu.Log.Error().Err(err).Msg("unable to marshal blob index")

		return blobIndex, err
	}

	return blobIndex, nil
}

func (olu OciLayoutUtils) GetImageInfo(storeController storage.StoreController, imageDir string,
	hash string) (ispec.Image, error) {
	var imageInfo ispec.Image

	imageStore := storeController.GetImageStore(imageDir)

	blobBuf, err := imageStore.GetBlobContent(imageDir, hash)
	if err != nil {
		olu.Log.Error().Err(err).Msg("unable to open image layers file")

		return imageInfo, err
	}

	if err := json.Unmarshal(blobBuf, &imageInfo); err != nil {
		olu.Log.Error().Err(err).Msg("unable to marshal blob index")

		return imageInfo, err
	}

	return imageInfo, err
}

func (olu OciLayoutUtils) IsValidImageFormat(storeController storage.StoreController, image string) (bool, error) {
	imageDir, inputTag := GetImageDirAndTag(image)

	manifests, err := olu.GetImageManifests(storeController, imageDir)

	if err != nil {
		return false, err
	}

	for _, m := range manifests {
		tag, ok := m.Annotations[ispec.AnnotationRefName]

		if ok && inputTag != "" && tag != inputTag {
			continue
		}

		blobManifest, err := olu.GetImageBlobManifest(storeController, imageDir, m.Digest.String())
		if err != nil {
			return false, err
		}

		imageLayers := blobManifest.Layers

		for _, imageLayer := range imageLayers {
			switch imageLayer.MediaType {
			case types.OCILayer, types.DockerLayer:
				return true, nil

			default:
				olu.Log.Debug().Msg("image media type not supported for scanning")
				return false, errors.ErrScanNotSupported
			}
		}
	}

	return false, nil
}

// GetImageTagsWithTimestamp returns a list of image tags with timestamp available in the specified repository.
func (olu OciLayoutUtils) GetImageTagsWithTimestamp(storeController storage.StoreController,
	repo string) ([]TagInfo, error) {
	tagsInfo := make([]TagInfo, 0)

	manifests, err := olu.GetImageManifests(storeController, repo)

	if err != nil {
		olu.Log.Error().Err(err).Msg("unable to read image manifests")

		return tagsInfo, err
	}

	for _, manifest := range manifests {
		digest := manifest.Digest

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := olu.GetImageBlobManifest(storeController, repo, digest.String())

			if err != nil {
				olu.Log.Error().Err(err).Msg("unable to read image blob manifest")

				return tagsInfo, err
			}

			imageInfo, err := olu.GetImageInfo(storeController, repo, imageBlobManifest.Config.Digest.String())
			if err != nil {
				olu.Log.Error().Err(err).Msg("unable to read image info")

				return tagsInfo, err
			}

			timeStamp := *imageInfo.History[0].Created

			tagsInfo = append(tagsInfo, TagInfo{Name: v, Timestamp: timeStamp, Digest: digest.String()})
		}
	}

	return tagsInfo, nil
}

func (olu OciLayoutUtils) DirExists(storeController storage.StoreController, d string) bool {
	imageStore := storeController.GetImageStore(d)
	return imageStore.DirExists(d)
}

func GetImageDirAndTag(imageName string) (string, string) {
	var imageDir string

	var imageTag string

	if strings.Contains(imageName, ":") {
		splitImageName := strings.Split(imageName, ":")
		imageDir = splitImageName[0]
		imageTag = splitImageName[1]
	} else {
		imageDir = imageName
	}

	return imageDir, imageTag
}
