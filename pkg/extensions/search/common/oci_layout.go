// Package common ...
package common

import (
	"encoding/json"
	goerrors "errors"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

const cosignedAnnotation = "dev.cosign.signature.baseimage"

// OciLayoutInfo ...
type OciLayoutUtils struct {
	Log             log.Logger
	StoreController storage.StoreController
}

type RepoInfo struct {
	Manifests   []Manifest `json:"manifests"`
	LastUpdated time.Time
}

type Manifest struct {
	Tag      string  `json:"tag"`
	Digest   string  `json:"digest"`
	IsSigned bool    `json:"isSigned"`
	Layers   []Layer `json:"layers"`
}

type Layer struct {
	Size   string `json:"size"`
	Digest string `json:"digest"`
	Os     string `json:"os"`
	Arch   string `json:"arch"`
}

// NewOciLayoutUtils initializes a new OciLayoutUtils object.
func NewOciLayoutUtils(storeController storage.StoreController, log log.Logger) *OciLayoutUtils {
	return &OciLayoutUtils{Log: log, StoreController: storeController}
}

// Below method will return image path including root dir, root dir is determined by splitting.
func (olu OciLayoutUtils) GetImageManifests(image string) ([]ispec.Descriptor, error) {
	imageStore := olu.StoreController.GetImageStore(image)

	buf, err := imageStore.GetIndexContent(image)
	if err != nil {
		if goerrors.Is(errors.ErrRepoNotFound, err) {
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

//nolint: interfacer
func (olu OciLayoutUtils) GetImageBlobManifest(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
	var blobIndex v1.Manifest

	imageStore := olu.StoreController.GetImageStore(imageDir)

	blobBuf, err := imageStore.GetBlobContent(imageDir, digest.String())
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

//nolint: interfacer
func (olu OciLayoutUtils) GetImageInfo(imageDir string, hash v1.Hash) (ispec.Image, error) {
	var imageInfo ispec.Image

	imageStore := olu.StoreController.GetImageStore(imageDir)

	blobBuf, err := imageStore.GetBlobContent(imageDir, hash.String())
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

func (olu OciLayoutUtils) IsValidImageFormat(image string) (bool, error) {
	imageDir, inputTag := GetImageDirAndTag(image)

	manifests, err := olu.GetImageManifests(imageDir)
	if err != nil {
		return false, err
	}

	for _, manifest := range manifests {
		tag, ok := manifest.Annotations[ispec.AnnotationRefName]

		if ok && inputTag != "" && tag != inputTag {
			continue
		}

		blobManifest, err := olu.GetImageBlobManifest(imageDir, manifest.Digest)
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
func (olu OciLayoutUtils) GetImageTagsWithTimestamp(repo string) ([]TagInfo, error) {
	tagsInfo := make([]TagInfo, 0)

	manifests, err := olu.GetImageManifests(repo)
	if err != nil {
		olu.Log.Error().Err(err).Msg("unable to read image manifests")

		return tagsInfo, err
	}

	for _, manifest := range manifests {
		digest := manifest.Digest

		val, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := olu.GetImageBlobManifest(repo, digest)
			if err != nil {
				olu.Log.Error().Err(err).Msg("unable to read image blob manifest")

				return tagsInfo, err
			}

			tagInfo, err := olu.GetManifestTagInfo(repo, val, imageBlobManifest.Config.Digest)
			if err != nil {
				olu.Log.Error().Err(err).Str("repo", repo).Str("manifest", val).Msg("unable to get tag info")

				return tagsInfo, err
			}

			tagsInfo = append(tagsInfo, tagInfo)
		}
	}

	return tagsInfo, nil
}

// GetManifestTagInfo will return TagInfo(name,timestamp and digest)...
func (olu OciLayoutUtils) GetManifestTagInfo(repo, name string, digest v1.Hash) (TagInfo, error) {
	imageInfo, err := olu.GetImageInfo(repo, digest)
	if err != nil {
		olu.Log.Error().Err(err).Msg("unable to read image info")

		return TagInfo{}, err
	}

	var timeStamp time.Time

	if len(imageInfo.History) != 0 {
		timeStamp = *imageInfo.History[0].Created
	} else {
		timeStamp = time.Time{}
	}

	return TagInfo{Name: name, Timestamp: timeStamp, Digest: digest.String()}, nil
}

func (olu OciLayoutUtils) GetExpandedRepoInfo(name string) (RepoInfo, error) {
	repo := RepoInfo{}

	manifests := make([]Manifest, 0)

	manifestList, err := olu.GetImageManifests(name)
	if err != nil {
		olu.Log.Error().Err(err).Msg("error getting image manifests")

		return RepoInfo{}, err
	}

	latestTag := TagInfo{}

	for _, manifest := range manifestList {
		manifestInfo := Manifest{}

		manifestInfo.Digest = manifest.Digest.Encoded()

		manifestInfo.IsSigned = false

		tag, ok := manifest.Annotations[ispec.AnnotationRefName]
		if !ok {
			tag = "latest"
		}

		manifestInfo.Tag = tag

		manifest, err := olu.GetImageBlobManifest(name, manifest.Digest)
		if err != nil {
			olu.Log.Error().Err(err).Msg("error getting image manifest blob")

			return RepoInfo{}, err
		}

		tagInfo, err := olu.GetManifestTagInfo(name, tag, manifest.Config.Digest)
		if err != nil {
			olu.Log.Error().Err(err).Msg("error getting tag info")

			return RepoInfo{}, err
		}

		if tagInfo.Timestamp.After(latestTag.Timestamp) {
			latestTag = tagInfo
		}

		layers := make([]Layer, 0)

		for _, layer := range manifest.Layers {
			layerInfo := Layer{}

			layerInfo.Digest = layer.Digest.Hex

			layerInfo.Size = strconv.FormatInt(layer.Size, 10)

			if layer.Platform != nil {
				layerInfo.Os = layer.Platform.OS

				layerInfo.Arch = layer.Platform.Architecture
			} else {
				olu.Log.Debug().Str("layer", layer.Digest.String()).Msg("platform field not present")
			}

			layers = append(layers, layerInfo)

			if _, ok := layer.Annotations[cosignedAnnotation]; ok {
				manifestInfo.IsSigned = true
			}
		}

		manifestInfo.Layers = layers

		manifests = append(manifests, manifestInfo)
	}

	repo.Manifests = manifests

	repo.LastUpdated = latestTag.Timestamp

	return repo, nil
}

// GetLatestTag will return latest tag present in repo based on timestamp...
func (olu OciLayoutUtils) GetLatestTag(repo string) (TagInfo, error) {
	tagsInfo, err := olu.GetImageTagsWithTimestamp(repo)
	if err != nil {
		olu.Log.Error().Err(err).Msg("extension api: error getting tag timestamp info")

		return TagInfo{}, err
	}

	if len(tagsInfo) == 0 {
		olu.Log.Info().Str("no tagsinfo found for repo", repo).Msg(" continuing traversing")

		return TagInfo{}, errors.ErrEmptyValue
	}

	sort.Slice(tagsInfo, func(i, j int) bool {
		return tagsInfo[i].Timestamp.Before(tagsInfo[j].Timestamp)
	})

	return tagsInfo[len(tagsInfo)-1], nil
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
