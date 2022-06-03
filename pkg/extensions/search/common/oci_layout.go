// Package common ...
package common

import (
	"encoding/json"
	goerrors "errors"
	"fmt"
	"path"
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

// OciLayoutInfo ...
type OciLayoutUtils struct {
	Log             log.Logger
	StoreController storage.StoreController
}

type RepoInfo struct {
	Manifests []Manifest `json:"manifests"`
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

			imageInfo, err := olu.GetImageInfo(repo, imageBlobManifest.Config.Digest)
			if err != nil {
				olu.Log.Error().Err(err).Msg("unable to read image info")

				return tagsInfo, err
			}

			var timeStamp time.Time

			if len(imageInfo.History) != 0 {
				timeStamp = *imageInfo.History[0].Created
			} else {
				timeStamp = time.Time{}
			}

			tagsInfo = append(tagsInfo, TagInfo{Name: val, Timestamp: timeStamp, Digest: digest.String()})
		}
	}

	return tagsInfo, nil
}

// check notary signature corresponding to repo name, manifest digest and mediatype.
func (olu OciLayoutUtils) checkNotarySignature(name, digest, mediaType string) bool {
	imageStore := olu.StoreController.GetImageStore(name)

	_, err := imageStore.GetReferrers(name, digest, mediaType)
	if err != nil {
		olu.Log.Info().Str("repo", name).Str("digest",
			digest).Str("mediatype", mediaType).Msg("invalid notary signature")

		return false
	}

	return true
}

// check cosign signature corresponding to  manifest.
func (olu OciLayoutUtils) checkCosignSignature(name, digest string) bool {
	imageStore := olu.StoreController.GetImageStore(name)

	// if manifest is signed using cosign mechanism, cosign adds a new manifest.
	// new manifest is tagged as sha256-<manifest-digest>.sig.
	reference := fmt.Sprintf("sha256-%s.sig", digest)

	_, _, _, err := imageStore.GetImageManifest(name, reference) // nolint: dogsled
	if err != nil {
		olu.Log.Info().Str("repo", name).Str("digest",
			digest).Msg("invalid cosign signature")

		return false
	}

	return true
}

// checks if manifest is signed or not
// checks for notary or cosign signature
// if cosign signature found it does not looks for notary signature.
func (olu OciLayoutUtils) checkManifestSignature(name, digest, mediaType string) bool {
	if !olu.checkCosignSignature(name, digest) {
		return olu.checkNotarySignature(name, digest, mediaType)
	}

	return true
}

func (olu OciLayoutUtils) GetExpandedRepoInfo(name string) (RepoInfo, error) {
	repo := RepoInfo{}

	manifests := make([]Manifest, 0)

	manifestList, err := olu.GetImageManifests(name)
	if err != nil {
		olu.Log.Error().Err(err).Msg("error getting image manifests")

		return RepoInfo{}, err
	}

	for _, man := range manifestList {
		manifestInfo := Manifest{}

		manifestInfo.Digest = man.Digest.Encoded()

		manifestInfo.IsSigned = false

		tag, ok := man.Annotations[ispec.AnnotationRefName]
		if !ok {
			tag = "latest"
		}

		manifestInfo.Tag = tag

		manifest, err := olu.GetImageBlobManifest(name, man.Digest)
		if err != nil {
			olu.Log.Error().Err(err).Msg("error getting image manifest blob")

			return RepoInfo{}, err
		}

		manifestInfo.IsSigned = olu.checkManifestSignature(name, man.Digest.Encoded(), man.MediaType)

		layers := make([]Layer, 0)

		for _, layer := range manifest.Layers {
			layerInfo := Layer{}

			layerInfo.Digest = layer.Digest.Hex

			layerInfo.Size = strconv.FormatInt(layer.Size, 10)

			layers = append(layers, layerInfo)
		}

		manifestInfo.Layers = layers

		manifests = append(manifests, manifestInfo)
	}

	repo.Manifests = manifests

	return repo, nil
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
