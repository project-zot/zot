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

	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type OciLayoutUtils interface { //nolint: interfacebloat
	GetImageManifest(repo string, reference string) (ispec.Manifest, godigest.Digest, error)
	GetImageManifests(repo string) ([]ispec.Descriptor, error)
	GetImageBlobManifest(repo string, digest godigest.Digest) (ispec.Manifest, error)
	GetImageInfo(repo string, configDigest godigest.Digest) (ispec.Image, error)
	GetImageTagsWithTimestamp(repo string) ([]TagInfo, error)
	GetImagePlatform(imageInfo ispec.Image) (string, string)
	GetImageManifestSize(repo string, manifestDigest godigest.Digest) int64
	GetRepoLastUpdated(repo string) (TagInfo, error)
	GetExpandedRepoInfo(name string) (RepoInfo, error)
	GetImageConfigInfo(repo string, manifestDigest godigest.Digest) (ispec.Image, error)
	CheckManifestSignature(name string, digest godigest.Digest) bool
	GetRepositories() ([]string, error)
}

// OciLayoutInfo ...
type BaseOciLayoutUtils struct {
	Log             log.Logger
	StoreController storage.StoreController
}

// NewBaseOciLayoutUtils initializes a new OciLayoutUtils object.
func NewBaseOciLayoutUtils(storeController storage.StoreController, log log.Logger) *BaseOciLayoutUtils {
	return &BaseOciLayoutUtils{Log: log, StoreController: storeController}
}

func (olu BaseOciLayoutUtils) GetImageManifest(repo string, reference string) (ispec.Manifest, godigest.Digest, error) {
	imageStore := olu.StoreController.GetImageStore(repo)

	if reference == "" {
		reference = "latest"
	}

	manifestBlob, digest, _, err := imageStore.GetImageManifest(repo, reference)
	if err != nil {
		return ispec.Manifest{}, "", err
	}

	var manifest ispec.Manifest

	err = json.Unmarshal(manifestBlob, &manifest)
	if err != nil {
		return ispec.Manifest{}, "", err
	}

	return manifest, digest, nil
}

// Provide a list of repositories from all the available image stores.
func (olu BaseOciLayoutUtils) GetRepositories() ([]string, error) {
	defaultStore := olu.StoreController.DefaultStore
	substores := olu.StoreController.SubStore

	repoList, err := defaultStore.GetRepositories()
	if err != nil {
		return []string{}, err
	}

	for _, sub := range substores {
		repoListForSubstore, err := sub.GetRepositories()
		if err != nil {
			return []string{}, err
		}

		repoList = append(repoList, repoListForSubstore...)
	}

	return repoList, nil
}

// Below method will return image path including root dir, root dir is determined by splitting.
func (olu BaseOciLayoutUtils) GetImageManifests(repo string) ([]ispec.Descriptor, error) {
	var lockLatency time.Time

	imageStore := olu.StoreController.GetImageStore(repo)

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	buf, err := imageStore.GetIndexContent(repo)
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
		olu.Log.Error().Err(err).Str("dir", path.Join(imageStore.RootDir(), repo)).Msg("invalid JSON")

		return nil, errors.ErrRepoNotFound
	}

	return index.Manifests, nil
}

func (olu BaseOciLayoutUtils) GetImageBlobManifest(repo string, digest godigest.Digest) (ispec.Manifest, error) {
	var blobIndex ispec.Manifest

	var lockLatency time.Time

	imageStore := olu.StoreController.GetImageStore(repo)

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	blobBuf, err := imageStore.GetBlobContent(repo, digest)
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

func (olu BaseOciLayoutUtils) GetImageInfo(repo string, configDigest godigest.Digest) (ispec.Image, error) {
	var imageInfo ispec.Image

	var lockLatency time.Time

	imageStore := olu.StoreController.GetImageStore(repo)

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	blobBuf, err := imageStore.GetBlobContent(repo, configDigest)
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

// GetImageTagsWithTimestamp returns a list of image tags with timestamp available in the specified repository.
func (olu BaseOciLayoutUtils) GetImageTagsWithTimestamp(repo string) ([]TagInfo, error) {
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

			timeStamp := GetImageLastUpdated(imageInfo)

			tagsInfo = append(tagsInfo, TagInfo{Name: val, Timestamp: timeStamp, Digest: digest})
		}
	}

	return tagsInfo, nil
}

// check notary signature corresponding to repo name, manifest digest and mediatype.
func (olu BaseOciLayoutUtils) checkNotarySignature(name string, digest godigest.Digest) bool {
	imageStore := olu.StoreController.GetImageStore(name)
	mediaType := notreg.ArtifactTypeNotation

	_, err := imageStore.GetOrasReferrers(name, digest, mediaType)
	if err != nil {
		olu.Log.Info().Err(err).Str("repo", name).Str("digest",
			digest.String()).Str("mediatype", mediaType).Msg("invalid notary signature")

		return false
	}

	return true
}

// check cosign signature corresponding to  manifest.
func (olu BaseOciLayoutUtils) checkCosignSignature(name string, digest godigest.Digest) bool {
	imageStore := olu.StoreController.GetImageStore(name)

	// if manifest is signed using cosign mechanism, cosign adds a new manifest.
	// new manifest is tagged as sha256-<manifest-digest>.sig.
	reference := fmt.Sprintf("sha256-%s.sig", digest.Encoded())

	_, _, _, err := imageStore.GetImageManifest(name, reference) //nolint: dogsled
	if err != nil {
		olu.Log.Info().Err(err).Str("repo", name).Str("digest",
			digest.String()).Msg("invalid cosign signature")

		return false
	}

	return true
}

// checks if manifest is signed or not
// checks for notary or cosign signature
// if cosign signature found it does not looks for notary signature.
func (olu BaseOciLayoutUtils) CheckManifestSignature(name string, digest godigest.Digest) bool {
	if !olu.checkCosignSignature(name, digest) {
		return olu.checkNotarySignature(name, digest)
	}

	return true
}

func (olu BaseOciLayoutUtils) GetImagePlatform(imageConfig ispec.Image) (
	string, string,
) {
	return imageConfig.OS, imageConfig.Architecture
}

func (olu BaseOciLayoutUtils) GetImageConfigInfo(repo string, manifestDigest godigest.Digest) (ispec.Image, error) {
	imageBlobManifest, err := olu.GetImageBlobManifest(repo, manifestDigest)
	if err != nil {
		return ispec.Image{}, err
	}

	imageInfo, err := olu.GetImageInfo(repo, imageBlobManifest.Config.Digest)
	if err != nil {
		return ispec.Image{}, err
	}

	return imageInfo, nil
}

func (olu BaseOciLayoutUtils) GetImageManifestSize(repo string, manifestDigest godigest.Digest) int64 {
	imageStore := olu.StoreController.GetImageStore(repo)

	var lockLatency time.Time

	imageStore.RLock(&lockLatency)
	defer imageStore.RUnlock(&lockLatency)

	manifestBlob, err := imageStore.GetBlobContent(repo, manifestDigest)
	if err != nil {
		olu.Log.Error().Err(err).Msg("error when getting manifest blob content")

		return int64(len(manifestBlob))
	}

	return int64(len(manifestBlob))
}

func (olu BaseOciLayoutUtils) GetImageConfigSize(repo string, manifestDigest godigest.Digest) int64 {
	imageBlobManifest, err := olu.GetImageBlobManifest(repo, manifestDigest)
	if err != nil {
		olu.Log.Error().Err(err).Msg("can't get image blob manifest")

		return 0
	}

	return imageBlobManifest.Config.Size
}

func (olu BaseOciLayoutUtils) GetRepoLastUpdated(repo string) (TagInfo, error) {
	tagsInfo, err := olu.GetImageTagsWithTimestamp(repo)
	if err != nil || len(tagsInfo) == 0 {
		return TagInfo{}, err
	}

	latestTag := GetLatestTag(tagsInfo)

	return latestTag, nil
}

func (olu BaseOciLayoutUtils) GetExpandedRepoInfo(name string) (RepoInfo, error) {
	repo := RepoInfo{}

	repoBlob2Size := make(map[string]int64, 10)

	// made up of all manifests, configs and image layers
	repoSize := int64(0)

	imageSummaries := make([]ImageSummary, 0)

	manifestList, err := olu.GetImageManifests(name)
	if err != nil {
		olu.Log.Error().Err(err).Msg("error getting image manifests")

		return RepoInfo{}, err
	}

	lastUpdatedTag, err := olu.GetRepoLastUpdated(name)
	if err != nil {
		olu.Log.Error().Err(err).Msgf("can't get last updated manifest for repo: %s", name)

		return RepoInfo{}, err
	}

	repoVendorsSet := make(map[string]bool, len(manifestList))
	repoPlatformsSet := make(map[string]OsArch, len(manifestList))

	var lastUpdatedImageSummary ImageSummary

	for _, man := range manifestList {
		imageLayersSize := int64(0)

		tag, ok := man.Annotations[ispec.AnnotationRefName]
		if !ok {
			olu.Log.Info().Msgf("skipping manifest with digest %s because it doesn't have a tag",
				man.Digest.String())

			continue
		}

		manifest, err := olu.GetImageBlobManifest(name, man.Digest)
		if err != nil {
			olu.Log.Error().Err(err).Msg("error getting image manifest blob")

			return RepoInfo{}, err
		}

		isSigned := olu.CheckManifestSignature(name, man.Digest)

		manifestSize := olu.GetImageManifestSize(name, man.Digest)
		olu.Log.Debug().Msg(fmt.Sprintf("%v", man.Digest.String()))
		configSize := manifest.Config.Size

		repoBlob2Size[man.Digest.String()] = manifestSize
		repoBlob2Size[manifest.Config.Digest.String()] = configSize

		imageConfigInfo, err := olu.GetImageConfigInfo(name, man.Digest)
		if err != nil {
			olu.Log.Error().Err(err).Msgf("can't retrieve config info for the image %s %s", name, man.Digest)

			continue
		}

		opSys, arch := olu.GetImagePlatform(imageConfigInfo)
		osArch := OsArch{
			Os:   opSys,
			Arch: arch,
		}

		if opSys != "" || arch != "" {
			osArchString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
			repoPlatformsSet[osArchString] = osArch
		}

		layers := make([]LayerSummary, 0)

		for _, layer := range manifest.Layers {
			layerInfo := LayerSummary{}

			layerInfo.Digest = layer.Digest.String()

			repoBlob2Size[layerInfo.Digest] = layer.Size

			layerInfo.Size = strconv.FormatInt(layer.Size, 10)

			imageLayersSize += layer.Size

			layers = append(layers, layerInfo)
		}

		imageSize := imageLayersSize + manifestSize + configSize

		// get image info from manifest annotation, if not found get from image config labels.
		annotations := GetAnnotations(manifest.Annotations, imageConfigInfo.Config.Labels)

		if annotations.Vendor != "" {
			repoVendorsSet[annotations.Vendor] = true
		}

		imageConfigHistory := imageConfigInfo.History
		allHistory := []LayerHistory{}

		if len(imageConfigHistory) == 0 {
			for _, layer := range layers {
				allHistory = append(allHistory, LayerHistory{
					Layer:              layer,
					HistoryDescription: HistoryDescription{},
				})
			}
		} else {
			// iterator over manifest layers
			var layersIterator int
			// since we are appending pointers, it is important to iterate with an index over slice
			for i := range imageConfigHistory {
				allHistory = append(allHistory, LayerHistory{
					HistoryDescription: HistoryDescription{
						Created:    *imageConfigHistory[i].Created,
						CreatedBy:  imageConfigHistory[i].CreatedBy,
						Author:     imageConfigHistory[i].Author,
						Comment:    imageConfigHistory[i].Comment,
						EmptyLayer: imageConfigHistory[i].EmptyLayer,
					},
				})

				if imageConfigHistory[i].EmptyLayer {
					continue
				}

				if layersIterator+1 > len(layers) {
					olu.Log.Error().Err(errors.ErrBadLayerCount).
						Msgf("error on creating layer history for imaeg %s %s", name, man.Digest)

					break
				}

				allHistory[i].Layer = layers[layersIterator]

				layersIterator++
			}
		}

		olu.Log.Debug().Msgf("all history %v", allHistory)

		size := strconv.Itoa(int(imageSize))
		manifestDigest := man.Digest.String()
		configDigest := manifest.Config.Digest.String()
		lastUpdated := GetImageLastUpdated(imageConfigInfo)
		score := 0

		imageSummary := ImageSummary{
			RepoName:      name,
			Tag:           tag,
			LastUpdated:   lastUpdated,
			Digest:        manifestDigest,
			ConfigDigest:  configDigest,
			IsSigned:      isSigned,
			Size:          size,
			Platform:      osArch,
			Vendor:        annotations.Vendor,
			Score:         score,
			Description:   annotations.Description,
			Title:         annotations.Title,
			Documentation: annotations.Documentation,
			Licenses:      annotations.Licenses,
			Labels:        annotations.Labels,
			Source:        annotations.Source,
			Layers:        layers,
			History:       allHistory,
		}

		imageSummaries = append(imageSummaries, imageSummary)

		if man.Digest.String() == lastUpdatedTag.Digest.String() {
			lastUpdatedImageSummary = imageSummary
		}
	}

	repo.ImageSummaries = imageSummaries

	for blob := range repoBlob2Size {
		repoSize += repoBlob2Size[blob]
	}

	size := strconv.FormatInt(repoSize, 10)

	repoPlatforms := make([]OsArch, 0, len(repoPlatformsSet))

	for _, osArch := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, osArch)
	}

	repoVendors := make([]string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, vendor)
	}

	summary := RepoSummary{
		Name:        name,
		LastUpdated: lastUpdatedTag.Timestamp,
		Size:        size,
		Platforms:   repoPlatforms,
		NewestImage: lastUpdatedImageSummary,
		Vendors:     repoVendors,
		Score:       -1,
	}

	repo.Summary = summary

	return repo, nil
}
