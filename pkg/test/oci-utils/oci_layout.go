//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package ociutils

import (
	"encoding/json"
	goerrors "errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/search/convert"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
	stypes "zotregistry.dev/zot/pkg/storage/types"
)

type OciUtils interface { //nolint: interfacebloat
	GetImageManifest(repo string, reference string) (ispec.Manifest, godigest.Digest, error)
	GetImageManifests(repo string) ([]ispec.Descriptor, error)
	GetImageBlobManifest(repo string, digest godigest.Digest) (ispec.Manifest, error)
	GetImageInfo(repo string, configDigest godigest.Digest) (ispec.Image, error)
	GetImageTagsWithTimestamp(repo string) ([]cvemodel.TagInfo, error)
	GetImagePlatform(imageInfo ispec.Image) (string, string)
	GetImageManifestSize(repo string, manifestDigest godigest.Digest) int64
	GetRepoLastUpdated(repo string) (cvemodel.TagInfo, error)
	GetExpandedRepoInfo(name string) (common.RepoInfo, error)
	GetImageConfigInfo(repo string, manifestDigest godigest.Digest) (ispec.Image, error)
	CheckManifestSignature(name string, digest godigest.Digest) bool
	GetRepositories() ([]string, error)
	ExtractImageDetails(repo string, tag string, log log.Logger) (godigest.Digest,
		*ispec.Manifest, *ispec.Image, error)
}

// OciLayoutInfo ...
type BaseOciLayoutUtils struct {
	Log             log.Logger
	StoreController stypes.StoreController
}

// NewBaseOciLayoutUtils initializes a new OciLayoutUtils object.
func NewBaseOciLayoutUtils(storeController stypes.StoreController, log log.Logger) *BaseOciLayoutUtils {
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
	defaultStore := olu.StoreController.GetDefaultImageStore()
	substores := olu.StoreController.GetImageSubStores()

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
		if goerrors.Is(zerr.ErrRepoNotFound, err) {
			olu.Log.Error().Err(err).Msg("failed to get index.json contents because the file is missing")

			return nil, zerr.ErrRepoNotFound
		}

		olu.Log.Error().Err(err).Msg("failed to open index.json")

		return nil, zerr.ErrRepoNotFound
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		olu.Log.Error().Err(err).Str("dir", path.Join(imageStore.RootDir(), repo)).
			Msg("failed to unmarshal json")

		return nil, zerr.ErrRepoNotFound
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
		olu.Log.Error().Err(err).Msg("failed to open image metadata file")

		return blobIndex, err
	}

	if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
		olu.Log.Error().Err(err).Msg("failed to marshal blob index")

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
		olu.Log.Error().Err(err).Msg("failed to open image layers file")

		return imageInfo, err
	}

	if err := json.Unmarshal(blobBuf, &imageInfo); err != nil {
		olu.Log.Error().Err(err).Msg("failed to marshal blob index")

		return imageInfo, err
	}

	return imageInfo, err
}

// GetImageTagsWithTimestamp returns a list of image tags with timestamp available in the specified repository.
func (olu BaseOciLayoutUtils) GetImageTagsWithTimestamp(repo string) ([]cvemodel.TagInfo, error) {
	tagsInfo := make([]cvemodel.TagInfo, 0)

	manifests, err := olu.GetImageManifests(repo)
	if err != nil {
		olu.Log.Error().Err(err).Msg("failed to read image manifests")

		return tagsInfo, err
	}

	for _, manifest := range manifests {
		digest := manifest.Digest

		val, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := olu.GetImageBlobManifest(repo, digest)
			if err != nil {
				olu.Log.Error().Err(err).Msg("failed to read image blob manifest")

				return tagsInfo, err
			}

			imageInfo, err := olu.GetImageInfo(repo, imageBlobManifest.Config.Digest)
			if err != nil {
				olu.Log.Error().Err(err).Msg("failed to read image info")

				return tagsInfo, err
			}

			timeStamp := common.GetImageLastUpdated(imageInfo)

			tagsInfo = append(tagsInfo,
				cvemodel.TagInfo{
					Tag:       val,
					Timestamp: timeStamp,
					Descriptor: cvemodel.Descriptor{
						Digest:    digest,
						MediaType: manifest.MediaType,
					},
				},
			)
		}
	}

	return tagsInfo, nil
}

// check notary signature corresponding to repo name, manifest digest and mediatype.
func (olu BaseOciLayoutUtils) checkNotarySignature(name string, digest godigest.Digest) bool {
	imageStore := olu.StoreController.GetImageStore(name)
	mediaType := common.ArtifactTypeNotation

	referrers, err := imageStore.GetReferrers(name, digest, []string{mediaType})
	if err != nil {
		olu.Log.Info().Err(err).Str("repository", name).Str("digest",
			digest.String()).Str("mediatype", mediaType).Msg("invalid notary signature")

		return false
	}

	if len(referrers.Manifests) == 0 {
		return false
	}

	return true
}

// check cosign signature corresponding to  manifest.
func (olu BaseOciLayoutUtils) checkCosignSignature(name string, digest godigest.Digest) bool {
	if digest.Validate() != nil {
		return false
	}

	imageStore := olu.StoreController.GetImageStore(name)

	// if manifest is signed using cosign mechanism, cosign adds a new manifest.
	// new manifest is tagged as sha256-<manifest-digest>.sig.
	reference := fmt.Sprintf("sha256-%s.sig", digest.Encoded())

	_, _, _, err := imageStore.GetImageManifest(name, reference) //nolint: dogsled
	if err == nil {
		return true
	}

	mediaType := common.ArtifactTypeCosign

	referrers, err := imageStore.GetReferrers(name, digest, []string{mediaType})
	if err != nil {
		olu.Log.Info().Err(err).Str("repository", name).Str("digest",
			digest.String()).Str("mediatype", mediaType).Msg("invalid cosign signature")

		return false
	}

	if len(referrers.Manifests) == 0 {
		olu.Log.Info().Err(err).Str("repository", name).Str("digest",
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
		olu.Log.Error().Err(err).Msg("failed to get manifest blob content")

		return int64(len(manifestBlob))
	}

	return int64(len(manifestBlob))
}

func (olu BaseOciLayoutUtils) GetImageConfigSize(repo string, manifestDigest godigest.Digest) int64 {
	imageBlobManifest, err := olu.GetImageBlobManifest(repo, manifestDigest)
	if err != nil {
		olu.Log.Error().Err(err).Msg("failed to get image blob manifest")

		return 0
	}

	return imageBlobManifest.Config.Size
}

func (olu BaseOciLayoutUtils) GetRepoLastUpdated(repo string) (cvemodel.TagInfo, error) {
	tagsInfo, err := olu.GetImageTagsWithTimestamp(repo)
	if err != nil || len(tagsInfo) == 0 {
		return cvemodel.TagInfo{}, err
	}

	latestTag := GetLatestTag(tagsInfo)

	return latestTag, nil
}

func (olu BaseOciLayoutUtils) GetExpandedRepoInfo(repoName string) (common.RepoInfo, error) {
	repo := common.RepoInfo{}
	repoBlob2Size := make(map[string]int64, 10)

	// made up of all manifests, configs and image layers
	repoSize := int64(0)

	imageSummaries := make([]common.ImageSummary, 0)

	manifestList, err := olu.GetImageManifests(repoName)
	if err != nil {
		olu.Log.Error().Err(err).Msg("failed to get image manifests")

		return common.RepoInfo{}, err
	}

	lastUpdatedTag, err := olu.GetRepoLastUpdated(repoName)
	if err != nil {
		olu.Log.Error().Err(err).Str("repository", repoName).Msg("failed to get last updated manifest for repo")

		return common.RepoInfo{}, err
	}

	repoVendorsSet := make(map[string]bool, len(manifestList))
	repoPlatformsSet := make(map[string]common.Platform, len(manifestList))

	var lastUpdatedImageSummary common.ImageSummary

	for _, man := range manifestList {
		imageLayersSize := int64(0)

		tag, ok := man.Annotations[ispec.AnnotationRefName]
		if !ok {
			olu.Log.Info().Str("digest", man.Digest.String()).
				Msg("skipping manifest with digest because it doesn't have a tag")

			continue
		}

		manifest, err := olu.GetImageBlobManifest(repoName, man.Digest)
		if err != nil {
			olu.Log.Error().Err(err).Msg("failed to get image manifest blob")

			return common.RepoInfo{}, err
		}

		isSigned := olu.CheckManifestSignature(repoName, man.Digest)

		manifestSize := olu.GetImageManifestSize(repoName, man.Digest)
		olu.Log.Debug().Msg(fmt.Sprintf("%v", man.Digest.String()))
		configSize := manifest.Config.Size

		repoBlob2Size[man.Digest.String()] = manifestSize
		repoBlob2Size[manifest.Config.Digest.String()] = configSize

		imageConfigInfo, err := olu.GetImageConfigInfo(repoName, man.Digest)
		if err != nil {
			olu.Log.Error().Err(err).Str("repository", repoName).Str("manifest digest", man.Digest.String()).
				Msg("failed to retrieve config info for the image")

			continue
		}

		opSys, arch := olu.GetImagePlatform(imageConfigInfo)
		platform := common.Platform{
			Os:   opSys,
			Arch: arch,
		}

		if opSys != "" || arch != "" {
			platformString := strings.TrimSpace(fmt.Sprintf("%s %s", opSys, arch))
			repoPlatformsSet[platformString] = platform
		}

		layers := make([]common.LayerSummary, 0)

		for _, layer := range manifest.Layers {
			layerInfo := common.LayerSummary{}

			layerInfo.Digest = layer.Digest.String()

			repoBlob2Size[layerInfo.Digest] = layer.Size

			layerInfo.Size = strconv.FormatInt(layer.Size, 10)

			imageLayersSize += layer.Size

			layers = append(layers, layerInfo)
		}

		imageSize := imageLayersSize + manifestSize + configSize

		// get image info from manifest annotation, if not found get from image config labels.
		annotations := convert.GetAnnotations(manifest.Annotations, imageConfigInfo.Config.Labels)

		if annotations.Vendor != "" {
			repoVendorsSet[annotations.Vendor] = true
		}

		imageConfigHistory := imageConfigInfo.History
		allHistory := []common.LayerHistory{}

		if len(imageConfigHistory) == 0 {
			for _, layer := range layers {
				allHistory = append(allHistory, common.LayerHistory{
					Layer:              layer,
					HistoryDescription: common.HistoryDescription{},
				})
			}
		} else {
			// iterator over manifest layers
			var layersIterator int
			// since we are appending pointers, it is important to iterate with an index over slice
			for i := range imageConfigHistory {
				allHistory = append(allHistory, common.LayerHistory{
					HistoryDescription: common.HistoryDescription{
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
					olu.Log.Error().Err(err).Str("repository", repoName).Str("manifest digest", man.Digest.String()).
						Msg("error on creating layer history for image")

					break
				}

				allHistory[i].Layer = layers[layersIterator]

				layersIterator++
			}
		}

		olu.Log.Debug().Interface("history", allHistory).Msg("all history")

		size := strconv.Itoa(int(imageSize))
		manifestDigest := man.Digest.String()
		configDigest := manifest.Config.Digest.String()
		lastUpdated := common.GetImageLastUpdated(imageConfigInfo)

		imageSummary := common.ImageSummary{
			RepoName: repoName,
			Tag:      tag,
			Manifests: []common.ManifestSummary{
				{
					Digest:       manifestDigest,
					ConfigDigest: configDigest,
					LastUpdated:  lastUpdated,
					Size:         size,
					Platform:     platform,
					Layers:       layers,
					History:      allHistory,
				},
			},
			LastUpdated:   lastUpdated,
			IsSigned:      isSigned,
			Size:          size,
			Description:   annotations.Description,
			Title:         annotations.Title,
			Documentation: annotations.Documentation,
			Licenses:      annotations.Licenses,
			Labels:        annotations.Labels,
			Vendor:        annotations.Vendor,
			Source:        annotations.Source,
		}

		imageSummaries = append(imageSummaries, imageSummary)

		if man.Digest.String() == lastUpdatedTag.Descriptor.Digest.String() {
			lastUpdatedImageSummary = imageSummary
		}
	}

	repo.ImageSummaries = imageSummaries

	for blob := range repoBlob2Size {
		repoSize += repoBlob2Size[blob]
	}

	size := strconv.FormatInt(repoSize, 10)

	repoPlatforms := make([]common.Platform, 0, len(repoPlatformsSet))

	for _, platform := range repoPlatformsSet {
		repoPlatforms = append(repoPlatforms, platform)
	}

	repoVendors := make([]string, 0, len(repoVendorsSet))

	for vendor := range repoVendorsSet {
		vendor := vendor
		repoVendors = append(repoVendors, vendor)
	}

	summary := common.RepoSummary{
		Name:        repoName,
		LastUpdated: lastUpdatedTag.Timestamp,
		Size:        size,
		Platforms:   repoPlatforms,
		NewestImage: lastUpdatedImageSummary,
		Vendors:     repoVendors,
	}

	repo.Summary = summary

	return repo, nil
}

func (olu BaseOciLayoutUtils) ExtractImageDetails(
	repo, tag string,
	log log.Logger) (
	godigest.Digest, *ispec.Manifest, *ispec.Image, error,
) {
	manifest, dig, err := olu.GetImageManifest(repo, tag)
	if err != nil {
		log.Error().Err(err).Msg("failed to retrieve image manifest")

		return "", nil, nil, err
	}

	digest := dig

	imageConfig, err := olu.GetImageConfigInfo(repo, digest)
	if err != nil {
		log.Error().Err(err).Msg("failed to retrieve image config")

		return "", nil, nil, err
	}

	return digest, &manifest, &imageConfig, nil
}

func GetLatestTag(allTags []cvemodel.TagInfo) cvemodel.TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(allTags[j].Timestamp)
	})

	return allTags[len(allTags)-1]
}
