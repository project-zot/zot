package convert

import (
	"strconv"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
)

func BuildImageInfo(repo string, tag string, manifestDigest godigest.Digest,
	manifest v1.Manifest, imageConfig ispec.Image, isSigned bool,
) *gql_generated.ImageSummary {
	layers := []*gql_generated.LayerSummary{}
	size := int64(0)
	log := log.NewLogger("debug", "")
	allHistory := []*gql_generated.LayerHistory{}
	formattedManifestDigest := manifestDigest.Hex()
	annotations := common.GetAnnotations(manifest.Annotations, imageConfig.Config.Labels)
	lastUpdated := common.GetImageLastUpdated(imageConfig)

	history := imageConfig.History
	if len(history) == 0 {
		for _, layer := range manifest.Layers {
			size += layer.Size
			digest := layer.Digest.Hex
			layerSize := strconv.FormatInt(layer.Size, 10)

			layer := &gql_generated.LayerSummary{
				Size:   &layerSize,
				Digest: &digest,
			}

			layers = append(
				layers,
				layer,
			)

			allHistory = append(allHistory, &gql_generated.LayerHistory{
				Layer:              layer,
				HistoryDescription: &gql_generated.HistoryDescription{},
			})
		}

		formattedSize := strconv.FormatInt(size, 10)

		imageInfo := &gql_generated.ImageSummary{
			RepoName:      &repo,
			Tag:           &tag,
			Digest:        &formattedManifestDigest,
			ConfigDigest:  &manifest.Config.Digest.Hex,
			Size:          &formattedSize,
			Layers:        layers,
			History:       allHistory,
			Vendor:        &annotations.Vendor,
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
			LastUpdated:   &lastUpdated,
			IsSigned:      &isSigned,
			Platform: &gql_generated.OsArch{
				Os:   &imageConfig.OS,
				Arch: &imageConfig.Architecture,
			},
			Logo: &annotations.Logo,
		}

		return imageInfo
	}

	// iterator over manifest layers
	var layersIterator int
	// since we are appending pointers, it is important to iterate with an index over slice
	for i := range history {
		allHistory = append(allHistory, &gql_generated.LayerHistory{
			HistoryDescription: &gql_generated.HistoryDescription{
				Created:    history[i].Created,
				CreatedBy:  &history[i].CreatedBy,
				Author:     &history[i].Author,
				Comment:    &history[i].Comment,
				EmptyLayer: &history[i].EmptyLayer,
			},
		})

		if history[i].EmptyLayer {
			continue
		}

		if layersIterator+1 > len(manifest.Layers) {
			formattedSize := strconv.FormatInt(size, 10)

			log.Error().Err(zerr.ErrBadLayerCount).Msg("error on creating layer history for ImageSummary")

			return &gql_generated.ImageSummary{
				RepoName:      &repo,
				Tag:           &tag,
				Digest:        &formattedManifestDigest,
				ConfigDigest:  &manifest.Config.Digest.Hex,
				Size:          &formattedSize,
				Layers:        layers,
				History:       allHistory,
				Vendor:        &annotations.Vendor,
				Description:   &annotations.Description,
				Title:         &annotations.Title,
				Documentation: &annotations.Documentation,
				Licenses:      &annotations.Licenses,
				Labels:        &annotations.Labels,
				Source:        &annotations.Source,
				LastUpdated:   &lastUpdated,
				IsSigned:      &isSigned,
				Platform: &gql_generated.OsArch{
					Os:   &imageConfig.OS,
					Arch: &imageConfig.Architecture,
				},
				Logo: &annotations.Logo,
			}
		}

		size += manifest.Layers[layersIterator].Size
		digest := manifest.Layers[layersIterator].Digest.Hex
		layerSize := strconv.FormatInt(manifest.Layers[layersIterator].Size, 10)

		layer := &gql_generated.LayerSummary{
			Size:   &layerSize,
			Digest: &digest,
		}

		layers = append(
			layers,
			layer,
		)

		allHistory[i].Layer = layer

		layersIterator++
	}

	formattedSize := strconv.FormatInt(size, 10)

	imageInfo := &gql_generated.ImageSummary{
		RepoName:      &repo,
		Tag:           &tag,
		Digest:        &formattedManifestDigest,
		ConfigDigest:  &manifest.Config.Digest.Hex,
		Size:          &formattedSize,
		Layers:        layers,
		History:       allHistory,
		Vendor:        &annotations.Vendor,
		Description:   &annotations.Description,
		Title:         &annotations.Title,
		Documentation: &annotations.Documentation,
		Licenses:      &annotations.Licenses,
		Labels:        &annotations.Labels,
		Source:        &annotations.Source,
		LastUpdated:   &lastUpdated,
		IsSigned:      &isSigned,
		Platform: &gql_generated.OsArch{
			Os:   &imageConfig.OS,
			Arch: &imageConfig.Architecture,
		},
		Logo: &annotations.Logo,
	}

	return imageInfo
}

// updateRepoBlobsMap adds all the image blobs and their respective size to the repo blobs map
// and returnes the total size of the image.
func updateRepoBlobsMap(manifestDigest string, manifestSize int64, configDigest string, configSize int64,
	layers []ispec.Descriptor, repoBlob2Size map[string]int64,
) int64 {
	imgSize := int64(0)

	// add config size
	imgSize += configSize
	repoBlob2Size[configDigest] = configSize

	// add manifest size
	imgSize += manifestSize
	repoBlob2Size[manifestDigest] = manifestSize

	// add layers size
	for _, layer := range layers {
		repoBlob2Size[layer.Digest.String()] = layer.Size
		imgSize += layer.Size
	}

	return imgSize
}

func getLayersSummaries(manifestContent ispec.Manifest) []*gql_generated.LayerSummary {
	layers := make([]*gql_generated.LayerSummary, 0, len(manifestContent.Layers))

	for _, layer := range manifestContent.Layers {
		size := strconv.FormatInt(layer.Size, 10)
		digest := layer.Digest.String()

		layers = append(layers, &gql_generated.LayerSummary{
			Size:   &size,
			Digest: &digest,
		})
	}

	return layers
}

func getAllHistory(manifestContent ispec.Manifest, configContent ispec.Image) (
	[]*gql_generated.LayerHistory, error,
) {
	allHistory := []*gql_generated.LayerHistory{}
	layerSummaries := getLayersSummaries(manifestContent)

	history := configContent.History
	if len(history) == 0 {
		// We don't have any image history metadata
		// let's make due with just the layer metadata
		for _, layer := range layerSummaries {
			allHistory = append(allHistory, &gql_generated.LayerHistory{
				Layer:              layer,
				HistoryDescription: &gql_generated.HistoryDescription{},
			})
		}

		return allHistory, nil
	}

	// Iterator over manifest layers
	var layersIterator int
	// Since we are appending pointers, it is important to iterate with an index over slice
	for i := range history {
		allHistory = append(allHistory, &gql_generated.LayerHistory{
			HistoryDescription: &gql_generated.HistoryDescription{
				Created:    history[i].Created,
				CreatedBy:  &history[i].CreatedBy,
				Author:     &history[i].Author,
				Comment:    &history[i].Comment,
				EmptyLayer: &history[i].EmptyLayer,
			},
		})

		if history[i].EmptyLayer {
			continue
		}

		if layersIterator+1 > len(manifestContent.Layers) {
			return allHistory, zerr.ErrBadLayerCount
		}

		allHistory[i].Layer = layerSummaries[layersIterator]

		layersIterator++
	}

	return allHistory, nil
}

func imageHasSignatures(signatures map[string][]string) bool {
	// (sigType, signatures)
	for _, sigs := range signatures {
		if len(sigs) > 0 {
			return true
		}
	}

	return false
}
