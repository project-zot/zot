package convert

import (
	"strconv"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/extensions/search/gql_generated"
	"zotregistry.io/zot/pkg/log"
)

func BuildImageInfo(repo string, tag string, manifestDigest godigest.Digest,
	manifest ispec.Manifest, imageConfig ispec.Image, isSigned bool,
) *gql_generated.ImageSummary {
	layers := []*gql_generated.LayerSummary{}
	size := int64(0)
	log := log.NewLogger("debug", "")
	allHistory := []*gql_generated.LayerHistory{}
	formattedManifestDigest := manifestDigest.String()
	configDigest := manifest.Config.Digest.String()
	annotations := common.GetAnnotations(manifest.Annotations, imageConfig.Config.Labels)
	lastUpdated := common.GetImageLastUpdated(imageConfig)

	authors := annotations.Authors
	if authors == "" {
		authors = imageConfig.Author
	}

	history := imageConfig.History
	if len(history) == 0 {
		for _, layer := range manifest.Layers {
			size += layer.Size
			digest := layer.Digest.String()
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
			RepoName: &repo,
			Tag:      &tag,
			Manifests: []*gql_generated.ManifestSummary{
				{
					Digest:       &formattedManifestDigest,
					ConfigDigest: &configDigest,
					Layers:       layers,
					Size:         &formattedSize,
					History:      allHistory,
					Platform: &gql_generated.OsArch{
						Os:   &imageConfig.OS,
						Arch: &imageConfig.Architecture,
					},
					LastUpdated: &lastUpdated,
				},
			},
			Size:          &formattedSize,
			Description:   &annotations.Description,
			Title:         &annotations.Title,
			Documentation: &annotations.Documentation,
			Licenses:      &annotations.Licenses,
			Labels:        &annotations.Labels,
			Source:        &annotations.Source,
			Authors:       &authors,
			Vendor:        &annotations.Vendor,
			LastUpdated:   &lastUpdated,
			IsSigned:      &isSigned,
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
				RepoName: &repo,
				Tag:      &tag,
				Manifests: []*gql_generated.ManifestSummary{
					{
						Digest:       &formattedManifestDigest,
						ConfigDigest: &configDigest,
						Layers:       layers,
						Size:         &formattedSize,
						History:      allHistory,
						Platform: &gql_generated.OsArch{
							Os:   &imageConfig.OS,
							Arch: &imageConfig.Architecture,
						},
						LastUpdated: &lastUpdated,
					},
				},
				Size:          &formattedSize,
				Description:   &annotations.Description,
				Vendor:        &annotations.Vendor,
				Title:         &annotations.Title,
				Documentation: &annotations.Documentation,
				Licenses:      &annotations.Licenses,
				Labels:        &annotations.Labels,
				Source:        &annotations.Source,
				Authors:       &authors,
				LastUpdated:   &lastUpdated,
				IsSigned:      &isSigned,
			}
		}

		size += manifest.Layers[layersIterator].Size
		digest := manifest.Layers[layersIterator].Digest.String()
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
		RepoName: &repo,
		Tag:      &tag,
		Manifests: []*gql_generated.ManifestSummary{
			{
				Digest:       &formattedManifestDigest,
				ConfigDigest: &configDigest,
				Layers:       layers,
				History:      allHistory,
				Platform: &gql_generated.OsArch{
					Os:   &imageConfig.OS,
					Arch: &imageConfig.Architecture,
				},
				Size:        &formattedSize,
				LastUpdated: &lastUpdated,
			},
		},
		Size:          &formattedSize,
		Description:   &annotations.Description,
		Title:         &annotations.Title,
		Documentation: &annotations.Documentation,
		Licenses:      &annotations.Licenses,
		Labels:        &annotations.Labels,
		Source:        &annotations.Source,
		Vendor:        &annotations.Vendor,
		Authors:       &authors,
		LastUpdated:   &lastUpdated,
		IsSigned:      &isSigned,
	}

	return imageInfo
}

// updateRepoBlobsMap adds all the image blobs and their respective size to the repo blobs map
// and returnes the total size of the image.
func updateRepoBlobsMap(imageBlobs map[string]int64, repoBlob2Size map[string]int64) int64 {
	imgSize := int64(0)

	for digest, size := range imageBlobs {
		repoBlob2Size[digest] = size
		imgSize += size
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
