package convert

import (
	"strconv"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/extensions/search/gql_generated"
)

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
