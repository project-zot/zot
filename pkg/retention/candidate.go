package retention

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/retention/types"
)

func GetCandidates(repoMeta mTypes.RepoMeta) []*types.Candidate {
	candidates := make([]*types.Candidate, 0)

	// collect all statistic of repo's manifests
	for tag, desc := range repoMeta.Tags {
		for digestStr, stats := range repoMeta.Statistics {
			if digestStr == desc.Digest {
				candidate := &types.Candidate{
					MediaType:     desc.MediaType,
					DigestStr:     digestStr,
					Tag:           tag,
					PushTimestamp: stats.PushTimestamp,
					PullTimestamp: stats.LastPullTimestamp,
				}

				candidates = append(candidates, candidate)
			}
		}
	}

	return candidates
}

func GetCandidatesFromIndex(index ispec.Index) []*types.Candidate {
	candidates := make([]*types.Candidate, 0)

	// collect all manifests in the repo
	for _, manifest := range index.Manifests {
		tag, ok := manifest.Annotations[ispec.AnnotationRefName]
		if !ok {
			continue
		}

		candidate := &types.Candidate{
			MediaType: manifest.MediaType,
			DigestStr: string(manifest.Digest),
			Tag:       tag,
		}

		candidates = append(candidates, candidate)
	}

	return candidates
}
