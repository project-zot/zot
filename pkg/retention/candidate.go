package retention

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/retention/types"
)

func GetCandidates(repoMeta mTypes.RepoMeta) []*types.Candidate {
	candidates := make([]*types.Candidate, 0)

	// collect all statistic of repo's manifests
	for tag, desc := range repoMeta.Tags {
		// Check if statistics exist for this digest to prevent using zero-value statistics.
		// When statistics are missing for a tag's digest, we skip creating a candidate for it.
		// This prevents incorrect retention decisions based on zero-value timestamps (epoch time).
		// The retention policy manager handles tags without statistics separately by keeping them
		// (see GetRetainedTagsFromMetaDB in retention.go which explicitly retains tags not found
		// in candidates list).
		stats, hasStatistics := repoMeta.Statistics[desc.Digest]
		if !hasStatistics {
			continue
		}

		candidate := &types.Candidate{
			MediaType:     desc.MediaType,
			DigestStr:     desc.Digest,
			Tag:           tag,
			PushTimestamp: stats.PushTimestamp,
			PullTimestamp: stats.LastPullTimestamp,
		}

		candidates = append(candidates, candidate)
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
