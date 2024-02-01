package retention

import (
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
