package retention

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/retention/types"
)

// Count-based rules must select the same candidates whatever order the tag map produced them
// in, or a commit-time recomputation would disagree with the scan for no reason.
func TestCountRulesAreDeterministicWithTiedTimestamps(t *testing.T) {
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	build := func() []*types.Candidate {
		candidates := make([]*types.Candidate, 0, 6)
		for _, tag := range []string{"a", "b", "c", "d", "e", "f"} {
			candidates = append(candidates, &types.Candidate{
				Tag: tag, DigestStr: "sha256:" + tag, PullTimestamp: stamp, PushTimestamp: stamp,
			})
		}

		return candidates
	}

	selected := func(rule types.Rule) map[string]struct{} {
		candidates := build()
		rand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })

		set := make(map[string]struct{})
		for _, candidate := range rule.Perform(candidates) {
			set[candidate.Tag] = struct{}{}
		}

		return set
	}

	for _, rule := range []types.Rule{NewLatestPull(2), NewLatestPush(3)} {
		first := selected(rule)
		for range 50 {
			require.Equal(t, first, selected(rule), rule.Name())
		}
	}
}
