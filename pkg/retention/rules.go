package retention

import (
	"fmt"
	"sort"
	"time"

	"zotregistry.dev/zot/pkg/retention/types"
)

const (
	// rules name.
	daysPullName   = "pulledWithin"
	daysPushName   = "pushedWithin"
	latestPullName = "mostRecentlyPulledCount"
	latestPushName = "mostRecentlyPushedCount"
)

// rules implementatio

type DaysPull struct {
	duration time.Duration
}

func NewDaysPull(duration time.Duration) DaysPull {
	return DaysPull{duration: duration}
}

func (dp DaysPull) Name() string {
	return fmt.Sprintf("%s:%d", daysPullName, dp.duration)
}

func (dp DaysPull) Perform(candidates []*types.Candidate) []*types.Candidate {
	filtered := make([]*types.Candidate, 0)

	timestamp := time.Now().Add(-dp.duration)

	for _, candidate := range candidates {
		// we check pushtimestamp because we don't want to delete tags pushed after timestamp
		// ie: if the tag doesn't meet PulledWithin: "3days" and the image is 1day old then do not remove!
		if candidate.PullTimestamp.After(timestamp) || candidate.PushTimestamp.After(timestamp) {
			candidate.RetainedBy = dp.Name()
			filtered = append(filtered, candidate)
		}
	}

	return filtered
}

type DaysPush struct {
	duration time.Duration
}

func NewDaysPush(duration time.Duration) DaysPush {
	return DaysPush{duration: duration}
}

func (dp DaysPush) Name() string {
	return fmt.Sprintf("%s:%d", daysPushName, dp.duration)
}

func (dp DaysPush) Perform(candidates []*types.Candidate) []*types.Candidate {
	filtered := make([]*types.Candidate, 0)

	timestamp := time.Now().Add(-dp.duration)

	for _, candidate := range candidates {
		if candidate.PushTimestamp.After(timestamp) {
			candidate.RetainedBy = dp.Name()

			filtered = append(filtered, candidate)
		}
	}

	return filtered
}

type latestPull struct {
	count int
}

func NewLatestPull(count int) latestPull {
	return latestPull{count: count}
}

func (lp latestPull) Name() string {
	return fmt.Sprintf("%s:%d", latestPullName, lp.count)
}

func (lp latestPull) Perform(candidates []*types.Candidate) []*types.Candidate {
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].PullTimestamp.After(candidates[j].PullTimestamp)
	})

	// take top count candidates
	upper := lp.count
	if lp.count > len(candidates) {
		upper = len(candidates)
	}

	candidates = candidates[:upper]

	for _, candidate := range candidates {
		candidate.RetainedBy = lp.Name()
	}

	return candidates
}

type latestPush struct {
	count int
}

func NewLatestPush(count int) latestPush {
	return latestPush{count: count}
}

func (lp latestPush) Name() string {
	return fmt.Sprintf("%s:%d", latestPushName, lp.count)
}

func (lp latestPush) Perform(candidates []*types.Candidate) []*types.Candidate {
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].PushTimestamp.After(candidates[j].PushTimestamp)
	})

	// take top count candidates
	upper := lp.count
	if lp.count > len(candidates) {
		upper = len(candidates)
	}

	candidates = candidates[:upper]

	for _, candidate := range candidates {
		candidate.RetainedBy = lp.Name()
	}

	return candidates
}
