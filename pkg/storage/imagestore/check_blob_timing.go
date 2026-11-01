package imagestore

import "time"

type blobCheckStep struct {
	Calls   int     `json:"calls"`
	Seconds float64 `json:"seconds"`
}

// blobCheckTiming accumulates the time CheckBlob spends in each step, keyed by step name.
// A nil *blobCheckTiming records nothing, so callers can skip the clock reads entirely
// when the completion event would not be logged.
type blobCheckTiming struct {
	steps map[string]blobCheckStep
}

func newBlobCheckTiming(enabled bool) *blobCheckTiming {
	if !enabled {
		return nil
	}

	return &blobCheckTiming{steps: map[string]blobCheckStep{}}
}

func (timing *blobCheckTiming) start() time.Time {
	if timing == nil {
		return time.Time{}
	}

	return time.Now()
}

func (timing *blobCheckTiming) observe(step string, start time.Time) {
	if timing == nil {
		return
	}

	value := timing.steps[step]
	value.Calls++
	value.Seconds += time.Since(start).Seconds()
	timing.steps[step] = value
}
