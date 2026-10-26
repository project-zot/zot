package imagestore

import "time"

type blobCheckStep struct {
	Calls   int     `json:"calls"`
	Seconds float64 `json:"seconds"`
}

// blobCheckTiming accumulates the time CheckBlob spends in each step, keyed by step name.
type blobCheckTiming map[string]blobCheckStep

func (timing blobCheckTiming) observe(step string, start time.Time) {
	value := timing[step]
	value.Calls++
	value.Seconds += time.Since(start).Seconds()
	timing[step] = value
}
