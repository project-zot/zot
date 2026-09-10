package events

import (
	"sync"
)

// ReloadableRecorder is a Recorder whose delegate a reload can replace, so
// every consumer follows without touching an emit site.
type ReloadableRecorder struct {
	// held across the whole forwarded call, so Swap can drain the delegate
	mu       sync.RWMutex
	recorder Recorder
	closed   bool
}

var _ Recorder = (*ReloadableRecorder)(nil)

func NewReloadableRecorder(recorder Recorder) *ReloadableRecorder {
	return &ReloadableRecorder{recorder: recorder}
}

// Swap installs recorder and returns the delegate it replaced, once the calls
// still inside it have returned, for the caller to close.
func (r *ReloadableRecorder) Swap(recorder Recorder) Recorder {
	r.mu.Lock()
	defer r.mu.Unlock()

	// a reload that raced shutdown must not install into a closed wrapper, so
	// hand its recorder back to be closed rather than leaving it live
	if r.closed {
		return recorder
	}

	previous := r.recorder
	r.recorder = recorder

	return previous
}

// with runs record against the installed delegate, if there is one.
func (r *ReloadableRecorder) with(record func(recorder Recorder)) {
	if r == nil {
		return
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.recorder != nil {
		record(r.recorder)
	}
}

// Close detaches the delegate before closing it, so Swap drains it first.
func (r *ReloadableRecorder) Close() {
	if r == nil {
		return
	}

	r.mu.Lock()
	previous := r.recorder
	r.recorder = nil
	r.closed = true
	r.mu.Unlock()

	if previous != nil {
		previous.Close()
	}
}

func (r *ReloadableRecorder) RepositoryCreated(name string, ectx *EventContext) {
	r.with(func(recorder Recorder) { recorder.RepositoryCreated(name, ectx) })
}

func (r *ReloadableRecorder) ImageUpdated(name, reference, digest, mediaType, manifest string, ectx *EventContext) {
	r.with(func(recorder Recorder) {
		recorder.ImageUpdated(name, reference, digest, mediaType, manifest, ectx)
	})
}

func (r *ReloadableRecorder) ImageDeleted(name, reference, digest, mediaType string, ectx *EventContext) {
	r.with(func(recorder Recorder) {
		recorder.ImageDeleted(name, reference, digest, mediaType, ectx)
	})
}

func (r *ReloadableRecorder) ImageLintFailed(name, reference, digest, mediaType, manifest string, ectx *EventContext) {
	r.with(func(recorder Recorder) {
		recorder.ImageLintFailed(name, reference, digest, mediaType, manifest, ectx)
	})
}

func (r *ReloadableRecorder) ImageScanned(name, reference, digest, mediaType string,
	summary ImageScanSummary, ectx *EventContext,
) {
	r.with(func(recorder Recorder) {
		recorder.ImageScanned(name, reference, digest, mediaType, summary, ectx)
	})
}
