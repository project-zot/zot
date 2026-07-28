package mocks

import (
	"sync"

	"zotregistry.dev/zot/v2/pkg/extensions/events"
)

type RepositoryCreatedCall struct {
	Name string
	Ectx *events.EventContext
}

type ImageUpdatedCall struct {
	Name, Reference, Digest, MediaType, Manifest string
	Ectx                                         *events.EventContext
}

type ImageDeletedCall struct {
	Name, Reference, Digest, MediaType string
	Ectx                               *events.EventContext
}

type ImageLintFailedCall struct {
	Name, Reference, Digest, MediaType, Manifest string
	Ectx                                         *events.EventContext
}

type ImageScannedCall struct {
	Name, Reference, Digest, MediaType string
	Summary                            events.ImageScanSummary
	Ectx                               *events.EventContext
}

// EventRecorderMock is a thread-safe events.Recorder test double that records every
// call it receives, for tests that assert on what was published without needing a
// bespoke fake per package.
type EventRecorderMock struct {
	mu sync.Mutex

	RepositoryCreatedCalls []RepositoryCreatedCall
	ImageUpdatedCalls      []ImageUpdatedCall
	ImageDeletedCalls      []ImageDeletedCall
	ImageLintFailedCalls   []ImageLintFailedCall
	ImageScannedCalls      []ImageScannedCall
}

func (r *EventRecorderMock) Close() {}

// Lock/Unlock let callers read a consistent view across multiple *Calls fields
// (e.g. while a background goroutine may still be recording events concurrently).
func (r *EventRecorderMock) Lock() { r.mu.Lock() }

func (r *EventRecorderMock) Unlock() { r.mu.Unlock() }

func (r *EventRecorderMock) RepositoryCreated(name string, ectx *events.EventContext) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.RepositoryCreatedCalls = append(r.RepositoryCreatedCalls, RepositoryCreatedCall{Name: name, Ectx: ectx})
}

func (r *EventRecorderMock) ImageUpdated(name, reference, digest, mediaType, manifest string,
	ectx *events.EventContext,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.ImageUpdatedCalls = append(r.ImageUpdatedCalls, ImageUpdatedCall{
		Name: name, Reference: reference, Digest: digest, MediaType: mediaType, Manifest: manifest, Ectx: ectx,
	})
}

func (r *EventRecorderMock) ImageDeleted(name, reference, digest, mediaType string, ectx *events.EventContext) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.ImageDeletedCalls = append(r.ImageDeletedCalls, ImageDeletedCall{
		Name: name, Reference: reference, Digest: digest, MediaType: mediaType, Ectx: ectx,
	})
}

func (r *EventRecorderMock) ImageLintFailed(name, reference, digest, mediaType, manifest string,
	ectx *events.EventContext,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.ImageLintFailedCalls = append(r.ImageLintFailedCalls, ImageLintFailedCall{
		Name: name, Reference: reference, Digest: digest, MediaType: mediaType, Manifest: manifest, Ectx: ectx,
	})
}

func (r *EventRecorderMock) ImageScanned(name, reference, digest, mediaType string,
	summary events.ImageScanSummary, ectx *events.EventContext,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.ImageScannedCalls = append(r.ImageScannedCalls, ImageScannedCall{
		Name: name, Reference: reference, Digest: digest, MediaType: mediaType, Summary: summary, Ectx: ectx,
	})
}
