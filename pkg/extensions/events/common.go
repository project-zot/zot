package events

import (
	"context"
	"time"
)

const (
	DefaultHTTPTimeout = 30 * time.Second
	EventSource        = "zotregistry.dev"
)

type EventType string

const (
	ImageUpdatedEventType      EventType = "zotregistry.image.updated"
	ImageDeletedEventType      EventType = "zotregistry.image.deleted"
	ImageLintFailedEventType   EventType = "zotregistry.image.lint_failed"
	RepositoryCreatedEventType EventType = "zotregistry.repository.created"
)

func (e EventType) String() string {
	return string(e)
}

// Actor represents the authenticated user who triggered an event.
type Actor struct {
	Name string `json:"name"`
}

// RequestInfo holds metadata about the HTTP request that triggered an event.
type RequestInfo struct {
	Addr      string `json:"addr"`
	Method    string `json:"method"`
	UserAgent string `json:"useragent"`
}

type Recorder interface {
	Close()

	RepositoryCreated(name string)
	ImageUpdated(ctx context.Context, name, reference, digest, mediaType, manifest string)
	ImageDeleted(ctx context.Context, name, reference, digest, mediaType string)
	ImageLintFailed(ctx context.Context, name, reference, digest, mediaType, manifest string)
}
