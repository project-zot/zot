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

// ActorInfo describes who triggered an event.
type ActorInfo struct {
	Name string `json:"name"`
}

// RequestInfo describes the HTTP request that triggered an event.
type RequestInfo struct {
	Addr      string `json:"addr"`
	Method    string `json:"method"`
	UserAgent string `json:"useragent"`
}

// EventContext carries actor and request metadata for events.
type EventContext struct {
	Actor   *ActorInfo   `json:"actor,omitempty"`
	Request *RequestInfo `json:"request,omitempty"`
}

type eventContextKey struct{}

// WithEventContext attaches an EventContext to a context.Context.
func WithEventContext(ctx context.Context, ec *EventContext) context.Context {
	return context.WithValue(ctx, eventContextKey{}, ec)
}

// EventContextFromContext retrieves the EventContext from a context.Context.
func EventContextFromContext(ctx context.Context) *EventContext {
	ec, _ := ctx.Value(eventContextKey{}).(*EventContext)

	return ec
}

type Recorder interface {
	Close()

	RepositoryCreated(name string, ectx *EventContext)
	ImageUpdated(name, reference, digest, mediaType, manifest string, ectx *EventContext)
	ImageDeleted(name, reference, digest, mediaType string, ectx *EventContext)
	ImageLintFailed(name, reference, digest, mediaType, manifest string, ectx *EventContext)
}
