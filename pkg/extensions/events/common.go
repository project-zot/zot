package events

import (
	"context"
	"strings"
	"time"
)

const (
	DefaultHTTPTimeout = 30 * time.Second
	EventSource        = "zotregistry.dev"

	// DefaultEventTypePrefix is the namespace every built-in event type is
	// published under. It is the leading segment of the EventType constants
	// below, and Identity replaces it when an operator configures their own.
	DefaultEventTypePrefix = "zotregistry"
)

// Identity is the CloudEvents source and type namespace a recorder publishes
// under. Both fields are optional and fall back to the built-in values, so a
// zero Identity reproduces the previous behaviour exactly.
//
// An operator running zot as part of a larger service needs these: the source
// identifies the producer to a receiver, and a single hardcoded value cannot
// distinguish one deployment, or one tenant, from another.
type Identity struct {
	// Source is the CloudEvents source attribute. Defaults to EventSource.
	Source string

	// TypePrefix replaces the leading namespace of each event type, so
	// image.updated is published as "<TypePrefix>.image.updated". Defaults to
	// DefaultEventTypePrefix.
	TypePrefix string
}

// SourceOrDefault returns the configured source, or the built-in one.
func (i Identity) SourceOrDefault() string {
	if i.Source == "" {
		return EventSource
	}

	return i.Source
}

// TypeOf renders an event type under the configured namespace.
func (i Identity) TypeOf(eventType EventType) string {
	name := eventType.String()
	if i.TypePrefix == "" || i.TypePrefix == DefaultEventTypePrefix {
		return name
	}

	if suffix, found := strings.CutPrefix(name, DefaultEventTypePrefix+"."); found {
		return i.TypePrefix + "." + suffix
	}

	return name
}

type EventType string

const (
	ImageUpdatedEventType      EventType = "zotregistry.image.updated"
	ImageDeletedEventType      EventType = "zotregistry.image.deleted"
	ImageLintFailedEventType   EventType = "zotregistry.image.lint_failed"
	ImageScannedEventType      EventType = "zotregistry.image.scanned"
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

type ImageScanSummary struct {
	Count         int    `json:"count"`
	FixableCount  int    `json:"fixableCount"`
	UnknownCount  int    `json:"unknownCount"`
	LowCount      int    `json:"lowCount"`
	MediumCount   int    `json:"mediumCount"`
	HighCount     int    `json:"highCount"`
	CriticalCount int    `json:"criticalCount"`
	MaxSeverity   string `json:"maxSeverity"`
}

type eventContextKey struct{}

// WithEventContext attaches an EventContext to a context.Context.
func WithEventContext(ctx context.Context, ec *EventContext) context.Context {
	return context.WithValue(ctx, eventContextKey{}, ec)
}

// EventContextFromContext retrieves the EventContext from a context.Context.
func EventContextFromContext(ctx context.Context) *EventContext {
	if ctx == nil {
		return nil
	}

	ec, _ := ctx.Value(eventContextKey{}).(*EventContext)

	return ec
}

type Recorder interface {
	Close()

	RepositoryCreated(name string, ectx *EventContext)
	ImageUpdated(name, reference, digest, mediaType, manifest string, ectx *EventContext)
	ImageDeleted(name, reference, digest, mediaType string, ectx *EventContext)
	ImageLintFailed(name, reference, digest, mediaType, manifest string, ectx *EventContext)
	ImageScanned(name, reference, digest, mediaType string, summary ImageScanSummary, ectx *EventContext)
}
