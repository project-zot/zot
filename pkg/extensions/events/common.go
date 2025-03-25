package events

import (
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

type Recorder interface {
	RepositoryCreated(name string) error
	ImageUpdated(name, reference, digest, mediaType, manifest string) error
	ImageDeleted(name, reference, digest, mediaType string) error
	ImageLintFailed(name, reference, digest, mediaType, manifest string) error
}
