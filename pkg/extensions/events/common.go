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
	Close()

	RepositoryCreated(name string)
	ImageUpdated(name, reference, digest, mediaType, manifest string)
	ImageDeleted(name, reference, digest, mediaType string)
	ImageLintFailed(name, reference, digest, mediaType, manifest string)
}
