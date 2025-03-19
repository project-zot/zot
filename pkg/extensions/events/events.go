package events

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"

	"zotregistry.dev/zot/pkg/log"
)

const EventSource = "zotregistry.dev"

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

type Sink interface {
	Emit(*cloudevents.Event) cloudevents.Result
}

type Recorder interface {
	RepositoryCreated(name string) error
	ImageUpdated(name, reference, digest, mediaType, manifest string) error
	ImageDeleted(name, reference, digest, mediaType string) error
	ImageLintFailed(name, reference, digest, mediaType, manifest string) error
}

type eventRecorder struct {
	log log.Logger
	Sink
}

var _ Recorder = (*eventRecorder)(nil)

func (r eventRecorder) RepositoryCreated(name string) error {
	event, err := newEventBuilder().
		WithEventType(RepositoryCreatedEventType).
		WithDataField("name", name).
		Build()
	if err != nil {
		return err
	}

	return r.Emit(event)
}

func (r eventRecorder) ImageUpdated(name, reference, digest, mediaType, manifest string) error {
	event, err := newEventBuilder().
		WithEventType(ImageUpdatedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithDataField("manifest", manifest).
		Build()
	if err != nil {
		return err
	}

	return r.Emit(event)
}

func (r eventRecorder) ImageDeleted(name, reference, digest, mediaType string) error {
	event, err := newEventBuilder().
		WithEventType(ImageDeletedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		Build()
	if err != nil {
		return err
	}

	return r.Emit(event)
}

func (r eventRecorder) ImageLintFailed(name, reference, digest, mediaType, manifest string) error {
	event, err := newEventBuilder().
		WithEventType(ImageLintFailedEventType).
		WithDataField("name", name).
		WithDataField("reference", reference).
		WithDataField("digest", digest).
		WithDataField("mediaType", mediaType).
		WithDataField("manifest", manifest).
		Build()
	if err != nil {
		return err
	}

	return r.Emit(event)
}
