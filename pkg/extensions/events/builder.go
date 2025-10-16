//go:build events
// +build events

package events

import (
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/google/uuid"

	zerr "zotregistry.dev/zot/v2/errors"
)

type eventBuilder struct {
	data      map[string]any
	eventType EventType
}

func newEventBuilder() *eventBuilder {
	return &eventBuilder{
		data: make(map[string]any),
	}
}

func (b *eventBuilder) WithDataField(name string, value any) *eventBuilder {
	b.data[name] = value

	return b
}

func (b *eventBuilder) WithEventType(eventType EventType) *eventBuilder {
	b.eventType = eventType

	return b
}

func (b *eventBuilder) Build() (*cloudevents.Event, error) {
	if b.eventType == "" {
		return nil, zerr.ErrEventTypeEmpty
	}
	event := cloudevents.NewEvent()
	event.SetType(b.eventType.String())
	event.SetID(uuid.New().String())
	event.SetTime(time.Now())
	event.SetSource(EventSource)

	if b.data != nil {
		if err := event.SetData(cloudevents.ApplicationJSON, b.data); err != nil {
			return nil, err
		}
	}

	return &event, nil
}
