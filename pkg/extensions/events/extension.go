//go:build events
// +build events

package events

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
)

type Sink interface {
	Emit(*cloudevents.Event) cloudevents.Result
	Close() error
}

func NewRecorder(logger log.Logger, sinks ...Sink) (Recorder, error) {
	if sinks == nil {
		return nil, zerr.ErrEventSinkIsNil
	}

	return &eventRecorder{
		sinks: sinks,
		log:   logger,
	}, nil
}
