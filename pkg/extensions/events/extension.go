//go:build events

package events

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

type Sink interface {
	Emit(*cloudevents.Event) cloudevents.Result
	Close() error
}

// NewRecorder builds a recorder publishing under the built-in source and type
// namespace.
func NewRecorder(logger log.Logger, sinks ...Sink) (Recorder, error) {
	return NewRecorderWithIdentity(logger, Identity{}, sinks...)
}

// NewRecorderWithIdentity builds a recorder publishing under the given source
// and type namespace. A zero Identity behaves exactly like NewRecorder.
func NewRecorderWithIdentity(logger log.Logger, identity Identity, sinks ...Sink) (Recorder, error) {
	if sinks == nil {
		return nil, zerr.ErrEventSinkIsNil
	}

	return &eventRecorder{
		sinks:    sinks,
		log:      logger,
		identity: identity,
	}, nil
}
