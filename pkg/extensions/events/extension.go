//go:build events
// +build events

package events

import (
	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
)

func NewRecorder(logger log.Logger, sinks ...Sink) (Recorder, error) {
	if sinks == nil {
		return nil, zerr.ErrEventSinkIsNil
	}

	return &eventRecorder{
		sinks: sinks,
		log:   logger,
	}, nil
}
