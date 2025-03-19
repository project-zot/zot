//go:build !events
// +build !events

package events

import (
	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/log"
)

func NewRecorder(sink Sink, logger log.Logger) (Recorder, error) {
	if sink == nil {
		return nil, zerr.ErrEventSinkIsNil
	}

	return &eventRecorder{
		Sink: sink,
		log:  logger,
	}, nil
}
