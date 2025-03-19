package events

import (
	cloudevents "github.com/cloudevents/sdk-go/v2"

	"zotregistry.dev/zot/pkg/log"
)

type logSink struct {
	logger log.Logger
}

func LogSink(logger log.Logger) Sink {
	return &logSink{
		logger: logger,
	}
}

func (s *logSink) Emit(e *cloudevents.Event) cloudevents.Result {
	s.logger.Info().Msg(e.String())

	return nil
}
