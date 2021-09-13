package log

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger extends zerolog's Logger.
type Logger struct {
	zerolog.Logger
}

func (l Logger) Println(v ...interface{}) {
	l.Logger.Error().Msg("panic recovered")
}

func NewLogger(level string, output string) Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	lvl, err := zerolog.ParseLevel(level)

	if err != nil {
		panic(err)
	}

	zerolog.SetGlobalLevel(lvl)

	var log zerolog.Logger

	if output == "" {
		log = zerolog.New(os.Stdout)
	} else {
		file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		log = zerolog.New(file)
	}

	return Logger{Logger: log.With().Caller().Timestamp().Logger()}
}

func NewAuditLogger(level string, audit string) *Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	lvl, err := zerolog.ParseLevel(level)

	if err != nil {
		panic(err)
	}

	zerolog.SetGlobalLevel(lvl)

	var auditLog zerolog.Logger

	auditFile, err := os.OpenFile(audit, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	auditLog = zerolog.New(auditFile)

	return &Logger{Logger: auditLog.With().Timestamp().Logger()}
}
