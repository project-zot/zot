package log

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

const defaultPerms = 0o0600

//nolint:gochecknoglobals
var loggerSetTimeFormat sync.Once

// Logger extends zerolog's Logger.
type Logger struct {
	zerolog.Logger
}

func (l Logger) Println(v ...interface{}) {
	l.Logger.Error().Msg("panic recovered") //nolint: check-logs
}

func NewLogger(level, output string) Logger {
	loggerSetTimeFormat.Do(func() {
		zerolog.TimeFieldFormat = time.RFC3339Nano
	})

	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		panic(err)
	}

	zerolog.SetGlobalLevel(lvl)

	var log zerolog.Logger

	if output == "" {
		log = zerolog.New(os.Stdout)
	} else {
		file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, defaultPerms)
		if err != nil {
			panic(err)
		}
		log = zerolog.New(file)
	}

	return Logger{Logger: log.Hook(goroutineHook{}).With().Caller().Timestamp().Logger()}
}

func NewAuditLogger(level, output string) *Logger {
	loggerSetTimeFormat.Do(func() {
		zerolog.TimeFieldFormat = time.RFC3339Nano
	})

	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		panic(err)
	}

	zerolog.SetGlobalLevel(lvl)

	var auditLog zerolog.Logger

	if output == "" {
		auditLog = zerolog.New(os.Stdout)
	} else {
		auditFile, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, defaultPerms)
		if err != nil {
			panic(err)
		}

		auditLog = zerolog.New(auditFile)
	}

	return &Logger{Logger: auditLog.With().Timestamp().Logger()}
}

// GoroutineID adds goroutine-id to logs to help debug concurrency issues.
func GoroutineID() int {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]

	id, err := strconv.Atoi(idField)
	if err != nil {
		return -1
	}

	return id
}

type goroutineHook struct{}

func (h goroutineHook) Run(e *zerolog.Event, level zerolog.Level, _ string) {
	if level != zerolog.NoLevel {
		e.Int("goroutine", GoroutineID())
	}
}
