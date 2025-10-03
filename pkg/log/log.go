package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"zotregistry.dev/zot/errors"
)

const (
	defaultPerms         = 0o0600
	messageKey           = "message"
	callerSkipFrameCount = 5
)

// Logger extends slog's Logger with zerolog-compatible API.
type Logger struct {
	*slog.Logger
}

// Event represents a log event, mimicking zerolog.Event.
type Event struct {
	logger  *Logger
	level   slog.Level
	attrs   []slog.Attr
	isPanic bool
}

// Info returns an event for info level logging.
func (l Logger) Info() *Event {
	return &Event{logger: &l, level: slog.LevelInfo, attrs: []slog.Attr{}}
}

// Debug returns an event for debug level logging.
func (l Logger) Debug() *Event {
	return &Event{logger: &l, level: slog.LevelDebug, attrs: []slog.Attr{}}
}

// Error returns an event for error level logging.
func (l Logger) Error() *Event {
	return &Event{logger: &l, level: slog.LevelError, attrs: []slog.Attr{}}
}

// Warn returns an event for warn level logging.
func (l Logger) Warn() *Event {
	return &Event{logger: &l, level: slog.LevelWarn, attrs: []slog.Attr{}}
}

// Panic returns an event for panic level logging (maps to error + panic).
func (l Logger) Panic() *Event {
	return &Event{logger: &l, level: slog.LevelError, attrs: []slog.Attr{}, isPanic: true}
}

// Fatal returns an event for fatal level logging (maps to error + panic).
func (l Logger) Fatal() *Event {
	return &Event{logger: &l, level: slog.LevelError, attrs: []slog.Attr{}, isPanic: true}
}

// Err logs an error directly on the logger (convenience method).
func (l Logger) Err(err error) *Event {
	event := l.Error()
	if err != nil {
		event.attrs = append(event.attrs, slog.String("error", err.Error()))
	}

	return event
}

// With returns a logger with additional context.
func (l Logger) With() *Event {
	return &Event{logger: &l, level: slog.LevelInfo, attrs: []slog.Attr{}}
}

// Logger returns the logger from an event (for method chaining).
func (e *Event) Logger() Logger {
	// Create a new logger with the accumulated attributes
	handler := e.logger.Handler()
	if len(e.attrs) > 0 {
		handler = handler.WithAttrs(e.attrs)
	}

	return Logger{Logger: slog.New(handler)}
}

// Str adds a string field to the event.
func (e *Event) Str(key, val string) *Event {
	e.attrs = append(e.attrs, slog.String(key, val))

	return e
}

// Int adds an int field to the event.
func (e *Event) Int(key string, val int) *Event {
	e.attrs = append(e.attrs, slog.Int(key, val))

	return e
}

// Int64 adds an int64 field to the event.
func (e *Event) Int64(key string, val int64) *Event {
	e.attrs = append(e.attrs, slog.Int64(key, val))

	return e
}

// Uint64 adds a uint64 field to the event.
func (e *Event) Uint64(key string, val uint64) *Event {
	e.attrs = append(e.attrs, slog.Uint64(key, val))

	return e
}

// Bool adds a bool field to the event.
func (e *Event) Bool(key string, val bool) *Event {
	e.attrs = append(e.attrs, slog.Bool(key, val))

	return e
}

// Err adds an error field to the event.
func (e *Event) Err(err error) *Event {
	if err != nil {
		e.attrs = append(e.attrs, slog.String("error", err.Error()))
	}

	return e
}

// Interface adds any interface field to the event.
func (e *Event) Interface(key string, val interface{}) *Event {
	e.attrs = append(e.attrs, slog.Any(key, val))

	return e
}

// Any adds any interface field to the event (alias for Interface).
func (e *Event) Any(key string, val interface{}) *Event {
	return e.Interface(key, val)
}

// Strs adds a slice of strings field to the event.
func (e *Event) Strs(key string, vals []string) *Event {
	e.attrs = append(e.attrs, slog.Any(key, vals))

	return e
}

// IPAddr adds an IP address field to the event.
func (e *Event) IPAddr(key string, ip interface{}) *Event {
	e.attrs = append(e.attrs, slog.String(key, fmt.Sprintf("%v", ip)))

	return e
}

// RawJSON adds a raw JSON field to the event.
func (e *Event) RawJSON(key string, data []byte) *Event {
	e.attrs = append(e.attrs, slog.String(key, string(data)))

	return e
}

// Dur adds a duration field to the event.
func (e *Event) Dur(key string, d time.Duration) *Event {
	e.attrs = append(e.attrs, slog.Duration(key, d))

	return e
}

// NewTestLogger creates a logger for testing purposes (replaces zerolog.New(os.Stdout)).
func NewTestLogger() Logger {
	return NewLogger("debug", "")
}

// NewTestLoggerPtr creates a pointer to a logger for testing purposes.
func NewTestLoggerPtr() *Logger {
	logger := NewLogger("debug", "")

	return &logger
}

// Msgf logs the event with a formatted message.
func (e *Event) Msgf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	e.logger.LogAttrs(nil, e.level, msg, e.attrs...)

	if e.isPanic {
		panic(msg)
	}
}

// Msg logs the event with a simple message.
func (e *Event) Msg(msg string) {
	e.logger.LogAttrs(nil, e.level, msg, e.attrs...)

	if e.isPanic {
		panic(msg)
	}
}

// parseLevel converts string level to slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, errors.ErrBadConfig
	}
}

func NewLogger(level, output string) Logger {
	// Determine output writer
	var writer io.Writer
	if output == "" {
		writer = os.Stdout
	} else {
		file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, defaultPerms)
		if err != nil {
			panic(err)
		}
		writer = file
	}

	return NewLoggerWithWriter(level, writer)
}

func NewAuditLogger(level, output string) *Logger {
	// Parse log level
	lvl, err := parseLevel(level)
	if err != nil {
		panic(err)
	}

	// Determine output writer
	var writer io.Writer
	if output == "" {
		writer = os.Stdout
	} else {
		auditFile, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, defaultPerms)
		if err != nil {
			panic(err)
		}
		writer = auditFile
	}

	logger := slog.New(defaultJSONHandler(lvl, writer))

	return &Logger{Logger: logger}
}

func defaultJSONHandler(lvl slog.Leveler, writer io.Writer) *slog.JSONHandler {
	// Create JSON handler with RFC3339Nano time format
	opts := &slog.HandlerOptions{
		Level: lvl,
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			// Format timestamp as RFC3339Nano to match zerolog
			if attr.Key == slog.TimeKey {
				return slog.String("time", attr.Value.Time().Format(time.RFC3339Nano))
			}
			// Rename the level field to match zerolog
			if attr.Key == slog.LevelKey {
				return slog.String("level", strings.ToLower(attr.Value.String()))
			}
			// Rename "msg" to "message" to match zerolog
			if attr.Key == slog.MessageKey {
				attr.Key = messageKey
			}

			return attr
		},
	}

	handler := slog.NewJSONHandler(writer, opts)

	return handler
}

func NewLoggerWithWriter(level string, writer io.Writer) Logger {
	// Parse log level
	lvl, err := parseLevel(level)
	if err != nil {
		panic(err)
	}

	// Add caller info handler wrapper
	callerHandler := &CallerHandler{handler: defaultJSONHandler(lvl, writer)}

	// Add goroutine hook handler wrapper
	goroutineHandler := &GoroutineHandler{handler: callerHandler}

	logger := slog.New(goroutineHandler)

	return Logger{Logger: logger}
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

// CallerHandler adds caller information to log records.
type CallerHandler struct {
	handler slog.Handler
}

func (h *CallerHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *CallerHandler) Handle(ctx context.Context, record slog.Record) error {
	// Add caller information
	if pc, file, line, ok := runtime.Caller(callerSkipFrameCount); ok { // Adjust stack depth as needed
		frame := runtime.CallersFrames([]uintptr{pc})
		f, _ := frame.Next()

		record.Add("caller", fmt.Sprintf("%s:%d", file, line))

		if f.Function != "" {
			record.Add("func", f.Function)
		}
	}

	return h.handler.Handle(ctx, record)
}

func (h *CallerHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &CallerHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *CallerHandler) WithGroup(name string) slog.Handler {
	return &CallerHandler{handler: h.handler.WithGroup(name)}
}

// GoroutineHandler adds goroutine ID to log records.
type GoroutineHandler struct {
	handler slog.Handler
}

func (h *GoroutineHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *GoroutineHandler) Handle(ctx context.Context, record slog.Record) error {
	// Add goroutine ID
	record.Add("goroutine", GoroutineID())

	return h.handler.Handle(ctx, record)
}

func (h *GoroutineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &GoroutineHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *GoroutineHandler) WithGroup(name string) slog.Handler {
	return &GoroutineHandler{handler: h.handler.WithGroup(name)}
}
