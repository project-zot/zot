package log

import (
	"encoding/base64"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
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

	return Logger{Logger: log.Hook(goroutineHook{}).With().Caller().Timestamp().Logger()}
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

type statusWriter struct {
	http.ResponseWriter
	status int
	length int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}

	n, err := w.ResponseWriter.Write(b)
	w.length += n

	return n, err
}

// SessionLogger logs session details.
func SessionLogger(log Logger) mux.MiddlewareFunc {
	l := log.With().Str("module", "http").Logger()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Start timer
			start := time.Now()
			path := r.URL.Path
			raw := r.URL.RawQuery

			sw := statusWriter{ResponseWriter: w}

			// Process request
			next.ServeHTTP(&sw, r)

			// Stop timer
			end := time.Now()
			latency := end.Sub(start)
			if latency > time.Minute {
				// Truncate in a golang < 1.8 safe way
				latency -= latency % time.Second
			}
			clientIP := r.RemoteAddr
			method := r.Method
			headers := map[string][]string{}
			username := ""
			log := l.Info()
			for key, value := range r.Header {
				if key == "Authorization" { // anonymize from logs
					s := strings.SplitN(value[0], " ", 2)
					if len(s) == 2 && strings.EqualFold(s[0], "basic") {
						b, err := base64.StdEncoding.DecodeString(s[1])
						if err == nil {
							pair := strings.SplitN(string(b), ":", 2)
							// nolint:gomnd
							if len(pair) == 2 {
								username = pair[0]
								log = log.Str("username", username)
							}
						}
					}
					value = []string{"******"}
				}
				headers[key] = value
			}
			statusCode := sw.status
			bodySize := sw.length
			if raw != "" {
				path = path + "?" + raw
			}

			log.Str("clientIP", clientIP).
				Str("method", method).
				Str("path", path).
				Int("statusCode", statusCode).
				Str("latency", latency.String()).
				Int("bodySize", bodySize).
				Interface("headers", headers).
				Msg("HTTP API")
		})
	}
}

func SessionAuditLogger(audit *Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			raw := r.URL.RawQuery

			sw := statusWriter{ResponseWriter: w}

			// Process request
			next.ServeHTTP(&sw, r)

			clientIP := r.RemoteAddr
			method := r.Method
			username := ""

			for key, value := range r.Header {
				if key == "Authorization" { // anonymize from logs
					s := strings.SplitN(value[0], " ", 2)
					if len(s) == 2 && strings.EqualFold(s[0], "basic") {
						b, err := base64.StdEncoding.DecodeString(s[1])
						if err == nil {
							pair := strings.SplitN(string(b), ":", 2)
							// nolint:gomnd
							if len(pair) == 2 {
								username = pair[0]
							}
						}
					}
				}
			}

			statusCode := sw.status
			if raw != "" {
				path = path + "?" + raw
			}

			if (method == http.MethodPost || method == http.MethodPut ||
				method == http.MethodPatch || method == http.MethodDelete) &&
				(statusCode == http.StatusOK || statusCode == http.StatusCreated || statusCode == http.StatusAccepted) {
				audit.Info().
					Str("clientIP", clientIP).
					Str("subject", username).
					Str("action", method).
					Str("object", path).
					Int("status", statusCode).
					Msg("HTTP API Audit")
			}
		})
	}
}

// goroutineID adds goroutine-id to logs to help debug concurrency issues.
func goroutineID() int {
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

func (h goroutineHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	if level != zerolog.NoLevel {
		e.Int("goroutine", goroutineID())
	}
}
