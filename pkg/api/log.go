package api

import (
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

func NewLogger(config *Config) zerolog.Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	lvl, err := zerolog.ParseLevel(config.Log.Level)
	if err != nil {
		panic(err)
	}
	zerolog.SetGlobalLevel(lvl)
	var log zerolog.Logger
	if config.Log.Output == "" {
		log = zerolog.New(os.Stdout)
	} else {
		file, err := os.OpenFile(config.Log.Output, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		log = zerolog.New(file)
	}
	return log.With().Timestamp().Logger()
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

func Logger(log zerolog.Logger) mux.MiddlewareFunc {
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
			headers := r.Header
			statusCode := sw.status
			bodySize := sw.length
			if raw != "" {
				path = path + "?" + raw
			}

			l.Info().
				Str("clientIP", clientIP).
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
