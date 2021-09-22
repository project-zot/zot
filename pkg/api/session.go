package api

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anuvu/zot/pkg/extensions/monitoring"
	"github.com/anuvu/zot/pkg/log"
	"github.com/gorilla/mux"
)

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
func SessionLogger(log log.Logger) mux.MiddlewareFunc {
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

			monitoring.IncHttpConnRequests(method, strconv.Itoa(statusCode))
			monitoring.ObserveHttpRepoLatency(path, latency) // summary
			monitoring.ObserveHttpMethodLatency(method, latency) // histogram

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

func SessionAuditLogger(audit *log.Logger) mux.MiddlewareFunc {
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
