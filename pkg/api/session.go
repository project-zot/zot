package api

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/didip/tollbooth/v6"
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
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
		w.status = http.StatusOK
	}

	n, err := w.ResponseWriter.Write(b)
	w.length += n

	return n, err
}

// RateLimiter limits handling of incoming requests.
func RateLimiter(ctlr *Controller, rate int) mux.MiddlewareFunc {
	ctlr.Log.Info().Int("rate", rate).Msg("ratelimiter enabled")

	limiter := tollbooth.NewLimiter(float64(rate), nil)
	limiter.SetMessage(http.StatusText(http.StatusTooManyRequests)).
		SetStatusCode(http.StatusTooManyRequests).
		SetOnLimitReached(nil)

	return func(next http.Handler) http.Handler {
		return tollbooth.LimitHandler(limiter, next)
	}
}

// MethodRateLimiter limits handling of incoming requests.
func MethodRateLimiter(ctlr *Controller, method string, rate int) mux.MiddlewareFunc {
	ctlr.Log.Info().Str("method", method).Int("rate", rate).Msg("per-method ratelimiter enabled")

	limiter := tollbooth.NewLimiter(float64(rate), nil)
	limiter.SetMethods([]string{method}).
		SetMessage(http.StatusText(http.StatusTooManyRequests)).
		SetStatusCode(http.StatusTooManyRequests).
		SetOnLimitReached(nil)

	return func(next http.Handler) http.Handler {
		return tollbooth.LimitHandler(limiter, next)
	}
}

// SessionLogger logs session details.
func SessionLogger(ctlr *Controller) mux.MiddlewareFunc {
	logger := ctlr.Log.With().Str("module", "http").Logger()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// Start timer
			start := time.Now()
			path := request.URL.Path
			raw := request.URL.RawQuery

			stwr := statusWriter{ResponseWriter: response}

			// Process request
			next.ServeHTTP(&stwr, request)

			// Stop timer
			end := time.Now()
			latency := end.Sub(start)
			latency = latency.Truncate(time.Second)

			clientIP := request.RemoteAddr
			method := request.Method
			headers := map[string][]string{}
			log := logger.Info()
			for key, value := range request.Header {
				if key == "Authorization" { // anonymize from logs
					s := strings.SplitN(value[0], " ", 2) //nolint:gomnd
					if len(s) == 2 && strings.EqualFold(s[0], "basic") {
						b, err := base64.StdEncoding.DecodeString(s[1])
						if err == nil {
							pair := strings.SplitN(string(b), ":", 2) //nolint:gomnd
							//nolint:gomnd
							if len(pair) == 2 {
								log = log.Str("username", pair[0])
							}
						}
					}
					value = []string{"******"}
				}
				headers[key] = value
			}
			statusCode := stwr.status
			bodySize := stwr.length
			if raw != "" {
				path = path + "?" + raw
			}

			if path != "/metrics" {
				// In order to test metrics feture,the instrumentation related to node exporter
				// should be handled by node exporter itself (ex: latency)
				monitoring.IncHTTPConnRequests(ctlr.Metrics, method, strconv.Itoa(statusCode))
				monitoring.ObserveHTTPRepoLatency(ctlr.Metrics, path, latency)     // summary
				monitoring.ObserveHTTPMethodLatency(ctlr.Metrics, method, latency) // histogram
			}

			log.Str("component", "session").
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

func SessionAuditLogger(audit *log.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			path := request.URL.Path
			raw := request.URL.RawQuery

			statusWr := statusWriter{ResponseWriter: response}

			// Process request
			next.ServeHTTP(&statusWr, request)

			clientIP := request.RemoteAddr
			method := request.Method
			username := ""

			for key, value := range request.Header {
				if key == "Authorization" { // anonymize from logs
					s := strings.SplitN(value[0], " ", 2) //nolint:gomnd
					if len(s) == 2 && strings.EqualFold(s[0], "basic") {
						b, err := base64.StdEncoding.DecodeString(s[1])
						if err == nil {
							pair := strings.SplitN(string(b), ":", 2) //nolint:gomnd
							if len(pair) == 2 {                       //nolint:gomnd
								username = pair[0]
							}
						}
					}
				}
			}

			statusCode := statusWr.status
			if raw != "" {
				path = path + "?" + raw
			}

			if (method == http.MethodPost || method == http.MethodPut ||
				method == http.MethodPatch || method == http.MethodDelete) &&
				(statusCode == http.StatusOK || statusCode == http.StatusCreated || statusCode == http.StatusAccepted) {
				audit.Info().
					Str("component", "session").
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
