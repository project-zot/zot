package api

import (
	"net/http"
	"time"

	"zotregistry.dev/zot/v2/pkg/log"
)

// rollingDeadlineWriter converts the server's WriteTimeout — which is an
// absolute deadline for the entire response — into a rolling per-write
// deadline. Multi-GB blob downloads can legitimately take much longer than
// the configured WriteTimeout, so without this every large blob response is
// cut off mid-stream with "write tcp ...: i/o timeout" once the absolute
// deadline expires. With a rolling deadline, a transfer that keeps making
// progress is never interrupted, while a stalled client is still disconnected
// after the configured timeout of write inactivity.
type rollingDeadlineWriter struct {
	http.ResponseWriter
	ctrl    *http.ResponseController
	timeout time.Duration
	// extendInterval rate-limits deadline extensions so that high-throughput
	// copies (32KB writes) do not update the connection deadline on every
	// call. It is kept well below the timeout so the deadline never expires
	// between the last extension and the next write (including the final
	// chunked-encoding terminator written after the handler returns).
	extendInterval time.Duration
	lastExtend     time.Time
}

func newRollingDeadlineWriter(writer http.ResponseWriter, timeout time.Duration, logger log.Logger) http.ResponseWriter {
	ctrl := http.NewResponseController(writer)

	// Probe deadline support up front. If the middleware wrapper chain or the
	// underlying connection does not expose SetWriteDeadline, the server-wide
	// absolute WriteTimeout stays in effect — make that visible instead of
	// silently degrading, because large blob downloads WILL be cut off.
	if err := ctrl.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		logger.Warn().Err(err).
			Msg("response writer does not support write deadline control;" +
				" large blob downloads may be cut off by the server WriteTimeout")

		return writer
	}

	return &rollingDeadlineWriter{
		ResponseWriter: writer,
		ctrl:           ctrl,
		timeout:        timeout,
		extendInterval: min(time.Second, timeout/2),
	}
}

func (w *rollingDeadlineWriter) Write(p []byte) (int, error) {
	if now := time.Now(); now.Sub(w.lastExtend) >= w.extendInterval {
		// Best effort: if the underlying connection does not support write
		// deadlines the server-wide timeout simply stays in effect.
		_ = w.ctrl.SetWriteDeadline(now.Add(w.timeout))
		w.lastExtend = now
	}

	return w.ResponseWriter.Write(p)
}

// Flush implements http.Flusher, which blob streaming relies on to push
// chunks to the client immediately.
func (w *rollingDeadlineWriter) Flush() {
	_ = w.ctrl.Flush()
}
