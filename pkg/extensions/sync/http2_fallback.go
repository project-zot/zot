//go:build sync

package sync

import (
	cryptotls "crypto/tls"
	"net/http"
	"strings"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

// http2FallbackTransport tries HTTP/2 first, falls back to HTTP/1.1 on framing errors.
// Docker Hub's LB occasionally sends raw HTTP/2 SETTINGS frames on connections that Go's
// net/http opened as HTTP/1.1, causing "malformed HTTP response" errors. This transport
// catches those errors at the RoundTrip level and retries transparently with HTTP/1.1,
// so regclient never sees the failure and never enters its backoff cycle.
type http2FallbackTransport struct {
	primary  http.RoundTripper
	fallback http.RoundTripper
	log      log.Logger
}

func (t *http2FallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.primary.RoundTrip(req)
	if err == nil || !isHTTP2FramingError(err) {
		return resp, err
	}

	t.log.Warn().Str("method", req.Method).Str("url", req.URL.String()).
		Err(err).Msg("HTTP/2 framing error from upstream, retrying with HTTP/1.1")

	if req.Body != nil && req.GetBody != nil {
		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, err
		}

		req.Body = body
	}

	return t.fallback.RoundTrip(req)
}

func isHTTP2FramingError(err error) bool {
	msg := err.Error()

	return strings.Contains(msg, "malformed HTTP response") ||
		strings.Contains(msg, "INTERNAL_ERROR") ||
		strings.Contains(msg, "stream error") ||
		strings.Contains(msg, "PROTOCOL_ERROR")
}

// newHTTP2FallbackTransport builds a RoundTripper that prefers HTTP/2 for upstream sync
// and falls back to HTTP/1.1 on the framing errors enumerated in isHTTP2FramingError.
// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/ for the
// timeout configuration rationale.
func newHTTP2FallbackTransport(opts syncconf.RegistryConfig, logger log.Logger) http.RoundTripper {
	primaryTransport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
	primaryTransport.ResponseHeaderTimeout = opts.ResponseHeaderTimeout

	fallbackTransport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
	fallbackTransport.TLSNextProto = make(map[string]func(string, *cryptotls.Conn) http.RoundTripper)
	fallbackTransport.ForceAttemptHTTP2 = false
	fallbackTransport.ResponseHeaderTimeout = opts.ResponseHeaderTimeout

	return &http2FallbackTransport{
		primary:  primaryTransport,
		fallback: fallbackTransport,
		log:      logger,
	}
}
