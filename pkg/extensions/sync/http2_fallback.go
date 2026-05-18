//go:build sync

package sync

import (
	cryptotls "crypto/tls"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/net/http2"

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
	var streamErr http2.StreamError
	if errors.As(err, &streamErr) {
		return true
	}

	var goAwayErr *http2.GoAwayError
	if errors.As(err, &goAwayErr) {
		return true
	}

	// The "malformed HTTP response" case is produced by net/http when an HTTP/1.1 connection
	// receives raw HTTP/2 SETTINGS frames. Go's stdlib does not expose a typed error for this
	// path (see https://github.com/golang/go/issues/40926), so we keep a substring match.
	return strings.Contains(err.Error(), "malformed HTTP response")
}

// clonedTransport returns a clone of http.DefaultTransport with the registry-specific
// ResponseHeaderTimeout applied. The timeout reflects how long a single sync request will
// wait for the upstream registry to start streaming a response and matches the rationale
// in https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/.
func clonedTransport(opts syncconf.RegistryConfig) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
	transport.ResponseHeaderTimeout = opts.ResponseHeaderTimeout

	return transport
}

// newHTTP2FallbackTransport builds a RoundTripper that prefers HTTP/2 for upstream sync
// and falls back to HTTP/1.1 on the framing errors enumerated in isHTTP2FramingError.
// Both transports share the same timeout configuration; the fallback only differs by
// disabling HTTP/2 negotiation, so an upstream that breaks HTTP/2 can still be reached.
func newHTTP2FallbackTransport(opts syncconf.RegistryConfig, logger log.Logger) http.RoundTripper {
	primaryTransport := clonedTransport(opts)

	fallbackTransport := clonedTransport(opts)
	fallbackTransport.TLSNextProto = make(map[string]func(string, *cryptotls.Conn) http.RoundTripper)
	fallbackTransport.ForceAttemptHTTP2 = false

	return &http2FallbackTransport{
		primary:  primaryTransport,
		fallback: fallbackTransport,
		log:      logger,
	}
}
