//go:build sync

package sync

import (
	cryptotls "crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

// http2FallbackStickyTTL is how long a host stays on the HTTP/1.1 fallback after it has
// framed-errored once. Picked to ride out a single LB rollout without permanently giving
// up HTTP/2 for a host that may recover.
const http2FallbackStickyTTL = 15 * time.Minute

// http2FallbackTransport tries HTTP/2 first, falls back to HTTP/1.1 on framing errors.
// Docker Hub's LB occasionally sends raw HTTP/2 SETTINGS frames on connections that Go's
// net/http opened as HTTP/1.1, causing "malformed HTTP response" errors. This transport
// catches those errors at the RoundTrip level and retries transparently with HTTP/1.1,
// so regclient never sees the failure and never enters its backoff cycle.
//
// Once a host has framed-errored, the transport remembers that choice for
// http2FallbackStickyTTL and routes subsequent requests for that host straight to the
// fallback. After the TTL expires the host gets another HTTP/2 attempt, so a temporary
// upstream issue does not pin the host to HTTP/1.1 forever.
type http2FallbackTransport struct {
	primary    http.RoundTripper
	fallback   http.RoundTripper
	log        log.Logger
	stickyTTL  time.Duration
	now        func() time.Time
	stickyHost sync.Map // host string -> time.Time when entry expires
}

func (t *http2FallbackTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if t.hostStuckOnFallback(host) {
		return t.fallback.RoundTrip(req)
	}

	resp, err := t.primary.RoundTrip(req)
	if err == nil || !isHTTP2FramingError(err) {
		return resp, err
	}

	t.markHostStuck(host)

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

func (t *http2FallbackTransport) hostStuckOnFallback(host string) bool {
	raw, ok := t.stickyHost.Load(host)
	if !ok {
		return false
	}

	expiresAt, ok := raw.(time.Time)
	if !ok {
		return false
	}

	if !t.now().Before(expiresAt) {
		t.stickyHost.Delete(host)

		return false
	}

	return true
}

func (t *http2FallbackTransport) markHostStuck(host string) {
	t.stickyHost.Store(host, t.now().Add(t.stickyTTL))
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
		primary:   primaryTransport,
		fallback:  fallbackTransport,
		log:       logger,
		stickyTTL: http2FallbackStickyTTL,
		now:       time.Now,
	}
}
