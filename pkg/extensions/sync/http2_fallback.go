//go:build sync

package sync

import (
	cryptotls "crypto/tls"
	"crypto/x509"
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

	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	t.markHostStuck(host)

	t.log.Warn().Str("method", req.Method).Str("url", req.URL.String()).
		Err(err).Msg("HTTP/2 framing error from upstream, retrying with HTTP/1.1")

	if req.Body != nil && req.Body != http.NoBody {
		// A real body with no GetBody can't be rewound; the primary may have consumed it,
		// so retrying would send a truncated payload. Return the primary error instead.
		if req.GetBody == nil {
			return nil, err
		}

		body, bodyErr := req.GetBody()
		if bodyErr != nil {
			return nil, err
		}

		fallbackReq := req.Clone(req.Context())
		fallbackReq.Body = body
		fallbackReq.GetBody = req.GetBody

		return t.fallback.RoundTrip(fallbackReq)
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

func clonedTransport(opts syncconf.RegistryConfig) *http.Transport {
	// Configure transport with timeouts to prevent indefinite hangs.
	// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
	// Clone DefaultTransport to preserve proxy/TLS settings and existing timeouts
	// (DialContext: 30s, TLSHandshakeTimeout: 10s).
	// regclient uses DefaultTransport internally if no custom transport is provided, so this ensures compatibility.
	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert

	// ResponseHeaderTimeout: prevents hanging when server connects but doesn't send headers.
	// Set programmatically in root.go. This timeout applies only to waiting for response headers
	// after the request is sent. It does NOT include DialContext (30s) or TLSHandshakeTimeout (10s),
	// which are separate component timeouts. Doesn't cover body transfer time, which is expected
	// to be slow for large images.
	transport.ResponseHeaderTimeout = opts.ResponseHeaderTimeout

	configureTransportTLS(transport, opts)

	return transport
}

func configureTransportTLS(transport *http.Transport, opts syncconf.RegistryConfig) {
	tlsConfig := &cryptotls.Config{}
	needsTLSConfig := false

	if opts.TLSVerify != nil && !*opts.TLSVerify {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // this is an explicit sync configuration option
		needsTLSConfig = true
	}

	if opts.CertDir == "" {
		if needsTLSConfig {
			transport.TLSClientConfig = tlsConfig
		}

		return
	}

	clientCert, clientKey, regCert, err := getCertificates(opts.CertDir)
	if err != nil {
		// Keep the transport usable; the sync path will surface the failure if
		// the cert files are actually required.
		if needsTLSConfig {
			transport.TLSClientConfig = tlsConfig
		}

		return
	}

	if regCert != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(regCert)) {
			tlsConfig.RootCAs = pool
			needsTLSConfig = true
		}
	}

	if clientCert != "" && clientKey != "" {
		cert, err := cryptotls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err == nil {
			tlsConfig.Certificates = []cryptotls.Certificate{cert}
			needsTLSConfig = true
		}
	}

	if needsTLSConfig {
		transport.TLSClientConfig = tlsConfig
	}
}

// newHTTP2FallbackTransport builds a RoundTripper that prefers HTTP/2 for upstream sync
// and falls back to HTTP/1.1 on the framing errors enumerated in isHTTP2FramingError.
// Both transports share the same timeout configuration; the fallback only differs by
// disabling HTTP/2 negotiation, so an upstream that breaks HTTP/2 can still be reached.
func newHTTP2FallbackTransport(opts syncconf.RegistryConfig, logger log.Logger) http.RoundTripper {
	primaryTransport := clonedTransport(opts)

	if err := http2.ConfigureTransport(primaryTransport); err != nil {
		logger.Warn().Err(err).
			Msg("failed to configure http2 on sync transport, framing-error fallback may be limited to substring detection")
	}

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
