//go:build sync

package sync

import (
	cryptotls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"golang.org/x/net/http2"

	zerr "zotregistry.dev/zot/v2/errors"
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
		// CompareAndDelete, not Delete: don't clobber a fresh entry a concurrent
		// markHostStuck may have stored between our Load and here.
		t.stickyHost.CompareAndDelete(host, expiresAt)

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

	// value, not pointer: x/net's transport emits GoAwayError as a value.
	var goAwayErr http2.GoAwayError
	if errors.As(err, &goAwayErr) {
		return true
	}

	// The "malformed HTTP response" case is produced by net/http when an HTTP/1.1 connection
	// receives raw HTTP/2 SETTINGS frames. net/http returns an unexported badStringError for
	// this path rather than a typed error, so a substring match is the only option.
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

	return transport
}

// fallbackTLSConfig mirrors the per-host TLS settings regclient injects into a plain
// *http.Transport (internal/reghttp): root CAs collected from <dir>/<host>/*.crt under
// the sync cert dir and /etc/docker/certs.d, the registry CA and client cert pair from
// the flat cert dir, and InsecureSkipVerify when TLS verification is disabled. regclient
// skips that injection when the configured transport is not a *http.Transport, so the
// HTTP/2 fallback wrapper has to carry the TLS material itself. Failures are logged and
// skipped rather than fatal, matching regclient's behavior for the same conditions.
// The material is also built for plain-http upstreams (TLSDisabled), matching regclient:
// it is used when an http upstream redirects to an https endpoint.
func fallbackTLSConfig(tlsMode config.TLSConf, hosts []string, certDir string, logger log.Logger) *cryptotls.Config {
	tlsConf := &cryptotls.Config{MinVersion: cryptotls.VersionTLS12}

	clientCert, clientKey, regCert, err := getCertificates(certDir)
	if err != nil {
		logger.Warn().Err(err).Str("certDir", certDir).Msg("failed to read certificates for sync transport")
	}

	if tlsMode == config.TLSInsecure {
		tlsConf.InsecureSkipVerify = true //nolint:gosec // explicitly requested via tlsVerify=false
	} else if pool, err := syncRootCAPool(hosts, certDir, regCert, logger); err != nil {
		logger.Warn().Err(err).Msg("failed to setup CA pool for sync transport")
	} else {
		tlsConf.RootCAs = pool
	}

	if clientCert != "" && clientKey != "" {
		cert, err := cryptotls.X509KeyPair([]byte(clientCert), []byte(clientKey))
		if err != nil {
			logger.Warn().Err(err).Msg("failed to configure client certs for sync transport")
		} else {
			tlsConf.Certificates = []cryptotls.Certificate{cert}
		}
	}

	return tlsConf
}

// syncRootCAPool builds the root CA pool the same way regclient's makeRootPool does:
// system roots, then <dir>/<host>/*.crt for every configured host under both the sync
// cert dir and the docker certs dir, then the registry CA from the flat cert dir.
// An unreadable or unparseable host cert only loses that cert (logged), so one bad file
// cannot drop the CA material of every other host of the registry.
func syncRootCAPool(hosts []string, certDir string, regCert string, logger log.Logger) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	dirs := []string{}
	if certDir != "" {
		dirs = append(dirs, certDir)
	}

	dirs = append(dirs, regclient.DockerCertDir)

	for _, dir := range dirs {
		for _, host := range hosts {
			hostDir := filepath.Join(dir, host)

			files, err := os.ReadDir(hostDir)
			if err != nil {
				if !os.IsNotExist(err) {
					logger.Warn().Err(err).Str("dir", hostDir).Msg("failed to read sync cert dir")
				}

				continue
			}

			for _, file := range files {
				if file.IsDir() || !strings.HasSuffix(file.Name(), ".crt") {
					continue
				}

				certPath := filepath.Join(hostDir, file.Name())

				cert, err := os.ReadFile(certPath) //nolint:gosec // path from user-configured cert dir
				if err != nil {
					logger.Warn().Err(err).Str("cert", certPath).Msg("failed to read sync CA cert")

					continue
				}

				if ok := pool.AppendCertsFromPEM(cert); !ok {
					logger.Warn().Str("cert", certPath).Msg("failed to parse sync CA cert")
				}
			}
		}
	}

	if regCert != "" {
		if ok := pool.AppendCertsFromPEM([]byte(regCert)); !ok {
			return nil, fmt.Errorf("%w: cert dir %s", zerr.ErrBadCACert, certDir)
		}
	}

	return pool, nil
}

// newHTTP2FallbackTransport builds a RoundTripper that prefers HTTP/2 for upstream sync
// and falls back to HTTP/1.1 on the framing errors enumerated in isHTTP2FramingError.
// Both transports share the same timeout and TLS configuration; the fallback only differs
// by disabling HTTP/2 negotiation, so an upstream that breaks HTTP/2 can still be reached.
func newHTTP2FallbackTransport(opts syncconf.RegistryConfig, tlsConf *cryptotls.Config,
	logger log.Logger,
) http.RoundTripper {
	primaryTransport := clonedTransport(opts)
	if tlsConf != nil {
		primaryTransport.TLSClientConfig = tlsConf.Clone()
	}

	if err := http2.ConfigureTransport(primaryTransport); err != nil {
		logger.Warn().Err(err).
			Msg("failed to configure http2 on sync transport, framing-error fallback may be limited to substring detection")
	}

	fallbackTransport := clonedTransport(opts)
	if tlsConf != nil {
		fallbackTransport.TLSClientConfig = tlsConf.Clone()
	}

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
