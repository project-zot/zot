//go:build sync

package sync

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/net/http2"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

var (
	errMalformedHTTP = errors.New("malformed HTTP response \"\\x00\\x00\\x12\\x04\"")
	errConnRefused   = errors.New("connection refused")
	errCtxCanceled   = errors.New("context canceled")
	errDialRefused   = errors.New("dial tcp: connection refused")
	errRewindFailed  = errors.New("rewind failed")
)

// newTestFallbackTransport builds an http2FallbackTransport configured with deterministic
// time and a 1-minute sticky window. Tests advance time via the returned *time.Time.
func newTestFallbackTransport(primary, fallback http.RoundTripper) (*http2FallbackTransport, *time.Time) {
	now := time.Unix(1700000000, 0)
	clock := &now

	transport := &http2FallbackTransport{
		primary:   primary,
		fallback:  fallback,
		log:       log.NewLogger("debug", ""),
		stickyTTL: time.Minute,
		now:       func() time.Time { return *clock },
	}

	return transport, clock
}

func TestIsHTTP2FramingError(t *testing.T) {
	Convey("isHTTP2FramingError classification", t, func() {
		Convey("http2.StreamError returns true", func() {
			err := http2.StreamError{StreamID: 1, Code: http2.ErrCodeInternal}
			So(isHTTP2FramingError(err), ShouldBeTrue)
		})

		Convey("wrapped http2.StreamError returns true", func() {
			err := fmt.Errorf("transport failure: %w", http2.StreamError{
				StreamID: 1, Code: http2.ErrCodeProtocol,
			})
			So(isHTTP2FramingError(err), ShouldBeTrue)
		})

		Convey("http2.GoAwayError returns true", func() {
			err := &http2.GoAwayError{ErrCode: http2.ErrCodeInternal, DebugData: "shutdown"}
			So(isHTTP2FramingError(err), ShouldBeTrue)
		})

		Convey("malformed HTTP response substring returns true", func() {
			So(isHTTP2FramingError(errMalformedHTTP), ShouldBeTrue)
		})

		Convey("unrelated error returns false", func() {
			So(isHTTP2FramingError(errConnRefused), ShouldBeFalse)
			So(isHTTP2FramingError(errCtxCanceled), ShouldBeFalse)
		})
	})
}

type stubRoundTripper struct {
	resp *http.Response
	err  error
	hits int
}

func (s *stubRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	s.hits++

	return s.resp, s.err
}

func newOKResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func writeTestCACert(t *testing.T, dir string) []byte {
	t.Helper()

	caCertPEM, _, err := tlsutils.GenerateCACert(&tlsutils.CertificateOptions{
		CommonName: "test-ca",
		NotAfter:   time.Now().AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("failed to generate CA cert: %v", err)
	}

	err = os.WriteFile(filepath.Join(dir, "ca.crt"), caCertPEM, 0o600)
	if err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	return caCertPEM
}

func certPoolSubjects(pool *x509.CertPool) []string {
	if pool == nil {
		return nil
	}

	subjects := make([]string, 0, len(pool.Subjects()))
	for _, subject := range pool.Subjects() {
		subjects = append(subjects, string(subject))
	}

	return subjects
}

func TestHTTP2FallbackTransportRoundTrip(t *testing.T) {
	Convey("RoundTrip behavior", t, func() {
		Convey("primary success short-circuits fallback", func() {
			primary := &stubRoundTripper{resp: newOKResponse("primary")}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer primary.resp.Body.Close()
			defer fallback.resp.Body.Close()

			transport, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			resp, err := transport.RoundTrip(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 0)
		})

		Convey("framing error triggers fallback", func() {
			primary := &stubRoundTripper{err: http2.StreamError{
				StreamID: 1, Code: http2.ErrCodeInternal,
			}}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer fallback.resp.Body.Close()

			transport, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			resp, err := transport.RoundTrip(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 1)
		})

		Convey("non-framing error is returned without fallback", func() {
			primary := &stubRoundTripper{err: errDialRefused}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer fallback.resp.Body.Close()

			transport, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			resp, err := transport.RoundTrip(req)
			So(err, ShouldEqual, errDialRefused)
			So(resp, ShouldBeNil)
			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 0)
		})

		Convey("request body is rewound before fallback", func() {
			primary := &stubRoundTripper{err: http2.StreamError{
				StreamID: 1, Code: http2.ErrCodeProtocol,
			}}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer fallback.resp.Body.Close()

			transport, _ := newTestFallbackTransport(primary, fallback)

			payload := []byte(`{"hello":"world"}`)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				"https://example.test/v2/", bytes.NewReader(payload))
			So(err, ShouldBeNil)
			So(req.GetBody, ShouldNotBeNil)

			originalGetBody := req.GetBody
			var getBodyCalls int
			req.GetBody = func() (io.ReadCloser, error) {
				getBodyCalls++

				return originalGetBody()
			}

			// Drain the body to simulate primary having consumed it before failing.
			drained, err := io.ReadAll(req.Body)
			So(err, ShouldBeNil)
			So(drained, ShouldResemble, payload)

			resp, err := transport.RoundTrip(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(getBodyCalls, ShouldEqual, 1)
		})

		Convey("body rewind failure surfaces original error", func() {
			primaryErr := http2.StreamError{StreamID: 1, Code: http2.ErrCodeInternal}
			primary := &stubRoundTripper{err: primaryErr}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer fallback.resp.Body.Close()

			transport, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
				"https://example.test/v2/", strings.NewReader("payload"))
			So(err, ShouldBeNil)

			req.GetBody = func() (io.ReadCloser, error) { return nil, errRewindFailed }

			resp, err := transport.RoundTrip(req)
			So(resp, ShouldBeNil)
			So(errors.Is(err, primaryErr), ShouldBeTrue)
			So(fallback.hits, ShouldEqual, 0)
		})
	})
}

func TestHTTP2FallbackRealTransport(t *testing.T) {
	Convey("Real HTTP/2 transport boundary", t, func() {
		var h2Hits, h1Hits int32

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor == 2 {
				atomic.AddInt32(&h2Hits, 1)
				panic(http.ErrAbortHandler)
			}

			atomic.AddInt32(&h1Hits, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		server.EnableHTTP2 = true
		server.StartTLS()
		defer server.Close()

		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		tlsConf := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

		newPrimary := func() *http.Transport {
			transport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
			transport.TLSClientConfig = tlsConf.Clone()
			So(http2.ConfigureTransport(transport), ShouldBeNil)

			return transport
		}

		Convey("ConfigureTransport'd primary surfaces a typed http2 framing error", func() {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				server.URL+"/v2/", http.NoBody)
			So(err, ShouldBeNil)

			_, err = newPrimary().RoundTrip(req)
			So(err, ShouldNotBeNil)
			So(isHTTP2FramingError(err), ShouldBeTrue)

			var streamErr http2.StreamError

			var goAwayErr *http2.GoAwayError

			So(errors.As(err, &streamErr) || errors.As(err, &goAwayErr), ShouldBeTrue)
			So(atomic.LoadInt32(&h2Hits), ShouldEqual, 1)
		})

		Convey("fallback transport retries the framing error over HTTP/1.1", func() {
			fallback := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
			fallback.TLSClientConfig = tlsConf.Clone()
			fallback.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
			fallback.ForceAttemptHTTP2 = false

			transport, _ := newTestFallbackTransport(newPrimary(), fallback)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				server.URL+"/v2/", http.NoBody)
			So(err, ShouldBeNil)

			resp, err := transport.RoundTrip(req)
			So(err, ShouldBeNil)

			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.ProtoMajor, ShouldEqual, 1)

			body, err := io.ReadAll(resp.Body)
			So(err, ShouldBeNil)
			So(string(body), ShouldEqual, "ok")

			So(transport.hostStuckOnFallback(req.URL.Host), ShouldBeTrue)
			So(atomic.LoadInt32(&h2Hits), ShouldEqual, 1)
			So(atomic.LoadInt32(&h1Hits), ShouldEqual, 1)
		})
	})
}

func TestHTTP2FallbackStickyPerHost(t *testing.T) {
	Convey("Sticky per-host fallback", t, func() {
		Convey("after a framing error the same host skips the primary", func() {
			primary := &stubRoundTripper{err: http2.StreamError{
				StreamID: 1, Code: http2.ErrCodeInternal,
			}}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer fallback.resp.Body.Close()

			transport, _ := newTestFallbackTransport(primary, fallback)

			for range 3 {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
					"https://example.test/v2/", http.NoBody)
				So(err, ShouldBeNil)

				resp, err := transport.RoundTrip(req)
				So(err, ShouldBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)
			}

			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 3)
		})

		Convey("different hosts have independent sticky state", func() {
			primary := &stubRoundTripper{err: http2.StreamError{
				StreamID: 1, Code: http2.ErrCodeProtocol,
			}}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer fallback.resp.Body.Close()

			transport, _ := newTestFallbackTransport(primary, fallback)

			for _, host := range []string{"a.test", "b.test"} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
					"https://"+host+"/v2/", http.NoBody)
				So(err, ShouldBeNil)

				_, err = transport.RoundTrip(req)
				So(err, ShouldBeNil)
			}

			So(primary.hits, ShouldEqual, 2)
			So(fallback.hits, ShouldEqual, 2)
		})

		Convey("sticky entry expires after the TTL elapses", func() {
			primary := &stubRoundTripper{err: http2.StreamError{
				StreamID: 1, Code: http2.ErrCodeInternal,
			}}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			defer fallback.resp.Body.Close()

			transport, clock := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				"https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			_, err = transport.RoundTrip(req)
			So(err, ShouldBeNil)
			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 1)

			// Advance past stickyTTL — primary should be retried.
			*clock = clock.Add(2 * time.Minute)

			req, err = http.NewRequestWithContext(t.Context(), http.MethodGet,
				"https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			_, err = transport.RoundTrip(req)
			So(err, ShouldBeNil)
			So(primary.hits, ShouldEqual, 2)
			So(fallback.hits, ShouldEqual, 2)
		})
	})
}

func TestConfigureTransportTLSAppendsRootCAs(t *testing.T) {
	Convey("configureTransportTLS preserves existing roots", t, func() {
		tempDir := t.TempDir()
		newCAPEM := writeTestCACert(t, tempDir)

		existingCAPEM, _, err := tlsutils.GenerateCACert(&tlsutils.CertificateOptions{
			CommonName: "existing-ca",
			NotAfter:   time.Now().AddDate(1, 0, 0),
		})
		So(err, ShouldBeNil)

		existingPool := x509.NewCertPool()
		So(existingPool.AppendCertsFromPEM(existingCAPEM), ShouldBeTrue)

		transport := http.DefaultTransport.(*http.Transport).Clone() //nolint: forcetypeassert
		transport.TLSClientConfig = &tls.Config{RootCAs: existingPool}

		configureTransportTLS(transport, syncconf.RegistryConfig{CertDir: tempDir})

		So(transport.TLSClientConfig, ShouldNotBeNil)
		So(transport.TLSClientConfig.RootCAs, ShouldNotBeNil)
		So(len(transport.TLSClientConfig.RootCAs.Subjects()), ShouldEqual, 2)

		newPool := x509.NewCertPool()
		So(newPool.AppendCertsFromPEM(newCAPEM), ShouldBeTrue)
		subjects := certPoolSubjects(transport.TLSClientConfig.RootCAs)
		So(subjects, ShouldContain, string(existingPool.Subjects()[0]))
		So(subjects, ShouldContain, string(newPool.Subjects()[0]))
	})
}

func TestHostAwareTransportLoadsHostSpecificRootCAs(t *testing.T) {
	Convey("hostAwareTransport appends host specific cert-dir roots", t, func() {
		tempDir := t.TempDir()
		hostDir := filepath.Join(tempDir, "example.test")
		err := os.MkdirAll(hostDir, 0o755)
		So(err, ShouldBeNil)

		hostCAPEM := writeTestCACert(t, hostDir)

		transport := &hostAwareTransport{
			base:     http.DefaultTransport.(*http.Transport).Clone(), //nolint: forcetypeassert
			certDirs: []string{tempDir},
			log:      log.NewLogger("debug", ""),
		}

		hostTransport := transport.transportForHost("example.test")
		So(hostTransport.TLSClientConfig, ShouldNotBeNil)
		So(hostTransport.TLSClientConfig.RootCAs, ShouldNotBeNil)

		hostPool := x509.NewCertPool()
		So(hostPool.AppendCertsFromPEM(hostCAPEM), ShouldBeTrue)
		subjects := certPoolSubjects(hostTransport.TLSClientConfig.RootCAs)
		So(subjects, ShouldContain, string(hostPool.Subjects()[0]))

		otherTransport := transport.transportForHost("other.test")
		if otherTransport.TLSClientConfig != nil && otherTransport.TLSClientConfig.RootCAs != nil {
			So(certPoolSubjects(otherTransport.TLSClientConfig.RootCAs), ShouldNotContain, string(hostPool.Subjects()[0]))
		}
	})
}
