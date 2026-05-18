//go:build sync

package sync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/net/http2"

	"zotregistry.dev/zot/v2/pkg/log"
)

// newTestFallbackTransport builds an http2FallbackTransport configured with deterministic
// time and a 1-minute sticky window. Tests advance time via the returned *time.Time.
func newTestFallbackTransport(primary, fallback http.RoundTripper) (*http2FallbackTransport, *time.Time) {
	now := time.Unix(1700000000, 0)
	clock := &now

	tr := &http2FallbackTransport{
		primary:   primary,
		fallback:  fallback,
		log:       log.NewLogger("debug", ""),
		stickyTTL: time.Minute,
		now:       func() time.Time { return *clock },
	}

	return tr, clock
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
			err := errors.New("malformed HTTP response \"\\x00\\x00\\x12\\x04\"")
			So(isHTTP2FramingError(err), ShouldBeTrue)
		})

		Convey("unrelated error returns false", func() {
			So(isHTTP2FramingError(errors.New("connection refused")), ShouldBeFalse)
			So(isHTTP2FramingError(errors.New("context canceled")), ShouldBeFalse)
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

func TestHTTP2FallbackTransportRoundTrip(t *testing.T) {
	Convey("RoundTrip behavior", t, func() {
		Convey("primary success short-circuits fallback", func() {
			primary := &stubRoundTripper{resp: newOKResponse("primary")}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			tr, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequest(http.MethodGet, "https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			resp, err := tr.RoundTrip(req)
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

			tr, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequest(http.MethodGet, "https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			resp, err := tr.RoundTrip(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 1)
		})

		Convey("non-framing error is returned without fallback", func() {
			nonFraming := errors.New("dial tcp: connection refused")
			primary := &stubRoundTripper{err: nonFraming}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			tr, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequest(http.MethodGet, "https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			resp, err := tr.RoundTrip(req)
			So(err, ShouldEqual, nonFraming)
			So(resp, ShouldBeNil)
			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 0)
		})

		Convey("request body is rewound before fallback", func() {
			primary := &stubRoundTripper{err: http2.StreamError{
				StreamID: 1, Code: http2.ErrCodeProtocol,
			}}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			tr, _ := newTestFallbackTransport(primary, fallback)

			payload := []byte(`{"hello":"world"}`)
			req, err := http.NewRequest(http.MethodPost, "https://example.test/v2/",
				bytes.NewReader(payload))
			So(err, ShouldBeNil)
			So(req.GetBody, ShouldNotBeNil)

			// Drain the body to simulate primary having consumed it before failing.
			drained, err := io.ReadAll(req.Body)
			So(err, ShouldBeNil)
			So(drained, ShouldResemble, payload)

			resp, err := tr.RoundTrip(req)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			// After fallback, req.Body has been replaced with a fresh reader.
			refetched, err := io.ReadAll(req.Body)
			So(err, ShouldBeNil)
			So(refetched, ShouldResemble, payload)
		})

		Convey("body rewind failure surfaces original error", func() {
			primaryErr := http2.StreamError{StreamID: 1, Code: http2.ErrCodeInternal}
			primary := &stubRoundTripper{err: primaryErr}
			fallback := &stubRoundTripper{resp: newOKResponse("fallback")}

			tr, _ := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequest(http.MethodPost, "https://example.test/v2/",
				strings.NewReader("payload"))
			So(err, ShouldBeNil)

			rewindErr := errors.New("rewind failed")
			req.GetBody = func() (io.ReadCloser, error) { return nil, rewindErr }

			resp, err := tr.RoundTrip(req)
			So(resp, ShouldBeNil)
			So(errors.Is(err, primaryErr), ShouldBeTrue)
			So(fallback.hits, ShouldEqual, 0)
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

			tr, _ := newTestFallbackTransport(primary, fallback)

			for i := 0; i < 3; i++ {
				req, err := http.NewRequest(http.MethodGet, "https://example.test/v2/", http.NoBody)
				So(err, ShouldBeNil)

				resp, err := tr.RoundTrip(req)
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

			tr, _ := newTestFallbackTransport(primary, fallback)

			for _, host := range []string{"a.test", "b.test"} {
				req, err := http.NewRequest(http.MethodGet, "https://"+host+"/v2/", http.NoBody)
				So(err, ShouldBeNil)

				_, err = tr.RoundTrip(req)
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

			tr, clock := newTestFallbackTransport(primary, fallback)

			req, err := http.NewRequest(http.MethodGet, "https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			_, err = tr.RoundTrip(req)
			So(err, ShouldBeNil)
			So(primary.hits, ShouldEqual, 1)
			So(fallback.hits, ShouldEqual, 1)

			// Advance past stickyTTL — primary should be retried.
			*clock = clock.Add(2 * time.Minute)

			req, err = http.NewRequest(http.MethodGet, "https://example.test/v2/", http.NoBody)
			So(err, ShouldBeNil)

			_, err = tr.RoundTrip(req)
			So(err, ShouldBeNil)
			So(primary.hits, ShouldEqual, 2)
			So(fallback.hits, ShouldEqual, 2)
		})
	})
}
