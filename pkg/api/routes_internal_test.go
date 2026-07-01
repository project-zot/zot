package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

var errTestTokenProxyRead = errors.New("test token proxy read error")

type errTokenProxyReadCloser struct{}

func (errTokenProxyReadCloser) Read(_ []byte) (int, error) {
	return 0, errTestTokenProxyRead
}

func (errTokenProxyReadCloser) Close() error {
	return nil
}

func TestParseRangeHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		size    int64
		want    []httpRange
		wantErr bool
	}{
		{
			name:   "open ended range",
			header: "bytes=0-",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "range end is capped to size",
			header: "bytes=0-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "suffix range",
			header: "bytes=-3",
			size:   10,
			want:   []httpRange{{start: 7, end: 9}},
		},
		{
			name:   "oversized suffix range returns whole blob",
			header: "bytes=-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "ranges are sorted",
			header: "bytes=7-8, 0-1",
			size:   10,
			want: []httpRange{
				{start: 0, end: 1},
				{start: 7, end: 8},
			},
		},
		{
			name:   "overlapping and adjacent ranges are coalesced",
			header: "bytes=0-2,3-4,6-8,7-9",
			size:   10,
			want: []httpRange{
				{start: 0, end: 4},
				{start: 6, end: 9},
			},
		},
		{name: "zero size", header: "bytes=0-", wantErr: true},
		{name: "wrong unit", header: "byte=0-1", size: 10, wantErr: true},
		{name: "empty range set", header: "bytes=", size: 10, wantErr: true},
		{name: "empty range spec", header: "bytes=0-1,", size: 10, wantErr: true},
		{name: "zero suffix", header: "bytes=-0", size: 10, wantErr: true},
		{name: "bad suffix", header: "bytes=-x", size: 10, wantErr: true},
		{name: "bad start", header: "bytes=x-1", size: 10, wantErr: true},
		{name: "bad end", header: "bytes=1-x", size: 10, wantErr: true},
		{name: "inverted range", header: "bytes=2-1", size: 10, wantErr: true},
		{name: "range starts at size", header: "bytes=10-", size: 10, wantErr: true},
		{name: "range without dash", header: "bytes=0", size: 10, wantErr: true},
		{
			name:    "too many ranges",
			header:  "bytes=" + strings.TrimSuffix(strings.Repeat("0-0,", maxRangeSpecCount+1), ","),
			size:    10,
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseRangeHeader(test.header, test.size)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected parse error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("expected ranges %v, got %v", test.want, got)
			}
		})
	}
}

func TestNormalizeBlobRedirectURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		wantURL string
		wantOK  bool
	}{
		{
			name:    "preserves signed url bytes unchanged",
			rawURL:  "HTTPS://storage.example.com/blob?X-Amz-Signature=a%2Fb%2Bc",
			wantURL: "HTTPS://storage.example.com/blob?X-Amz-Signature=a%2Fb%2Bc",
			wantOK:  true,
		},
		{
			name:    "allows http scheme",
			rawURL:  "http://storage.example.com/blob",
			wantURL: "http://storage.example.com/blob",
			wantOK:  true,
		},
		{
			name:   "rejects disallowed scheme",
			rawURL: "javascript:alert(1)",
			wantOK: false,
		},
		{
			name:   "rejects parse failure",
			rawURL: "https://storage.example.com/%zz",
			wantOK: false,
		},
		{
			name:   "rejects missing host",
			rawURL: "https:///blob",
			wantOK: false,
		},
		{
			name:   "rejects crlf injection",
			rawURL: "https://storage.example.com/blob?sig=abc\r\nX-Test: y",
			wantOK: false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			gotURL, gotOK := normalizeBlobRedirectURL(test.rawURL)
			if gotOK != test.wantOK {
				t.Fatalf("expected ok=%v, got %v", test.wantOK, gotOK)
			}

			if gotURL != test.wantURL {
				t.Fatalf("expected url %q, got %q", test.wantURL, gotURL)
			}
		})
	}
}

func TestIsBlobRedirectEnabled(t *testing.T) {
	t.Parallel()

	routeHandler := &RouteHandler{
		c: &Controller{
			Config: &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						RedirectBlobURL: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/a": {
							RedirectBlobURL: true,
						},
					},
				},
			},
			StoreController: storage.StoreController{
				SubStore: map[string]storageTypes.ImageStore{
					"/a": nil,
				},
			},
		},
	}

	if !routeHandler.isBlobRedirectEnabled("a/repo") {
		t.Fatal("expected redirect to be enabled for /a subpath repo")
	}

	// Default storage remains disabled even when a specific subpath enables redirect.
	if routeHandler.isBlobRedirectEnabled("b/repo") {
		t.Fatal("expected redirect to be disabled for default storage")
	}
}

func TestTokenProxyRequestBody(t *testing.T) {
	t.Parallel()

	t.Run("nil body", func(t *testing.T) {
		t.Parallel()

		body, contentLength, err := tokenProxyRequestBody(&http.Request{}, "upstream")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if body != nil {
			t.Fatal("expected nil body")
		}

		if contentLength != 0 {
			t.Fatalf("expected content length 0, got %d", contentLength)
		}
	})

	t.Run("passes through non-form body", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("raw-body"))
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len("raw-body"))

		body, contentLength, err := tokenProxyRequestBody(request, "upstream")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if string(bodyBytes) != "raw-body" {
			t.Fatalf("expected raw body to be preserved, got %q", string(bodyBytes))
		}

		if contentLength != int64(len("raw-body")) {
			t.Fatalf("expected content length %d, got %d", len("raw-body"), contentLength)
		}
	})

	t.Run("rewrites form service", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(
			"grant_type=password&service=zot-service&scope=repository:test:pull",
		))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

		body, _, err := tokenProxyRequestBody(request, "upstream")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		got := string(bodyBytes)
		if !strings.Contains(got, "service=upstream") {
			t.Fatalf("expected service to be rewritten, got %q", got)
		}

		if !strings.Contains(got, "scope=repository%3Atest%3Apull") {
			t.Fatalf("expected scope to be preserved, got %q", got)
		}
	})

	t.Run("returns body read errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", nil)
		request.Body = errTokenProxyReadCloser{}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, _, err := tokenProxyRequestBody(request, "upstream")
		if !errors.Is(err, errTestTokenProxyRead) {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("returns form parse errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("service=%zz"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, _, err := tokenProxyRequestBody(request, "upstream")
		if !errors.Is(err, errInvalidTokenProxyForm) {
			t.Fatalf("expected invalid form error, got %v", err)
		}
	})
}

func TestTokenProxyHeaders(t *testing.T) {
	t.Parallel()

	src := http.Header{}
	src.Add("Connection", "X-Hop, X-Also-Hop")
	src.Set("X-Hop", "drop")
	src.Set("X-Also-Hop", "drop")
	src.Set("Content-Length", "10")
	src.Set("Keep-Alive", "timeout=5")
	src.Set("X-Keep", "preserve")

	dst := http.Header{}
	copyTokenProxyHeaders(dst, src)

	if dst.Get("X-Keep") != "preserve" {
		t.Fatalf("expected X-Keep to be preserved, got %q", dst.Get("X-Keep"))
	}

	for _, header := range []string{"X-Hop", "X-Also-Hop", "Content-Length", "Keep-Alive", "Connection"} {
		if dst.Get(header) != "" {
			t.Fatalf("expected %s to be stripped, got %q", header, dst.Get(header))
		}
	}
}

func TestIsFormURLEncoded(t *testing.T) {
	t.Parallel()

	if isFormURLEncoded("application/%zz") {
		t.Fatal("expected invalid content type to be rejected")
	}
}

func TestProxyOIDCBearerTokenExchangeErrorsAndRedirect(t *testing.T) {
	t.Parallel()

	routeHandler := &RouteHandler{}

	t.Run("rejects invalid proxy realm", func(t *testing.T) {
		t.Parallel()

		err := routeHandler.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
			&config.BearerConfig{ProxyRealm: "http://[::1", ProxyService: "upstream"},
		)
		if !errors.Is(err, errInvalidProxyRealm) {
			t.Fatalf("expected invalid proxy realm error, got %v", err)
		}
	})

	t.Run("rejects relative proxy realm", func(t *testing.T) {
		t.Parallel()

		err := routeHandler.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
			&config.BearerConfig{ProxyRealm: "/token", ProxyService: "upstream"},
		)
		if !errors.Is(err, errInvalidProxyRealm) {
			t.Fatalf("expected invalid proxy realm error, got %v", err)
		}
	})

	t.Run("returns form rewrite errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("service=%zz"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		err := routeHandler.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			request,
			&config.BearerConfig{ProxyRealm: "http://example.com/token", ProxyService: "upstream"},
		)
		if !errors.Is(err, errInvalidTokenProxyForm) {
			t.Fatalf("expected invalid form error, got %v", err)
		}
	})

	t.Run("returns request construction errors", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodGet, "/token", nil)
		request.Method = "bad\nmethod"

		err := routeHandler.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			request,
			&config.BearerConfig{ProxyRealm: "http://example.com/token", ProxyService: "upstream"},
		)
		if err == nil {
			t.Fatal("expected request construction error")
		}
	})

	t.Run("returns upstream request errors", func(t *testing.T) {
		t.Parallel()

		proxyServer := httptest.NewServer(http.NotFoundHandler())
		proxyRealm := proxyServer.URL + "/token"
		proxyServer.Close()

		err := routeHandler.proxyOIDCBearerTokenExchange(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/token", nil),
			&config.BearerConfig{ProxyRealm: proxyRealm, ProxyService: "upstream"},
		)
		if err == nil {
			t.Fatal("expected upstream request error")
		}
	})

	t.Run("relays redirect responses", func(t *testing.T) {
		t.Parallel()

		proxyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			http.Redirect(response, request, "/next", http.StatusFound)
		}))
		defer proxyServer.Close()

		response := httptest.NewRecorder()
		err := routeHandler.proxyOIDCBearerTokenExchange(
			response,
			httptest.NewRequest(http.MethodGet, "/token", nil),
			&config.BearerConfig{ProxyRealm: proxyServer.URL + "/token", ProxyService: "upstream"},
		)
		if err != nil {
			t.Fatalf("unexpected proxy error: %v", err)
		}

		if response.Code != http.StatusFound {
			t.Fatalf("expected status %d, got %d", http.StatusFound, response.Code)
		}

		if response.Header().Get("Location") != "/next" {
			t.Fatalf("expected redirect location to be relayed, got %q", response.Header().Get("Location"))
		}
	})
}

func TestOIDCBearerTokenExchangeProxyError(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{
		Bearer: &config.BearerConfig{
			Realm:        "zot",
			Service:      "zot",
			ProxyRealm:   "/token",
			ProxyService: "upstream",
		},
	}

	routeHandler := &RouteHandler{
		c: &Controller{
			Config: conf,
			Log:    log.NewTestLogger(),
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/zot/auth/token", nil)
	request.SetBasicAuth("user", "not-an-oidc-token")

	response := httptest.NewRecorder()
	routeHandler.OIDCBearerTokenExchange(&OIDCBearerAuthorizer{})(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("expected status %d, got %d", http.StatusBadGateway, response.Code)
	}
}

func TestOIDCBearerTokenExchangeRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "zot"}}

	routeHandler := &RouteHandler{
		c: &Controller{
			Config: conf,
			Log:    log.NewTestLogger(),
		},
	}

	request := httptest.NewRequest(http.MethodPut, "/zot/auth/token", nil)
	response := httptest.NewRecorder()

	routeHandler.OIDCBearerTokenExchange(&OIDCBearerAuthorizer{})(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, response.Code)
	}
}

func TestOIDCBearerTokenExchangeRejectsMultipleAuthorizationHeaders(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{Bearer: &config.BearerConfig{Realm: "zot"}}

	routeHandler := &RouteHandler{
		c: &Controller{
			Config: conf,
			Log:    log.NewTestLogger(),
		},
	}

	request := httptest.NewRequest(http.MethodGet, "/zot/auth/token", nil)
	request.Header.Add("Authorization", "Basic dXNlcjpwYXNz")
	request.Header.Add("Authorization", "Bearer token")
	response := httptest.NewRecorder()

	routeHandler.OIDCBearerTokenExchange(&OIDCBearerAuthorizer{})(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}
}
