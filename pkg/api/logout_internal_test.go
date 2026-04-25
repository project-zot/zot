package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"golang.org/x/oauth2"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestComposeEndSessionURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		endpoint    string
		clientID    string
		redirectURI string
		wantEmpty   bool
		wantErr     bool
		wantQuery   url.Values
		wantPath    string
	}{
		{
			name:      "empty endpoint yields empty URL and no error",
			endpoint:  "",
			clientID:  "id",
			wantEmpty: true,
		},
		{
			name:     "client_id only when redirect is empty",
			endpoint: "https://idp.example.com/logout",
			clientID: "zot-client",
			wantPath: "/logout",
			wantQuery: url.Values{
				"client_id": []string{"zot-client"},
			},
		},
		{
			name:        "client_id and post_logout_redirect_uri merged",
			endpoint:    "https://idp.example.com/realms/zot/protocol/openid-connect/logout",
			clientID:    "zot-client",
			redirectURI: "https://zot.example.com/login",
			wantPath:    "/realms/zot/protocol/openid-connect/logout",
			wantQuery: url.Values{
				"client_id":                []string{"zot-client"},
				"post_logout_redirect_uri": []string{"https://zot.example.com/login"},
			},
		},
		{
			name:        "preserves pre-existing query parameters",
			endpoint:    "https://idp.example.com/logout?ui_locales=en",
			clientID:    "zot-client",
			redirectURI: "https://zot.example.com/login",
			wantPath:    "/logout",
			wantQuery: url.Values{
				"ui_locales":               []string{"en"},
				"client_id":                []string{"zot-client"},
				"post_logout_redirect_uri": []string{"https://zot.example.com/login"},
			},
		},
		{
			name:     "invalid endpoint returns error",
			endpoint: "://not-a-url",
			wantErr:  true,
		},
		{
			name:     "relative endpoint is rejected",
			endpoint: "/realms/zot/protocol/openid-connect/logout",
			wantErr:  true,
		},
		{
			name:     "scheme-less endpoint with host is rejected",
			endpoint: "//idp.example.com/logout",
			wantErr:  true,
		},
		{
			name:     "non-http scheme is rejected",
			endpoint: "javascript:alert(1)",
			wantErr:  true,
		},
		{
			name:     "ftp scheme is rejected",
			endpoint: "ftp://idp.example.com/logout",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := composeEndSessionURL(tc.endpoint, tc.clientID, tc.redirectURI)

			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			if tc.wantEmpty {
				assert.Empty(t, got)

				return
			}

			parsed, err := url.Parse(got)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPath, parsed.Path)
			assert.Equal(t, tc.wantQuery, parsed.Query())
		})
	}
}

func TestPostLogoutRedirectURI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		externalURL string
		address     string
		port        string
		tls         bool
		want        string
	}{
		{
			name:    "plain http from address:port when no external URL",
			address: "zot.example.com",
			port:    "5000",
			want:    "http://zot.example.com:5000/login",
		},
		{
			name:    "https when TLS is configured",
			address: "zot.example.com",
			port:    "5000",
			tls:     true,
			want:    "https://zot.example.com:5000/login",
		},
		{
			name:        "externalURL wins over address:port",
			externalURL: "https://zot.example.com",
			address:     "internal.local",
			port:        "5000",
			want:        "https://zot.example.com/login",
		},
		{
			name:        "externalURL trailing slash is trimmed",
			externalURL: "https://zot.example.com/",
			address:     "internal.local",
			port:        "5000",
			want:        "https://zot.example.com/login",
		},
		{
			name:        "externalURL with subpath is preserved",
			externalURL: "https://example.com/zot",
			want:        "https://example.com/zot/login",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{HTTP: config.HTTPConfig{
				ExternalURL: tc.externalURL,
				Address:     tc.address,
				Port:        tc.port,
			}}
			if tc.tls {
				cfg.HTTP.TLS = &config.TLSConfig{}
			}

			assert.Equal(t, tc.want, postLogoutRedirectURI(cfg))
		})
	}
}

// newTestCookieStore builds a cookie store suitable for in-process handler tests.
// MaxAge is short-circuited to 0 so the underlying cookie is encoded as a plain session
// cookie, which httptest recorders can round-trip without worrying about expiry skew.
func newTestCookieStore(t *testing.T) *CookieStore {
	t.Helper()

	memStore := sessions.NewCookieStore(
		[]byte("test-hash-key-0123456789abcdef01"),
		[]byte("test-encryption-key-0123456789ab"),
	)
	memStore.MaxAge(0)

	return &CookieStore{Store: memStore}
}

// newTestRouteHandler builds the minimum RouteHandler needed to exercise the Logout
// handler directly, bypassing NewController/SetupRoutes which require much more plumbing.
func newTestRouteHandler(t *testing.T) *RouteHandler {
	t.Helper()

	logger := log.NewLogger("debug", "")
	ctlr := &Controller{
		Config:         &config.Config{HTTP: config.HTTPConfig{}},
		Log:            logger,
		CookieStore:    newTestCookieStore(t),
		RelyingParties: map[string]rp.RelyingParty{},
	}

	return &RouteHandler{c: ctlr}
}

// seedSessionProvider writes a value into session.Values["provider"] and returns the
// cookies produced. Callers re-attach those cookies to the subsequent request so the
// handler sees the same session.
func seedSessionProvider(t *testing.T, rh *RouteHandler, provider string) []*http.Cookie {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
	rec := httptest.NewRecorder()

	session, err := rh.c.CookieStore.Get(req, "session")
	require.NoError(t, err)

	session.Values["provider"] = provider
	require.NoError(t, session.Save(req, rec))

	return rec.Result().Cookies()
}

func TestLogoutHandler(t *testing.T) {
	t.Parallel()

	t.Run("no session → 200 OK with empty LogoutResponse JSON", func(t *testing.T) {
		t.Parallel()

		rh := newTestRouteHandler(t)
		req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
		rec := httptest.NewRecorder()

		rh.Logout(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
		assert.JSONEq(t, `{}`, rec.Body.String(),
			"non-OIDC logout should still return the LogoutResponse shape (endSessionUrl omitted)")
	})

	t.Run("OPTIONS preflight is a no-op", func(t *testing.T) {
		t.Parallel()

		rh := newTestRouteHandler(t)
		req := httptest.NewRequest(http.MethodOptions, "/zot/auth/logout", nil)
		rec := httptest.NewRecorder()

		rh.Logout(rec, req)

		// The handler returns before touching the response, so status stays at the
		// recorder default (200) and body is empty.
		assert.Equal(t, http.StatusOK, rec.Result().StatusCode)
		assert.Empty(t, rec.Body.Bytes())
	})

	t.Run("session has provider but no matching RelyingParty → JSON with no endSessionUrl", func(t *testing.T) {
		t.Parallel()

		rh := newTestRouteHandler(t)
		cookies := seedSessionProvider(t, rh, "oidc") // supported provider name, but map is empty

		req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}

		rec := httptest.NewRecorder()
		rh.Logout(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
		assert.JSONEq(t, `{}`, rec.Body.String(),
			"absent RelyingParty should degrade to an empty LogoutResponse (local-only logout)")
	})

	t.Run("session has provider not in OIDC-supported list → JSON with no endSessionUrl", func(t *testing.T) {
		t.Parallel()

		rh := newTestRouteHandler(t)
		cookies := seedSessionProvider(t, rh, "github") // github is oauth2-only, not OIDC

		req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}

		rec := httptest.NewRecorder()
		rh.Logout(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
		assert.JSONEq(t, `{}`, rec.Body.String(),
			"non-OIDC provider should degrade to an empty LogoutResponse")
	})

	t.Run("LogoutResponse JSON shape round-trips endSessionUrl", func(t *testing.T) {
		t.Parallel()

		// The full Logout→IdP path requires a live OIDC discovery server; the pure URL
		// construction is covered by TestComposeEndSessionURL. Here we just verify the
		// JSON contract the zui client relies on: a "LogoutResponse" with the field name
		// "endSessionUrl" encodes as expected and decodes back to the same struct.
		orig := LogoutResponse{EndSessionURL: "https://idp.example.com/logout?client_id=zot"}

		encoded, err := json.Marshal(orig)
		require.NoError(t, err)
		assert.JSONEq(t, `{"endSessionUrl":"https://idp.example.com/logout?client_id=zot"}`, string(encoded))

		var decoded LogoutResponse

		require.NoError(t, json.Unmarshal(encoded, &decoded))
		assert.Equal(t, orig, decoded)

		// And verify the omitempty behavior: missing URL should yield an empty object.
		empty, err := json.Marshal(LogoutResponse{})
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(empty))
	})
}

// TestSaveUserLoggedSessionClearsStaleProvider guards against a re-login regression: if
// a previous OIDC session left provider="oidc" on the cookie and the user re-authenticates
// via a non-OIDC path (basic/LDAP/GitHub), the provider key must be cleared, otherwise a
// later Logout would return an endSessionUrl pointing at an IdP the user is no longer
// authenticated against.
func TestSaveUserLoggedSessionClearsStaleProvider(t *testing.T) {
	t.Parallel()

	rh := newTestRouteHandler(t)
	cookies := seedSessionProvider(t, rh, "oidc")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()

	require.NoError(t,
		saveUserLoggedSession(rh.c.CookieStore, rec, req, "alice", "", false, rh.c.Log))

	// Round-trip the new cookies and assert the provider key is gone.
	readReq := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		readReq.AddCookie(c)
	}

	session, err := rh.c.CookieStore.Get(readReq, "session")
	require.NoError(t, err)
	_, hasProvider := session.Values["provider"]
	assert.False(t, hasProvider, "stale provider must be cleared after non-OIDC re-login")
}

// failingStore wraps a real sessions.Store and forces Save to return a supplied error,
// so we can exercise the error branch that plain in-memory stores never trigger.
type failingStore struct {
	sessions.Store

	saveErr error
}

// Get routes through the request-scoped session registry but registers THIS wrapper as
// the session's owning store. Without that, gorilla would cache the inner sessions.Store
// under the session's .store field and later Save calls would bypass our saveErr gate.
func (f *failingStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(f, name)
}

func (f *failingStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return f.Store.New(r, name)
}

func (f *failingStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	if f.saveErr != nil {
		return f.saveErr
	}

	return f.Store.Save(r, w, s)
}

// newTestRouteHandlerWithStore is newTestRouteHandler but lets the caller inject a
// custom CookieStore — used to drive the failingStore paths.
func newTestRouteHandlerWithStore(t *testing.T, store *CookieStore) *RouteHandler {
	t.Helper()

	return &RouteHandler{c: &Controller{
		Config:         &config.Config{HTTP: config.HTTPConfig{}},
		Log:            log.NewLogger("debug", ""),
		CookieStore:    store,
		RelyingParties: map[string]rp.RelyingParty{},
	}}
}

// fakeEndSessionRP satisfies the rp.RelyingParty interface just enough for
// buildEndSessionURL, which only calls GetEndSessionEndpoint and OAuthConfig. Any other
// method on the embedded interface remains nil and would panic if called — keeping the
// fake honest: tests will blow up if a future change starts calling a new RP method.
type fakeEndSessionRP struct {
	rp.RelyingParty

	endSessionURL string
	clientID      string
}

func (f *fakeEndSessionRP) GetEndSessionEndpoint() string {
	return f.endSessionURL
}

func (f *fakeEndSessionRP) OAuthConfig() *oauth2.Config {
	return &oauth2.Config{ClientID: f.clientID}
}

func TestLogoutSessionSaveError(t *testing.T) {
	t.Parallel()

	saveErr := errors.New("cookie store save failed")
	memStore := sessions.NewCookieStore(
		[]byte("test-hash-key-0123456789abcdef01"),
		[]byte("test-encryption-key-0123456789ab"),
	)
	rh := newTestRouteHandlerWithStore(t,
		&CookieStore{Store: &failingStore{Store: memStore, saveErr: saveErr}})

	req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
	rec := httptest.NewRecorder()

	rh.Logout(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Result().StatusCode,
		"a failing session.Save should surface as 500 rather than a partial body")
}

func TestLogoutReturnsEndSessionURL(t *testing.T) {
	t.Parallel()

	// Happy path: a RelyingParty with a well-formed end_session_endpoint produces a
	// LogoutResponse whose endSessionUrl carries client_id and the resolved
	// post_logout_redirect_uri.
	rh := newTestRouteHandler(t)
	rh.c.Config.HTTP.ExternalURL = "https://zot.example.com"
	rh.c.RelyingParties["oidc"] = &fakeEndSessionRP{
		endSessionURL: "https://idp.example.com/logout",
		clientID:      "zot-client",
	}

	cookies := seedSessionProvider(t, rh, "oidc")

	req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	rh.Logout(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "application/json", res.Header.Get("Content-Type"))

	var body LogoutResponse

	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	parsed, err := url.Parse(body.EndSessionURL)
	require.NoError(t, err)
	assert.Equal(t, "https://idp.example.com/logout", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	assert.Equal(t, "zot-client", parsed.Query().Get("client_id"))
	assert.Equal(t, "https://zot.example.com/login", parsed.Query().Get("post_logout_redirect_uri"))
}

func TestLogoutBuildEndSessionURLComposeError(t *testing.T) {
	t.Parallel()

	// A RelyingParty whose GetEndSessionEndpoint returns a relative URL forces
	// composeEndSessionURL to reject it; buildEndSessionURL logs the error and returns
	// "", so the handler degrades to an empty LogoutResponse.
	rh := newTestRouteHandler(t)
	rh.c.RelyingParties["oidc"] = &fakeEndSessionRP{
		endSessionURL: "/realms/zot/logout", // relative, IsAbs() == false
		clientID:      "zot-client",
	}

	cookies := seedSessionProvider(t, rh, "oidc")

	req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	rh.Logout(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
	assert.JSONEq(t, `{}`, rec.Body.String(),
		"a malformed end_session_endpoint should not leak into the response")
}
