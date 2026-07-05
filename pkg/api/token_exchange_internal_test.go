package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
)

func testJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "none"})
	payload, _ := json.Marshal(claims)

	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestNormalizeTokenExchangeRequest(t *testing.T) {
	t.Parallel()

	t.Run("basic only", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodGet, constants.TokenPath, nil)
		request.SetBasicAuth("user", " basic-token ")

		tokenRequest, err := normalizeTokenExchangeRequest(request)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !reflect.DeepEqual(tokenRequest.credentials, []string{"basic-token"}) {
			t.Fatalf("unexpected credentials: %#v", tokenRequest.credentials)
		}
	})

	t.Run("ignores non form body", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath, strings.NewReader("raw-body"))
		request.Header.Set("Content-Type", "application/json")

		tokenRequest, err := normalizeTokenExchangeRequest(request)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(tokenRequest.credentials) != 0 {
			t.Fatalf("unexpected credentials: %#v", tokenRequest.credentials)
		}
	})

	t.Run("form credentials are normalized and deduped", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath, strings.NewReader(
			"password=form-token&id_token=id-token&access_token=access-token&"+
				"refresh_token=refresh-token&token=token-token&id_token=id-token"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth("user", "basic-token")

		tokenRequest, err := normalizeTokenExchangeRequest(request)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := []string{"basic-token", "form-token", "id-token", "access-token", "refresh-token", "token-token"}
		if !reflect.DeepEqual(tokenRequest.credentials, want) {
			t.Fatalf("unexpected credentials: %#v", tokenRequest.credentials)
		}

		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("failed to reread request body: %v", err)
		}
		if !strings.Contains(string(body), "password=form-token") {
			t.Fatalf("expected request body to be restored, got %q", string(body))
		}
	})

	t.Run("read error", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath, nil)
		request.Body = errTokenProxyReadCloser{}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := normalizeTokenExchangeRequest(request)
		if !errors.Is(err, errTestTokenProxyRead) {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("form parse error", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath, strings.NewReader("password=%zz"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := normalizeTokenExchangeRequest(request)
		if !errors.Is(err, zerr.ErrInvalidTokenProxyForm) {
			t.Fatalf("expected form parse error, got %v", err)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		t.Parallel()

		request := httptest.NewRequest(http.MethodPost, constants.TokenPath,
			strings.NewReader(strings.Repeat("a", constants.MaxTokenRequestBodySize+1)))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := normalizeTokenExchangeRequest(request)
		if !errors.Is(err, errTokenRequestBodyTooLarge) {
			t.Fatalf("expected body too large error, got %v", err)
		}
	})
}

func TestLocalOIDCTokenOwnerForCredential(t *testing.T) {
	t.Parallel()

	const issuer = "https://issuer.example.com"
	const bearerAudience = "workload-audience"
	const openIDClientID = "human-client"

	authConfig := &config.AuthConfig{
		Bearer: &config.BearerConfig{
			OIDC: []config.BearerOIDCConfig{{Issuer: issuer, Audiences: []string{bearerAudience}}},
		},
		OpenID: &config.OpenIDConfig{Providers: map[string]config.OpenIDProviderConfig{
			"oidc":        {Issuer: issuer, ClientID: openIDClientID},
			"unsupported": {Issuer: issuer, ClientID: "unsupported-client"},
		}},
	}

	tests := []struct {
		name       string
		credential string
		want       localOIDCTokenOwner
	}{
		{name: "not jwt", credential: "not-a-jwt", want: localOIDCTokenOwnerNone},
		{name: "bad payload base64", credential: "a.%zz.c", want: localOIDCTokenOwnerNone},
		{name: "bad payload json", credential: "a." + base64.RawURLEncoding.EncodeToString([]byte("{")) + ".c", want: localOIDCTokenOwnerNone},
		{name: "missing issuer", credential: testJWT(map[string]any{"aud": bearerAudience}), want: localOIDCTokenOwnerNone},
		{name: "missing audience", credential: testJWT(map[string]any{"iss": issuer}), want: localOIDCTokenOwnerNone},
		{name: "bearer oidc", credential: testJWT(map[string]any{"iss": issuer, "aud": []string{bearerAudience}}), want: localOIDCTokenOwnerBearer},
		{name: "openid", credential: testJWT(map[string]any{"iss": issuer, "aud": openIDClientID}), want: localOIDCTokenOwnerOpenID},
		{name: "unsupported openid", credential: testJWT(map[string]any{"iss": issuer, "aud": "unsupported-client"}), want: localOIDCTokenOwnerNone},
		{name: "unknown", credential: testJWT(map[string]any{"iss": issuer, "aud": "other"}), want: localOIDCTokenOwnerNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := localOIDCTokenOwnerForCredential(tt.credential, authConfig)
			if got != tt.want {
				t.Fatalf("expected owner %v, got %v", tt.want, got)
			}
		})
	}

	if owner := localOIDCTokenOwnerForCredential(testJWT(map[string]any{"iss": issuer, "aud": bearerAudience}), nil); owner != localOIDCTokenOwnerNone {
		t.Fatalf("expected nil auth config to have no owner, got %v", owner)
	}
}

func TestAudienceAndOwnershipHelpers(t *testing.T) {
	t.Parallel()

	if got := audiencesFromClaim("aud"); !reflect.DeepEqual(got, []string{"aud"}) {
		t.Fatalf("unexpected string audience: %#v", got)
	}
	if got := audiencesFromClaim(""); got != nil {
		t.Fatalf("expected empty string audience to return nil, got %#v", got)
	}
	if got := audiencesFromClaim([]string{"", "a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("unexpected string slice audience: %#v", got)
	}
	if got := audiencesFromClaim([]any{"a", 1, "b", ""}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("unexpected any slice audience: %#v", got)
	}
	if got := audiencesFromClaim(42); got != nil {
		t.Fatalf("expected unsupported audience to return nil, got %#v", got)
	}

	claims := unverifiedJWTClaims{issuer: "issuer", audiences: []string{"aud"}}
	if bearerOIDCOwnsClaims(claims, nil) {
		t.Fatal("expected nil auth config not to own bearer claims")
	}
	if bearerOIDCOwnsClaims(claims, &config.AuthConfig{Bearer: &config.BearerConfig{}}) {
		t.Fatal("expected empty bearer config not to own claims")
	}
	if openIDOwnsClaims(claims, nil) {
		t.Fatal("expected nil auth config not to own openid claims")
	}
	if openIDOwnsClaims(claims, &config.AuthConfig{OpenID: &config.OpenIDConfig{}}) {
		t.Fatal("expected empty openid config not to own claims")
	}
	if !intersects([]string{"a", "b"}, []string{"c", "b"}) {
		t.Fatal("expected slices to intersect")
	}
	if intersects([]string{"a"}, []string{"b"}) {
		t.Fatal("expected slices not to intersect")
	}
}

func TestOIDCBearerTokenResponse(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0).UTC()
	resp := newOIDCBearerTokenResponse("jwt", map[string]any{
		"exp": json.Number("160"),
		"iat": json.Number("90"),
	}, now)
	if resp.Token != "jwt" || resp.AccessToken != "jwt" || resp.ExpiresIn != 60 || resp.IssuedAt != time.Unix(90, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("unexpected response: %#v", resp)
	}

	resp = newOIDCBearerTokenResponse("jwt", map[string]any{"exp": float64(50), "iat": int64(80)}, now)
	if resp.ExpiresIn != 0 || resp.IssuedAt != time.Unix(80, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("unexpected expired response: %#v", resp)
	}

	resp = newOIDCBearerTokenResponse("jwt", map[string]any{}, time.Time{})
	if resp.ExpiresIn != 0 || resp.IssuedAt != "" {
		t.Fatalf("unexpected empty-claims response: %#v", resp)
	}
}

func TestUnixTimeClaim(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
		want  int64
		ok    bool
	}{
		{name: "json int", value: json.Number("123"), want: 123, ok: true},
		{name: "json float", value: json.Number("123.9"), want: 123, ok: true},
		{name: "json invalid", value: json.Number("nope"), ok: false},
		{name: "float64", value: float64(11.7), want: 11, ok: true},
		{name: "float32", value: float32(12.7), want: 12, ok: true},
		{name: "int64", value: int64(13), want: 13, ok: true},
		{name: "int", value: 14, want: 14, ok: true},
		{name: "string", value: "15", want: 15, ok: true},
		{name: "string invalid", value: "bad", ok: false},
		{name: "unsupported", value: []string{"bad"}, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := unixTimeClaim(tt.value)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("expected (%d, %v), got (%d, %v)", tt.want, tt.ok, got, ok)
			}
		})
	}
}
