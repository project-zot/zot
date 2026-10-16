package api

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestSupportedOIDCSigningAlgorithms(t *testing.T) {
	t.Parallel()

	advertised := []string{
		oidc.RS256, oidc.RS384, oidc.RS512,
		oidc.ES256, oidc.ES384, oidc.ES512,
		oidc.PS256, oidc.PS384, oidc.PS512,
		oidc.EdDSA,
		"HS256",
		"none",
	}
	expected := advertised[:len(advertised)-2]

	if actual := supportedOIDCSigningAlgorithms(advertised); !slices.Equal(actual, expected) {
		t.Fatalf("unexpected supported signing algorithms: got %v, want %v", actual, expected)
	}
}

// omitOIDCTokenIssuer makes newOIDCOutageTestServer sign a token without an iss claim.
const omitOIDCTokenIssuer = "<omit>"

func newOIDCOutageTestServer(t *testing.T, tokenIssuer string) (*httptest.Server, string, *atomic.Bool, *atomic.Int32) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	down := &atomic.Bool{}
	keyRequests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			keyRequests.Add(1)
		}
		if down.Load() {
			http.Error(w, "issuer unavailable", http.StatusServiceUnavailable)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/jwks" {
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &key.PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig",
			}}})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks",
			})
		}
	}))
	t.Cleanup(server.Close)

	if tokenIssuer == "" {
		tokenIssuer = server.URL
	}
	claims := jwt.MapClaims{
		"iss": tokenIssuer, "aud": []string{"zot"}, "sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	if tokenIssuer == omitOIDCTokenIssuer {
		delete(claims, "iss")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	return server, "Bearer " + signed, down, keyRequests
}

func TestOIDCCachedKeySetSelectsKeyID(t *testing.T) {
	t.Parallel()

	firstKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &firstKey.PublicKey, KeyID: "first-key", Algorithm: string(jose.RS256), Use: "sig"},
			{Key: &secondKey.PublicKey, KeyID: "second-key", Algorithm: string(jose.RS256), Use: "sig"},
			{Key: &secondKey.PublicKey, KeyID: "encryption-key", Algorithm: string(jose.RSA_OAEP), Use: "enc"},
		}})
	}))
	defer server.Close()

	provider := &oidcProvider{httpClient: server.Client()}
	keySet, err := provider.fetchKeySet(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(keySet.keys) != 2 || keySet.keys[0].KeyID != "first-key" || keySet.keys[1].KeyID != "second-key" {
		t.Fatal("cached key set did not preserve JWK key IDs")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "test-user"})
	token.Header["kid"] = "second-key"
	signedWithWrongKey, err := token.SignedString(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keySet.VerifySignature(context.Background(), signedWithWrongKey); err == nil {
		t.Fatal("cached key set verified a signature with a key whose ID did not match the token")
	}

	signedWithMatchingKey, err := token.SignedString(secondKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keySet.VerifySignature(context.Background(), signedWithMatchingKey); err != nil {
		t.Fatalf("cached key set did not verify the key matching the token key ID: %v", err)
	}

	delete(token.Header, "kid")
	signedWithoutKeyID, err := token.SignedString(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keySet.VerifySignature(context.Background(), signedWithoutKeyID); err != nil {
		t.Fatalf("cached key set did not preserve verification for tokens without a key ID: %v", err)
	}
}

func TestOIDCIssuerIsolation(t *testing.T) {
	t.Parallel()

	server, header, _, _ := newOIDCOutageTestServer(t, "")
	var requests atomic.Int32
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer unavailable.Close()

	authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: unavailable.URL, Audiences: []string{"zot"}},
		{Issuer: server.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := authorizer.Authenticate(ctx, header); err != nil {
		t.Fatalf("healthy issuer must authenticate despite another issuer hanging: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("authentication contacted an unrelated issuer")
	}

	unknown, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: unavailable.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{header, "Bearer " + "not-a-jwt", "Basic abc", ""} {
		if _, err := unknown.Authenticate(context.Background(), token); err == nil {
			t.Fatal("unknown issuer or malformed token authenticated")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("unknown issuer or malformed token triggered discovery")
	}

	alternate, alternateHeader, _, _ := newOIDCOutageTestServer(t, "https://alternate.example")
	skipIssuer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: alternate.URL, Audiences: []string{"zot"}, SkipIssuerVerification: true},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := skipIssuer.Authenticate(context.Background(), alternateHeader); err != nil {
		t.Fatalf("skipIssuerVerification must still allow a different token issuer: %v", err)
	}

	// A token without iss has no issuer to route by: only skipIssuerVerification providers try it.
	noIssuer, noIssuerHeader, _, _ := newOIDCOutageTestServer(t, omitOIDCTokenIssuer)
	skipNoIssuer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: unavailable.URL, Audiences: []string{"zot"}},
		{
			Issuer: noIssuer.URL, Audiences: []string{"zot"}, SkipIssuerVerification: true,
			// the default username, claims.iss + '/' + claims.sub, needs an issuer
			ClaimMapping: &config.CELClaimValidationAndMapping{Username: "claims.sub"},
		},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := skipNoIssuer.Authenticate(context.Background(), noIssuerHeader); err != nil {
		t.Fatalf("skipIssuerVerification must allow a token without an issuer: %v", err)
	}
	if _, err := unknown.Authenticate(context.Background(), noIssuerHeader); err == nil {
		t.Fatal("a token without an issuer authenticated without skipIssuerVerification")
	}
	if requests.Load() != 0 {
		t.Fatal("a token without an issuer contacted an issuer that verifies issuers")
	}
}

func TestOIDCVerifierRefreshRetainsKeys(t *testing.T) {
	t.Parallel()

	server, header, down, keyRequests := newOIDCOutageTestServer(t, "")
	authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: server.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authenticate(context.Background(), header); err != nil {
		t.Fatal(err)
	}

	provider := authorizer.providers[0]
	expectedKeyRequests := int32(1)
	for _, unavailable := range []bool{false, true} {
		down.Store(unavailable)
		provider.verifierMu.Lock()
		provider.verifierDeadline = time.Time{}
		provider.verifierMu.Unlock()

		if _, err := authorizer.Authenticate(context.Background(), header); err != nil {
			t.Fatalf("cached token must authenticate during discovery refresh (down=%v): %v", unavailable, err)
		}
		provider.verifierMu.RLock()
		done := provider.refreshDone
		provider.verifierMu.RUnlock()
		if done != nil {
			<-done
		}
		if _, err := authorizer.Authenticate(context.Background(), header); err != nil {
			t.Fatalf("cached token must authenticate after discovery refresh (down=%v): %v", unavailable, err)
		}
		if !unavailable {
			expectedKeyRequests++
		}
		if keyRequests.Load() != expectedKeyRequests {
			t.Fatalf("discovery refresh did not fetch signing keys: got %d requests, want %d",
				keyRequests.Load(), expectedKeyRequests)
		}
	}
}

func TestOIDCVerifierRefreshReplacesRemovedKey(t *testing.T) {
	t.Parallel()

	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var signingKey atomic.Pointer[rsa.PrivateKey]
	signingKey.Store(oldKey)
	var jwksUnavailable atomic.Bool
	var keyRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/jwks" {
			keyRequests.Add(1)
			if jwksUnavailable.Load() {
				http.Error(w, "JWKS unavailable", http.StatusServiceUnavailable)

				return
			}
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &signingKey.Load().PublicKey, KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig",
			}}})

			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer server.Close()

	authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: server.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": server.URL, "aud": []string{"zot"}, "sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = "test-key"
	oldSigned, err := token.SignedString(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authenticate(context.Background(), "Bearer "+oldSigned); err != nil {
		t.Fatal(err)
	}
	provider := authorizer.providers[0]
	originalVerifier := provider.verifier

	signingKey.Store(newKey)
	jwksUnavailable.Store(true)
	provider.refreshVerifier(context.Background(), make(chan struct{}))
	if provider.verifier != originalVerifier {
		t.Fatal("a failed JWKS refresh must retain the previous verifier")
	}
	if _, err := authorizer.Authenticate(context.Background(), "Bearer "+oldSigned); err != nil {
		t.Fatalf("a failed JWKS refresh must retain the previous signing keys: %v", err)
	}

	jwksUnavailable.Store(false)
	provider.refreshVerifier(context.Background(), make(chan struct{}))
	if _, err := authorizer.Authenticate(context.Background(), "Bearer "+oldSigned); err == nil {
		t.Fatal("a token signed by a removed key must be rejected after refresh")
	}

	newSigned, err := token.SignedString(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authenticate(context.Background(), "Bearer "+newSigned); err != nil {
		t.Fatalf("a token signed by the refreshed key must authenticate: %v", err)
	}
	if keyRequests.Load() != 4 {
		t.Fatalf("expected initial, failed, successful, and removed-key JWKS requests, got %d", keyRequests.Load())
	}
}

func TestOIDCOnDemandKeyRotationUsesProviderHTTPClient(t *testing.T) {
	t.Parallel()

	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var rotated atomic.Bool
	var keyRequests atomic.Int32
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/jwks" {
			keyRequests.Add(1)
			key := oldKey
			keyID := "old-key"
			if rotated.Load() {
				key = newKey
				keyID = "new-key"
			}
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig",
			}}})

			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": server.URL, "jwks_uri": server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer server.Close()

	authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: server.URL, Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	provider := authorizer.providers[0]
	provider.httpClient = server.Client()
	provider.httpClient.Timeout = oidcHTTPTimeout

	claims := jwt.MapClaims{
		"iss": server.URL, "aud": []string{"zot"}, "sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	oldToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	oldToken.Header["kid"] = "old-key"
	oldSigned, err := oldToken.SignedString(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authenticate(context.Background(), "Bearer "+oldSigned); err != nil {
		t.Fatal(err)
	}

	rotated.Store(true)
	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	newToken.Header["kid"] = "new-key"
	newSigned, err := newToken.SignedString(newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authenticate(context.Background(), "Bearer "+newSigned); err != nil {
		t.Fatalf("a token signed by an on-demand rotated key must authenticate with the provider HTTP client: %v", err)
	}
	if keyRequests.Load() != 2 {
		t.Fatalf("expected initial and on-demand JWKS requests, got %d", keyRequests.Load())
	}
}

func TestOIDCGoogleIssuerAlias(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
		{Issuer: "https://accounts.google.com", Audiences: []string{"zot"}},
	}, log.NewTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	provider := authorizer.providers[0]
	provider.verifier = oidc.NewVerifier(provider.issuer, &oidc.StaticKeySet{
		PublicKeys: []crypto.PublicKey{&key.PublicKey},
	}, &oidc.Config{SkipClientIDCheck: true})
	provider.verifierDeadline = time.Now().Add(time.Hour)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "accounts.google.com", "aud": []string{"zot"}, "sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authenticate(context.Background(), "Bearer "+signed); err != nil {
		t.Fatalf("go-oidc's Google issuer alias must remain accepted: %v", err)
	}
}

func TestOIDCIssuerRoutingRequiresSignatureVerification(t *testing.T) {
	t.Parallel()

	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	untrustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name        string
		issuer      string
		tokenIssuer string
		skipIssuer  bool
	}{
		{name: "matching issuer", issuer: "https://issuer.example.com", tokenIssuer: "https://issuer.example.com"},
		{name: "Google alias", issuer: "https://accounts.google.com", tokenIssuer: "accounts.google.com"},
		{name: "skip issuer", issuer: "https://issuer.example.com", tokenIssuer: "https://other.example.com", skipIssuer: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{{
				Issuer: testCase.issuer, Audiences: []string{"zot"}, SkipIssuerVerification: testCase.skipIssuer,
			}}, log.NewTestLogger())
			if err != nil {
				t.Fatal(err)
			}
			provider := authorizer.providers[0]
			provider.verifier = oidc.NewVerifier(provider.issuer, &oidc.StaticKeySet{
				PublicKeys: []crypto.PublicKey{&trustedKey.PublicKey},
			}, &oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: testCase.skipIssuer})
			provider.verifierDeadline = time.Now().Add(time.Hour)

			claims := jwt.MapClaims{
				"iss": testCase.tokenIssuer, "aud": []string{"zot"}, "sub": "test-user",
				"exp": time.Now().Add(time.Hour).Unix(),
			}
			valid, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(trustedKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authorizer.Authenticate(context.Background(), "Bearer "+valid); err != nil {
				t.Fatalf("trusted token must authenticate: %v", err)
			}

			forged, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(untrustedKey)
			if err != nil {
				t.Fatal(err)
			}
			unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
			if err != nil {
				t.Fatal(err)
			}
			claims["sub"] = "admin"
			changed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(trustedKey)
			if err != nil {
				t.Fatal(err)
			}
			// Retain the original signature while replacing the signed identity claims.
			originalParts := strings.Split(valid, ".")
			changedParts := strings.Split(changed, ".")
			tampered := originalParts[0] + "." + changedParts[1] + "." + originalParts[2]
			for _, token := range []string{forged, unsigned, tampered} {
				result, err := authorizer.Authenticate(context.Background(), "Bearer "+token)
				if err == nil || result != nil {
					t.Fatal("issuer routing allowed an invalid signature to authenticate")
				}
			}
		})
	}
}

func TestOIDCHTTPTimeout(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{"/.well-known/openid-configuration", "/jwks"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == endpoint {
					<-r.Context().Done()

					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/jwks",
				})
			}))
			defer server.Close()
			_, header, _, _ := newOIDCOutageTestServer(t, server.URL)
			authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
				{Issuer: server.URL, Audiences: []string{"zot"}},
			}, log.NewTestLogger())
			if err != nil {
				t.Fatal(err)
			}
			provider := authorizer.providers[0]
			if provider.httpClient == nil || provider.httpClient.Timeout != oidcHTTPTimeout {
				t.Fatal("OIDC HTTP client must have a timeout by default")
			}
			provider.httpClient.Timeout = 50 * time.Millisecond

			done := make(chan error, 1)
			go func() {
				_, err := authorizer.Authenticate(context.Background(), header)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("hanging endpoint must fail authentication")
				}
			case <-time.After(time.Second):
				t.Fatal("OIDC network request did not time out")
			}
		})
	}
}

func TestOIDCMalformedInput(t *testing.T) {
	t.Parallel()

	encode := base64.RawURLEncoding.EncodeToString

	t.Run("cached key set rejects malformed tokens", func(t *testing.T) {
		t.Parallel()

		keySet := &cachedOIDCKeySet{}
		for _, token := range []string{
			"only.two",
			"!!!." + encode([]byte("{}")) + ".sig",
			encode([]byte("not json")) + "." + encode([]byte("{}")) + ".sig",
		} {
			if _, err := keySet.VerifySignature(context.Background(), token); err == nil {
				t.Fatalf("malformed token %q verified", token)
			}
		}
	})

	t.Run("non-string issuer is rejected before routing", func(t *testing.T) {
		t.Parallel()

		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
		}))
		defer server.Close()

		authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
			{Issuer: server.URL, Audiences: []string{"zot"}, SkipIssuerVerification: true},
		}, log.NewTestLogger())
		if err != nil {
			t.Fatal(err)
		}
		token := encode([]byte(`{"alg":"RS256"}`)) + "." + encode([]byte(`{"iss":1}`)) + "." + encode([]byte("sig"))
		if _, err := authorizer.Authenticate(context.Background(), "Bearer "+token); err == nil {
			t.Fatal("token with a non-string issuer authenticated")
		}
		if requests.Load() != 0 {
			t.Fatal("token with a non-string issuer triggered discovery")
		}
	})

	t.Run("initial discovery gives up with the request", func(t *testing.T) {
		t.Parallel()

		hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer hanging.Close()
		_, header, _, _ := newOIDCOutageTestServer(t, hanging.URL)

		authorizer, err := NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{
			{Issuer: hanging.URL, Audiences: []string{"zot"}},
		}, log.NewTestLogger())
		if err != nil {
			t.Fatal(err)
		}
		// the request gives up first; the shorter client timeout only ends the background discovery sooner
		authorizer.providers[0].httpClient.Timeout = 500 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if _, err := authorizer.Authenticate(ctx, header); err == nil {
			t.Fatal("authentication succeeded while initial discovery hung")
		}
	})

	t.Run("JWKS fetch errors", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/truncated":
				// promise more than is sent, so reading the body fails
				w.Header().Set("Content-Length", "100")
				_, _ = w.Write([]byte("{"))
			case "/not-json":
				_, _ = w.Write([]byte("not json"))
			case "/bad-key":
				_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","n":"!!","e":"AQAB"}]}`))
			case "/unsupported-key":
				_, _ = w.Write([]byte(`{"keys":[{"kty":"OKP","crv":"Ed448","x":"AAAA"}]}`))
			}
		}))
		defer server.Close()

		provider, err := newOIDCProvider(&config.BearerOIDCConfig{Issuer: server.URL, Audiences: []string{"zot"}},
			log.NewTestLogger())
		if err != nil {
			t.Fatal(err)
		}
		for _, jwksURL := range []string{"://bad-url", server.URL + "/truncated", server.URL + "/not-json",
			server.URL + "/bad-key"} {
			if _, err := provider.fetchKeySet(context.Background(), jwksURL); err == nil {
				t.Fatalf("JWKS from %s was accepted", jwksURL)
			}
		}

		// like go-oidc, keys of a type go-jose does not support are skipped, not fatal
		keySet, err := provider.fetchKeySet(context.Background(), server.URL+"/unsupported-key")
		if err != nil {
			t.Fatal(err)
		}
		if len(keySet.keys) != 0 {
			t.Fatal("unsupported key was cached")
		}
	})
}

func TestNewBearerAuthCreatesOIDCBearerAuthorizer(t *testing.T) {
	t.Parallel()

	authConfig := &config.AuthConfig{Bearer: &config.BearerConfig{
		OIDC: config.BearerOIDCConfigs{{
			Issuer:    "https://issuer.example.com",
			Audiences: []string{"zot"},
		}},
	}}

	bearerAuth := NewBearerAuth(authConfig, log.NewTestLogger())
	if bearerAuth.oidc == nil {
		t.Fatal("expected OIDC bearer authorizer")
	}

	if bearerAuth.TokenExchangeHandler(nil) == nil {
		t.Fatal("expected OIDC bearer token exchange handler")
	}
}

func TestNewBearerAuthOIDCBearerAuthorizerInvalidConfigPanics(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for invalid OIDC bearer config")
		}
	}()

	NewBearerAuth(&config.AuthConfig{Bearer: &config.BearerConfig{
		OIDC: config.BearerOIDCConfigs{{
			Issuer:               "https://issuer.example.com",
			Audiences:            []string{"zot"},
			CertificateAuthority: "not a valid PEM certificate",
		}},
	}}, log.NewTestLogger())
}

func TestRouteSetupRegistersOIDCBearerTokenHandler(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.Auth = &config.AuthConfig{
		Bearer: &config.BearerConfig{
			OIDC: config.BearerOIDCConfigs{{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"zot"},
			}},
		},
	}

	ctlr := NewController(conf)
	ctlr.Router = mux.NewRouter()
	NewRouteHandler(ctlr)

	request := httptest.NewRequest(http.MethodOptions, constants.TokenPath, nil)
	response := httptest.NewRecorder()
	ctlr.Router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected token exchange OPTIONS status %d, got %d", http.StatusNoContent, response.Code)
	}
}
