//go:build sync

package sync_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

func writeAssertionFile(t *testing.T, content string) string {
	t.Helper()

	assertionFile := filepath.Join(t.TempDir(), "assertion.jwt")
	if err := os.WriteFile(assertionFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write assertion file: %v", err)
	}

	return assertionFile
}

func writeKeyFile(t *testing.T, content string) string {
	t.Helper()

	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	return keyFile
}

func writeSigningFile(t *testing.T, config map[string]any) string {
	t.Helper()

	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal signing config: %v", err)
	}

	signingFile := filepath.Join(t.TempDir(), "signing-config.json")
	if err := os.WriteFile(signingFile, raw, 0o600); err != nil {
		t.Fatalf("failed to write signing config file: %v", err)
	}

	return signingFile
}

func generateRSAKeyPEM(t *testing.T) (privateKeyPEM string, publicKey *rsa.PublicKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})

	return string(pemBytes), &key.PublicKey
}

// defaultsigningFile writes a minimal RS256 signing config and returns its path
// together with the public key needed to verify the minted assertions.
func defaultsigningFile(t *testing.T) (signingFile string, publicKey *rsa.PublicKey) {
	t.Helper()

	privateKeyPEM, publicKey := generateRSAKeyPEM(t)
	signingFile = writeSigningFile(t, map[string]any{
		"privateKeyFile": writeKeyFile(t, privateKeyPEM),
		"algorithm":      "RS256",
	})

	return signingFile, publicKey
}

// parseAssertion verifies the minted assertion against the public key and returns its claims.
func parseAssertion(t *testing.T, assertion string, publicKey *rsa.PublicKey) (*jwt.Token, jwt.MapClaims) {
	t.Helper()

	token, err := jwt.Parse(assertion, func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse the minted assertion: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", token.Claims)
	}

	return token, claims
}

func TestOAuth2CredentialsHelper(t *testing.T) {
	Convey("Test OAuth2 Credentials Helper", t, func() {
		registryURL := "https://registry.example.com"
		remoteAddress := sync.StripRegistryTransport(registryURL)

		Convey("Validation of required fields", func() {
			signingFile, _ := defaultsigningFile(t)
			assertionFile := writeAssertionFile(t, "the-jwt-assertion")

			_, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(), nil)
			So(err, ShouldNotBeNil)

			// missing tokenURL
			_, err = sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{SigningFile: signingFile})
			So(err, ShouldNotBeNil)

			// missing both assertion sources
			_, err = sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{TokenURL: "https://idp.example.com/token"})
			So(err, ShouldNotBeNil)

			// assertionFile and signingFile are mutually exclusive
			_, err = sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:      "https://idp.example.com/token",
					AssertionFile: assertionFile,
					SigningFile:   signingFile,
				})
			So(err, ShouldNotBeNil)
		})

		Convey("Token retrieval reads a pre-signed assertion from a file", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			assertionFile := writeAssertionFile(t, "the-jwt-assertion\n")

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:      server.URL,
					AssertionFile: assertionFile,
					ClientID:      "the-client",
				})
			So(err, ShouldBeNil)

			creds, err := credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(creds[remoteAddress].Password, ShouldEqual, "the-access-token")

			// the file contents are sent verbatim (trimmed) as the client_assertion
			So(receivedBody.Get("client_assertion"), ShouldEqual, "the-jwt-assertion")
		})

		Convey("Error when the assertion file is missing", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:      "https://idp.example.com/token",
					AssertionFile: filepath.Join(t.TempDir(), "does-not-exist.jwt"),
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Token retrieval mints and exchanges a signed assertion", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","token_type":"Bearer","expires_in":3600}`))
			}))
			defer server.Close()

			signingFile, publicKey := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:    server.URL,
					SigningFile: signingFile,
					ClientID:    "the-client",
					Scopes:      []string{"repository:pull"},
				})
			So(err, ShouldBeNil)

			creds, err := credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(creds[remoteAddress].Username, ShouldEqual, "<token>")
			So(creds[remoteAddress].Password, ShouldEqual, "the-access-token")
			So(credentialHelper.AreCredentialsValid(remoteAddress), ShouldBeTrue)

			// the minted assertion is sent as a client_assertion by default
			So(receivedBody.Get("grant_type"), ShouldEqual, "client_credentials")
			So(receivedBody.Get("client_id"), ShouldEqual, "the-client")
			So(receivedBody.Get("scope"), ShouldEqual, "repository:pull")

			_, claims := parseAssertion(t, receivedBody.Get("client_assertion"), publicKey)
			// issuer and subject default to the clientID, audience defaults to the tokenURL
			So(claims["iss"], ShouldEqual, "the-client")
			So(claims["sub"], ShouldEqual, "the-client")
			So(claims["aud"], ShouldEqual, server.URL)
			So(claims["jti"], ShouldNotBeEmpty)
		})

		Convey("Each minted assertion is single-use with a unique jti", func() {
			var assertions []string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				assertions = append(assertions, r.Form.Get("client_assertion"))

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			signingFile, publicKey := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{TokenURL: server.URL, SigningFile: signingFile})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			_, err = credentialHelper.RefreshCredentials(remoteAddress)
			So(err, ShouldBeNil)

			So(assertions, ShouldHaveLength, 2)
			So(assertions[0], ShouldNotEqual, assertions[1])

			_, first := parseAssertion(t, assertions[0], publicKey)
			_, second := parseAssertion(t, assertions[1], publicKey)
			So(first["jti"], ShouldNotEqual, second["jti"])
		})

		Convey("jwt-bearer grant sends the assertion parameter", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			signingFile, publicKey := defaultsigningFile(t)
			secretFile := filepath.Join(t.TempDir(), "client-secret")
			So(os.WriteFile(secretFile, []byte("the-secret\n"), 0o600), ShouldBeNil)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:         server.URL,
					SigningFile:      signingFile,
					GrantType:        "urn:ietf:params:oauth:grant-type:jwt-bearer",
					ClientID:         "the-client",
					ClientSecretFile: secretFile,
					Username:         "robot",
				})
			So(err, ShouldBeNil)

			creds, err := credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(creds[remoteAddress].Username, ShouldEqual, "robot")
			So(receivedBody.Get("grant_type"), ShouldEqual, "urn:ietf:params:oauth:grant-type:jwt-bearer")
			So(receivedBody.Get("client_id"), ShouldEqual, "the-client")
			So(receivedBody.Get("client_secret"), ShouldEqual, "the-secret")

			_, claims := parseAssertion(t, receivedBody.Get("assertion"), publicKey)
			So(claims["jti"], ShouldNotBeEmpty)
		})

		Convey("Signing config claims override the defaults", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			privateKeyPEM, publicKey := generateRSAKeyPEM(t)
			signingFile := writeSigningFile(t, map[string]any{
				"privateKeyFile": writeKeyFile(t, privateKeyPEM),
				"algorithm":      "RS256",
				"keyId":          "the-key-id",
				"issuer":         "custom-issuer",
				"subject":        "custom-subject",
				"audience":       "https://idp.example.com/oauth2/token",
			})

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:    server.URL,
					SigningFile: signingFile,
					ClientID:    "the-client",
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)

			token, claims := parseAssertion(t, receivedBody.Get("client_assertion"), publicKey)
			So(token.Header["kid"], ShouldEqual, "the-key-id")
			So(claims["iss"], ShouldEqual, "custom-issuer")
			So(claims["sub"], ShouldEqual, "custom-subject")
			So(claims["aud"], ShouldEqual, "https://idp.example.com/oauth2/token")
		})

		Convey("Signing key can be loaded from a separate file", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			privateKeyPEM, _ := generateRSAKeyPEM(t)
			keyFile := filepath.Join(t.TempDir(), "signing-key.pem")
			So(os.WriteFile(keyFile, []byte(privateKeyPEM), 0o600), ShouldBeNil)

			signingFile := writeSigningFile(t, map[string]any{
				"privateKeyFile": keyFile,
				"algorithm":      "RS256",
			})

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:    server.URL,
					SigningFile: signingFile,
				})
			So(err, ShouldBeNil)

			creds, err := credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(creds[remoteAddress].Password, ShouldEqual, "the-access-token")
		})

		Convey("Client secret is read from a file when configured", func() {
			var receivedBody url.Values

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				receivedBody = r.Form

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"access_token":"the-access-token","expires_in":3600}`))
			}))
			defer server.Close()

			signingFile, _ := defaultsigningFile(t)
			secretFile := filepath.Join(t.TempDir(), "client-secret")
			So(os.WriteFile(secretFile, []byte("file-secret\n"), 0o600), ShouldBeNil)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:         server.URL,
					SigningFile:      signingFile,
					ClientSecretFile: secretFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldBeNil)
			So(receivedBody.Get("client_secret"), ShouldEqual, "file-secret")
		})

		Convey("Error when the signing algorithm is unsupported", func() {
			privateKeyPEM, _ := generateRSAKeyPEM(t)
			signingFile := writeSigningFile(t, map[string]any{
				"privateKey": privateKeyPEM,
				"algorithm":  "NOPE",
			})

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:    "https://idp.example.com/token",
					SigningFile: signingFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the signing key is missing", func() {
			signingFile := writeSigningFile(t, map[string]any{
				"algorithm": "RS256",
			})

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:    "https://idp.example.com/token",
					SigningFile: signingFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the signing key is not valid PEM", func() {
			signingFile := writeSigningFile(t, map[string]any{
				"privateKey": "not-a-pem-key",
				"algorithm":  "RS256",
			})

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:    "https://idp.example.com/token",
					SigningFile: signingFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the signing config file is missing", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:    "https://idp.example.com/token",
					SigningFile: filepath.Join(t.TempDir(), "missing.json"),
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on non-200 from the token endpoint", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "invalid_grant", http.StatusBadRequest)
			}))
			defer server.Close()

			signingFile, _ := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{TokenURL: server.URL, SigningFile: signingFile})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the token endpoint returns an empty access token", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3600}`))
			}))
			defer server.Close()

			signingFile, _ := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{TokenURL: server.URL, SigningFile: signingFile})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the token endpoint returns invalid JSON", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`not-json`))
			}))
			defer server.Close()

			signingFile, _ := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{TokenURL: server.URL, SigningFile: signingFile})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the token endpoint is unreachable", func() {
			signingFile, _ := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				&syncconf.OAuth2HelperConfig{
					TokenURL:    "http://127.0.0.1:1/token",
					SigningFile: signingFile,
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Error when the client secret file is missing", func() {
			signingFile, _ := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:         "https://idp.example.com/token",
					SigningFile:      signingFile,
					ClientSecretFile: filepath.Join(t.TempDir(), "no-secret"),
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.GetCredentials([]string{registryURL})
			So(err, ShouldNotBeNil)
		})

		Convey("Credentials are invalid when no token is cached or it expired", func() {
			signingFile, _ := defaultsigningFile(t)

			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:    "https://idp.example.com/token",
					SigningFile: signingFile,
				})
			So(err, ShouldBeNil)

			So(credentialHelper.AreCredentialsValid(remoteAddress), ShouldBeFalse)
		})

		Convey("RefreshCredentials fails when the signing config file is missing", func() {
			credentialHelper, err := sync.NewOAuth2CredentialHelper(log.NewTestLogger(),
				//nolint:gosec // test token endpoint URL, not a credential
				&syncconf.OAuth2HelperConfig{
					TokenURL:    "https://idp.example.com/token",
					SigningFile: filepath.Join(t.TempDir(), "does-not-exist.json"),
				})
			So(err, ShouldBeNil)

			_, err = credentialHelper.RefreshCredentials(remoteAddress)
			So(err, ShouldNotBeNil)
		})
	})
}
