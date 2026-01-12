package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"

	auth "zotregistry.dev/zot/v2/pkg/test/auth"
)

func TestBearerServer(t *testing.T) {
	Convey("test MakeAuthTestServer() no serve key", t, func() {
		So(func() { auth.MakeAuthTestServer("", "", "") }, ShouldPanic)
	})
}

func TestBearerServerLegacy(t *testing.T) {
	Convey("test MakeAuthTestServerLegacy() no serve key", t, func() {
		So(func() { auth.MakeAuthTestServerLegacy("", "") }, ShouldPanic)
	})
}

// doGet performs an HTTP GET request with context.
func doGet(url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	return http.DefaultClient.Do(req)
}

// doPost performs an HTTP POST request with context.
func doPost(url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}

// writeRSAPrivateKey writes an RSA private key to a file in PEM format.
func writeRSAPrivateKey(path string, privateKey *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(path, keyPEM, 0o600)
}

// writeECPrivateKey writes an EC private key to a file in PEM format.
func writeECPrivateKey(path string, privateKey *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(path, keyPEM, 0o600)
}

// writeEd25519PrivateKey writes an Ed25519 private key to a file in PEM format.
func writeEd25519PrivateKey(path string, privateKey ed25519.PrivateKey) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	return os.WriteFile(path, keyPEM, 0o600)
}

func TestLegacyTokenGeneration(t *testing.T) {
	Convey("test legacy token generation for backward compatibility", t, func() {
		// Create a temporary directory for test keys
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "server.key")

		// Generate an RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		// Write the private key to a file
		err = writeRSAPrivateKey(keyPath, privateKey)
		So(err, ShouldBeNil)

		Convey("legacy server should generate valid tokens", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			// Request a token with a scope
			resp, err := doGet(server.URL + "?scope=repository:test-repo:pull,push")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.AccessToken, ShouldNotBeEmpty)

			// Parse the token to verify its structure
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)
			So(token.Valid, ShouldBeTrue)

			// Verify the token has a 'kid' header (legacy format requirement)
			kid, ok := token.Header["kid"]
			So(ok, ShouldBeTrue)
			So(kid, ShouldNotBeEmpty)

			// Verify the signing method is RS256
			So(token.Method.Alg(), ShouldEqual, "RS256")

			// Verify claims structure
			claims, ok := token.Claims.(jwt.MapClaims)
			So(ok, ShouldBeTrue)

			// Check that iat and exp are numeric (legacy format)
			iat, ok := claims["iat"]
			So(ok, ShouldBeTrue)
			_, isFloat := iat.(float64)
			So(isFloat, ShouldBeTrue)

			exp, ok := claims["exp"]
			So(ok, ShouldBeTrue)
			_, isFloat = exp.(float64)
			So(isFloat, ShouldBeTrue)

			// Verify issuer and audience
			So(claims["iss"], ShouldEqual, "Zot")
			So(claims["aud"], ShouldEqual, "Zot Registry")

			// Verify access claim structure
			access, ok := claims["access"]
			So(ok, ShouldBeTrue)
			accessList, ok := access.([]any)
			So(ok, ShouldBeTrue)
			So(len(accessList), ShouldEqual, 1)

			accessEntry, ok := accessList[0].(map[string]any)
			So(ok, ShouldBeTrue)
			So(accessEntry["name"], ShouldEqual, "test-repo")
			So(accessEntry["type"], ShouldEqual, "repository")

			actions, ok := accessEntry["actions"].([]any)
			So(ok, ShouldBeTrue)
			So(len(actions), ShouldEqual, 2)
			So(actions[0], ShouldEqual, "pull")
			So(actions[1], ShouldEqual, "push")
		})

		Convey("legacy server should handle multiple scopes", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			// Request a token with multiple scopes
			resp, err := doGet(server.URL + "?scope=repository:repo1:pull&scope=repository:repo2:push")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)

			// Parse and verify the token has both access entries
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)

			claims, ok := token.Claims.(jwt.MapClaims)
			So(ok, ShouldBeTrue)

			access, ok := claims["access"].([]any)
			So(ok, ShouldBeTrue)
			So(len(access), ShouldEqual, 2)
		})

		Convey("legacy server should handle empty scopes", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			// Request a token with empty scope parameter
			resp, err := doGet(server.URL + "?scope=")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.AccessToken, ShouldNotBeEmpty)
		})

		Convey("legacy server should handle no scope parameter", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			// Request a token without any scope
			resp, err := doGet(server.URL)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.AccessToken, ShouldNotBeEmpty)
		})

		Convey("legacy server should deny unauthorized namespace", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			// Request a token for the unauthorized namespace
			resp, err := doGet(server.URL + "?scope=repository:unauthorized-repo:pull,push")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)

			// Parse and verify the token has empty actions for unauthorized repo
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)

			claims, ok := token.Claims.(jwt.MapClaims)
			So(ok, ShouldBeTrue)

			access, ok := claims["access"].([]any)
			So(ok, ShouldBeTrue)
			So(len(access), ShouldEqual, 1)

			accessEntry, ok := access[0].(map[string]any)
			So(ok, ShouldBeTrue)

			actions, ok := accessEntry["actions"].([]any)
			So(ok, ShouldBeTrue)
			So(len(actions), ShouldEqual, 0)
		})

		Convey("legacy server should reject non-GET requests", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			resp, err := doPost(server.URL)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusMethodNotAllowed)
			resp.Body.Close()
		})
	})
}

func TestNewTokenGeneration(t *testing.T) {
	Convey("test new token generation", t, func() {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "server.key")
		certPath := filepath.Join(tempDir, "server.crt")

		// Generate an RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		// Write the private key to a file
		err = writeRSAPrivateKey(keyPath, privateKey)
		So(err, ShouldBeNil)

		// Create a self-signed certificate
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "test",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(
			rand.Reader, template, template, &privateKey.PublicKey, privateKey,
		)
		So(err, ShouldBeNil)

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
		err = os.WriteFile(certPath, certPEM, 0o600)
		So(err, ShouldBeNil)

		Convey("new server should generate valid tokens", func() {
			server := auth.MakeAuthTestServer(keyPath, "RS256", "unauthorized-repo")
			defer server.Close()

			resp, err := doGet(server.URL + "?scope=repository:test-repo:pull,push")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.AccessToken, ShouldNotBeEmpty)

			// Parse and verify the token
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)
			So(token.Valid, ShouldBeTrue)
			So(token.Method.Alg(), ShouldEqual, "RS256")
		})

		Convey("new server should generate tokens without scope", func() {
			server := auth.MakeAuthTestServer(keyPath, "RS256", "unauthorized-repo")
			defer server.Close()

			resp, err := doGet(server.URL)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.AccessToken, ShouldNotBeEmpty)
		})

		Convey("new server should deny unauthorized namespace", func() {
			server := auth.MakeAuthTestServer(keyPath, "RS256", "unauthorized-repo")
			defer server.Close()

			resp, err := doGet(server.URL + "?scope=repository:unauthorized-repo:pull,push")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)

			// Parse and verify the token has empty actions
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)

			claims, ok := token.Claims.(jwt.MapClaims)
			So(ok, ShouldBeTrue)

			access, ok := claims["access"].([]any)
			So(ok, ShouldBeTrue)
			So(len(access), ShouldEqual, 1)

			accessEntry, ok := access[0].(map[string]any)
			So(ok, ShouldBeTrue)

			actions, ok := accessEntry["actions"].([]any)
			So(ok, ShouldBeTrue)
			So(len(actions), ShouldEqual, 0)
		})

		Convey("new server should reject non-GET requests", func() {
			server := auth.MakeAuthTestServer(keyPath, "RS256", "unauthorized-repo")
			defer server.Close()

			resp, err := doPost(server.URL)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusMethodNotAllowed)
			resp.Body.Close()
		})
	})
}

func TestTokenGenerationWithECKey(t *testing.T) {
	Convey("test token generation with EC key", t, func() {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "ec.key")

		// Generate an EC key pair (P-256)
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		So(err, ShouldBeNil)

		// Write the private key to a file
		err = writeECPrivateKey(keyPath, privateKey)
		So(err, ShouldBeNil)

		Convey("server should generate valid tokens with ES256", func() {
			server := auth.MakeAuthTestServer(keyPath, "ES256", "unauthorized-repo")
			defer server.Close()

			resp, err := doGet(server.URL + "?scope=repository:test-repo:pull")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.AccessToken, ShouldNotBeEmpty)

			// Parse and verify the token
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)
			So(token.Valid, ShouldBeTrue)
			So(token.Method.Alg(), ShouldEqual, "ES256")
		})
	})
}

func TestTokenGenerationWithEd25519Key(t *testing.T) {
	Convey("test token generation with Ed25519 key", t, func() {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "ed25519.key")

		// Generate an Ed25519 key pair
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		So(err, ShouldBeNil)

		// Write the private key to a file
		err = writeEd25519PrivateKey(keyPath, privateKey)
		So(err, ShouldBeNil)

		Convey("server should generate valid tokens with EdDSA", func() {
			server := auth.MakeAuthTestServer(keyPath, "EdDSA", "unauthorized-repo")
			defer server.Close()

			resp, err := doGet(server.URL + "?scope=repository:test-repo:pull")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)
			So(tokenResp.AccessToken, ShouldNotBeEmpty)

			// Parse and verify the token
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return privateKey.Public(), nil
			})
			So(err, ShouldBeNil)
			So(token.Valid, ShouldBeTrue)
			So(token.Method.Alg(), ShouldEqual, "EdDSA")
		})
	})
}

func TestLoadPrivateKeyFromFileErrors(t *testing.T) {
	Convey("test loadPrivateKeyFromFile error cases", t, func() {
		tempDir := t.TempDir()

		Convey("should panic on non-existent file", func() {
			So(func() {
				auth.MakeAuthTestServer("/nonexistent/path/key.pem", "RS256", "")
			}, ShouldPanic)
		})

		Convey("should panic on invalid key file", func() {
			invalidKeyPath := filepath.Join(tempDir, "invalid.key")
			err := os.WriteFile(invalidKeyPath, []byte("not a valid key"), 0o600)
			So(err, ShouldBeNil)

			So(func() {
				auth.MakeAuthTestServer(invalidKeyPath, "RS256", "")
			}, ShouldPanic)
		})
	})
}

func TestLoadRSAPrivateKeyFromFileErrors(t *testing.T) {
	Convey("test loadRSAPrivateKeyFromFile error cases", t, func() {
		tempDir := t.TempDir()

		Convey("should panic on non-existent file", func() {
			So(func() {
				auth.MakeAuthTestServerLegacy("/nonexistent/path/key.pem", "")
			}, ShouldPanic)
		})

		Convey("should panic on invalid RSA key file", func() {
			invalidKeyPath := filepath.Join(tempDir, "invalid.key")
			err := os.WriteFile(invalidKeyPath, []byte("not a valid RSA key"), 0o600)
			So(err, ShouldBeNil)

			So(func() {
				auth.MakeAuthTestServerLegacy(invalidKeyPath, "")
			}, ShouldPanic)
		})

		Convey("should panic on EC key file (not RSA)", func() {
			ecKeyPath := filepath.Join(tempDir, "ec.key")
			ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			So(err, ShouldBeNil)

			err = writeECPrivateKey(ecKeyPath, ecKey)
			So(err, ShouldBeNil)

			So(func() {
				auth.MakeAuthTestServerLegacy(ecKeyPath, "")
			}, ShouldPanic)
		})
	})
}

func TestParseBearerAuthHeader(t *testing.T) {
	Convey("test ParseBearerAuthHeader", t, func() {
		Convey("should parse valid bearer auth header", func() {
			header := `Bearer realm="https://auth.example.com/token",` +
				`service="registry.example.com",scope="repository:myrepo:pull"`
			parsed := auth.ParseBearerAuthHeader(header)

			So(parsed.Realm, ShouldEqual, "https://auth.example.com/token")
			So(parsed.Service, ShouldEqual, "registry.example.com")
			So(parsed.Scope, ShouldEqual, "repository:myrepo:pull")
		})

		Convey("should handle empty scope", func() {
			header := `Bearer realm="https://auth.example.com/token",` +
				`service="registry.example.com",scope=""`
			parsed := auth.ParseBearerAuthHeader(header)

			So(parsed.Realm, ShouldEqual, "https://auth.example.com/token")
			So(parsed.Service, ShouldEqual, "registry.example.com")
			So(parsed.Scope, ShouldEqual, "")
		})

		Convey("should handle header with only realm", func() {
			header := `Bearer realm="https://auth.example.com/token"`
			parsed := auth.ParseBearerAuthHeader(header)

			So(parsed.Realm, ShouldEqual, "https://auth.example.com/token")
			So(parsed.Service, ShouldEqual, "")
			So(parsed.Scope, ShouldEqual, "")
		})

		Convey("should handle empty header", func() {
			header := ""
			parsed := auth.ParseBearerAuthHeader(header)

			So(parsed.Realm, ShouldEqual, "")
			So(parsed.Service, ShouldEqual, "")
			So(parsed.Scope, ShouldEqual, "")
		})
	})
}

func TestLegacyClaimsInterface(t *testing.T) {
	Convey("test legacyClaims jwt.Claims interface methods", t, func() {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "server.key")

		// Generate an RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		err = writeRSAPrivateKey(keyPath, privateKey)
		So(err, ShouldBeNil)

		Convey("claims methods should be called during token validation", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			resp, err := doGet(server.URL + "?scope=repository:test-repo:pull")
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)

			// Parse with claims validation - this exercises all the Get* methods
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			}, jwt.WithExpirationRequired(), jwt.WithIssuedAt())
			So(err, ShouldBeNil)
			So(token.Valid, ShouldBeTrue)

			// Verify claims are accessible
			claims, ok := token.Claims.(jwt.MapClaims)
			So(ok, ShouldBeTrue)
			So(claims["iss"], ShouldEqual, "Zot")
			So(claims["aud"], ShouldEqual, "Zot Registry")

			// Verify iat and exp exist and are valid
			iat, ok := claims["iat"]
			So(ok, ShouldBeTrue)
			So(iat, ShouldNotBeNil)

			exp, ok := claims["exp"]
			So(ok, ShouldBeTrue)
			So(exp, ShouldNotBeNil)
		})
	})
}

func TestLegacyClaimsWithZeroValues(t *testing.T) {
	Convey("test legacy claims with zero/empty values", t, func() {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "server.key")

		// Generate an RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		err = writeRSAPrivateKey(keyPath, privateKey)
		So(err, ShouldBeNil)

		Convey("token without scope should have empty access", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			// Request without scope - tests empty claims paths
			resp, err := doGet(server.URL)
			So(err, ShouldBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			defer resp.Body.Close()

			var tokenResp auth.AccessTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResp)
			So(err, ShouldBeNil)

			// Parse and verify
			token, err := jwt.Parse(tokenResp.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)
			So(token.Valid, ShouldBeTrue)

			claims, ok := token.Claims.(jwt.MapClaims)
			So(ok, ShouldBeTrue)

			// Access should be nil or empty when no scope provided
			access := claims["access"]
			So(access, ShouldBeNil)
		})
	})
}

func TestKeyIDGeneration(t *testing.T) {
	Convey("test KID generation consistency", t, func() {
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "server.key")

		// Generate an RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		err = writeRSAPrivateKey(keyPath, privateKey)
		So(err, ShouldBeNil)

		Convey("same key should produce same KID", func() {
			server := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server.Close()

			// Get first token
			resp1, err := doGet(server.URL + "?scope=repository:repo1:pull")
			So(err, ShouldBeNil)
			defer resp1.Body.Close()

			var tokenResp1 auth.AccessTokenResponse
			err = json.NewDecoder(resp1.Body).Decode(&tokenResp1)
			So(err, ShouldBeNil)

			token1, err := jwt.Parse(tokenResp1.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)

			// Get second token
			resp2, err := doGet(server.URL + "?scope=repository:repo2:push")
			So(err, ShouldBeNil)
			defer resp2.Body.Close()

			var tokenResp2 auth.AccessTokenResponse
			err = json.NewDecoder(resp2.Body).Decode(&tokenResp2)
			So(err, ShouldBeNil)

			token2, err := jwt.Parse(tokenResp2.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)

			// KIDs should be identical for the same key
			kid1 := token1.Header["kid"]
			kid2 := token2.Header["kid"]
			So(kid1, ShouldEqual, kid2)
		})

		Convey("different keys should produce different KIDs", func() {
			// Create second key
			keyPath2 := filepath.Join(tempDir, "server2.key")
			privateKey2, err := rsa.GenerateKey(rand.Reader, 2048)
			So(err, ShouldBeNil)

			err = writeRSAPrivateKey(keyPath2, privateKey2)
			So(err, ShouldBeNil)

			server1 := auth.MakeAuthTestServerLegacy(keyPath, "unauthorized-repo")
			defer server1.Close()

			server2 := auth.MakeAuthTestServerLegacy(keyPath2, "unauthorized-repo")
			defer server2.Close()

			// Get token from first server
			resp1, err := doGet(server1.URL + "?scope=repository:repo:pull")
			So(err, ShouldBeNil)
			defer resp1.Body.Close()

			var tokenResp1 auth.AccessTokenResponse
			err = json.NewDecoder(resp1.Body).Decode(&tokenResp1)
			So(err, ShouldBeNil)

			token1, err := jwt.Parse(tokenResp1.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			})
			So(err, ShouldBeNil)

			// Get token from second server
			resp2, err := doGet(server2.URL + "?scope=repository:repo:pull")
			So(err, ShouldBeNil)
			defer resp2.Body.Close()

			var tokenResp2 auth.AccessTokenResponse
			err = json.NewDecoder(resp2.Body).Decode(&tokenResp2)
			So(err, ShouldBeNil)

			token2, err := jwt.Parse(tokenResp2.AccessToken, func(token *jwt.Token) (any, error) {
				return &privateKey2.PublicKey, nil
			})
			So(err, ShouldBeNil)

			// KIDs should be different for different keys
			kid1 := token1.Header["kid"]
			kid2 := token2.Header["kid"]
			So(kid1, ShouldNotEqual, kid2)
		})
	})
}
