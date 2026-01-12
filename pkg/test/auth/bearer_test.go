package auth_test

import (
	"context"
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

func TestLegacyTokenGeneration(t *testing.T) {
	Convey("test legacy token generation for backward compatibility", t, func() {
		// Create a temporary directory for test keys
		tempDir := t.TempDir()
		keyPath := filepath.Join(tempDir, "server.key")

		// Generate an RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		// Write the private key to a file
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		})
		err = os.WriteFile(keyPath, keyPEM, 0o600)
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
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		})
		err = os.WriteFile(keyPath, keyPEM, 0o600)
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
	})
}
