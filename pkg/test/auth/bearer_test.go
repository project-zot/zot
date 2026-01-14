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
