package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

// mockOIDCServer creates a mock OIDC provider server for testing.
func mockOIDCServer(t *testing.T, pubKey *rsa.PublicKey) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// OpenID configuration endpoint
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		config := map[string]any{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
		}

		_ = json.NewEncoder(w).Encode(config)
	})

	// JWKS endpoint
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Create JWK from public key
		jwk := jose.JSONWebKey{
			Key:       pubKey,
			KeyID:     "test-key-id",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}

		jwks := map[string]any{
			"keys": []jose.JSONWebKey{jwk},
		}

		_ = json.NewEncoder(w).Encode(jwks)
	})

	return httptest.NewServer(mux)
}

// createTestOIDCToken creates a test OIDC ID token.
func createTestOIDCToken(privKey *rsa.PrivateKey, issuer, audience, subject string,
	claims map[string]any,
) (string, error) {
	now := time.Now()

	tokenClaims := jwt.MapClaims{
		"iss": issuer,
		"aud": audience,
		"sub": subject,
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	// Add additional claims
	maps.Copy(tokenClaims, claims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	token.Header["kid"] = "test-key-id"

	return token.SignedString(privKey)
}

func TestOIDCBearerAuthorizer(t *testing.T) {
	Convey("Test OIDC bearer token authorization", t, func() {
		// Generate test keys
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		So(err, ShouldBeNil)

		pubKey := &privKey.PublicKey

		// Start mock OIDC server
		server := mockOIDCServer(t, pubKey)
		defer server.Close()

		issuer := server.URL
		audience := "test-zot"

		logger := log.NewLogger("debug", "")

		Convey("Configuration validation", func() {
			ctx := context.Background()

			Convey("Nil config should fail", func() {
				_, err := api.NewOIDCBearerAuthorizer(ctx, nil, logger)
				So(err, ShouldNotBeNil)
			})

			Convey("Empty issuer should fail", func() {
				cfg := &config.BearerOIDCConfig{
					Audiences: []string{audience},
				}
				_, err := api.NewOIDCBearerAuthorizer(ctx, cfg, logger)
				So(err, ShouldNotBeNil)
			})

			Convey("Empty audiences should fail", func() {
				cfg := &config.BearerOIDCConfig{
					Issuer:    issuer,
					Audiences: []string{},
				}
				_, err := api.NewOIDCBearerAuthorizer(ctx, cfg, logger)
				So(err, ShouldNotBeNil)
			})

			Convey("Valid config should succeed", func() {
				cfg := &config.BearerOIDCConfig{
					Issuer:    issuer,
					Audiences: []string{audience},
				}
				authorizer, err := api.NewOIDCBearerAuthorizer(ctx, cfg, logger)
				So(err, ShouldBeNil)
				So(authorizer, ShouldNotBeNil)
			})
		})

		Convey("Token authentication", func() {
			cfg := &config.BearerOIDCConfig{
				Issuer:    issuer,
				Audiences: []string{audience},
			}

			ctx := context.Background()
			authorizer, err := api.NewOIDCBearerAuthorizer(ctx, cfg, logger)
			So(err, ShouldBeNil)

			Convey("Empty header should fail", func() {
				username, groups, err := authorizer.Authenticate(ctx, "")
				So(err, ShouldNotBeNil)
				So(username, ShouldEqual, "")
				So(groups, ShouldBeEmpty)
			})

			Convey("Invalid token format should fail", func() {
				username, groups, err := authorizer.Authenticate(ctx, "Bearer invalid-token")
				So(err, ShouldNotBeNil)
				So(username, ShouldEqual, "")
				So(groups, ShouldBeEmpty)
			})

			Convey("Valid token with default claims", func() {
				subject := "test-user" //nolint:goconst
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, groups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(username, ShouldEqual, subject)
				So(groups, ShouldBeEmpty)
			})

			Convey("Valid token with groups", func() {
				subject := "test-user"
				testGroups := []string{"group1", "group2"}

				token, err := createTestOIDCToken(privKey, issuer, audience, subject, map[string]any{
					"groups": testGroups,
				})
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, extractedGroups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(username, ShouldEqual, subject)
				So(extractedGroups, ShouldResemble, testGroups)
			})

			Convey("Token with wrong audience should fail", func() {
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, "wrong-audience", subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, groups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldNotBeNil)
				So(username, ShouldEqual, "")
				So(groups, ShouldBeEmpty)
			})

			Convey("Expired token should fail", func() {
				now := time.Now()
				subject := "test-user"

				tokenClaims := jwt.MapClaims{
					"iss": issuer,
					"aud": audience,
					"sub": subject,
					"exp": now.Add(-time.Hour).Unix(), // Expired
					"iat": now.Add(-2 * time.Hour).Unix(),
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privKey)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + tokenString

				username, groups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldNotBeNil)
				So(username, ShouldEqual, "")
				So(groups, ShouldBeEmpty)
			})
		})

		Convey("Custom claim mapping", func() {
			customClaimName := "preferred_username"
			customUsername := "custom-user"

			cfg := &config.BearerOIDCConfig{
				Issuer:    issuer,
				Audiences: []string{audience},
				ClaimMapping: &config.ClaimMapping{
					Username: customClaimName,
				},
			}

			ctx := context.Background()
			authorizer, err := api.NewOIDCBearerAuthorizer(ctx, cfg, logger)
			So(err, ShouldBeNil)

			Convey("Extract username from custom claim", func() {
				subject := "original-sub"

				token, err := createTestOIDCToken(privKey, issuer, audience, subject, map[string]any{
					customClaimName: customUsername,
				})
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, groups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(username, ShouldEqual, customUsername)
				So(groups, ShouldBeEmpty)
			})

			Convey("Fallback to sub when custom claim missing", func() {
				subject := "fallback-user"
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, groups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(username, ShouldEqual, subject)
				So(groups, ShouldBeEmpty)
			})
		})

		Convey("Multiple audiences", func() {
			audiences := []string{"audience1", "audience2", "audience3"}

			cfg := &config.BearerOIDCConfig{
				Issuer:    issuer,
				Audiences: audiences,
			}

			ctx := context.Background()
			authorizer, err := api.NewOIDCBearerAuthorizer(ctx, cfg, logger)
			So(err, ShouldBeNil)

			Convey("Token with first audience should work", func() {
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audiences[0], subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, groups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(username, ShouldEqual, subject)
				So(groups, ShouldBeEmpty)
			})

			Convey("Token with second audience should work", func() {
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audiences[1], subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, groups, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(username, ShouldEqual, subject)
				So(groups, ShouldBeEmpty)
			})
		})
	})
}

func TestBearerOIDCConfig(t *testing.T) {
	Convey("Test Bearer OIDC configuration", t, func() {
		Convey("IsBearerAuthEnabled with OIDC config", func() {
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: &config.BearerOIDCConfig{
						Issuer:    "https://issuer.example.com",
						Audiences: []string{"zot"},
					},
				},
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeTrue)
		})

		Convey("IsBearerAuthEnabled with traditional bearer", func() {
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   "zot",
					Service: "zot-service",
					Cert:    "/path/to/cert",
				},
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeTrue)
		})

		Convey("IsBearerAuthEnabled with both", func() {
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   "zot",
					Service: "zot-service",
					Cert:    "/path/to/cert",
					OIDC: &config.BearerOIDCConfig{
						Issuer:    "https://issuer.example.com",
						Audiences: []string{"zot"},
					},
				},
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeTrue)
		})

		Convey("IsBearerAuthEnabled without proper config", func() {
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: &config.BearerOIDCConfig{
						Issuer: "https://issuer.example.com",
						// Missing audiences
					},
				},
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("IsBearerAuthEnabled with nil bearer", func() {
			authConfig := &config.AuthConfig{
				Bearer: nil,
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeFalse)
		})
	})
}
