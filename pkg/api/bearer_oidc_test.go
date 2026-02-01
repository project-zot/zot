package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		"aud": []string{audience}, // Must be a slice for CEL processing
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
			Convey("Empty config slice creates authorizer with no providers", func() {
				authorizer, err := api.NewOIDCBearerAuthorizer([]config.BearerOIDCConfig{}, logger)
				So(err, ShouldBeNil)
				So(authorizer, ShouldNotBeNil)
				// But authentication will always fail
				result, err := authorizer.Authenticate(context.Background(), "Bearer token")
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
			})

			Convey("Empty issuer should fail", func() {
				cfg := []config.BearerOIDCConfig{{
					Audiences: []string{audience},
				}}
				_, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldNotBeNil)
			})

			Convey("Empty audiences should fail", func() {
				cfg := []config.BearerOIDCConfig{{
					Issuer:    issuer,
					Audiences: []string{},
				}}
				_, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldNotBeNil)
			})

			Convey("Valid config should succeed", func() {
				cfg := []config.BearerOIDCConfig{{
					Issuer:    issuer,
					Audiences: []string{audience},
				}}
				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)
				So(authorizer, ShouldNotBeNil)
			})
		})

		Convey("Token authentication", func() {
			cfg := []config.BearerOIDCConfig{{
				Issuer:    issuer,
				Audiences: []string{audience},
			}}

			ctx := context.Background()
			authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldBeNil)

			Convey("Empty header should fail", func() {
				result, err := authorizer.Authenticate(ctx, "")
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
			})

			Convey("Invalid token format should fail", func() {
				result, err := authorizer.Authenticate(ctx, "Bearer invalid-token")
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
			})

			Convey("Valid token with default claims", func() {
				subject := "test-user" //nolint:goconst
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, issuer+"/"+subject)
				So(result.Groups, ShouldBeEmpty)
			})

			Convey("Valid token with groups", func() {
				subject := "test-user"
				testGroups := []string{"group1", "group2"}

				cfg := []config.BearerOIDCConfig{{
					Issuer:    issuer,
					Audiences: []string{audience},
					ClaimMapping: &config.CELClaimValidationAndMapping{
						Groups: "claims.groups",
					},
				}}
				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)

				token, err := createTestOIDCToken(privKey, issuer, audience, subject, map[string]any{
					"groups": testGroups,
				})
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, issuer+"/"+subject)
				So(result.Groups, ShouldResemble, testGroups)
			})

			Convey("Token with wrong audience should fail", func() {
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, "wrong-audience", subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
			})

			Convey("Expired token should fail", func() {
				now := time.Now()
				subject := "test-user"

				tokenClaims := jwt.MapClaims{
					"iss": issuer,
					"aud": []string{audience},
					"sub": subject,
					"exp": now.Add(-time.Hour).Unix(), // Expired
					"iat": now.Add(-2 * time.Hour).Unix(),
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
				token.Header["kid"] = "test-key-id"
				tokenString, err := token.SignedString(privKey)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + tokenString

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
			})
		})

		Convey("Custom claim mapping", func() {
			customClaimName := "preferred_username"
			customUsername := "custom-user"

			cfg := []config.BearerOIDCConfig{{
				Issuer:    issuer,
				Audiences: []string{audience},
				ClaimMapping: &config.CELClaimValidationAndMapping{
					Username: "claims.preferred_username",
				},
			}}

			ctx := context.Background()
			authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldBeNil)

			Convey("Extract username from custom claim", func() {
				subject := "original-sub"

				token, err := createTestOIDCToken(privKey, issuer, audience, subject, map[string]any{
					customClaimName: customUsername,
				})
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, customUsername)
				So(result.Groups, ShouldBeEmpty)
			})

			Convey("Error when custom claim missing (no fallback)", func() {
				subject := "fallback-user"
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				// With CEL expressions, missing claims cause an error (no automatic fallback)
				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
			})
		})

		Convey("Multiple audiences", func() {
			audiences := []string{"audience1", "audience2", "audience3"}

			cfg := []config.BearerOIDCConfig{{
				Issuer:    issuer,
				Audiences: audiences,
			}}

			ctx := context.Background()
			authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldBeNil)

			Convey("Token with first audience should work", func() {
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audiences[0], subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, issuer+"/"+subject)
				So(result.Groups, ShouldBeEmpty)
			})

			Convey("Token with second audience should work", func() {
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audiences[1], subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, issuer+"/"+subject)
				So(result.Groups, ShouldBeEmpty)
			})
		})

		Convey("Multiple OIDC providers", func() {
			ctx := context.Background()

			// Create a second mock server with a different key
			privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
			So(err, ShouldBeNil)
			pubKey2 := &privKey2.PublicKey
			server2 := mockOIDCServer(t, pubKey2)
			defer server2.Close()

			issuer2 := server2.URL
			audience2 := "test-zot-2"

			Convey("Token valid for second provider succeeds", func() {
				// Configure two providers - token is only valid for the second one
				cfg := []config.BearerOIDCConfig{
					{
						Issuer:    issuer,
						Audiences: []string{audience},
					},
					{
						Issuer:    issuer2,
						Audiences: []string{audience2},
					},
				}

				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)

				// Create token for second provider
				subject := "test-user"
				token, err := createTestOIDCToken(privKey2, issuer2, audience2, subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, issuer2+"/"+subject)
			})

			Convey("Token valid for first provider succeeds immediately", func() {
				cfg := []config.BearerOIDCConfig{
					{
						Issuer:    issuer,
						Audiences: []string{audience},
					},
					{
						Issuer:    issuer2,
						Audiences: []string{audience2},
					},
				}

				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)

				// Create token for first provider
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, issuer+"/"+subject)
			})

			Convey("Token invalid for all providers returns aggregated errors", func() {
				cfg := []config.BearerOIDCConfig{
					{
						Issuer:    issuer,
						Audiences: []string{audience},
					},
					{
						Issuer:    issuer2,
						Audiences: []string{audience2},
					},
				}

				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)

				// Create token with wrong audience for both providers
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, "wrong-audience", subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
				// Error should contain information from both providers
				So(err.Error(), ShouldContainSubstring, "invalid bearer token")
			})
		})

		Convey("AuthenticateRequest convenience method", func() {
			cfg := []config.BearerOIDCConfig{{
				Issuer:    issuer,
				Audiences: []string{audience},
			}}

			ctx := context.Background()
			authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldBeNil)

			Convey("Successful authentication returns username, groups, and true", func() {
				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, nil)
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				username, groups, ok, err := authorizer.AuthenticateRequest(ctx, authHeader)
				So(err, ShouldBeNil)
				So(ok, ShouldBeTrue)
				So(username, ShouldEqual, issuer+"/"+subject)
				So(groups, ShouldBeEmpty)
			})

			Convey("Failed authentication returns false and error", func() {
				result, groups, ok, err := authorizer.AuthenticateRequest(ctx, "Bearer invalid-token")
				So(err, ShouldNotBeNil)
				So(ok, ShouldBeFalse)
				So(result, ShouldBeEmpty)
				So(groups, ShouldBeEmpty)
			})
		})

		Convey("CEL validations", func() {
			ctx := context.Background()

			Convey("Validation passes when expression is true", func() {
				cfg := []config.BearerOIDCConfig{{
					Issuer:    issuer,
					Audiences: []string{audience},
					ClaimMapping: &config.CELClaimValidationAndMapping{
						Validations: []config.CELValidation{
							{
								Expression: "claims.email_verified == true",
								Message:    "email must be verified",
							},
						},
					},
				}}

				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)

				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, map[string]any{
					"email_verified": true,
				})
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, issuer+"/"+subject)
			})

			Convey("Validation fails when expression is false", func() {
				cfg := []config.BearerOIDCConfig{{
					Issuer:    issuer,
					Audiences: []string{audience},
					ClaimMapping: &config.CELClaimValidationAndMapping{
						Validations: []config.CELValidation{
							{
								Expression: "claims.email_verified == true",
								Message:    "email must be verified",
							},
						},
					},
				}}

				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)

				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, map[string]any{
					"email_verified": false,
				})
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldNotBeNil)
				So(result, ShouldBeNil)
				So(err.Error(), ShouldContainSubstring, "email must be verified")
			})

			Convey("CEL variables can be used in validations and username", func() {
				cfg := []config.BearerOIDCConfig{{
					Issuer:    issuer,
					Audiences: []string{audience},
					ClaimMapping: &config.CELClaimValidationAndMapping{
						Variables: []config.CELVariable{
							{
								Name:       "org",
								Expression: "claims.organization",
							},
						},
						Validations: []config.CELValidation{
							{
								Expression: "vars.org in ['allowed-org', 'another-org']",
								Message:    "organization not allowed",
							},
						},
						Username: "vars.org + '/' + claims.sub",
					},
				}}

				authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
				So(err, ShouldBeNil)

				subject := "test-user"
				token, err := createTestOIDCToken(privKey, issuer, audience, subject, map[string]any{
					"organization": "allowed-org",
				})
				So(err, ShouldBeNil)

				authHeader := "Bearer " + token

				result, err := authorizer.Authenticate(ctx, authHeader)
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Username, ShouldEqual, "allowed-org/test-user")
			})
		})
	})
}

func TestBearerOIDCConfig(t *testing.T) {
	Convey("Test Bearer OIDC configuration", t, func() {
		Convey("IsBearerAuthEnabled with OIDC config", func() {
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    "https://issuer.example.com",
						Audiences: []string{"zot"},
					}},
				},
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeTrue)
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeTrue)
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)
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
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeTrue)
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("IsBearerAuthEnabled with both", func() {
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   "zot",
					Service: "zot-service",
					Cert:    "/path/to/cert",
					OIDC: []config.BearerOIDCConfig{{
						Issuer:    "https://issuer.example.com",
						Audiences: []string{"zot"},
					}},
				},
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeTrue)
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeTrue)
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeTrue)
		})

		Convey("IsBearerAuthEnabled without proper config", func() {
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					OIDC: []config.BearerOIDCConfig{{
						Issuer: "https://issuer.example.com",
						// Missing audiences
					}},
				},
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("IsBearerAuthEnabled with nil bearer", func() {
			authConfig := &config.AuthConfig{
				Bearer: nil,
			}

			So(authConfig.IsBearerAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("IsOIDCBearerAuthEnabled with nil AuthConfig", func() {
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsOIDCBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("IsTraditionalBearerAuthEnabled with nil AuthConfig", func() {
			var authConfig *config.AuthConfig = nil

			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)
		})

		Convey("IsTraditionalBearerAuthEnabled with partial config", func() {
			// Missing Cert
			authConfig := &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm:   "zot",
					Service: "zot-service",
				},
			}
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)

			// Missing Realm
			authConfig = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Service: "zot-service",
					Cert:    "/path/to/cert",
				},
			}
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)

			// Missing Service
			authConfig = &config.AuthConfig{
				Bearer: &config.BearerConfig{
					Realm: "zot",
					Cert:  "/path/to/cert",
				},
			}
			So(authConfig.IsTraditionalBearerAuthEnabled(), ShouldBeFalse)
		})
	})
}

// createTestCACertificate generates a self-signed CA certificate PEM for testing.
func createTestCACertificate(t *testing.T) []byte {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func TestOIDCProviderCertificateAuthority(t *testing.T) {
	Convey("Test OIDC provider certificate authority configuration", t, func() {
		logger := log.NewLogger("debug", "")

		Convey("Both certificateAuthority and certificateAuthorityFile set should fail", func() {
			caPEM := createTestCACertificate(t)

			tmpDir := t.TempDir()
			caFile := filepath.Join(tmpDir, "ca.crt")
			err := os.WriteFile(caFile, caPEM, 0o600)
			So(err, ShouldBeNil)

			cfg := []config.BearerOIDCConfig{{
				Issuer:                   "https://issuer.example.com",
				Audiences:                []string{"zot"},
				CertificateAuthority:     string(caPEM),
				CertificateAuthorityFile: caFile,
			}}

			_, err = api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "only one of certificateAuthority or certificateAuthorityFile can be set")
		})

		Convey("Valid inline certificateAuthority should succeed", func() {
			caPEM := createTestCACertificate(t)

			cfg := []config.BearerOIDCConfig{{
				Issuer:               "https://issuer.example.com",
				Audiences:            []string{"zot"},
				CertificateAuthority: string(caPEM),
			}}

			authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldBeNil)
			So(authorizer, ShouldNotBeNil)
		})

		Convey("Valid certificateAuthorityFile should succeed", func() {
			caPEM := createTestCACertificate(t)

			tmpDir := t.TempDir()
			caFile := filepath.Join(tmpDir, "ca.crt")
			err := os.WriteFile(caFile, caPEM, 0o600)
			So(err, ShouldBeNil)

			cfg := []config.BearerOIDCConfig{{
				Issuer:                   "https://issuer.example.com",
				Audiences:                []string{"zot"},
				CertificateAuthorityFile: caFile,
			}}

			authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldBeNil)
			So(authorizer, ShouldNotBeNil)
		})

		Convey("Non-existent certificateAuthorityFile should fail", func() {
			cfg := []config.BearerOIDCConfig{{
				Issuer:                   "https://issuer.example.com",
				Audiences:                []string{"zot"},
				CertificateAuthorityFile: "/nonexistent/path/to/ca.crt",
			}}

			_, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "failed to read certificate authority file")
		})

		Convey("Invalid PEM in certificateAuthority should fail", func() {
			cfg := []config.BearerOIDCConfig{{
				Issuer:               "https://issuer.example.com",
				Audiences:            []string{"zot"},
				CertificateAuthority: "not a valid PEM certificate",
			}}

			_, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "failed to append certificate authority PEM")
		})

		Convey("Invalid PEM in certificateAuthorityFile should fail", func() {
			tmpDir := t.TempDir()
			caFile := filepath.Join(tmpDir, "invalid-ca.crt")
			err := os.WriteFile(caFile, []byte("not a valid PEM certificate"), 0o600)
			So(err, ShouldBeNil)

			cfg := []config.BearerOIDCConfig{{
				Issuer:                   "https://issuer.example.com",
				Audiences:                []string{"zot"},
				CertificateAuthorityFile: caFile,
			}}

			_, err = api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "failed to append certificate authority PEM")
		})

		Convey("PEM block that is not a certificate should fail", func() {
			pemBlock := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: []byte("fake key data"),
			})

			cfg := []config.BearerOIDCConfig{{
				Issuer:               "https://issuer.example.com",
				Audiences:            []string{"zot"},
				CertificateAuthority: string(pemBlock),
			}}

			_, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "failed to append certificate authority PEM")
		})

		Convey("No certificate authority configured should succeed", func() {
			cfg := []config.BearerOIDCConfig{{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"zot"},
			}}

			authorizer, err := api.NewOIDCBearerAuthorizer(cfg, logger)
			So(err, ShouldBeNil)
			So(authorizer, ShouldNotBeNil)
		})
	})
}
