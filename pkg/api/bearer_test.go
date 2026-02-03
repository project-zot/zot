package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
)

func TestBearerAuthorizer(t *testing.T) {
	Convey("Test bearer token authorization", t, func() {
		signingMethod := jwt.SigningMethodRS256

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		pubKey := privKey.Public()
		keyFunc := func(_ context.Context, token *jwt.Token) (any, error) {
			return pubKey, nil
		}

		authorizer := api.NewBearerAuthorizer("realm", "service", keyFunc)

		Convey("Empty authorization header given", func() {
			err := authorizer.Authorize(context.Background(), "", nil)
			So(err, ShouldBeError, zerr.ErrNoBearerToken)
		})

		Convey("Valid token", func() {
			access := []api.ResourceAccess{
				{
					Name:    "authorized-repository",
					Type:    "repository",
					Actions: []string{"pull"},
				},
			}

			now := time.Now()
			claims := api.ClaimsWithAccess{
				Access: access,
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * 1)),
					IssuedAt:  jwt.NewNumericDate(now),
					Issuer:    "Zot",
					Audience:  []string{"Zot Registry"},
				},
			}

			token, err := jwt.NewWithClaims(signingMethod, claims).SignedString(privKey)
			if err != nil {
				panic(err)
			}

			authHeader := "Bearer " + token

			Convey("Unauthorized type", func() {
				requested := &api.ResourceAction{
					Type:   "registry",
					Name:   "catalog",
					Action: "*",
				}

				err := authorizer.Authorize(context.Background(), authHeader, requested)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})

			Convey("Unauthorized name", func() {
				requested := &api.ResourceAction{
					Type:   "repository",
					Name:   "unauthorized-repository",
					Action: "pull",
				}

				err := authorizer.Authorize(context.Background(), authHeader, requested)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})

			Convey("Unauthorized action", func() {
				requested := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "push",
				}

				err := authorizer.Authorize(context.Background(), authHeader, requested)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})

			Convey("Successful authorization with requested access", func() {
				requested := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "pull",
				}

				err := authorizer.Authorize(context.Background(), authHeader, requested)
				So(err, ShouldBeNil)
			})

			Convey("Successful authorization without requested access", func() {
				err := authorizer.Authorize(context.Background(), authHeader, nil)
				So(err, ShouldBeNil)
			})
		})

		Convey("Access entry with per-entry ExpiresAt", func() {
			now := time.Now()

			Convey("Authorized when ExpiresAt is in the future", func() {
				access := []api.ResourceAccess{
					{
						Name:      "authorized-repository",
						Type:      "repository",
						Actions:   []string{"pull"},
						ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					},
				}

				claims := api.ClaimsWithAccess{
					Access: access,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
						IssuedAt:  jwt.NewNumericDate(now),
						Issuer:    "Zot",
						Audience:  []string{"Zot Registry"},
					},
				}

				token, err := jwt.NewWithClaims(signingMethod, claims).SignedString(privKey)
				So(err, ShouldBeNil)

				requested := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "pull",
				}

				err = authorizer.Authorize(context.Background(), "Bearer "+token, requested)
				So(err, ShouldBeNil)
			})

			Convey("Denied when ExpiresAt is in the past", func() {
				access := []api.ResourceAccess{
					{
						Name:      "authorized-repository",
						Type:      "repository",
						Actions:   []string{"pull"},
						ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
					},
				}

				claims := api.ClaimsWithAccess{
					Access: access,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
						IssuedAt:  jwt.NewNumericDate(now),
						Issuer:    "Zot",
						Audience:  []string{"Zot Registry"},
					},
				}

				token, err := jwt.NewWithClaims(signingMethod, claims).SignedString(privKey)
				So(err, ShouldBeNil)

				requested := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "pull",
				}

				err = authorizer.Authorize(context.Background(), "Bearer "+token, requested)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})

			Convey("Only the expired entry is skipped, other entries still work", func() {
				access := []api.ResourceAccess{
					{
						Name:      "authorized-repository",
						Type:      "repository",
						Actions:   []string{"pull"},
						ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
					},
					{
						Name:    "authorized-repository",
						Type:    "repository",
						Actions: []string{"pull", "push"},
					},
				}

				claims := api.ClaimsWithAccess{
					Access: access,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
						IssuedAt:  jwt.NewNumericDate(now),
						Issuer:    "Zot",
						Audience:  []string{"Zot Registry"},
					},
				}

				token, err := jwt.NewWithClaims(signingMethod, claims).SignedString(privKey)
				So(err, ShouldBeNil)

				requested := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "pull",
				}

				err = authorizer.Authorize(context.Background(), "Bearer "+token, requested)
				So(err, ShouldBeNil)
			})

			Convey("All entries expired results in insufficient scope", func() {
				access := []api.ResourceAccess{
					{
						Name:      "authorized-repository",
						Type:      "repository",
						Actions:   []string{"pull"},
						ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
					},
					{
						Name:      "authorized-repository",
						Type:      "repository",
						Actions:   []string{"pull"},
						ExpiresAt: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
					},
				}

				claims := api.ClaimsWithAccess{
					Access: access,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
						IssuedAt:  jwt.NewNumericDate(now),
						Issuer:    "Zot",
						Audience:  []string{"Zot Registry"},
					},
				}

				token, err := jwt.NewWithClaims(signingMethod, claims).SignedString(privKey)
				So(err, ShouldBeNil)

				requested := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "pull",
				}

				err = authorizer.Authorize(context.Background(), "Bearer "+token, requested)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})
		})

		Convey("Invalid token", func() {
			authHeader := "invalid"

			err := authorizer.Authorize(context.Background(), authHeader, nil)
			So(err, ShouldWrap, zerr.ErrInvalidBearerToken)
		})
	})
}

// TestBearerAuthorizerJWKSEdDSA verifies that an Ed25519 key pair in JWKS format can be used to
// sign and verify JWTs through the BearerAuthorizer. The hardcoded JWKS key pair below was
// generated externally using standard JWKS tooling.
func TestBearerAuthorizerJWKSEdDSA(t *testing.T) {
	Convey("Test bearer authorization with JWKS Ed25519 key pair", t, func() {
		// Hardcoded Ed25519 JWKS private key set (generated externally).
		const privateJWKS = `{
  "keys": [
    {
      "use": "sig",
      "kty": "OKP",
      "kid": "01f0ff96-0286-62c9-9fe0-68c6ac4f48e0",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "x": "3pL95mHbZYNG6-YT_MqXKibGQrXF7WziWk25EcgEJGs",
      "d": "YJxZxGtBfy7lKKwuld1SQJn_9-YANmP0P_ZYG_ExUj4"
    }
  ]
}`

		// Hardcoded Ed25519 JWKS public key set (generated externally).
		const publicJWKS = `{
  "keys": [
    {
      "use": "sig",
      "kty": "OKP",
      "kid": "01f0ff96-0286-62c9-9fe0-68c6ac4f48e0",
      "crv": "Ed25519",
      "alg": "EdDSA",
      "x": "3pL95mHbZYNG6-YT_MqXKibGQrXF7WziWk25EcgEJGs"
    }
  ]
}`

		// Parse the JWKS public key set (same logic as loadPublicKeyFromBytes).
		var pubKeySet jose.JSONWebKeySet
		err := json.Unmarshal([]byte(publicJWKS), &pubKeySet)
		So(err, ShouldBeNil)
		So(pubKeySet.Keys, ShouldHaveLength, 1)

		pubJWK := pubKeySet.Keys[0]
		So(pubJWK.KeyID, ShouldEqual, "01f0ff96-0286-62c9-9fe0-68c6ac4f48e0")

		pubKey, ok := pubJWK.Key.(ed25519.PublicKey)
		So(ok, ShouldBeTrue)

		// Parse the JWKS private key set to sign JWTs.
		var privKeySet jose.JSONWebKeySet
		err = json.Unmarshal([]byte(privateJWKS), &privKeySet)
		So(err, ShouldBeNil)
		So(privKeySet.Keys, ShouldHaveLength, 1)

		privJWK := privKeySet.Keys[0]
		privKey, ok := privJWK.Key.(ed25519.PrivateKey)
		So(ok, ShouldBeTrue)

		// Build a keyFunc that selects the public key by kid.
		keyFunc := func(_ context.Context, token *jwt.Token) (any, error) {
			kid, ok := token.Header["kid"]
			if !ok {
				return nil, fmt.Errorf("%w: missing kid", zerr.ErrInvalidBearerToken)
			}
			if kid != pubJWK.KeyID {
				return nil, fmt.Errorf("%w: unknown kid %v", zerr.ErrInvalidBearerToken, kid)
			}

			return pubKey, nil
		}

		authorizer := api.NewBearerAuthorizer("realm", "service", keyFunc)

		Convey("Sign and verify a JWT using JWKS Ed25519 keys", func() {
			now := time.Now()
			claims := api.ClaimsWithAccess{
				Access: []api.ResourceAccess{
					{
						Name:    "test-repo",
						Type:    "repository",
						Actions: []string{"pull"},
					},
				},
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
					IssuedAt:  jwt.NewNumericDate(now),
					Issuer:    "https://test-issuer",
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
			token.Header["kid"] = pubJWK.KeyID

			signedToken, err := token.SignedString(privKey)
			So(err, ShouldBeNil)

			authHeader := "Bearer " + signedToken

			requested := &api.ResourceAction{
				Type:   "repository",
				Name:   "test-repo",
				Action: "pull",
			}
			err = authorizer.Authorize(context.Background(), authHeader, requested)
			So(err, ShouldBeNil)
		})

		Convey("Verify a pre-signed JWT using JWKS Ed25519 public key", func() {
			// This JWT was signed externally with the same private key above.
			//nolint:lll
			const preSignedJWT = `eyJhbGciOiJFZERTQSIsImtpZCI6IjAxZjBmZjk2LTAyODYtNjJjOS05ZmUwLTY4YzZhYzRmNDhlMCIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIwMWYwZmY5Ni0wYWNjLTY3YjMtYWY5Yy02OGM2YWM0ZjQ4ZTAiLCJpc3MiOiJodHRwczovL3Rlc3QtaXNzdWVyIiwic3ViIjoiYy1lN2YyMjFhY2ZlZmJiOWNlIiwiYXVkIjpbImZsdXgtb3BlcmF0b3IiXSwiZXhwIjoxODAxNTA0MDMzLCJpYXQiOjE3Njk5NjgwMzMsIm5iZiI6MTc2OTk2ODAzM30.-4_9d1llJ8nCvW8AQdyQKvidx6DtV9lm78pWhbS0w49hq5tRcx3bt_zGGyhj-VGPFIGF86LTL25hcgOVKLEZBg`

			authHeader := "Bearer " + preSignedJWT
			err := authorizer.Authorize(context.Background(), authHeader, nil)
			So(err, ShouldBeNil)
		})
	})
}
