package api_test

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"
	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"

	. "github.com/smartystreets/goconvey/convey"
)

func TestBearerAuthorizer(t *testing.T) {
	Convey("Test bearer token authorization", t, func() {
		signingMethod := jwt.SigningMethodRS256

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		pubKey := privKey.Public()

		authorizer := api.NewBearerAuthorizer("realm", "service", pubKey)

		Convey("Empty authorization header given", func() {
			err := authorizer.Authorize("", nil)
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
				r := &api.ResourceAction{
					Type:   "registry",
					Name:   "catalog",
					Action: "*",
				}

				err := authorizer.Authorize(authHeader, r)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})

			Convey("Unauthorized name", func() {
				r := &api.ResourceAction{
					Type:   "repository",
					Name:   "unauthorized-repository",
					Action: "pull",
				}

				err := authorizer.Authorize(authHeader, r)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})

			Convey("Unauthorized action", func() {
				r := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "push",
				}

				err := authorizer.Authorize(authHeader, r)
				So(err, ShouldHaveSameTypeAs, &api.AuthChallengeError{})
				So(err, ShouldBeError, zerr.ErrInsufficientScope)
			})

			Convey("Successful authorization with requested access", func() {
				r := &api.ResourceAction{
					Type:   "repository",
					Name:   "authorized-repository",
					Action: "pull",
				}

				err := authorizer.Authorize(authHeader, r)
				So(err, ShouldBeNil)
			})

			Convey("Successful authorization without requested access", func() {
				err := authorizer.Authorize(authHeader, nil)
				So(err, ShouldBeNil)
			})
		})

		Convey("Invalid token", func() {
			authHeader := "invalid"

			err := authorizer.Authorize(authHeader, nil)
			So(err, ShouldWrap, zerr.ErrInvalidBearerToken)
		})
	})
}
