package api

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	zerr "zotregistry.dev/zot/v2/errors"
)

var bearerTokenMatch = regexp.MustCompile("(?i)bearer (.*)")

// ResourceAccess is a single entry in the private 'access' claim specified by the distribution token authentication
// specification.
type ResourceAccess struct {
	// Standard claims defined in the Distribution spec:
	// https://distribution.github.io/distribution/spec/auth/jwt/

	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`

	// Zot extensions

	// ExpiresAt is an optional expiration time for this specific resource access entry.
	// If not set, the overall token expiration time (the standard 'exp' claim) applies.
	ExpiresAt *jwt.NumericDate `json:"exp,omitempty"`
}

type ResourceAction struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Action string `json:"action"`
}

// ClaimsWithAccess is a claim set containing the private 'access' claim specified by the distribution token
// authentication specification, in addition to the standard registered claims.
// https://distribution.github.io/distribution/spec/auth/jwt/
type ClaimsWithAccess struct {
	jwt.RegisteredClaims

	Access []ResourceAccess `json:"access"`
}

type AuthChallengeError struct {
	err            error
	realm          string
	service        string
	resourceAction *ResourceAction
}

func (c AuthChallengeError) Error() string {
	return c.err.Error()
}

// Header constructs an appropriate value for the WWW-Authenticate header to be returned to the client.
func (c AuthChallengeError) Header() string {
	if c.resourceAction == nil {
		// no access was requested, so return an empty scope
		return fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\",scope=\"\"",
			c.realm, c.service)
	}

	return fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\",scope=\"%s:%s:%s\"",
		c.realm, c.service, c.resourceAction.Type, c.resourceAction.Name, c.resourceAction.Action)
}

type BearerAuthorizer struct {
	realm   string
	service string
	keyFunc BearerAuthorizerKeyFunc
}

type BearerAuthorizerKeyFunc func(context.Context, *jwt.Token) (any, error)

func NewBearerAuthorizer(realm string, service string, keyFunc BearerAuthorizerKeyFunc) *BearerAuthorizer {
	return &BearerAuthorizer{
		realm:   realm,
		service: service,
		keyFunc: keyFunc,
	}
}

// Authorize verifies whether the bearer token in the given Authorization header is valid, and whether it has sufficient
// scope for the requested resource action. If an authorization error occurs (e.g. no token is given or the token has
// insufficient scope), an AuthChallengeError is returned as the error.
func (a *BearerAuthorizer) Authorize(ctx context.Context, header string, requested *ResourceAction) error {
	challenge := &AuthChallengeError{
		realm:          a.realm,
		service:        a.service,
		resourceAction: requested,
	}

	if header == "" {
		// if no bearer token is set in the authorization header, return the authentication challenge
		challenge.err = zerr.ErrNoBearerToken

		return challenge
	}

	signedString := bearerTokenMatch.ReplaceAllString(header, "$1")

	token, err := jwt.ParseWithClaims(signedString, &ClaimsWithAccess{}, func(token *jwt.Token) (any, error) {
		return a.keyFunc(ctx, token)
	}, jwt.WithValidMethods(a.allowedSigningAlgorithms()), jwt.WithIssuedAt())
	if err != nil {
		return fmt.Errorf("%w: %w", zerr.ErrInvalidBearerToken, err)
	}

	if requested == nil {
		// the token is valid and no access is requested, so we do not have to validate the access claim
		return nil
	}

	claims, ok := token.Claims.(*ClaimsWithAccess)
	if !ok {
		return fmt.Errorf("%w: invalid claims type", zerr.ErrInvalidBearerToken)
	}

	// check whether the requested access is allowed by the scope of the token
	for _, allowed := range claims.Access {
		if allowed.Type != requested.Type {
			continue
		}

		if allowed.Name != requested.Name {
			continue
		}

		if !slices.Contains(allowed.Actions, requested.Action) {
			continue
		}

		if allowed.ExpiresAt != nil && allowed.ExpiresAt.Time.Before(time.Now()) {
			continue
		}

		// requested action is allowed, so don't return an error
		return nil
	}

	challenge.err = zerr.ErrInsufficientScope

	return challenge
}

func (a *BearerAuthorizer) allowedSigningAlgorithms() []string {
	return []string{"EdDSA", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
}
