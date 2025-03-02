package api

import (
	"crypto"
	"fmt"
	"regexp"
	"slices"

	"github.com/golang-jwt/jwt/v5"

	zerr "zotregistry.dev/zot/errors"
)

var bearerTokenMatch = regexp.MustCompile("(?i)bearer (.*)")

// resourceAccess is a single entry in the private 'access' claim specified by the distribution token authentication
// specification.
type resourceAccess struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

type resourceAction struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Action string `json:"action"`
}

// claimsWithAccess is a claim set containing the private 'access' claim specified by the distribution token
// authentication specification, in addition to the standard registered claims.
// https://distribution.github.io/distribution/spec/auth/jwt/
type claimsWithAccess struct {
	Access []resourceAccess `json:"access"`
	jwt.RegisteredClaims
}

type authChallengeError struct {
	err            error
	realm          string
	service        string
	resourceAction *resourceAction
}

func (c authChallengeError) Error() string {
	return c.err.Error()
}

// Header constructs an appropriate value for the WWW-Authenticate header to be returned to the client.
func (c authChallengeError) Header() string {
	if c.resourceAction == nil {
		// no access was requested, so return an empty scope
		return fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\",scope=\"\"",
			c.realm, c.service)
	}

	return fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\",scope=\"%s:%s:%s\"",
		c.realm, c.service, c.resourceAction.Type, c.resourceAction.Name, c.resourceAction.Action)
}

type bearerAuthorizer struct {
	realm   string
	service string
	key     crypto.PublicKey
}

func newBearerAuthorizer(realm string, service string, key crypto.PublicKey) bearerAuthorizer {
	return bearerAuthorizer{
		realm:   realm,
		service: service,
		key:     key,
	}
}

// Authorize verifies whether the bearer token in the given Authorization header is valid, and whether it has sufficient
// scope for the requested resource action. If an authorization error occurs (e.g. no token is given or the token has
// insufficient scope), an authChallengeError is returned as the error.
func (a *bearerAuthorizer) Authorize(header string, requested *resourceAction) error {
	challenge := &authChallengeError{
		realm:          a.realm,
		service:        a.service,
		resourceAction: requested,
	}

	if header == "" {
		// if no bearer token is set in the authorization header, return the authentication challenge
		return challenge
	}

	signedString := bearerTokenMatch.ReplaceAllString(header, "$1")

	token, err := jwt.ParseWithClaims(signedString, &claimsWithAccess{}, func(token *jwt.Token) (interface{}, error) {
		return a.key, nil
	})
	if err != nil {
		return fmt.Errorf("%w: %w", zerr.ErrInvalidBearerToken, err)
	}

	if requested == nil {
		// the token is valid and no access is requested, so we do not have to validate the access claim
		return nil
	}

	claims, ok := token.Claims.(*claimsWithAccess)
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

		// requested action is allowed, so don't return an error
		return nil
	}

	return challenge
}
