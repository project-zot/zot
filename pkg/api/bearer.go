package api

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
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

// UserAccessControlFromBearerAccess maps distribution token access entries to
// UserAccessControl glob patterns so secondary authorization checks (e.g. dedupe
// mount source-repo read) can reuse the same permission model as config-based authz.
//
// Authenticate matches access names exactly; only map OCI-valid repository names
// here so glob-based Can() cannot widen scope (e.g. a "**" entry must not imply
// read on every repository). Catalog uses repository::pull and registry:catalog:*
// scopes whose names are not valid repository paths and are skipped.
func UserAccessControlFromBearerAccess(access []ResourceAccess) *reqCtx.UserAccessControl {
	userAc := reqCtx.NewUserAccessControl()

	readPatterns := map[string]bool{}
	createPatterns := map[string]bool{}
	updatePatterns := map[string]bool{}
	deletePatterns := map[string]bool{}

	now := time.Now()

	for _, resourceAccess := range access {
		if resourceAccess.Type != "repository" {
			continue
		}

		if !zreg.FullNameRegexp.MatchString(resourceAccess.Name) {
			continue
		}

		if resourceAccess.ExpiresAt != nil && resourceAccess.ExpiresAt.Time.Before(now) {
			continue
		}

		for _, action := range resourceAccess.Actions {
			switch action {
			case "pull":
				readPatterns[resourceAccess.Name] = true
			case "push":
				createPatterns[resourceAccess.Name] = true
				updatePatterns[resourceAccess.Name] = true
			case "delete":
				deletePatterns[resourceAccess.Name] = true
			}
		}
	}

	// Token has no valid repository names (common for catalog-only scopes such as
	// repository::pull on /v2/_catalog). Skip installing permissions: empty glob
	// maps would list no repos in _catalog and still mark the caller as scoped.
	if !hasNonEmptyGlobPatterns(readPatterns, createPatterns, updatePatterns, deletePatterns) {
		return userAc
	}

	userAc.SetIsAdmin(false)
	userAc.SetGlobPatterns(constants.ReadPermission, readPatterns)
	userAc.SetGlobPatterns(constants.CreatePermission, createPatterns)
	userAc.SetGlobPatterns(constants.UpdatePermission, updatePatterns)
	userAc.SetGlobPatterns(constants.DeletePermission, deletePatterns)

	return userAc
}

// hasNonEmptyGlobPatterns reports whether any action map contains at least one
// repository pattern (used to distinguish scoped repo grants from catalog-only tokens).
func hasNonEmptyGlobPatterns(patterns ...map[string]bool) bool {
	for _, patternMap := range patterns {
		if len(patternMap) > 0 {
			return true
		}
	}

	return false
}

// Authenticate verifies the bearer token and, when requested is non-nil, that
// the token scope covers the requested resource action. On success it returns
// the parsed access claims.
func (a *BearerAuthorizer) Authenticate(
	ctx context.Context, header string, requested *ResourceAction,
) (*ClaimsWithAccess, error) {
	challenge := &AuthChallengeError{
		realm:          a.realm,
		service:        a.service,
		resourceAction: requested,
	}

	if header == "" {
		// if no bearer token is set in the authorization header, return the authentication challenge
		challenge.err = zerr.ErrNoBearerToken

		return nil, challenge
	}

	signedString := bearerTokenMatch.ReplaceAllString(header, "$1")

	token, err := jwt.ParseWithClaims(signedString, &ClaimsWithAccess{}, func(token *jwt.Token) (any, error) {
		return a.keyFunc(ctx, token)
	}, jwt.WithValidMethods(a.allowedSigningAlgorithms()), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", zerr.ErrInvalidBearerToken, err)
	}

	claims, ok := token.Claims.(*ClaimsWithAccess)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims type", zerr.ErrInvalidBearerToken)
	}

	if requested == nil {
		// the token is valid and no access is requested, so we do not have to validate the access claim
		return claims, nil
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
		return claims, nil
	}

	challenge.err = zerr.ErrInsufficientScope

	return nil, challenge
}

// Authorize verifies whether the bearer token in the given Authorization header is valid, and whether it has sufficient
// scope for the requested resource action. If an authorization error occurs (e.g. no token is given or the token has
// insufficient scope), an AuthChallengeError is returned as the error.
func (a *BearerAuthorizer) Authorize(ctx context.Context, header string, requested *ResourceAction) error {
	_, err := a.Authenticate(ctx, header, requested)

	return err
}

func (a *BearerAuthorizer) allowedSigningAlgorithms() []string {
	return []string{"EdDSA", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
}
