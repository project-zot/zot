package requestcontext

import (
	"context"

	glob "github.com/bmatcuk/doublestar/v4" //nolint:gci

	"zotregistry.io/zot/errors"
)

type Key int

// request-local context key.
var authzCtxKey = Key(0) //nolint: gochecknoglobals

// pointer needed for use in context.WithValue.
func GetContextKey() *Key {
	return &authzCtxKey
}

// AccessControlContext - contains user authn/authz information.
type AccessControlContext struct {
	// read method action
	ReadGlobPatterns map[string]bool
	// detectManifestCollision behaviour action
	DmcGlobPatterns map[string]bool
	IsAdmin         bool
	Username        string
	Groups          []string
}

/*
	GetAccessControlContext returns an AccessControlContext struct made available on all http requests
	(using context.Context values) by authz and authn middlewares.

its methods and attributes can be used in http.Handlers to get user info for that specific request
(username, groups, if it's an admin, if it can access certain resources).
*/
func GetAccessControlContext(ctx context.Context) (*AccessControlContext, error) {
	authzCtxKey := GetContextKey()
	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, ok := authCtx.(AccessControlContext)
		if !ok {
			return nil, errors.ErrBadType
		}

		return &acCtx, nil
	}

	return nil, nil //nolint: nilnil
}

// returns whether or not the user/anonymous who made the request has read permission on 'repository'.
func (acCtx *AccessControlContext) CanReadRepo(repository string) bool {
	if acCtx.ReadGlobPatterns != nil {
		return acCtx.matchesRepo(acCtx.ReadGlobPatterns, repository)
	}

	return true
}

/*
returns whether or not the user/anonymous who made the request
has detectManifestCollision permission on 'repository'.
*/
func (acCtx *AccessControlContext) CanDetectManifestCollision(repository string) bool {
	if acCtx.DmcGlobPatterns != nil {
		return acCtx.matchesRepo(acCtx.DmcGlobPatterns, repository)
	}

	return false
}

/*
returns whether or not 'repository' can be found in the list of patterns
on which the user who made the request has read permission on.
*/
func (acCtx *AccessControlContext) matchesRepo(globPatterns map[string]bool, repository string) bool {
	var longestMatchedPattern string

	// because of the longest path matching rule, we need to check all patterns from config
	for pattern := range globPatterns {
		matched, err := glob.Match(pattern, repository)
		if err == nil {
			if matched && len(pattern) > len(longestMatchedPattern) {
				longestMatchedPattern = pattern
			}
		}
	}

	allowed := globPatterns[longestMatchedPattern]

	return allowed
}
