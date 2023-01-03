package requestcontext

import (
	"context"

	glob "github.com/bmatcuk/doublestar/v4" //nolint:gci

	"zotregistry.io/zot/errors"
)

type Key int

// request-local context key.
var authzCtxKey = Key(0) //nolint: gochecknoglobals

// request-local context key.
var authnMdwCtxKey = Key(1) //nolint: gochecknoglobals

// pointer needed for use in context.WithValue.
func GetContextKey() *Key {
	return &authzCtxKey
}

// pointer needed for use in context.WithValue.
func GetAuthnMdwCtxKey() *Key {
	return &authnMdwCtxKey
}

// AccessControlContext context passed down to http.Handlers.
type AccessControlContext struct {
	// read method action
	ReadGlobPatterns map[string]bool
	// detectManifestCollision behaviour action
	DmcGlobPatterns map[string]bool
	IsAdmin         bool
	Username        string
	Groups          []string
}

type AuthnMdwContext struct {
	PassedAuthnMdwType string
}

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

func GetAuthnMdwContext(ctx context.Context) (*AuthnMdwContext, error) {
	authnMdwCtxKey := GetAuthnMdwCtxKey()
	if authnMdwCtx := ctx.Value(authnMdwCtxKey); authnMdwCtx != nil {
		amCtx, ok := authnMdwCtx.(AuthnMdwContext)
		if !ok {
			return nil, errors.ErrBadType
		}

		return &amCtx, nil
	}

	return nil, nil //nolint: nilnil
}

// returns either a user has or not rights on 'repository'.
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

// returns either a user has or not read rights on 'repository'.
func (acCtx *AccessControlContext) CanReadRepo(repository string) bool {
	if acCtx.ReadGlobPatterns != nil {
		return acCtx.matchesRepo(acCtx.ReadGlobPatterns, repository)
	}

	return true
}

// returns either a user has or not detectManifestCollision rights on 'repository'.
func (acCtx *AccessControlContext) CanDetectManifestCollision(repository string) bool {
	if acCtx.DmcGlobPatterns != nil {
		return acCtx.matchesRepo(acCtx.DmcGlobPatterns, repository)
	}

	return false
}
