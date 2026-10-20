package requestcontext

import (
	"context"

	"zotregistry.dev/zot/v2/errors"
)

// request-local context key.
var amwCtxKey = Key(1) //nolint: gochecknoglobals

// GetAuthnMiddlewareCtxKey returns a pointer needed for use in context.WithValue.
func GetAuthnMiddlewareCtxKey() *Key {
	return &amwCtxKey
}

// AuthnTypeBearer is the authn type recorded for traditional bearer token requests.
const AuthnTypeBearer = "Bearer"

type AuthnMiddlewareContext struct {
	AuthnType string
}

func GetAuthnMiddlewareContext(ctx context.Context) (*AuthnMiddlewareContext, error) {
	authnMiddlewareCtxKey := GetAuthnMiddlewareCtxKey()
	if authnMiddlewareCtx := ctx.Value(authnMiddlewareCtxKey); authnMiddlewareCtx != nil {
		amCtx, ok := authnMiddlewareCtx.(AuthnMiddlewareContext)
		if !ok {
			return nil, errors.ErrBadType
		}

		return &amCtx, nil
	}

	return nil, nil //nolint: nilnil
}

// IsAuthenticated reports whether the request was made by an authenticated caller.
// Traditional bearer tokens never set a username, so the authn context is also consulted.
func IsAuthenticated(ctx context.Context) bool {
	userAc, err := UserAcFromContext(ctx)
	if err == nil && !userAc.IsAnonymous() {
		return true
	}

	authnMwCtx, err := GetAuthnMiddlewareContext(ctx)

	return err == nil && authnMwCtx != nil && authnMwCtx.AuthnType == AuthnTypeBearer
}
