package uac

import (
	"context"

	"zotregistry.dev/zot/errors"
)

// request-local context key.
var amwCtxKey = Key(1) //nolint: gochecknoglobals

// pointer needed for use in context.WithValue.
func GetAuthnMiddlewareCtxKey() *Key {
	return &amwCtxKey
}

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
