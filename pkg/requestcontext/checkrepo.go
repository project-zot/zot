package requestcontext

import (
	"context"
	"errors"
)

var ErrBadCtxFormat = errors.New("type assertion failed")

func RepoIsUserAvailable(ctx context.Context, repoName string) (bool, error) {
	authzCtxKey := GetContextKey()

	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, ok := authCtx.(AccessControlContext)
		if !ok {
			err := ErrBadCtxFormat

			return false, err
		}

		if acCtx.IsAdmin || acCtx.CanReadRepo(repoName) {
			return true, nil
		}

		return false, nil
	}

	return true, nil
}
