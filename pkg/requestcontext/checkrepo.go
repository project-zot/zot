package requestcontext

import (
	"context"

	zerr "zotregistry.io/zot/errors"
)

func RepoIsUserAvailable(ctx context.Context, repoName string) (bool, error) {
	authzCtxKey := GetContextKey()

	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, ok := authCtx.(AccessControlContext)
		if !ok {
			err := zerr.ErrBadCtxFormat

			return false, err
		}

		if acCtx.IsAdmin || acCtx.CanReadRepo(repoName) {
			return true, nil
		}

		return false, nil
	}

	return true, nil
}
