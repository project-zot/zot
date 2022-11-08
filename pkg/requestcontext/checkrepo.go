package requestcontext

import (
	"context"

	glob "github.com/bmatcuk/doublestar/v4"

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

		if acCtx.IsAdmin || matchesRepo(acCtx.GlobPatterns, repoName) {
			return true, nil
		}

		return false, nil
	}

	return true, nil
}

// returns either a user has or not rights on 'repository'.
func matchesRepo(globPatterns map[string]bool, repository string) bool {
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
