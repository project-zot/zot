package common

import (
	"context"

	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

func Contains(slice []string, item string) bool {
	for _, v := range slice {
		if item == v {
			return true
		}
	}

	return false
}

// first match of item in [].
func Index(slice []string, item string) int {
	for k, v := range slice {
		if item == v {
			return k
		}
	}

	return -1
}

// remove matches of item in [].
func RemoveFrom(input []string, item string) []string {
	var newList []string

	for _, v := range input {
		if item != v {
			newList = append(newList, v)
		}
	}

	return newList
}

func GetAccessContext(ctx context.Context) localCtx.AccessControlContext {
	authzCtxKey := localCtx.GetContextKey()
	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, _ := authCtx.(localCtx.AccessControlContext)
		// acCtx.Username = "bob"
		return acCtx
	}

	// anonymous / default is the empty access control ctx
	return localCtx.AccessControlContext{
		IsAdmin:  false,
		Username: "",
	}
}
