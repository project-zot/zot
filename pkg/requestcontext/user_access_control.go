package uac

import (
	"context"
	"net/http"

	glob "github.com/bmatcuk/doublestar/v4" //nolint:gci

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/constants"
)

type Key int

// request-local context key.
var uacCtxKey = Key(0) //nolint: gochecknoglobals

// pointer needed for use in context.WithValue.
func GetContextKey() *Key {
	return &uacCtxKey
}

type UserAccessControl struct {
	authzInfo        *UserAuthzInfo
	authnInfo        *UserAuthnInfo
	methodActions    []string
	behaviourActions []string
}

type UserAuthzInfo struct {
	// {action: {repo: bool}}
	globPatterns map[string]map[string]bool
	isAdmin      bool
}

type UserAuthnInfo struct {
	groups   []string
	username string
}

func NewUserAccessControl() *UserAccessControl {
	return &UserAccessControl{
		// authzInfo will be populated in authz.go middleware
		// if no authz enabled on server this will be nil
		authzInfo: nil,
		// authnInfo will be populated in authn.go middleware
		// if no authn enabled on server this will be nil
		authnInfo: nil,
		// actions type
		behaviourActions: []string{constants.DetectManifestCollisionPermission},
		methodActions: []string{
			constants.ReadPermission,
			constants.CreatePermission,
			constants.UpdatePermission,
			constants.DeletePermission,
		},
	}
}

func (uac *UserAccessControl) SetUsername(username string) {
	if uac.authnInfo == nil {
		uac.authnInfo = &UserAuthnInfo{}
	}

	uac.authnInfo.username = username
}

func (uac *UserAccessControl) GetUsername() string {
	if uac.authnInfo == nil {
		return ""
	}

	return uac.authnInfo.username
}

func (uac *UserAccessControl) AddGroups(groups []string) {
	if uac.authnInfo == nil {
		uac.authnInfo = &UserAuthnInfo{
			groups: []string{},
		}
	}

	uac.authnInfo.groups = append(uac.authnInfo.groups, groups...)
}

func (uac *UserAccessControl) GetGroups() []string {
	if uac.authnInfo == nil {
		return []string{}
	}

	return uac.authnInfo.groups
}

func (uac *UserAccessControl) IsAnonymous() bool {
	if uac.authnInfo == nil {
		return true
	}

	return uac.authnInfo.username == ""
}

func (uac *UserAccessControl) IsAdmin() bool {
	// if isAdmin was not set in authz.go then everybody is admin
	if uac.authzInfo == nil {
		return true
	}

	return uac.authzInfo.isAdmin
}

func (uac *UserAccessControl) SetIsAdmin(isAdmin bool) {
	if uac.authzInfo == nil {
		uac.authzInfo = &UserAuthzInfo{}
	}

	uac.authzInfo.isAdmin = isAdmin
}

/*
	UserAcFromContext returns an UserAccessControl struct made available on all http requests
	(using context.Context values) by authz and authn middlewares.

	If no UserAccessControl is found on context, it will return an empty one.

its methods and attributes can be used in http.Handlers to get user info for that specific request
(username, groups, if it's an admin, if it can access certain resources).
*/
func UserAcFromContext(ctx context.Context) (*UserAccessControl, error) {
	if uacValue := ctx.Value(GetContextKey()); uacValue != nil {
		uac, ok := uacValue.(UserAccessControl)
		if !ok {
			return nil, errors.ErrBadType
		}

		return &uac, nil
	}

	return NewUserAccessControl(), nil
}

func (uac *UserAccessControl) SetGlobPatterns(action string, patterns map[string]bool) {
	if uac.authzInfo == nil {
		uac.authzInfo = &UserAuthzInfo{
			globPatterns: make(map[string]map[string]bool),
		}
	}

	uac.authzInfo.globPatterns[action] = patterns
}

/*
Can returns whether or not the user/anonymous who made the request has 'action' permission on 'repository'.
*/
func (uac *UserAccessControl) Can(action, repository string) bool {
	var defaultRet bool
	if uac.isBehaviourAction(action) {
		defaultRet = false
	} else if uac.isMethodAction(action) {
		defaultRet = true
	}

	if uac.IsAdmin() {
		return defaultRet
	}

	// if glob patterns are not set then authz is not enabled, so everybody have access.
	if !uac.areGlobPatternsSet() {
		return defaultRet
	}

	return uac.matchesRepo(uac.authzInfo.globPatterns[action], repository)
}

func (uac *UserAccessControl) isBehaviourAction(action string) bool {
	for _, behaviourAction := range uac.behaviourActions {
		if action == behaviourAction {
			return true
		}
	}

	return false
}

func (uac *UserAccessControl) isMethodAction(action string) bool {
	for _, methodAction := range uac.methodActions {
		if action == methodAction {
			return true
		}
	}

	return false
}

// returns whether or not glob patterns have been set in authz.go.
func (uac *UserAccessControl) areGlobPatternsSet() bool {
	notSet := uac.authzInfo == nil || uac.authzInfo.globPatterns == nil

	return !notSet
}

/*
returns whether or not 'repository' can be found in the list of patterns
on which the user who made the request has read permission on.
*/
func (uac *UserAccessControl) matchesRepo(globPatterns map[string]bool, repository string) bool {
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

/*
	SaveOnRequest saves UserAccessControl on the request's context.

Later UserAcFromContext(request.Context()) can be used to obtain UserAccessControl that was saved on it.
*/
func (uac *UserAccessControl) SaveOnRequest(request *http.Request) {
	uacContext := context.WithValue(request.Context(), GetContextKey(), *uac)

	*request = *request.WithContext(uacContext)
}

/*
	DeriveContext takes a context(parent) and returns a derived context(child) containing this UserAccessControl.

Later UserAcFromContext(ctx context.Context) can be used to obtain the UserAccessControl that was added on it.
*/
func (uac *UserAccessControl) DeriveContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, GetContextKey(), *uac)
}

func RepoIsUserAvailable(ctx context.Context, repoName string) (bool, error) {
	uac, err := UserAcFromContext(ctx)
	if err != nil {
		return false, err
	}

	return uac.Can(constants.ReadPermission, repoName), nil
}

func CanDelete(ctx context.Context, repoName string) (bool, error) {
	uac, err := UserAcFromContext(ctx)
	if err != nil {
		return false, err
	}

	return uac.Can(constants.DeletePermission, repoName), nil
}
