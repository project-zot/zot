package api

import (
	"context"
	"net/http"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
)

const (
	BASIC  = "Basic"
	BEARER = "Bearer"
	OPENID = "OpenID"
)

// AccessController authorizes users to act on resources.
type AccessController struct {
	Config *config.AccessControlConfig
	Log    log.Logger
}

func NewAccessController(conf *config.Config) *AccessController {
	if conf.HTTP.AccessControl == nil {
		return &AccessController{
			Config: &config.AccessControlConfig{},
			Log:    log.NewLogger(conf.Log.Level, conf.Log.Output),
		}
	}

	return &AccessController{
		Config: conf.HTTP.AccessControl,
		Log:    log.NewLogger(conf.Log.Level, conf.Log.Output),
	}
}

// getGlobPatterns gets glob patterns from authz config on which <username> has <action> perms.
// used to filter /v2/_catalog repositories based on user rights.
func (ac *AccessController) getGlobPatterns(username string, groups []string, action string) map[string]bool {
	globPatterns := make(map[string]bool)

	for pattern, policyGroup := range ac.Config.Repositories {
		if username == "" {
			// check anonymous policy
			if common.Contains(policyGroup.AnonymousPolicy, action) {
				globPatterns[pattern] = true
			}
		} else {
			// check default policy (authenticated user)
			if common.Contains(policyGroup.DefaultPolicy, action) {
				globPatterns[pattern] = true
			}
		}

		// check user based policy
		for _, p := range policyGroup.Policies {
			if common.Contains(p.Users, username) && common.Contains(p.Actions, action) {
				globPatterns[pattern] = true
			}
		}

		// check group based policy
		for _, group := range groups {
			for _, p := range policyGroup.Policies {
				if common.Contains(p.Groups, group) && common.Contains(p.Actions, action) {
					globPatterns[pattern] = true
				}
			}
		}

		// if not allowed then mark it
		if _, ok := globPatterns[pattern]; !ok {
			globPatterns[pattern] = false
		}
	}

	return globPatterns
}

// can verifies if a user can do action on repository.
func (ac *AccessController) can(userAc *reqCtx.UserAccessControl, action, repository string) bool {
	can := false

	var longestMatchedPattern string

	for pattern := range ac.Config.Repositories {
		matched, err := glob.Match(pattern, repository)
		if err == nil {
			if matched && len(pattern) > len(longestMatchedPattern) {
				longestMatchedPattern = pattern
			}
		}
	}

	userGroups := userAc.GetGroups()
	username := userAc.GetUsername()

	// check matched repo based policy
	pg, ok := ac.Config.Repositories[longestMatchedPattern]
	if ok {
		can = ac.isPermitted(userGroups, username, action, pg)
	}

	// check admins based policy
	if !can {
		if ac.isAdmin(username, userGroups) && common.Contains(ac.Config.AdminPolicy.Actions, action) {
			can = true
		}
	}

	return can
}

// isAdmin .
func (ac *AccessController) isAdmin(username string, userGroups []string) bool {
	if common.Contains(ac.Config.AdminPolicy.Users, username) || ac.isAnyGroupInAdminPolicy(userGroups) {
		return true
	}

	return false
}

func (ac *AccessController) isAnyGroupInAdminPolicy(userGroups []string) bool {
	for _, group := range userGroups {
		if common.Contains(ac.Config.AdminPolicy.Groups, group) {
			return true
		}
	}

	return false
}

func (ac *AccessController) getUserGroups(username string) []string {
	var groupNames []string

	for groupName, group := range ac.Config.Groups {
		for _, user := range group.Users {
			// find if the user is part of any groups
			if user == username {
				groupNames = append(groupNames, groupName)
			}
		}
	}

	return groupNames
}

// getContext updates an UserAccessControl with admin status and specific permissions on repos.
func (ac *AccessController) updateUserAccessControl(userAc *reqCtx.UserAccessControl) {
	identity := userAc.GetUsername()
	groups := userAc.GetGroups()

	readGlobPatterns := ac.getGlobPatterns(identity, groups, constants.ReadPermission)
	createGlobPatterns := ac.getGlobPatterns(identity, groups, constants.CreatePermission)
	updateGlobPatterns := ac.getGlobPatterns(identity, groups, constants.UpdatePermission)
	deleteGlobPatterns := ac.getGlobPatterns(identity, groups, constants.DeletePermission)
	dmcGlobPatterns := ac.getGlobPatterns(identity, groups, constants.DetectManifestCollisionPermission)

	userAc.SetGlobPatterns(constants.ReadPermission, readGlobPatterns)
	userAc.SetGlobPatterns(constants.CreatePermission, createGlobPatterns)
	userAc.SetGlobPatterns(constants.UpdatePermission, updateGlobPatterns)
	userAc.SetGlobPatterns(constants.DeletePermission, deleteGlobPatterns)
	userAc.SetGlobPatterns(constants.DetectManifestCollisionPermission, dmcGlobPatterns)

	if ac.isAdmin(userAc.GetUsername(), userAc.GetGroups()) {
		userAc.SetIsAdmin(true)
	} else {
		userAc.SetIsAdmin(false)
	}
}

// getAuthnMiddlewareContext builds ac context(allowed to read repos and if user is admin) and returns it.
func (ac *AccessController) getAuthnMiddlewareContext(authnType string, request *http.Request) context.Context {
	amwCtx := reqCtx.AuthnMiddlewareContext{
		AuthnType: authnType,
	}

	amwCtxKey := reqCtx.GetAuthnMiddlewareCtxKey()
	ctx := context.WithValue(request.Context(), amwCtxKey, amwCtx)

	return ctx
}

// isPermitted returns true if username can do action on a repository policy.
func (ac *AccessController) isPermitted(userGroups []string, username, action string,
	policyGroup config.PolicyGroup,
) bool {
	// check repo/system based policies
	for _, p := range policyGroup.Policies {
		if common.Contains(p.Users, username) && common.Contains(p.Actions, action) {
			return true
		}
	}

	if userGroups != nil {
		for _, p := range policyGroup.Policies {
			if common.Contains(p.Actions, action) {
				for _, group := range p.Groups {
					if common.Contains(userGroups, group) {
						return true
					}
				}
			}
		}
	}

	// check defaultPolicy
	if common.Contains(policyGroup.DefaultPolicy, action) && username != "" {
		return true
	}

	// check anonymousPolicy
	if common.Contains(policyGroup.AnonymousPolicy, action) && username == "" {
		return true
	}

	return false
}

func BaseAuthzHandler(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			/* NOTE:
			since we only do READ actions in extensions, this middleware is enough for them because
			it populates the context with user relevant data to be processed by each individual extension
			*/

			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)

				return
			}

			// request comes from bearer authn, bypass it
			authnMwCtx, err := reqCtx.GetAuthnMiddlewareContext(request.Context())
			if err != nil || (authnMwCtx != nil && authnMwCtx.AuthnType == BEARER) {
				next.ServeHTTP(response, request)

				return
			}

			// bypass authz for /v2/ route
			if request.RequestURI == "/v2/" {
				next.ServeHTTP(response, request)

				return
			}

			aCtlr := NewAccessController(ctlr.Config)

			// get access control context made in authn.go
			userAc, err := reqCtx.UserAcFromContext(request.Context())
			if err != nil { // should never happen
				authFail(response, request, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

				return
			}

			aCtlr.updateUserAccessControl(userAc)
			userAc.SaveOnRequest(request)

			next.ServeHTTP(response, request) //nolint:contextcheck
		})
	}
}

func DistSpecAuthzHandler(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)

				return
			}

			// request comes from bearer authn, bypass it
			authnMwCtx, err := reqCtx.GetAuthnMiddlewareContext(request.Context())
			if err != nil || (authnMwCtx != nil && authnMwCtx.AuthnType == BEARER) {
				next.ServeHTTP(response, request)

				return
			}

			vars := mux.Vars(request)
			resource := vars["name"]
			reference, ok := vars["reference"]

			acCtrlr := NewAccessController(ctlr.Config)

			// get userAc built in authn and previous authz middlewares
			userAc, err := reqCtx.UserAcFromContext(request.Context())
			if err != nil { // should never happen
				authFail(response, request, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

				return
			}

			var action string
			if request.Method == http.MethodGet || request.Method == http.MethodHead {
				action = constants.ReadPermission
			}

			if request.Method == http.MethodPut || request.Method == http.MethodPatch || request.Method == http.MethodPost {
				// assume user wants to create
				action = constants.CreatePermission
				// if we get a reference (tag)
				if ok {
					is := ctlr.StoreController.GetImageStore(resource)
					tags, err := is.GetImageTags(resource)
					// if repo exists and request's tag exists then action is UPDATE
					if err == nil && common.Contains(tags, reference) && reference != "latest" {
						action = constants.UpdatePermission
					}
				}
			}

			if request.Method == http.MethodDelete {
				action = constants.DeletePermission
			}

			can := acCtrlr.can(userAc, action, resource) //nolint:contextcheck
			if !can {
				common.AuthzFail(response, request, userAc.GetUsername(), ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)
			} else {
				next.ServeHTTP(response, request) //nolint:contextcheck
			}
		})
	}
}

func MetricsAuthzHandler(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if ctlr.Config.HTTP.AccessControl == nil {
				// allow access to authenticated user as anonymous policy does not exist
				next.ServeHTTP(response, request)

				return
			}
			if len(ctlr.Config.HTTP.AccessControl.Metrics.Users) == 0 {
				log := ctlr.Log
				log.Warn().Msg("auth is enabled but no metrics users in accessControl: /metrics is unaccesible")
				common.AuthzFail(response, request, "", ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

				return
			}

			// get access control context made in authn.go
			userAc, err := reqCtx.UserAcFromContext(request.Context())
			if err != nil { // should never happen
				common.AuthzFail(response, request, "", ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

				return
			}

			username := userAc.GetUsername()
			if !common.Contains(ctlr.Config.HTTP.AccessControl.Metrics.Users, username) {
				common.AuthzFail(response, request, username, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

				return
			}

			next.ServeHTTP(response, request) //nolint:contextcheck
		})
	}
}
