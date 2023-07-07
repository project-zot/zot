package api

import (
	"context"
	"net/http"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

const (
	// method actions.
	Create = "create"
	Read   = "read"
	Update = "update"
	Delete = "delete"
	// behaviour actions.
	DetectManifestCollision = "detectManifestCollision"
	BASIC                   = "Basic"
	BEARER                  = "Bearer"
	OPENID                  = "OpenID"
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
func (ac *AccessController) can(ctx context.Context, username, action, repository string) bool {
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

	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return false
	}

	userGroups := acCtx.Groups

	// check matched repo based policy
	pg, ok := ac.Config.Repositories[longestMatchedPattern]
	if ok {
		can = ac.isPermitted(userGroups, username, action, pg)
	}

	// check admins based policy
	if !can {
		if ac.isAdmin(username) && common.Contains(ac.Config.AdminPolicy.Actions, action) {
			can = true
		}

		if ac.isAnyGroupInAdminPolicy(userGroups) && common.Contains(ac.Config.AdminPolicy.Actions, action) {
			can = true
		}
	}

	return can
}

// isAdmin .
func (ac *AccessController) isAdmin(username string) bool {
	return common.Contains(ac.Config.AdminPolicy.Users, username)
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

// getContext updates an AccessControlContext for a user/anonymous and returns a context.Context containing it.
func (ac *AccessController) getContext(acCtx *localCtx.AccessControlContext, request *http.Request) context.Context {
	readGlobPatterns := ac.getGlobPatterns(acCtx.Username, acCtx.Groups, Read)
	dmcGlobPatterns := ac.getGlobPatterns(acCtx.Username, acCtx.Groups, DetectManifestCollision)

	acCtx.ReadGlobPatterns = readGlobPatterns
	acCtx.DmcGlobPatterns = dmcGlobPatterns

	if ac.isAdmin(acCtx.Username) {
		acCtx.IsAdmin = true
	} else {
		acCtx.IsAdmin = false
	}

	authzCtxKey := localCtx.GetContextKey()
	ctx := context.WithValue(request.Context(), authzCtxKey, *acCtx)

	return ctx
}

// getAuthnMiddlewareContext builds ac context(allowed to read repos and if user is admin) and returns it.
func (ac *AccessController) getAuthnMiddlewareContext(authnType string, request *http.Request) context.Context {
	amwCtx := localCtx.AuthnMiddlewareContext{
		AuthnType: authnType,
	}

	amwCtxKey := localCtx.GetAuthnMiddlewareCtxKey()
	ctx := context.WithValue(request.Context(), amwCtxKey, amwCtx)

	return ctx
}

// isPermitted returns true if username can do action on a repository policy.
func (ac *AccessController) isPermitted(userGroups []string, username, action string,
	policyGroup config.PolicyGroup,
) bool {
	var result bool

	// check repo/system based policies
	for _, p := range policyGroup.Policies {
		if common.Contains(p.Users, username) && common.Contains(p.Actions, action) {
			result = true

			return result
		}
	}

	if userGroups != nil {
		for _, p := range policyGroup.Policies {
			if common.Contains(p.Actions, action) {
				for _, group := range p.Groups {
					if common.Contains(userGroups, group) {
						result = true

						return result
					}
				}
			}
		}
	}

	// check defaultPolicy
	if !result {
		if common.Contains(policyGroup.DefaultPolicy, action) && username != "" {
			result = true
		}
	}

	// check anonymousPolicy
	if !result {
		if common.Contains(policyGroup.AnonymousPolicy, action) && username == "" {
			result = true
		}
	}

	return result
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
			authnMwCtx, err := localCtx.GetAuthnMiddlewareContext(request.Context())
			if err != nil || (authnMwCtx != nil && authnMwCtx.AuthnType == BEARER) {
				next.ServeHTTP(response, request)

				return
			}

			// bypass authz for /v2/ route
			if request.RequestURI == "/v2/" {
				next.ServeHTTP(response, request)

				return
			}

			acCtrlr := NewAccessController(ctlr.Config)

			var identity string

			// anonymous context
			acCtx := &localCtx.AccessControlContext{}

			// get username from context made in authn.go
			if isAuthnEnabled(ctlr.Config) {
				// get access control context made in authn.go if authn is enabled
				acCtx, err = localCtx.GetAccessControlContext(request.Context())
				if err != nil { // should never happen
					authFail(response, request, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

					return
				}

				identity = acCtx.Username
			}

			if request.TLS != nil {
				verifiedChains := request.TLS.VerifiedChains
				// still no identity, get it from TLS certs
				if identity == "" && verifiedChains != nil &&
					len(verifiedChains) > 0 && len(verifiedChains[0]) > 0 {
					for _, cert := range request.TLS.PeerCertificates {
						identity = cert.Subject.CommonName
					}

					// if we still don't have an identity
					if identity == "" {
						acCtrlr.Log.Info().Msg("couldn't get identity from TLS certificate")
						authFail(response, request, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

						return
					}

					// assign identity to authz context, needed for extensions
					acCtx.Username = identity
				}
			}

			ctx := acCtrlr.getContext(acCtx, request)

			next.ServeHTTP(response, request.WithContext(ctx)) //nolint:contextcheck
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
			authnMwCtx, err := localCtx.GetAuthnMiddlewareContext(request.Context())
			if err != nil || (authnMwCtx != nil && authnMwCtx.AuthnType == BEARER) {
				next.ServeHTTP(response, request)

				return
			}

			vars := mux.Vars(request)
			resource := vars["name"]
			reference, ok := vars["reference"]

			acCtrlr := NewAccessController(ctlr.Config)

			var identity string

			// get acCtx built in authn and previous authz middlewares
			acCtx, err := localCtx.GetAccessControlContext(request.Context())
			if err != nil { // should never happen
				authFail(response, request, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)

				return
			}

			// get username from context made in authn.go
			identity = acCtx.Username

			var action string
			if request.Method == http.MethodGet || request.Method == http.MethodHead {
				action = Read
			}

			if request.Method == http.MethodPut || request.Method == http.MethodPatch || request.Method == http.MethodPost {
				// assume user wants to create
				action = Create
				// if we get a reference (tag)
				if ok {
					is := ctlr.StoreController.GetImageStore(resource)
					tags, err := is.GetImageTags(resource)
					// if repo exists and request's tag exists then action is UPDATE
					if err == nil && common.Contains(tags, reference) && reference != "latest" {
						action = Update
					}
				}
			}

			if request.Method == http.MethodDelete {
				action = Delete
			}

			can := acCtrlr.can(request.Context(), identity, action, resource) //nolint:contextcheck
			if !can {
				common.AuthzFail(response, request, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)
			} else {
				next.ServeHTTP(response, request) //nolint:contextcheck
			}
		})
	}
}
