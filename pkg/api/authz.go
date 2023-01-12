package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
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
)

// AccessController authorizes users to act on resources.
type AccessController struct {
	Config *config.AccessControlConfig
	Log    log.Logger
}

func NewAccessController(config *config.Config) *AccessController {
	return &AccessController{
		Config: config.HTTP.AccessControl,
		Log:    log.NewLogger(config.Log.Level, config.Log.Output),
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

// getContext builds ac context(allowed to read repos and if user is admin) and returns it.
func (ac *AccessController) getContext(username string, request *http.Request) context.Context {
	acCtx, err := localCtx.GetAccessControlContext(request.Context())
	if err != nil {
		return nil
	}

	readGlobPatterns := ac.getGlobPatterns(username, acCtx.Groups, Read)
	dmcGlobPatterns := ac.getGlobPatterns(username, acCtx.Groups, DetectManifestCollision)

	acCtx.ReadGlobPatterns = readGlobPatterns
	acCtx.DmcGlobPatterns = dmcGlobPatterns

	if ac.isAdmin(username) {
		acCtx.IsAdmin = true
	} else {
		acCtx.IsAdmin = false
	}

	authzCtxKey := localCtx.GetContextKey()
	ctx := context.WithValue(request.Context(), authzCtxKey, *acCtx)

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

func AuthzHandler(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			vars := mux.Vars(request)
			resource := vars["name"]
			reference, ok := vars["reference"]

			// bypass authz for /v2/ route
			if request.RequestURI == "/v2/" {
				next.ServeHTTP(response, request)

				return
			}

			acCtrlr := NewAccessController(ctlr.Config)

			// allow anonymous authz if no authn present and only default policies are present
			var identity string
			var err error

			// allow anonymous authz if no authn present and only default policies are present
			identity = ""
			if isAuthnEnabled(ctlr.Config) && request.Header.Get("Authorization") != "" {
				identity, _, err = getUsernamePasswordBasicAuth(request)

				if err != nil {
					authFail(response, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)
				}
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
						authFail(response, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)
					}
				}
			}

			ctx := acCtrlr.getContext(identity, request)

			// will return only repos on which client is authorized to read
			if request.RequestURI == fmt.Sprintf("%s%s", constants.RoutePrefix, constants.ExtCatalogPrefix) {
				next.ServeHTTP(response, request.WithContext(ctx)) //nolint:contextcheck

				return
			}

			if strings.Contains(request.RequestURI, constants.FullSearchPrefix) {
				next.ServeHTTP(response, request.WithContext(ctx)) //nolint:contextcheck

				return
			}

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

			can := acCtrlr.can(ctx, identity, action, resource) //nolint:contextcheck
			if !can {
				authzFail(response, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)
			} else {
				next.ServeHTTP(response, request.WithContext(ctx)) //nolint:contextcheck
			}
		})
	}
}

func authzFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Set("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusForbidden, NewErrorList(NewError(DENIED)))
}

func anonymousPolicyExists(config *config.AccessControlConfig) bool {
	if config == nil {
		return false
	}

	for _, repository := range config.Repositories {
		if len(repository.AnonymousPolicy) > 0 {
			return true
		}
	}

	return false
}
