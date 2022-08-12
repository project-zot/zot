package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/gorilla/mux"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
)

type contextKey int

const (
	// actions.
	CREATE = "create"
	READ   = "read"
	UPDATE = "update"
	DELETE = "delete"

	// request-local context key.
	authzCtxKey contextKey = 0
)

// AccessController authorizes users to act on resources.
type AccessController struct {
	Config *config.AccessControlConfig
	Log    log.Logger
}

// AccessControlContext context passed down to http.Handlers.
type AccessControlContext struct {
	globPatterns map[string]bool
	isAdmin      bool
}

func NewAccessController(config *config.Config) *AccessController {
	return &AccessController{
		Config: config.AccessControl,
		Log:    log.NewLogger(config.Log.Level, config.Log.Output),
	}
}

// getReadRepos get glob patterns from config file that the user has or doesn't have READ perms.
// used to filter /v2/_catalog repositories based on user rights.
func (ac *AccessController) getReadGlobPatterns(username string) map[string]bool {
	globPatterns := make(map[string]bool)

	for pattern, policyGroup := range ac.Config.Repositories {
		// check default policy
		if common.Contains(policyGroup.DefaultPolicy, READ) {
			globPatterns[pattern] = true
		}
		// check user based policy
		for _, p := range policyGroup.Policies {
			if common.Contains(p.Users, username) && common.Contains(p.Actions, READ) {
				globPatterns[pattern] = true
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
func (ac *AccessController) can(username, action, repository string) bool {
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

	// check matched repo based policy
	pg, ok := ac.Config.Repositories[longestMatchedPattern]
	if ok {
		can = isPermitted(username, action, pg)
	}

	// check admins based policy
	if !can {
		if ac.isAdmin(username) && common.Contains(ac.Config.AdminPolicy.Actions, action) {
			can = true
		}
	}

	return can
}

// isAdmin .
func (ac *AccessController) isAdmin(username string) bool {
	return common.Contains(ac.Config.AdminPolicy.Users, username)
}

// getContext builds ac context(allowed to read repos and if user is admin) and returns it.
func (ac *AccessController) getContext(username string, request *http.Request) context.Context {
	readGlobPatterns := ac.getReadGlobPatterns(username)
	acCtx := AccessControlContext{globPatterns: readGlobPatterns}

	if ac.isAdmin(username) {
		acCtx.isAdmin = true
	} else {
		acCtx.isAdmin = false
	}

	ctx := context.WithValue(request.Context(), authzCtxKey, acCtx)

	return ctx
}

// isPermitted returns true if username can do action on a repository policy.
func isPermitted(username, action string, policyGroup config.PolicyGroup) bool {
	var result bool
	// check repo/system based policies
	for _, p := range policyGroup.Policies {
		if common.Contains(p.Users, username) && common.Contains(p.Actions, action) {
			result = true

			break
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
				next.ServeHTTP(response, request.WithContext(ctx))

				return
			}

			var action string
			if request.Method == http.MethodGet || request.Method == http.MethodHead {
				action = READ
			}

			if request.Method == http.MethodPut || request.Method == http.MethodPatch || request.Method == http.MethodPost {
				// assume user wants to create
				action = CREATE
				// if we get a reference (tag)
				if ok {
					is := ctlr.StoreController.GetImageStore(resource)
					tags, err := is.GetImageTags(resource)
					// if repo exists and request's tag exists then action is UPDATE
					if err == nil && common.Contains(tags, reference) && reference != "latest" {
						action = UPDATE
					}
				}
			}

			if request.Method == http.MethodDelete {
				action = DELETE
			}

			can := acCtrlr.can(identity, action, resource)
			if !can {
				authzFail(response, ctlr.Config.HTTP.Realm, ctlr.Config.HTTP.Auth.FailDelay)
			} else {
				next.ServeHTTP(response, request.WithContext(ctx))
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
