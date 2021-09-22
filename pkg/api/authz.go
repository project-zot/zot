package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/anuvu/zot/pkg/log"
	"github.com/gorilla/mux"
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

type AccessControlConfig struct {
	Repositories Repositories
	AdminPolicy  Policy
}

type Repositories map[string]PolicyGroup

type PolicyGroup struct {
	Policies      []Policy
	DefaultPolicy []string
}

type Policy struct {
	Users   []string
	Actions []string
}

// AccessController authorizes users to act on resources.
type AccessController struct {
	Config *AccessControlConfig
	Log    log.Logger
}

// AccessControlContext context passed down to http.Handlers.
type AccessControlContext struct {
	userAllowedRepos []string
	isAdmin          bool
}

func NewAccessController(config *Config) *AccessController {
	return &AccessController{
		Config: config.AccessControl,
		Log:    log.NewLogger(config.Log.Level, config.Log.Output),
	}
}

// getReadRepos get repositories from config file that the user has READ perms.
func (ac *AccessController) getReadRepos(username string) []string {
	var repos []string

	for r, pg := range ac.Config.Repositories {
		for _, p := range pg.Policies {
			if (contains(p.Users, username) && contains(p.Actions, READ)) ||
				contains(pg.DefaultPolicy, READ) {
				repos = append(repos, r)
			}
		}
	}

	return repos
}

// can verifies if a user can do action on repository.
func (ac *AccessController) can(username, action, repository string) bool {
	can := false
	// check repo based policy
	pg, ok := ac.Config.Repositories[repository]
	if ok {
		can = isPermitted(username, action, pg)
	}

	//check admins based policy
	if !can {
		if ac.isAdmin(username) && contains(ac.Config.AdminPolicy.Actions, action) {
			can = true
		}
	}

	return can
}

// isAdmin .
func (ac *AccessController) isAdmin(username string) bool {
	return contains(ac.Config.AdminPolicy.Users, username)
}

// getContext builds ac context(allowed to read repos and if user is admin) and returns it.
func (ac *AccessController) getContext(username string, r *http.Request) context.Context {
	userAllowedRepos := ac.getReadRepos(username)
	acCtx := AccessControlContext{userAllowedRepos: userAllowedRepos}

	if ac.isAdmin(username) {
		acCtx.isAdmin = true
	} else {
		acCtx.isAdmin = false
	}

	ctx := context.WithValue(r.Context(), authzCtxKey, acCtx)

	return ctx
}

// isPermitted returns true if username can do action on a repository policy.
func isPermitted(username, action string, pg PolicyGroup) bool {
	var result bool
	// check repo/system based policies
	for _, p := range pg.Policies {
		if contains(p.Users, username) && contains(p.Actions, action) {
			result = true
			break
		}
	}

	// check defaultPolicy
	if !result {
		if contains(pg.DefaultPolicy, action) {
			result = true
		}
	}

	return result
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if item == v {
			return true
		}
	}

	return false
}

func containsRepo(slice []string, item string) bool {
	for _, v := range slice {
		if strings.HasPrefix(item, v) {
			return true
		}
	}

	return false
}

func AuthzHandler(c *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)
			resource := vars["name"]
			reference, ok := vars["reference"]

			ac := NewAccessController(c.Config)
			username := getUsername(r)
			ctx := ac.getContext(username, r)

			if r.RequestURI == "/v2/_catalog" || r.RequestURI == "/v2/" {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			var action string
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				action = READ
			}

			if r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodPost {
				// assume user wants to create
				action = CREATE
				// if we get a reference (tag)
				if ok {
					is := c.StoreController.GetImageStore(resource)
					tags, err := is.GetImageTags(resource)
					// if repo exists and request's tag doesn't exist yet then action is UPDATE
					if err == nil && contains(tags, reference) && reference != "latest" {
						action = UPDATE
					}
				}
			}

			if r.Method == http.MethodDelete {
				action = DELETE
			}

			can := ac.can(username, action, resource)
			if !can {
				authzFail(w, c.Config.HTTP.Realm, c.Config.HTTP.Auth.FailDelay)
			} else {
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		})
	}
}

func getUsername(r *http.Request) string {
	// this should work because it worked in auth middleware
	basicAuth := r.Header.Get("Authorization")
	s := strings.SplitN(basicAuth, " ", 2)
	b, _ := base64.StdEncoding.DecodeString(s[1])
	pair := strings.SplitN(string(b), ":", 2)

	return pair[0]
}

func authzFail(w http.ResponseWriter, realm string, delay int) {
	time.Sleep(time.Duration(delay) * time.Second)
	w.Header().Set("WWW-Authenticate", realm)
	w.Header().Set("Content-Type", "application/json")
	WriteJSON(w, http.StatusForbidden, NewErrorList(NewError(DENIED)))
}
