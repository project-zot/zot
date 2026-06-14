package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	"github.com/gorilla/mux"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/cel"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

const (
	BASIC       = "Basic"
	BEARER      = "Bearer"
	BEARER_OIDC = "BearerOIDC" // OIDC bearer tokens use accessControl config for authorization
	OPENID      = "OpenID"
)

func AuthzFilterFunc(userAc *reqCtx.UserAccessControl) storageTypes.FilterRepoFunc {
	return func(repo string) (bool, error) {
		if userAc == nil {
			return true, nil
		}

		if userAc.Can(constants.ReadPermission, repo) {
			return true, nil
		}

		return false, nil
	}
}

// AccessController authorizes users to act on resources.
type AccessController struct {
	Config *config.AccessControlConfig
	Log    log.Logger
}

func NewAccessController(conf *config.Config) *AccessController {
	// Get access control config safely
	accessControlConfig := conf.CopyAccessControlConfig()
	logConfig := conf.CopyLogConfig()

	if accessControlConfig == nil {
		return &AccessController{
			Config: &config.AccessControlConfig{},
			Log:    log.NewLogger(logConfig.Level, logConfig.Output),
		}
	}

	return &AccessController{
		Config: accessControlConfig,
		Log:    log.NewLogger(logConfig.Level, logConfig.Output),
	}
}

// getGlobPatterns gets glob patterns from authz config on which <username> has <action> perms.
// used to filter /v2/_catalog repositories based on user rights.
func (ac *AccessController) getGlobPatterns(evalReq *evalRequest) map[string]bool {
	globPatterns := make(map[string]bool)

	username := evalReq.username()
	groups := evalReq.groups()
	action := evalReq.action

	for pattern, policyGroup := range ac.Config.Repositories {
		if username == "" {
			// check anonymous policy
			if slices.Contains(policyGroup.AnonymousPolicy, action) {
				globPatterns[pattern] = true
			}
		} else {
			// check default policy (authenticated user)
			if slices.Contains(policyGroup.DefaultPolicy, action) {
				globPatterns[pattern] = true
			}
		}

		// check user based policy. Conditions are NOT evaluated at glob-time
		// because the concrete repository / reference are unknown; evaluating
		// them against empty placeholders would produce false negatives for
		// conditions like `req.repository.startsWith("prod/")`. We include
		// such policies optimistically — per-request authz (ac.can) does the
		// real enforcement once repo + ref are known. The trade-off is that
		// the catalog filter may over-list (a repo shows in /v2/_catalog
		// even though the eventual GET is denied with 403); under-listing
		// (hiding a repo the user can actually access) is the worse failure
		// mode and is what we avoid here.
		for _, policy := range policyGroup.Policies {
			if !slices.Contains(policy.Users, username) || !slices.Contains(policy.Actions, action) {
				continue
			}

			globPatterns[pattern] = true
		}

		// check group based policy
		for _, group := range groups {
			for _, policy := range policyGroup.Policies {
				if !slices.Contains(policy.Groups, group) || !slices.Contains(policy.Actions, action) {
					continue
				}

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

// can verifies if a user can do action on repository. When access is denied
// and a matched policy's condition was the reason, the second return value is
// the operator-authored Message for that condition.
func (ac *AccessController) can(httpReq *http.Request, userAc *reqCtx.UserAccessControl,
	action, repository, reference string,
) (bool, string) {
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
	evalReq := &evalRequest{
		httpReq:    httpReq,
		userAc:     userAc,
		isAdmin:    userAc.IsAdmin(),
		action:     action,
		repository: repository,
		reference:  reference,
	}

	// check matched repo based policy
	var (
		can    bool
		reason string
	)

	repositories := ac.Config.GetRepositories()
	if pg, ok := repositories[longestMatchedPattern]; ok {
		can, reason = ac.isPermitted(evalReq, pg)
	}

	// check admins based policy
	if !can {
		adminPolicy := ac.Config.GetAdminPolicy()
		if ac.isAdmin(username, userGroups) && slices.Contains(adminPolicy.Actions, action) {
			// AdminPolicy conditions are repo-agnostic by design: they
			// gate the blanket admin grant on per-request properties
			// (e.g. require TLS, restrict to a corp CIDR, time-of-day
			// windows). When a condition denies, surface its Message
			// instead of any earlier repo-policy denial reason — the
			// admin-path denial is the most specific explanation.
			ok, denyReason := ac.policyConditionsMet(adminPolicy, evalReq)
			if ok {
				can = true
				reason = ""
			} else if denyReason != "" {
				reason = denyReason
			}
		}
	}

	return can, reason
}

// isAdmin .
func (ac *AccessController) isAdmin(username string, userGroups []string) bool {
	adminPolicy := ac.Config.GetAdminPolicy()
	if slices.Contains(adminPolicy.Users, username) || ac.isAnyGroupInAdminPolicy(userGroups) {
		return true
	}

	return false
}

func (ac *AccessController) isAnyGroupInAdminPolicy(userGroups []string) bool {
	adminPolicy := ac.Config.GetAdminPolicy()

	return slices.ContainsFunc(userGroups, func(group string) bool {
		return slices.Contains(adminPolicy.Groups, group)
	})
}

func (ac *AccessController) getUserGroups(username string) []string {
	var groupNames []string

	groups := ac.Config.GetGroups()
	for groupName, group := range groups {
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
func (ac *AccessController) updateUserAccessControl(httpReq *http.Request, userAc *reqCtx.UserAccessControl) {
	isAdmin := ac.isAdmin(userAc.GetUsername(), userAc.GetGroups())
	userAc.SetIsAdmin(isAdmin)

	mkER := func(action string) *evalRequest {
		return &evalRequest{
			httpReq: httpReq,
			userAc:  userAc,
			isAdmin: isAdmin,
			action:  action,
			// repository/reference unknown at glob-computation time
		}
	}

	userAc.SetGlobPatterns(constants.ReadPermission,
		ac.getGlobPatterns(mkER(constants.ReadPermission)))
	userAc.SetGlobPatterns(constants.CreatePermission,
		ac.getGlobPatterns(mkER(constants.CreatePermission)))
	userAc.SetGlobPatterns(constants.UpdatePermission,
		ac.getGlobPatterns(mkER(constants.UpdatePermission)))
	userAc.SetGlobPatterns(constants.DeletePermission,
		ac.getGlobPatterns(mkER(constants.DeletePermission)))
	userAc.SetGlobPatterns(constants.DetectManifestCollisionPermission,
		ac.getGlobPatterns(mkER(constants.DetectManifestCollisionPermission)))
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

// CompileAccessControl walks every policy condition in cfg, compiles its CEL
// expression, and returns the resulting expression -> program map. Called at
// config validation (LoadConfiguration) to surface syntax errors at load
// time, and again at controller startup / hot reload to refresh the live
// program cache attached to the Controller.
//
// The map values are *cel.Expression; the return type is map[string]any so
// the result can be passed straight to AccessControlConfig.StoreCompiledConditions
// without an extra conversion. See AccessControlConfig.compiledConditions for why
// that field is type-erased.
func CompileAccessControl(cfg *config.AccessControlConfig) (map[string]any, error) {
	if cfg == nil {
		return nil, nil //nolint:nilnil // empty cfg = no programs to compile
	}

	programs := map[string]any{}

	compileAll := func(policy config.Policy, where string) error {
		for i, cond := range policy.Conditions {
			if _, ok := programs[cond.Expression]; ok {
				continue
			}

			// We don't pass WithOutputType(BoolType): values pulled out of
			// the dyn `req` struct (e.g. `req.tls.enabled`) carry the dyn
			// type even when they are concretely booleans. EvaluateBoolean
			// enforces the bool result at runtime instead.
			program, err := cel.NewExpression(cond.Expression,
				cel.WithCompile(),
				cel.WithDynMapVariables("req"))
			if err != nil {
				return fmt.Errorf("%s: condition[%d]: %w", where, i, err)
			}

			programs[cond.Expression] = program
		}

		return nil
	}

	for pattern, pg := range cfg.Repositories {
		for i, policy := range pg.Policies {
			if err := compileAll(policy, fmt.Sprintf("repositories[%q].policies[%d]", pattern, i)); err != nil {
				return nil, err
			}
		}
	}

	if err := compileAll(cfg.AdminPolicy, "adminPolicy"); err != nil {
		return nil, err
	}

	return programs, nil
}

// lookupCondition returns the pre-compiled program for expr from the
// access-control config's snapshot. The expression must have been registered
// by CompileAccessControl; otherwise authorization fails closed.
func (ac *AccessController) lookupCondition(expr string) (*cel.Expression, error) {
	// The compiled-conditions map is type-erased to keep pkg/cel out of
	// pkg/api/config's import graph (and thus out of zli); see the comment
	// on AccessControlConfig.compiledConditions. CompileAccessControl is the
	// only writer and always stores *cel.Expression, so this assertion is
	// safe — a failure means a programmer bug, not bad input.
	if v, ok := ac.Config.LoadCompiledConditions()[expr]; ok {
		program, ok := v.(*cel.Expression)
		if !ok {
			return nil, fmt.Errorf("%w: %q (unexpected type %T)", zerr.ErrPolicyConditionNotCompiled, expr, v)
		}

		return program, nil
	}

	return nil, fmt.Errorf("%w: %q", zerr.ErrPolicyConditionNotCompiled, expr)
}

// evalRequest is the bundle of per-request inputs fed to CEL policy
// conditions. Any field may be zero-valued: missing inputs surface as empty
// strings / nils on the corresponding `req.*` paths in the expression.
type evalRequest struct {
	httpReq    *http.Request
	userAc     *reqCtx.UserAccessControl
	isAdmin    bool
	action     string
	repository string
	reference  string
}

func (evalReq *evalRequest) username() string {
	if evalReq == nil || evalReq.userAc == nil {
		return ""
	}

	return evalReq.userAc.GetUsername()
}

func (evalReq *evalRequest) groups() []string {
	if evalReq == nil || evalReq.userAc == nil {
		return nil
	}

	return evalReq.userAc.GetGroups()
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}

	return ""
}

// data builds the CEL evaluation input map exposing the `req` struct.
func (evalReq *evalRequest) data() map[string]any {
	var (
		username     string
		groups       []string
		claims       map[string]any
		anonymous    = true
		method       string
		userAgent    string
		clientIP     string
		forwardedFor []string
		tlsOn        bool
		tlsVer       string
		refType      string
		tag          string
		digest       string
	)

	if evalReq.userAc != nil {
		username = evalReq.userAc.GetUsername()
		groups = evalReq.userAc.GetGroups()
		claims = evalReq.userAc.GetClaims()
		anonymous = username == ""
	}

	if evalReq.httpReq != nil {
		method = evalReq.httpReq.Method
		userAgent = evalReq.httpReq.UserAgent()
		if host, _, err := net.SplitHostPort(evalReq.httpReq.RemoteAddr); err == nil {
			clientIP = host
		} else {
			clientIP = evalReq.httpReq.RemoteAddr
		}

		// X-Forwarded-For is exposed verbatim (untrusted). Conditions are
		// expected to validate the chain themselves — typically by checking
		// req.client.ip is a known proxy before reading req.client.forwardedFor.
		for _, header := range evalReq.httpReq.Header.Values("X-Forwarded-For") {
			for ip := range strings.SplitSeq(header, ",") {
				if ip = strings.TrimSpace(ip); ip != "" {
					forwardedFor = append(forwardedFor, ip)
				}
			}
		}

		if evalReq.httpReq.TLS != nil {
			tlsOn = true
			tlsVer = tlsVersionString(evalReq.httpReq.TLS.Version)
		}
	}

	// A digest reference contains an algorithm separator (e.g. "sha256:...");
	// anything else is a tag.
	if evalReq.reference != "" {
		if strings.Contains(evalReq.reference, ":") {
			refType = "digest"
			digest = evalReq.reference
		} else {
			refType = "tag"
			tag = evalReq.reference
		}
	}

	return map[string]any{
		"req": map[string]any{
			"time":          time.Now().UTC(),
			"method":        method,
			"userAgent":     userAgent,
			"action":        evalReq.action,
			"repository":    evalReq.repository,
			"reference":     evalReq.reference,
			"referenceType": refType,
			"tag":           tag,
			"digest":        digest,
			"user": map[string]any{
				"username": username,
				"groups":   groups,
			},
			"auth": map[string]any{
				"anonymous": anonymous,
				"admin":     evalReq.isAdmin,
			},
			"client": map[string]any{
				"ip":           clientIP,
				"forwardedFor": forwardedFor,
			},
			"tls": map[string]any{
				"enabled": tlsOn,
				"version": tlsVer,
			},
			"claims": claims,
		},
	}
}

// policyConditionsMet reports whether every condition on the policy
// evaluates to true. When a condition denies, the second return value is the
// operator-authored Message for that condition (intended to be surfaced to
// the client). When a condition fails to look up or evaluate, the policy is
// treated as not granting and the second return value is empty (we do not
// leak internal failure modes to the client).
func (ac *AccessController) policyConditionsMet(policy config.Policy, evalReq *evalRequest) (bool, string) {
	if len(policy.Conditions) == 0 {
		return true, ""
	}

	data := evalReq.data()

	ctx := context.Background()
	if evalReq.httpReq != nil {
		ctx = evalReq.httpReq.Context()
	}

	for _, cond := range policy.Conditions {
		expr, err := ac.lookupCondition(cond.Expression)
		if err != nil {
			ac.Log.Warn().Err(err).
				Str("expression", cond.Expression).
				Str("message", cond.Message).
				Msg("policy condition lookup failed")

			return false, ""
		}

		ok, err := expr.EvaluateBoolean(ctx, data)
		if err != nil {
			ac.Log.Warn().Err(err).
				Str("expression", cond.Expression).
				Str("message", cond.Message).
				Msg("failed to evaluate policy condition")

			return false, ""
		}

		if !ok {
			ac.Log.Debug().
				Str("expression", cond.Expression).
				Str("message", cond.Message).
				Msg("policy condition not met")

			return false, cond.Message
		}
	}

	return true, ""
}

// isPermitted returns true if the request, as described by evalReq, is
// allowed by any entry in the policy group. When no entry grants access but
// some matching entry's condition denied, the second return value is the
// operator-authored Message of the most-recent condition denial seen, which
// the caller can surface to the client.
func (ac *AccessController) isPermitted(evalReq *evalRequest, policyGroup config.PolicyGroup) (bool, string) {
	username := evalReq.username()
	userGroups := evalReq.groups()
	action := evalReq.action

	var lastDenyReason string

	// check repo/system based policies
	for _, policy := range policyGroup.Policies {
		if !slices.Contains(policy.Users, username) || !slices.Contains(policy.Actions, action) {
			continue
		}

		ok, reason := ac.policyConditionsMet(policy, evalReq)
		if ok {
			return true, ""
		}

		if reason != "" {
			lastDenyReason = reason
		}
	}

	if userGroups != nil {
		for _, policy := range policyGroup.Policies {
			if !slices.Contains(policy.Actions, action) {
				continue
			}

			matchedGroup := false

			for _, group := range policy.Groups {
				if slices.Contains(userGroups, group) {
					matchedGroup = true

					break
				}
			}

			if !matchedGroup {
				continue
			}

			ok, reason := ac.policyConditionsMet(policy, evalReq)
			if ok {
				return true, ""
			}

			if reason != "" {
				lastDenyReason = reason
			}
		}
	}

	// check defaultPolicy
	if slices.Contains(policyGroup.DefaultPolicy, action) && username != "" {
		return true, ""
	}

	// check anonymousPolicy
	if slices.Contains(policyGroup.AnonymousPolicy, action) && username == "" {
		return true, ""
	}

	return false, lastDenyReason
}

func BaseAuthzHandler(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// Get configs safely
			authConfig := ctlr.Config.CopyAuthConfig()
			realm := ctlr.Config.GetRealm()
			failDelay := authConfig.GetFailDelay()

			/* NOTE:
			since we only do READ actions in extensions, this middleware is enough for them because
			it populates the context with user relevant data to be processed by each individual extension
			*/
			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)

				return
			}

			// request comes from bearer authn, bypass it. note: we don't bypass for BEARER_OIDC
			// tokens since they use accessControl config for authorization
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
				authFail(response, request, realm, failDelay)

				return
			}

			aCtlr.updateUserAccessControl(request, userAc)
			userAc.SaveOnRequest(request)

			next.ServeHTTP(response, request) //nolint:contextcheck
		})
	}
}

func DistSpecAuthzHandler(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// Get configs safely
			authConfig := ctlr.Config.CopyAuthConfig()
			realm := ctlr.Config.GetRealm()
			failDelay := authConfig.GetFailDelay()

			if request.Method == http.MethodOptions {
				next.ServeHTTP(response, request)

				return
			}

			// request comes from bearer authn, bypass it. note: we don't bypass for BEARER_OIDC
			// tokens since they use accessControl config for authorization
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
				authFail(response, request, realm, failDelay)

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
					if err == nil && slices.Contains(tags, reference) {
						// if repo exists and request's tag exists then action is UPDATE
						action = constants.UpdatePermission
					}
				}
			}

			if request.Method == http.MethodDelete {
				action = constants.DeletePermission
			}

			can, denyReason := acCtrlr.can(request, userAc, action, resource, reference) //nolint:contextcheck
			if !can {
				common.AuthzFailWithReason(response, request, userAc.GetUsername(), realm, failDelay, denyReason)
			} else {
				next.ServeHTTP(response, request) //nolint:contextcheck
			}
		})
	}
}

func MetricsAuthzHandler(ctlr *Controller) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			// Get configs safely
			authConfig := ctlr.Config.CopyAuthConfig()
			realm := ctlr.Config.GetRealm()
			failDelay := authConfig.GetFailDelay()

			accessControlConfig := ctlr.Config.CopyAccessControlConfig()

			if accessControlConfig == nil {
				// allow access to authenticated user as anonymous policy does not exist
				next.ServeHTTP(response, request)

				return
			}

			// get access control context made in authn.go
			userAc, err := reqCtx.UserAcFromContext(request.Context())
			if err != nil { // should never happen
				common.AuthzFail(response, request, "", realm, failDelay)

				return
			}

			metricsAccessConfig := accessControlConfig.GetMetrics()

			if userAc.IsAnonymous() {
				// If anonymous read is not specified in access control, deny.
				if !slices.Contains(metricsAccessConfig.AnonymousPolicy, constants.ReadPermission) {
					common.AuthzFail(response, request, "", realm, failDelay)

					return
				}
			} else {
				username := userAc.GetUsername()
				if len(metricsAccessConfig.Users) == 0 {
					log := ctlr.Log
					log.Warn().Msg("no users configured in metrics user list; " +
						"metrics are not accessible to any authenticated user.")
					common.AuthzFail(response, request, username, realm, failDelay)

					return
				}

				if !slices.Contains(metricsAccessConfig.Users, username) {
					common.AuthzFail(response, request, username, realm, failDelay)

					return
				}
			}

			next.ServeHTTP(response, request) //nolint:contextcheck
		})
	}
}
