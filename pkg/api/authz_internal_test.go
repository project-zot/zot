package api

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

// permitted returns just the bool from AccessController.isPermitted; tests
// that don't care about the deny reason use this for assert readability.
func permitted(ac *AccessController, evalReq *evalRequest, pg config.PolicyGroup) bool {
	ok, _ := ac.isPermitted(evalReq, pg)
	return ok
}

func TestAuthzFailWithReasonChallengeHeaders(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodPost, "/v2/repo/blobs/uploads/", nil)
	request = mux.SetURLVars(request, map[string]string{"name": "repo"})

	basicResponse := httptest.NewRecorder()
	authzFailWithReason(
		basicResponse,
		request,
		"",
		&config.AuthConfig{HTPasswd: config.AuthHTPasswd{Path: "/tmp/htpasswd"}},
		"zot",
		0,
		"",
	)

	assert.Equal(t, http.StatusUnauthorized, basicResponse.Code)
	assert.Equal(t, `Basic realm="zot"`, basicResponse.Header().Get("WWW-Authenticate"))

	bearerResponse := httptest.NewRecorder()
	authzFailWithReason(
		bearerResponse,
		request,
		"alice",
		&config.AuthConfig{
			Bearer: &config.BearerConfig{
				Realm:   "https://auth.example.test/token",
				Service: "zot",
				Cert:    "/tmp/server.cert",
			},
		},
		"zot",
		0,
		"write denied",
	)

	assert.Equal(t, http.StatusForbidden, bearerResponse.Code)
	assert.Equal(t,
		`Bearer realm="https://auth.example.test/token",service="zot",scope="repository:repo:push"`,
		bearerResponse.Header().Get("WWW-Authenticate"),
	)
	assert.True(t, strings.Contains(bearerResponse.Body.String(), "write denied"))

	sessionRequest := httptest.NewRequest(http.MethodPost, "/v2/repo/blobs/uploads/", nil)
	sessionRequest = mux.SetURLVars(sessionRequest, map[string]string{"name": "repo"})
	sessionRequest.Header.Set(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

	sessionResponse := httptest.NewRecorder()
	authzFailWithReason(
		sessionResponse,
		sessionRequest,
		"alice",
		&config.AuthConfig{
			Bearer: &config.BearerConfig{
				Realm:   "https://auth.example.test/token",
				Service: "zot",
				Cert:    "/tmp/server.cert",
			},
		},
		"zot",
		0,
		"",
	)

	assert.Equal(t, http.StatusForbidden, sessionResponse.Code)
	assert.Empty(t, sessionResponse.Header().Get("WWW-Authenticate"))
}

func TestPolicyConditions(t *testing.T) {
	t.Parallel()

	pastRFC := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	futureRFC := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	makeAC := func(policies []config.Policy, groups config.Groups) *AccessController {
		cfg := &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{Policies: policies},
			},
			Groups: groups,
		}
		programs, err := CompileAccessControl(cfg)
		if err != nil {
			t.Fatalf("CompileAccessControl: %v", err)
		}
		cfg.StoreCompiledConditions(programs)

		return &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	}

	makeER := func(username, repo string, groups []string) *evalRequest {
		uac := reqCtx.NewUserAccessControl()
		uac.SetUsername(username)
		uac.AddGroups(groups)

		return &evalRequest{
			userAc:     uac,
			action:     constants.ReadPermission,
			repository: repo,
		}
	}

	t.Run("user policy without conditions is permitted", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
		}}, nil)

		assert.True(t, permitted(ac, makeER("alice", "repo", nil), ac.Config.Repositories["**"]))
	})

	t.Run("user policy with future-time condition is permitted", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `req.time < timestamp("` + futureRFC + `")`,
				Message:    "access expired",
			}},
		}}, nil)

		assert.True(t, permitted(ac, makeER("alice", "repo", nil), ac.Config.Repositories["**"]))
	})

	t.Run("user policy with past-time condition is denied", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `req.time < timestamp("` + pastRFC + `")`,
				Message:    "access expired",
			}},
		}}, nil)

		assert.False(t, permitted(ac, makeER("alice", "repo", nil), ac.Config.Repositories["**"]))
	})

	t.Run("group policy with failing condition is denied", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Groups:  []string{"devs"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `req.time < timestamp("` + pastRFC + `")`,
				Message:    "access expired",
			}},
		}}, config.Groups{"devs": config.Group{Users: []string{"alice"}}})

		assert.False(t, permitted(ac, makeER("alice", "repo", []string{"devs"}),
			ac.Config.Repositories["**"]))
	})

	t.Run("condition can reference repository", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `req.repository.startsWith("prod/")`,
				Message:    "only prod/* allowed",
			}},
		}}, nil)

		assert.True(t, permitted(ac, makeER("alice", "prod/api", nil), ac.Config.Repositories["**"]))
		assert.False(t, permitted(ac, makeER("alice", "staging/api", nil), ac.Config.Repositories["**"]))
	})

	t.Run("invalid expression fails CompileAccessControl", func(t *testing.T) {
		t.Parallel()

		cfg := &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{Policies: []config.Policy{{
					Users:   []string{"alice"},
					Actions: []string{constants.ReadPermission},
					Conditions: []config.Condition{{
						Expression: `this is not valid CEL`,
						Message:    "broken",
					}},
				}}},
			},
		}
		_, err := CompileAccessControl(cfg)
		assert.Error(t, err)
	})

	t.Run("uncompiled expression denies (defense in depth)", func(t *testing.T) {
		t.Parallel()

		// Build the AccessController without going through CompileAccessControl.
		// At authz time the lookup misses and the policy is treated as not granting.
		ac := &AccessController{
			Config: &config.AccessControlConfig{
				Repositories: config.Repositories{
					"**": config.PolicyGroup{Policies: []config.Policy{{
						Users:   []string{"alice"},
						Actions: []string{constants.ReadPermission},
						Conditions: []config.Condition{{
							// A unique expression unlikely to be cached by other tests.
							Expression: `req.repository == "uncompiled-fixture-only"`,
							Message:    "no compile",
						}},
					}}},
				},
			},
			Log: log.NewLogger("debug", ""),
		}

		assert.False(t, permitted(ac, makeER("alice", "uncompiled-fixture-only", nil),
			ac.Config.Repositories["**"]))
	})

	t.Run("conditional entry contributes glob patterns optimistically", func(t *testing.T) {
		t.Parallel()

		// Glob computation does NOT evaluate conditions because repo and
		// reference are unknown at glob-time. A policy with a condition
		// that would deny at request-time still contributes its pattern;
		// per-request can() does the real enforcement. Over-listing in
		// catalog is the chosen tradeoff over under-listing.
		ac := makeAC([]config.Policy{{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `req.time < timestamp("` + pastRFC + `")`,
				Message:    "access expired",
			}},
		}}, nil)

		patterns := ac.getGlobPatterns(makeER("alice", "", nil))
		assert.True(t, patterns["**"])
	})
}

// TestPolicyConditionsRequestFields verifies the full set of req.* fields
// exposed to CEL conditions: HTTP context, TLS, reference parsing, auth
// flags, and OIDC claims passthrough.
func TestPolicyConditionsRequestFields(t *testing.T) {
	t.Parallel()

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")
	uac.SetClaims(map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
		"roles":          []any{"prod-pusher", "dev"},
	})

	httpReq := httptest.NewRequest("PUT", "/v2/prod/api/manifests/v1.2.3", nil)
	httpReq.RemoteAddr = "10.0.0.5:54321"
	httpReq.Header.Set("User-Agent", "docker/24.0.7")
	httpReq.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}

	makeER := func() *evalRequest {
		return &evalRequest{
			httpReq:    httpReq,
			userAc:     uac,
			action:     constants.ReadPermission,
			repository: "prod/api",
			reference:  "v1.2.3",
		}
	}

	cases := []struct {
		name string
		expr string
	}{
		{"method", `req.method == "PUT"`},
		{"userAgent", `req.userAgent.startsWith("docker/")`},
		{"client.ip", `req.client.ip == "10.0.0.5"`},
		{"tls.enabled", `req.tls.enabled`},
		{"tls.version", `req.tls.version == "1.3"`},
		{"reference (tag)", `req.reference == "v1.2.3"`},
		{"referenceType is tag", `req.referenceType == "tag"`},
		{"tag set", `req.tag == "v1.2.3"`},
		{"digest empty for tag", `req.digest == ""`},
		{"auth.anonymous false", `!req.auth.anonymous`},
		{"auth.admin false", `!req.auth.admin`},
		{"claims passthrough", `req.claims.email_verified == true`},
		{"claims list", `"prod-pusher" in req.claims.roles`},
		{"action", `req.action == "read"`},
		{"repository", `req.repository == "prod/api"`},
		{"user.username", `req.user.username == "alice"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.AccessControlConfig{
				Repositories: config.Repositories{
					"**": config.PolicyGroup{Policies: []config.Policy{{
						Users:   []string{"alice"},
						Actions: []string{constants.ReadPermission},
						Conditions: []config.Condition{{
							Expression: tc.expr,
							Message:    "denied",
						}},
					}}},
				},
			}
			programs, err := CompileAccessControl(cfg)
			if err != nil {
				t.Fatalf("CompileAccessControl: %v", err)
			}
			cfg.StoreCompiledConditions(programs)

			ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}

			assert.True(t, permitted(ac, makeER(), ac.Config.Repositories["**"]), tc.expr)
		})
	}
}

func TestPolicyConditionsDigestReference(t *testing.T) {
	t.Parallel()

	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.referenceType == "digest" && req.digest.startsWith("sha256:")`,
					Message:    "expected digest",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}
	cfg.StoreCompiledConditions(programs)

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	evalReq := &evalRequest{
		userAc:     uac,
		action:     constants.ReadPermission,
		repository: "prod/api",
		reference:  digest,
	}

	assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestTLSVersionString(t *testing.T) {
	t.Parallel()

	cases := map[uint16]string{
		tls.VersionTLS10: "1.0",
		tls.VersionTLS11: "1.1",
		tls.VersionTLS12: "1.2",
		tls.VersionTLS13: "1.3",
		0xffff:           "",
	}
	for v, want := range cases {
		if got := tlsVersionString(v); got != want {
			t.Errorf("tlsVersionString(%#x) = %q, want %q", v, got, want)
		}
	}
}

func TestEvalRequestNilSafety(t *testing.T) {
	t.Parallel()

	var nilER *evalRequest
	assert.Equal(t, "", nilER.username())
	assert.Nil(t, nilER.groups())

	emptyER := &evalRequest{}
	assert.Equal(t, "", emptyER.username())
	assert.Nil(t, emptyER.groups())
}

func TestCompileAccessControlNilAndAdminPolicy(t *testing.T) {
	t.Parallel()

	programs, err := CompileAccessControl(nil)
	assert.NoError(t, err)
	assert.Nil(t, programs)

	cfg := &config.AccessControlConfig{
		AdminPolicy: config.Policy{
			Users:   []string{"alice"},
			Actions: []string{constants.ReadPermission},
			Conditions: []config.Condition{{
				Expression: `definitely not valid`,
				Message:    "broken admin",
			}},
		},
	}
	_, err = CompileAccessControl(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "adminPolicy")
}

func TestEvalRequestRemoteAddrWithoutPort(t *testing.T) {
	t.Parallel()

	httpReq := httptest.NewRequest("GET", "/v2/", nil)
	httpReq.RemoteAddr = "no-port-here"

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.client.ip == "no-port-here"`,
					Message:    "bad ip",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}
	cfg.StoreCompiledConditions(programs)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	evalReq := &evalRequest{httpReq: httpReq, userAc: uac, action: constants.ReadPermission, repository: "r"}

	assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestPolicyConditionRuntimeTypeError(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.repository`,
					Message:    "wrong type",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}
	cfg.StoreCompiledConditions(programs)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r"}

	assert.False(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestPolicyGroupNonMatchingNoActionOrGroup(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{
				{Groups: []string{"devs"}, Actions: []string{constants.CreatePermission}},
				{Groups: []string{"others"}, Actions: []string{constants.ReadPermission}},
			}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	if err != nil {
		t.Fatalf("CompileAccessControl: %v", err)
	}
	cfg.StoreCompiledConditions(programs)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")
	uac.AddGroups([]string{"devs"})

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r"}

	assert.False(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
}

func TestCompileAccessControlDedupesIdenticalExpressions(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{
				{
					Users:   []string{"alice"},
					Actions: []string{constants.ReadPermission},
					Conditions: []config.Condition{
						{Expression: `req.repository == "x"`, Message: "first"},
						{Expression: `req.repository == "x"`, Message: "duplicate"},
					},
				},
			}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	assert.NoError(t, err)
	assert.Len(t, programs, 1)
}

func TestNewAccessControllerNilAccessControl(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		HTTP: config.HTTPConfig{}, // AccessControl is nil
		Log:  &config.LogConfig{Level: "debug"},
	}

	ac := NewAccessController(cfg)
	assert.NotNil(t, ac)
	assert.NotNil(t, ac.Config)
	assert.Empty(t, ac.Config.Repositories)
}

func TestControllerLoadNewConfigRecompilesConditions(t *testing.T) {
	t.Parallel()

	htp := NewHTPasswd(log.NewLogger("debug", ""))
	htw, err := NewHTPasswdWatcher(htp, "")
	assert.NoError(t, err)

	original := config.New()
	original.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{
					{Expression: `req.repository == "old"`, Message: "old"},
				},
			}}},
		},
	}
	originalPrograms, err := CompileAccessControl(original.HTTP.AccessControl)
	assert.NoError(t, err)
	original.HTTP.AccessControl.StoreCompiledConditions(originalPrograms)

	ctlr := &Controller{
		Config:          original,
		Log:             log.NewLogger("debug", ""),
		HTPasswd:        htp,
		HTPasswdWatcher: htw,
	}

	newConfig := config.New()
	newConfig.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{
					{Expression: `req.repository == "new"`, Message: "new"},
				},
			}}},
		},
	}

	ctlr.LoadNewConfig(newConfig)

	updated := ctlr.Config.HTTP.AccessControl.LoadCompiledConditions()
	_, hasNew := updated[`req.repository == "new"`]
	assert.True(t, hasNew, "new expression should be compiled after reload")
	_, hasOld := updated[`req.repository == "old"`]
	assert.False(t, hasOld, "old expression should be evicted after reload")
}

// TestPolicyConditionForwardedFor verifies that req.client.forwardedFor
// exposes the X-Forwarded-For chain split into a list, and that conditions
// can express "trust XFF only when the TCP peer is the configured proxy".
func TestPolicyConditionForwardedFor(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.client.ip == "10.0.0.5" && size(req.client.forwardedFor) > 0 && req.client.forwardedFor[0] == "192.0.2.7"`,
					Message:    "must arrive via trusted proxy from 192.0.2.7",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	assert.NoError(t, err)
	cfg.StoreCompiledConditions(programs)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	mk := func(remoteAddr, xff string) *evalRequest {
		req := httptest.NewRequest("GET", "/v2/", nil)
		req.RemoteAddr = remoteAddr

		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}

		return &evalRequest{
			httpReq:    req,
			userAc:     uac,
			action:     constants.ReadPermission,
			repository: "r",
		}
	}

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}

	// Through the trusted proxy with the expected client IP at the head of XFF: granted.
	assert.True(t, permitted(ac, mk("10.0.0.5:1234", "192.0.2.7, 10.0.0.5"),
		ac.Config.Repositories["**"]))

	// Same XFF claim but TCP peer is NOT the trusted proxy: denied (XFF is spoofable).
	assert.False(t, permitted(ac, mk("203.0.113.9:1234", "192.0.2.7"),
		ac.Config.Repositories["**"]))

	// Trusted proxy but no XFF header: denied.
	assert.False(t, permitted(ac, mk("10.0.0.5:1234", ""),
		ac.Config.Repositories["**"]))
}

// TestPolicyConditionDenyReasonIsSurfaced verifies that when a condition
// denies, the operator-authored Message bubbles up through isPermitted/can
// so the handler can put it in the 403 response detail.
func TestPolicyConditionDenyReasonIsSurfaced(t *testing.T) {
	t.Parallel()

	cfg := &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{Policies: []config.Policy{{
				Users:   []string{"alice"},
				Actions: []string{constants.ReadPermission},
				Conditions: []config.Condition{{
					Expression: `req.repository.startsWith("prod/")`,
					Message:    "alice may only read prod/*",
				}},
			}}},
		},
	}
	programs, err := CompileAccessControl(cfg)
	assert.NoError(t, err)
	cfg.StoreCompiledConditions(programs)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	ac := &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "staging/api"}

	ok, reason := ac.isPermitted(evalReq, ac.Config.Repositories["**"])
	assert.False(t, ok)
	assert.Equal(t, "alice may only read prod/*", reason)
}

// TestSetGlobPatternsOrderIndependence verifies that SetGlobPatterns can be
// called before SetIsAdmin without panicking on a nil internal map. This is a
// regression guard for an earlier ordering hazard between the two setters.
func TestSetGlobPatternsOrderIndependence(t *testing.T) {
	t.Parallel()

	uac := reqCtx.NewUserAccessControl()
	uac.SetGlobPatterns(constants.ReadPermission, map[string]bool{"**": true})
	uac.SetIsAdmin(true)
	assert.True(t, uac.IsAdmin())

	uac2 := reqCtx.NewUserAccessControl()
	uac2.SetIsAdmin(true)
	uac2.SetGlobPatterns(constants.ReadPermission, map[string]bool{"**": true})
	assert.True(t, uac2.IsAdmin())
}

func TestPolicyConditionsAnonymousAndAdminFlags(t *testing.T) {
	t.Parallel()

	mkAC := func(expr string) *AccessController {
		cfg := &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{Policies: []config.Policy{{
					Users:      []string{"alice", ""},
					Actions:    []string{constants.ReadPermission},
					Conditions: []config.Condition{{Expression: expr, Message: "denied"}},
				}}},
			},
		}
		programs, err := CompileAccessControl(cfg)
		if err != nil {
			t.Fatalf("CompileAccessControl: %v", err)
		}
		cfg.StoreCompiledConditions(programs)

		return &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	}

	t.Run("anonymous true when username empty", func(t *testing.T) {
		t.Parallel()

		ac := mkAC(`req.auth.anonymous`)
		uac := reqCtx.NewUserAccessControl()
		evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r"}
		assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
	})

	t.Run("admin reflects evalRequest.isAdmin", func(t *testing.T) {
		t.Parallel()

		ac := mkAC(`req.auth.admin`)
		uac := reqCtx.NewUserAccessControl()
		uac.SetUsername("alice")
		evalReq := &evalRequest{userAc: uac, action: constants.ReadPermission, repository: "r", isAdmin: true}
		assert.True(t, permitted(ac, evalReq, ac.Config.Repositories["**"]))
	})
}

func TestAdminPolicyConditions(t *testing.T) {
	t.Parallel()

	makeAC := func(adminConditions []config.Condition) *AccessController {
		cfg := &config.AccessControlConfig{
			AdminPolicy: config.Policy{
				Users:      []string{"alice"},
				Actions:    []string{constants.ReadPermission},
				Conditions: adminConditions,
			},
		}
		programs, err := CompileAccessControl(cfg)
		if err != nil {
			t.Fatalf("CompileAccessControl: %v", err)
		}
		cfg.StoreCompiledConditions(programs)

		return &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	}

	httpReqTLS := httptest.NewRequest("GET", "/v2/", nil)
	httpReqTLS.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}

	httpReqPlain := httptest.NewRequest("GET", "/v2/", nil)

	uac := reqCtx.NewUserAccessControl()
	uac.SetUsername("alice")

	t.Run("admin without conditions is permitted (existing behavior)", func(t *testing.T) {
		t.Parallel()

		ac := makeAC(nil)
		can, reason := ac.can(httpReqPlain, uac, constants.ReadPermission, "any/repo", "ref")
		assert.True(t, can)
		assert.Equal(t, "", reason)
	})

	t.Run("admin condition met grants access", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Condition{{
			Expression: `req.tls.enabled`,
			Message:    "admin actions require TLS",
		}})
		can, reason := ac.can(httpReqTLS, uac, constants.ReadPermission, "any/repo", "ref")
		assert.True(t, can)
		assert.Equal(t, "", reason)
	})

	t.Run("admin condition denied surfaces operator message", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Condition{{
			Expression: `req.tls.enabled`,
			Message:    "admin actions require TLS",
		}})
		can, reason := ac.can(httpReqPlain, uac, constants.ReadPermission, "any/repo", "ref")
		assert.False(t, can)
		assert.Equal(t, "admin actions require TLS", reason)
	})

	t.Run("non-admin user is unaffected by admin conditions", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]config.Condition{{
			Expression: `req.tls.enabled`,
			Message:    "admin actions require TLS",
		}})
		bob := reqCtx.NewUserAccessControl()
		bob.SetUsername("bob")
		can, _ := ac.can(httpReqTLS, bob, constants.ReadPermission, "any/repo", "ref")
		assert.False(t, can)
	})
}

func TestClassifyDigestQueryTags(t *testing.T) {
	t.Parallel()

	existingRepoTags := []string{"stable", "latest", "dev"}

	existing, newTags := classifyDigestQueryTags(existingRepoTags, []string{"new", "stable"})
	assert.Equal(t, []string{"stable"}, existing)
	assert.Equal(t, []string{"new"}, newTags)

	existing, newTags = classifyDigestQueryTags(existingRepoTags, []string{"", "bad/ref", "stable", "latest", "stable"})
	assert.Equal(t, []string{"stable", "latest"}, existing)
	assert.Empty(t, newTags)

	existing, newTags = classifyDigestQueryTags(existingRepoTags, []string{"brand-new", "bad/ref", "", "brand-new"})
	assert.Empty(t, existing)
	assert.Equal(t, []string{"brand-new"}, newTags)

	existing, newTags = classifyDigestQueryTags(existingRepoTags, nil)
	assert.Empty(t, existing)
	assert.Empty(t, newTags)

	existing, newTags = classifyDigestQueryTags(existingRepoTags, []string{"  edge  ", "edge", "stable", "  "})
	assert.Equal(t, []string{"stable"}, existing)
	assert.Equal(t, []string{"edge"}, newTags)
}

func TestManifestWriteAuthzChecks(t *testing.T) {
	t.Parallel()

	repoTags := []string{"stable", "dev"}
	digest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	t.Run("tag path overwrite requires update on that tag", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []manifestWriteAuthzCheck{
			{action: constants.UpdatePermission, reference: "stable"},
		}, manifestWriteAuthzChecks(repoTags, "stable", []string{"ignored-by-route"}))
	})

	t.Run("tag path first push requires create on that tag", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []manifestWriteAuthzCheck{
			{action: constants.CreatePermission, reference: "v1"},
		}, manifestWriteAuthzChecks(repoTags, "v1", nil))
	})

	t.Run("digest with only new tags requires create on each tag and digest", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []manifestWriteAuthzCheck{
			{action: constants.CreatePermission, reference: "brand-new"},
			{action: constants.CreatePermission, reference: "edge"},
			{action: constants.CreatePermission, reference: digest},
		}, manifestWriteAuthzChecks(repoTags, digest, []string{"brand-new", "edge"}))
	})

	t.Run("digest overwriting existing tags requires update on each tag and digest", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []manifestWriteAuthzCheck{
			{action: constants.UpdatePermission, reference: "stable"},
			{action: constants.UpdatePermission, reference: "dev"},
			{action: constants.UpdatePermission, reference: digest},
		}, manifestWriteAuthzChecks(repoTags, digest, []string{"stable", "dev"}))
	})

	t.Run("digest mix requires per-tag create/update plus create and update on digest", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []manifestWriteAuthzCheck{
			{action: constants.UpdatePermission, reference: "stable"},
			{action: constants.CreatePermission, reference: "brand-new"},
			{action: constants.CreatePermission, reference: digest},
			{action: constants.UpdatePermission, reference: digest},
		}, manifestWriteAuthzChecks(repoTags, digest, []string{"stable", "brand-new"}))
	})

	t.Run("digest with no tag query requires create on digest", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []manifestWriteAuthzCheck{
			{action: constants.CreatePermission, reference: digest},
		}, manifestWriteAuthzChecks(repoTags, digest, nil))
	})

	t.Run("digest with only invalid tag query requires create on digest", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, []manifestWriteAuthzCheck{
			{action: constants.CreatePermission, reference: digest},
		}, manifestWriteAuthzChecks(repoTags, digest, []string{"", "bad/ref"}))
	})
}

func TestAuthorizeManifestWrite(t *testing.T) {
	t.Parallel()

	digest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	repoTags := []string{"stable", "dev"}
	req := httptest.NewRequest(http.MethodPut, "/v2/repo/manifests/"+digest, nil)

	makeAC := func(actions []string, conditions []config.Condition) *AccessController {
		cfg := &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{Policies: []config.Policy{{
					Users:      []string{"alice"},
					Actions:    actions,
					Conditions: conditions,
				}}},
			},
		}
		programs, err := CompileAccessControl(cfg)
		if err != nil {
			t.Fatalf("CompileAccessControl: %v", err)
		}
		cfg.StoreCompiledConditions(programs)

		return &AccessController{Config: cfg, Log: log.NewLogger("debug", "")}
	}

	alice := reqCtx.NewUserAccessControl()
	alice.SetUsername("alice")

	t.Run("create and update allow digest mix", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.CreatePermission,
			constants.UpdatePermission,
		}, nil)

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", digest, repoTags,
			[]string{"stable", "brand-new"})
		assert.True(t, allowed)
		assert.Empty(t, reason)
	})

	t.Run("create-only denied when overwriting existing tag", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.CreatePermission,
		}, nil)

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", digest, repoTags,
			[]string{"stable", "brand-new"})
		assert.False(t, allowed)
		assert.Empty(t, reason)
	})

	t.Run("update-only denied when creating new tag", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.UpdatePermission,
		}, nil)

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", digest, repoTags,
			[]string{"stable", "brand-new"})
		assert.False(t, allowed)
		assert.Empty(t, reason)
	})

	t.Run("update-only allows overwrite of existing tags only", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.UpdatePermission,
		}, nil)

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", digest, repoTags,
			[]string{"stable"})
		assert.True(t, allowed)
		assert.Empty(t, reason)
	})

	t.Run("create-only allows new tags only", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.CreatePermission,
		}, nil)

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", digest, repoTags,
			[]string{"brand-new"})
		assert.True(t, allowed)
		assert.Empty(t, reason)
	})

	t.Run("tag path overwrite allowed with update", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.UpdatePermission,
		}, nil)

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", "stable", repoTags, nil)
		assert.True(t, allowed)
		assert.Empty(t, reason)
	})

	t.Run("tag path first push allowed with create", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.CreatePermission,
		}, nil)

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", "v1", repoTags, nil)
		assert.True(t, allowed)
		assert.Empty(t, reason)
	})

	t.Run("CEL denial on existing query tag surfaces message", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.CreatePermission,
			constants.UpdatePermission,
		}, []config.Condition{{
			Expression: `req.action != "update" || req.tag != "stable"`,
			Message:    "stable tag is immutable",
		}})

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", digest, repoTags,
			[]string{"stable", "brand-new"})
		assert.False(t, allowed)
		assert.Equal(t, "stable tag is immutable", reason)
	})

	t.Run("CEL denial on digest path surfaces message", func(t *testing.T) {
		t.Parallel()

		ac := makeAC([]string{
			constants.ReadPermission,
			constants.CreatePermission,
			constants.UpdatePermission,
		}, []config.Condition{{
			Expression: `req.referenceType != "digest"`,
			Message:    "digest path reference not permitted",
		}})

		reason, allowed := authorizeManifestWrite(ac, req, alice, "repo", digest, repoTags,
			[]string{"stable"})
		assert.False(t, allowed)
		assert.Equal(t, "digest path reference not permitted", reason)
	})
}

func TestRepoTagsForManifestWriteAuthz(t *testing.T) {
	t.Parallel()

	t.Run("no error returns discovered tags", func(t *testing.T) {
		t.Parallel()

		tags := []string{"stable", "dev"}
		got, err := repoTagsForManifestWriteAuthz(tags, nil)
		assert.NoError(t, err)
		assert.Equal(t, tags, got)
	})

	t.Run("repo not found maps to empty tags", func(t *testing.T) {
		t.Parallel()

		got, err := repoTagsForManifestWriteAuthz([]string{"ignored"}, zerr.ErrRepoNotFound)
		assert.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("unexpected storage error is returned", func(t *testing.T) {
		t.Parallel()

		expected := errors.New("storage backend unavailable")
		got, err := repoTagsForManifestWriteAuthz(nil, expected)
		assert.Nil(t, got)
		assert.ErrorIs(t, err, expected)
	})
}
