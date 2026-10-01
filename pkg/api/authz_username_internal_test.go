package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

func TestUsernameRepositoryPolicies(t *testing.T) {
	t.Parallel()

	ac := &AccessController{Config: &config.AccessControlConfig{
		Repositories: config.Repositories{
			"${username}/**":          {DefaultPolicy: []string{"read", "create", "update"}},
			"reserved/**":             {},
			"laurivosandi/private/**": {},
		},
	}}
	request := httptest.NewRequest(http.MethodGet, "/v2/", nil)

	for _, tc := range []struct {
		name, username, repository string
		allowed                    bool
	}{
		{"owner", "laurivosandi", "laurivosandi/app", true},
		{"nested", "laurivosandi", "laurivosandi/team/app", true},
		{"other owner", "alice", "alice/app", true},
		{"period", "alice.smith", "alice.smith/app", true},
		{"other namespace", "alice", "laurivosandi/app", false},
		{"prefix boundary", "laurivosandi", "laurivosandi-other/app", false},
		{"anonymous", "", "laurivosandi/app", false},
		{"wildcard", "*", "laurivosandi/app", false},
		{"recursive wildcard", "**", "laurivosandi/app", false},
		{"alternation", "{alice,laurivosandi}", "laurivosandi/app", false},
		{"character class", "[a-z]*", "laurivosandi/app", false},
		{"slash", "laurivosandi/team", "laurivosandi/team/app", false},
		{"traversal", "..", "../app", false},
		{"uppercase", "Alice", "alice/app", false},
		{"colon", "alice:smith", "alice:smith/app", false},
		{"reserved namespace", "reserved", "reserved/app", false},
		{"specific deny", "laurivosandi", "laurivosandi/private/app", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			uac := reqCtx.NewUserAccessControl()
			uac.SetUsername(tc.username)
			ac.updateUserAccessControl(request, uac)
			ac.attachPermissionEvaluator(request, uac)

			for _, action := range []string{"read", "create", "update"} {
				allowed, _ := ac.can(request, uac, action, tc.repository, "latest")
				assert.Equal(t, tc.allowed, allowed, "request %s", action)
				assert.Equal(t, tc.allowed, uac.Can(action, tc.repository), "glob %s", action)
				assert.Equal(t, tc.allowed, uac.CanOnResource(action, tc.repository, "latest"), "resource %s", action)
			}
			visible, err := AuthzFilterFunc(uac)(tc.repository)
			assert.NoError(t, err)
			assert.Equal(t, tc.allowed, visible, "catalog visibility")
			allowed, _ := ac.can(request, uac, constants.DeletePermission, tc.repository, "latest")
			assert.False(t, allowed, "delete requires an explicit grant")
		})
	}
}

func TestUsernameTemplateRequiresPathComponent(t *testing.T) {
	t.Parallel()

	_, err := CompileAccessControl(&config.AccessControlConfig{
		Repositories: config.Repositories{
			"[${username}]/**": {},
		},
	})
	assert.Error(t, err)
}
