package requestcontext_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/api/constants"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
)

// Defensive: empty installed action maps (globPatterns set, every map empty) must
// not report scoped permissions. Production bearer mapping skips installing empty
// maps; this covers the remaining HasScopedPermissions return for Codecov / future callers.
func TestHasScopedPermissionsEmptyInstalledMaps(t *testing.T) {
	t.Parallel()

	uac := reqCtx.NewUserAccessControl()
	uac.SetIsAdmin(false)
	uac.SetGlobPatterns(constants.ReadPermission, map[string]bool{})
	uac.SetGlobPatterns(constants.CreatePermission, map[string]bool{})
	uac.SetGlobPatterns(constants.UpdatePermission, map[string]bool{})
	uac.SetGlobPatterns(constants.DeletePermission, map[string]bool{})

	require.False(t, uac.HasScopedPermissions())
}

// IsAdmin treats a missing authz decision as admin (no accessControl configured); IsAdminByPolicy
// must not, since it gates admin-only routes. It also requires the adminPolicy evaluator to agree.
func TestIsAdminByPolicy(t *testing.T) {
	t.Parallel()

	isAdminByPolicy := func(uac *reqCtx.UserAccessControl) bool {
		ok, _ := uac.IsAdminByPolicy()

		return ok
	}

	uac := reqCtx.NewUserAccessControl()
	require.True(t, uac.IsAdmin())
	require.False(t, isAdminByPolicy(uac))

	uac.SetGlobPatterns(constants.ReadPermission, map[string]bool{"**": true})
	require.False(t, isAdminByPolicy(uac))

	uac.SetIsAdmin(false)
	require.False(t, isAdminByPolicy(uac))

	// admin membership alone, without an adminPolicy evaluator, is not enough
	uac.SetIsAdmin(true)
	require.False(t, isAdminByPolicy(uac))

	uac.SetAdminPolicyEvaluator(func() (bool, string) { return true, "" })
	require.True(t, isAdminByPolicy(uac))

	uac.SetAdminPolicyEvaluator(func() (bool, string) { return false, "admin requires TLS" })
	ok, reason := uac.IsAdminByPolicy()
	require.False(t, ok)
	require.Equal(t, "admin requires TLS", reason)

	// a non-admin is denied without consulting the evaluator
	uac.SetIsAdmin(false)
	uac.SetAdminPolicyEvaluator(func() (bool, string) { return true, "" })
	require.False(t, isAdminByPolicy(uac))
}
