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
