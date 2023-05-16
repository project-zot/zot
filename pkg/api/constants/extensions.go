package constants

// https://github.com/opencontainers/distribution-spec/tree/main/extensions#extensions-api-for-distribution
const (
	ExtCatalogPrefix     = "/_catalog"
	ExtOciDiscoverPrefix = "/_oci/ext/discover"
	// zot specific extensions.
	ExtPrefix = "/_zot/ext"

	ExtSearch        = "/search"
	ExtSearchPrefix  = ExtPrefix + ExtSearch
	FullSearchPrefix = RoutePrefix + ExtSearchPrefix

	ExtMgmt        = "/mgmt"
	ExtMgmtPrefix  = ExtPrefix + ExtMgmt
	FullMgmtPrefix = RoutePrefix + ExtMgmtPrefix

	ExtUserPreferences        = "/userprefs"
	ExtUserPreferencesPrefix  = ExtPrefix + ExtUserPreferences
	FullUserPreferencesPrefix = RoutePrefix + ExtUserPreferencesPrefix
)
