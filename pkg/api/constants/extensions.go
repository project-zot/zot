package constants

// https://github.com/opencontainers/distribution-spec/tree/main/extensions#extensions-api-for-distribution
const (
	ExtCatalogPrefix     = "/_catalog"
	ExtOciDiscoverPrefix = "/_oci/ext/discover"
	// zot specific extensions.
	ExtPrefix                 = "/_zot/ext"
	ExtSearchPrefix           = ExtPrefix + "/search"
	FullSearchPrefix          = RoutePrefix + ExtSearchPrefix
	ExtMgmtPrefix             = ExtPrefix + "/mgmt"
	FullMgmtPrefix            = RoutePrefix + ExtMgmtPrefix
	ExtUserPreferencesPrefix  = ExtPrefix + "/userprefs"
	FullUserPreferencesPrefix = RoutePrefix + ExtUserPreferencesPrefix
)
