package constants

// https://github.com/opencontainers/distribution-spec/tree/main/extensions#extensions-api-for-distribution
const (
	ExtCatalogPrefix     = "/_catalog"
	ExtOciDiscoverPrefix = "/_oci/ext/discover"

	BaseExtension = "_zot"

	// BasePrefix is a zot specific extension.
	BasePrefix = "/_zot"
	ExtPrefix  = BasePrefix + "/ext"

	// ExtSearch is the search extension.
	ExtSearch        = "/search"
	ExtSearchPrefix  = ExtPrefix + ExtSearch
	FullSearchPrefix = RoutePrefix + ExtSearchPrefix

	// Mgmt is the mgmt extension.
	Mgmt     = "/mgmt"
	ExtMgmt  = ExtPrefix + Mgmt
	FullMgmt = RoutePrefix + ExtMgmt

	// Notation is the signatures extension.
	Notation     = "/notation"
	ExtNotation  = ExtPrefix + Notation
	FullNotation = RoutePrefix + ExtNotation
	Cosign       = "/cosign"
	ExtCosign    = ExtPrefix + Cosign
	FullCosign   = RoutePrefix + ExtCosign

	// UserPrefs is the user preferences extension.
	UserPrefs     = "/userprefs"
	ExtUserPrefs  = ExtPrefix + UserPrefs
	FullUserPrefs = RoutePrefix + ExtUserPrefs
)
