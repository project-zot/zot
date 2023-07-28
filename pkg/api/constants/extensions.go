package constants

// https://github.com/opencontainers/distribution-spec/tree/main/extensions#extensions-api-for-distribution
const (
	ExtCatalogPrefix     = "/_catalog"
	ExtOciDiscoverPrefix = "/_oci/ext/discover"

	BaseExtension = "_zot"

	// zot specific extensions.
	BasePrefix = "/_zot"
	ExtPrefix  = BasePrefix + "/ext"

	// search extension.
	ExtSearch        = "/search"
	ExtSearchPrefix  = ExtPrefix + ExtSearch
	FullSearchPrefix = RoutePrefix + ExtSearchPrefix

	// mgmt extension.
	Mgmt     = "/mgmt"
	ExtMgmt  = ExtPrefix + Mgmt
	FullMgmt = RoutePrefix + ExtMgmt

	// signatures extension.
	Notation     = "/notation"
	ExtNotation  = ExtPrefix + Notation
	FullNotation = RoutePrefix + ExtNotation
	Cosign       = "/cosign"
	ExtCosign    = ExtPrefix + Cosign
	FullCosign   = RoutePrefix + ExtCosign

	// user preferences extension.
	UserPrefs     = "/userprefs"
	ExtUserPrefs  = ExtPrefix + UserPrefs
	FullUserPrefs = RoutePrefix + ExtUserPrefs
)
