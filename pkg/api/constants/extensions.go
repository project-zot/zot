package constants

// https://github.com/opencontainers/distribution-spec/tree/main/extensions#extensions-api-for-distribution
const (
	ExtCatalogPrefix     = "/_catalog"
	ExtOciDiscoverPrefix = "/_oci/ext/discover"
	// zot specific extensions.
	ExtSearchPrefix  = "/_zot/ext/search"
	FullSearchPrefix = RoutePrefix + ExtSearchPrefix
)
