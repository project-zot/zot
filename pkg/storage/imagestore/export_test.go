package imagestore

import (
	"time"

	godigest "github.com/opencontainers/go-digest"

	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// IsDigestReferencedOutsideRepo exposes the global-blob reclaim gate to tests that need a
// real storage driver, which the internal test package cannot import without a cycle.
func IsDigestReferencedOutsideRepo(store storageTypes.ImageStore, repo string, digest godigest.Digest) (bool, error) {
	return store.(*ImageStore).isDigestReferencedOutsideRepo(repo, digest) //nolint:forcetypeassert // test helper
}

// SetRepoGraphRefsTTL overrides how long a repository's manifest graph is trusted.
func SetRepoGraphRefsTTL(store storageTypes.ImageStore, ttl time.Duration) {
	store.(*ImageStore).repoGraphs.ttl = ttl //nolint:forcetypeassert // test helper
}

// SetReclaimClaimLease shortens how long a global blob reclaim claim is honoured.
func SetReclaimClaimLease(store storageTypes.ImageStore, lease time.Duration) {
	store.(*ImageStore).reclaimClaimLease = lease //nolint:forcetypeassert // test helper
}

// SetReclaimLatePinAfter shortens how long a linker that found no reclaim marker runs unpinned.
func SetReclaimLatePinAfter(store storageTypes.ImageStore, after time.Duration) {
	store.(*ImageStore).reclaimLatePinAfter = after //nolint:forcetypeassert // test helper
}

// GuardGlobalBlobLink runs link under the reclaim guard, as every linking path does.
func GuardGlobalBlobLink(store storageTypes.ImageStore, digest godigest.Digest, link func() error) error {
	return store.(*ImageStore).guardGlobalBlobLink(digest, link) //nolint:forcetypeassert // test helper
}
