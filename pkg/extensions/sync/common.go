package sync

import "context"

// OnDemand pulls images and referrers from upstream registries on client request.
type OnDemand interface {
	// SyncImage syncs a single image (repo:tag or repo:digest) into local storage.
	SyncImage(ctx context.Context, repo, reference string) error
	// SyncReferrers syncs referrers for the given subject digest into local storage.
	SyncReferrers(ctx context.Context, repo string, subjectDigestStr string, referenceTypes []string) error
	// ShouldCheckUpstreamManifest reports whether repo:reference still needs an upstream check.
	ShouldCheckUpstreamManifest(repo, reference string) bool
}
