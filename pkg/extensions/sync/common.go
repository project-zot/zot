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
	// ShouldQueueOnDemandSync reports whether a missing local manifest for repo should
	// return immediately while a background sync copies the image into storage.
	ShouldQueueOnDemandSync(repo string) bool
	// QueueImage schedules at most one background SyncImage for repo:reference from
	// onDemandInBackground registries that match the repo. The request context is detached.
	QueueImage(ctx context.Context, repo, reference string)
}
