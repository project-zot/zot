//go:build !sync

package sync

import (
	"context"

	"github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
)

type BaseOnDemand struct{}

func (onDemand *BaseOnDemand) SyncImage(ctx context.Context, repo, reference, _ string) error {
	return nil
}

func (onDemand *BaseOnDemand) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string, _ string,
) error {
	return nil
}

func (onDemand *BaseOnDemand) ShouldCheckUpstreamManifest(_, _, _ string) bool {
	return true
}

func (onDemand *BaseOnDemand) ShouldQueueOnDemandSync(_, _ string) bool {
	return false
}

func (onDemand *BaseOnDemand) QueueImage(_ context.Context, _, _, _ string) {}

// Streaming stubs for builds without the sync extension: nothing is ever streamed.

func (onDemand *BaseOnDemand) FetchManifestForStream(ctx context.Context, repo, reference string,
	_ string, onSynced func(manifest.Manifest),
) (manifest.Manifest, error) {
	return nil, zerr.ErrSyncOnDemandDisabled
}

func (onDemand *BaseOnDemand) StreamManager() StreamManager {
	return nil
}

func (onDemand *BaseOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	return false
}
