//go:build !sync

package sync

import (
	"context"

	"github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
)

type BaseOnDemand struct{}

func (onDemand *BaseOnDemand) SyncImage(ctx context.Context, repo, reference string) error {
	return nil
}

func (onDemand *BaseOnDemand) SyncReferrers(ctx context.Context, repo string,
	subjectDigestStr string, referenceTypes []string,
) error {
	return nil
}

func (onDemand *BaseOnDemand) ShouldCheckUpstreamManifest(repo, reference string) bool {
	return true
}

func (onDemand *BaseOnDemand) FetchManifestForStream(ctx context.Context, repo, reference string,
) (manifest.Manifest, error) {
	return nil, zerr.ErrSyncOnDemandDisabled
}

func (onDemand *BaseOnDemand) StreamManager() StreamManager {
	return nil
}

func (onDemand *BaseOnDemand) IsStreamingEnabledForRepo(repo string) bool {
	return false
}
