//go:build !sync

package sync

import (
	"context"

	"github.com/regclient/regclient/types/manifest"
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

func (onDemand *BaseOnDemand) FetchManifestForStream(
	ctx context.Context, repo, reference string,
) (manifest.Manifest, error) {
	return manifest.New()
}

func (onDemand *BaseOnDemand) StreamManager() StreamManager {
	return nil
}
