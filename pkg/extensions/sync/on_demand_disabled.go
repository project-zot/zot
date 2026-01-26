//go:build !sync

package sync

import (
	"context"

	godigest "github.com/opencontainers/go-digest"
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

func (onDemand *BaseOnDemand) SyncBlob(ctx context.Context, repo string, digest godigest.Digest) error {
	return nil
}
