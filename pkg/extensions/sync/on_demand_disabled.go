//go:build !sync
// +build !sync

package sync

import "context"

type BaseOnDemand struct{}

func (onDemand *BaseOnDemand) SyncImage(ctx context.Context, repo, reference string) error {
	return nil
}

func (onDemand *BaseOnDemand) SyncReference(ctx context.Context, repo string, subjectDigestStr string,
	referenceType string,
) error {
	return nil
}
