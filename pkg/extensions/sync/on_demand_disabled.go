//go:build !sync
// +build !sync

package sync

type BaseOnDemand struct{}

func (onDemand *BaseOnDemand) SyncImage(repo, reference string) error {
	return nil
}

func (onDemand *BaseOnDemand) SyncReference(repo string, subjectDigestStr string, referenceType string) error {
	return nil
}
