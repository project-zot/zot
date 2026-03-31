//go:build !sync

package sync

import (
	"context"
	"io"

	godigest "github.com/opencontainers/go-digest"

	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
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

func (onDemand *BaseOnDemand) SyncBlobOnDemand(ctx context.Context, repo string,
	digest godigest.Digest, imgStore storageTypes.ImageStore,
) (io.ReadCloser, int64, bool, <-chan struct{}, error) {
	return nil, 0, false, nil, nil
}

func (onDemand *BaseOnDemand) BlobDownloadDone(repo string, digest godigest.Digest, err error) {}

func (onDemand *BaseOnDemand) IsStreamEnabled() bool {
	return false
}
