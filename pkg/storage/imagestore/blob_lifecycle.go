package imagestore

import (
	"context"
	"errors"
	"io"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// blobLifecycle encapsulates backend-specific blob lifecycle operations.
// Implementations are behavior-preserving adapters for existing local/remote flows.
type blobLifecycle interface {
	PromoteCandidate(srcPath, dstPath string) error
	LinkBlob(srcPath, dstPath string) error
	ResolveReadPath(blobPath, globalBlobPath string, digest godigest.Digest, blobSize int64,
		resolveFromCache func(godigest.Digest) (string, error),
	) (string, error)
	ShouldGateDeleteUntilRebuild() bool
	IncludeRepoInMountCandidates(repo string) bool
}

func resolveReadPathWithCache(blobPath string, digest godigest.Digest, blobSize int64,
	resolveFromCache func(godigest.Digest) (string, error),
) (string, error) {
	if blobSize > 0 {
		return blobPath, nil
	}

	if digest.Algorithm().FromBytes(nil) == digest {
		return blobPath, nil
	}

	return resolveFromCache(digest)
}

func newBlobLifecycle(storeDriver storageTypes.Driver) blobLifecycle {
	if storeDriver.Name() == constants.LocalStorageDriverName {
		return &localHardlinkBlobLifecycle{storeDriver: storeDriver}
	}

	return &remoteMarkerBlobLifecycle{storeDriver: storeDriver}
}

type localHardlinkBlobLifecycle struct {
	storeDriver storageTypes.Driver
}

func (l *localHardlinkBlobLifecycle) PromoteCandidate(srcPath, dstPath string) error {
	return l.storeDriver.Link(srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return l.storeDriver.Link(srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) ResolveReadPath(blobPath, _ string, digest godigest.Digest, blobSize int64,
	resolveFromCache func(godigest.Digest) (string, error),
) (string, error) {
	return resolveReadPathWithCache(blobPath, digest, blobSize, resolveFromCache)
}

func (l *localHardlinkBlobLifecycle) ShouldGateDeleteUntilRebuild() bool {
	return false
}

func (l *localHardlinkBlobLifecycle) IncludeRepoInMountCandidates(repo string) bool {
	return repo != constants.GlobalBlobsRepo
}

type remoteMarkerBlobLifecycle struct {
	storeDriver storageTypes.Driver
}

func (r *remoteMarkerBlobLifecycle) PromoteCandidate(srcPath, dstPath string) error {
	blobReader, err := r.storeDriver.Reader(srcPath, 0)
	if err != nil {
		return err
	}

	blobWriter, err := r.storeDriver.Writer(dstPath, false)
	if err != nil {
		_ = blobReader.Close()

		return err
	}

	if _, err := io.Copy(blobWriter, blobReader); err != nil {
		_ = blobWriter.Cancel(context.Background())
		_ = blobReader.Close()
		_ = blobWriter.Close()

		return err
	}

	if err := blobWriter.Commit(context.Background()); err != nil {
		_ = blobWriter.Cancel(context.Background())
		_ = blobReader.Close()
		_ = blobWriter.Close()

		return err
	}

	if err := blobReader.Close(); err != nil {
		_ = blobWriter.Close()

		return err
	}

	if err := blobWriter.Close(); err != nil {
		return err
	}

	return nil
}

func (r *remoteMarkerBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return r.storeDriver.Link(srcPath, dstPath)
}

func (r *remoteMarkerBlobLifecycle) ResolveReadPath(blobPath, globalBlobPath string, digest godigest.Digest,
	blobSize int64, _ func(godigest.Digest) (string, error),
) (string, error) {
	if globalBlobPath != "" {
		if _, err := r.storeDriver.Stat(globalBlobPath); err == nil {
			return globalBlobPath, nil
		} else {
			var pathNotFoundErr driver.PathNotFoundError
			if !errors.As(err, &pathNotFoundErr) {
				return "", err
			}
		}
	}

	if blobSize > 0 || digest.Algorithm().FromBytes(nil) == digest {
		return blobPath, nil
	}

	return "", zerr.ErrBlobNotFound
}

func (r *remoteMarkerBlobLifecycle) ShouldGateDeleteUntilRebuild() bool {
	return true
}

func (r *remoteMarkerBlobLifecycle) IncludeRepoInMountCandidates(repo string) bool {
	return repo != constants.GlobalBlobsRepo
}
