package imagestore

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"

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
	ConvertMigratedRepoBlobToMarker(globalBlobPath, repoBlobPath string) error
	LinkBlob(srcPath, dstPath string) error
	ResolveReadPath(blobPath, globalBlobPath string, digest godigest.Digest, blobSize int64,
		resolveFromCache func(godigest.Digest) (string, error),
	) (string, error)
	ShouldDeleteGlobalBlob(globalBlobPath string, digest godigest.Digest,
		isDigestReferenced func(godigest.Digest) (bool, error),
	) (bool, error)
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
		return &localHardlinkBlobLifecycle{storeDriver: storeDriver, statFn: os.Stat}
	}

	return &remoteMarkerBlobLifecycle{storeDriver: storeDriver}
}

type localHardlinkBlobLifecycle struct {
	storeDriver storageTypes.Driver
	// statFn defaults to os.Stat (set by newBlobLifecycle); overridable in tests so
	// ShouldDeleteGlobalBlob's nlink-unavailable fallback can be driven deterministically
	// instead of depending on a real filesystem's syscall.Stat_t always being present.
	statFn func(name string) (os.FileInfo, error)
}

func (l *localHardlinkBlobLifecycle) PromoteCandidate(srcPath, dstPath string) error {
	return l.storeDriver.Link(srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) ConvertMigratedRepoBlobToMarker(_, _ string) error {
	// Local filesystem keeps hardlinks in repos; no marker conversion is needed.
	return nil
}

func (l *localHardlinkBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return l.storeDriver.Link(srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) ResolveReadPath(blobPath, _ string, digest godigest.Digest, blobSize int64,
	resolveFromCache func(godigest.Digest) (string, error),
) (string, error) {
	return resolveReadPathWithCache(blobPath, digest, blobSize, resolveFromCache)
}

func (l *localHardlinkBlobLifecycle) ShouldDeleteGlobalBlob(globalBlobPath string, digest godigest.Digest,
	isDigestReferenced func(godigest.Digest) (bool, error),
) (bool, error) {
	statFn := l.statFn
	if statFn == nil {
		statFn = os.Stat
	}

	fileInfo, err := statFn(globalBlobPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, err
	}

	nLink, ok := hardLinkCount(fileInfo)
	if ok {
		return nLink <= 1, nil
	}

	if isDigestReferenced == nil {
		return false, nil
	}

	isReferenced, err := isDigestReferenced(digest)
	if err != nil {
		return false, err
	}

	return !isReferenced, nil
}

func hardLinkCount(fileInfo os.FileInfo) (uint64, bool) {
	fileInfoValue := reflect.Indirect(reflect.ValueOf(fileInfo.Sys()))
	if !fileInfoValue.IsValid() || fileInfoValue.Kind() != reflect.Struct {
		return 0, false
	}

	nLink := fileInfoValue.FieldByName("Nlink")
	if !nLink.IsValid() || !nLink.CanUint() {
		return 0, false
	}

	return nLink.Uint(), true
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

func (r *remoteMarkerBlobLifecycle) ConvertMigratedRepoBlobToMarker(globalBlobPath, repoBlobPath string) error {
	return r.LinkBlob(globalBlobPath, repoBlobPath)
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

func (r *remoteMarkerBlobLifecycle) ShouldDeleteGlobalBlob(_ string, digest godigest.Digest,
	isDigestReferenced func(godigest.Digest) (bool, error),
) (bool, error) {
	isReferenced, err := isDigestReferenced(digest)
	if err != nil {
		return false, err
	}

	return !isReferenced, nil
}

func (r *remoteMarkerBlobLifecycle) ShouldGateDeleteUntilRebuild() bool {
	return true
}

func (r *remoteMarkerBlobLifecycle) IncludeRepoInMountCandidates(repo string) bool {
	return repo != constants.GlobalBlobsRepo
}
