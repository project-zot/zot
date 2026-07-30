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

// blobLifecycle encapsulates the operations that differ between local storage, which
// dedupes via real hardlinks, and a remote backend (S3/GCS/Azure), which has no hardlink
// equivalent and instead dedupes by keeping one real copy in the global blobstore repo
// (_blobstore/) and writing empty "marker" files at every other repo path that references
// it, redirecting reads to the global copy. Implementations are behavior-preserving
// adapters for the existing local/remote flows.
type blobLifecycle interface {
	// PromoteCandidate moves/copies a blob from a repo's local path into the global
	// blobstore, making it the canonical copy for that digest. Local: hardlink (cheap,
	// same inode). Remote: streamed copy of the actual bytes (dstPath has no content of
	// its own yet).
	PromoteCandidate(srcPath, dstPath string) error

	// ConvertMigratedRepoBlobToMarker runs once per pre-existing repo blob during the
	// one-time upgrade to the global blobstore (see upgradeToGlobalBlobstore): after
	// PromoteCandidate has copied one repo's blob into the global blobstore as the new
	// canonical copy, every *other* repo that already held a full, real copy of the same
	// digest must have that copy replaced by a marker, so the content only exists once.
	// Local: no-op - local repos already dedupe via hardlinks to a shared inode, so there
	// is nothing to convert. Remote: writes an empty marker at repoBlobPath (see LinkBlob),
	// replacing what was previously a full duplicate.
	ConvertMigratedRepoBlobToMarker(globalBlobPath, repoBlobPath string) error

	// LinkBlob records repoBlobPath (dstPath) as a reference to an existing blob at
	// srcPath during normal (non-migration) dedupe - e.g. a push whose content already
	// exists under a different repo or digest-only path. Local: hardlink. Remote: writes
	// an empty marker file; the real content is read back through ResolveReadPath instead.
	LinkBlob(srcPath, dstPath string) error

	// ResolveReadPath picks which path a read should actually use for blobPath. Local:
	// delegates to resolveReadPathWithCache, using blobSize to tell a real hardlink apart
	// from a zero-byte placeholder (see that function's comment for the full case
	// breakdown). Remote: prefers globalBlobPath if it exists (the usual case, since
	// content lives centrally there), falling back to blobPath only for blobs that
	// predate the global blobstore or are mid-upload; ignores resolveFromCache entirely.
	ResolveReadPath(blobPath, globalBlobPath string, digest godigest.Digest, blobSize int64,
		resolveFromCache func(godigest.Digest) (string, error),
	) (string, error)

	// ShouldDeleteGlobalBlob reports whether the global blobstore's copy of digest is
	// safe to delete now that globalBlobPath's caller-side reference is gone. Local: uses
	// the filesystem's hardlink count (nlink) when the platform reports it - if this was
	// the last link, it's safe; falls back to isDigestReferenced (a cache-based scan)
	// otherwise. Remote: always uses isDigestReferenced, since there is no hardlink count
	// to consult.
	ShouldDeleteGlobalBlob(globalBlobPath string, digest godigest.Digest,
		isDigestReferenced func(godigest.Digest) (bool, error),
	) (bool, error)

	// ShouldGateDeleteUntilRebuild reports whether deletes must wait until
	// RunDedupeBlobs's startup rebuild has walked every pre-existing blob (see
	// dedupeRebuildDone). Local: false - ShouldDeleteGlobalBlob's nlink check doesn't
	// depend on the cache being warm. Remote: true - reference-checking is entirely
	// cache-based here, so deleting before the rebuild completes risks deleting a blob
	// the cache doesn't know is still referenced elsewhere yet.
	ShouldGateDeleteUntilRebuild() bool

	// IncludeRepoInMountCandidates reports whether repo should be considered a candidate
	// source for cross-repo blob mount/dedupe lookups (see GetAllDedupeReposCandidates).
	// Both implementations exclude the global blobstore repo itself (_blobstore/), an
	// internal implementation detail rather than a real repo a mount could come from.
	IncludeRepoInMountCandidates(repo string) bool
}

// resolveReadPathWithCache is localHardlinkBlobLifecycle.ResolveReadPath's body (remote
// has its own, globalBlobPath-based logic - see remoteMarkerBlobLifecycle.ResolveReadPath).
// blobSize is blobPath's on-disk size, as already Stat'd by the caller.
//
//   - blobSize > 0: blobPath's hardlink already holds the real content (its Stat size is
//     the real content's size, not zero, since hardlinks share the same inode/bytes as
//     whatever they're linked to). Nothing to resolve - return blobPath unchanged.
//   - blobSize <= 0: blobPath is a zero-byte file, which is ambiguous on its own. Compare
//     digest against the hash of empty content for its algorithm: if it matches, this is
//     a genuine empty blob and blobPath (still zero bytes, correctly) is the right answer.
//     Otherwise, a real hardlink to non-empty content can't legitimately be zero bytes, so
//     something's off (e.g. an interrupted or legacy write left a stub) - fall back to
//     resolveFromCache (checkCacheBlob), which looks up a path elsewhere in the store that
//     actually has the bytes for this digest, rather than serving up the empty stub.
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
