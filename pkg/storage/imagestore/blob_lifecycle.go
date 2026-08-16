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
// dedupes via real hardlinks, and remote storage, which keeps payloads only in the
// global blobstore while repository ownership is tracked separately.
type blobLifecycle interface {
	// PromoteCandidate moves/copies a blob from a repo's local path into the global
	// blobstore, making it the canonical copy for that digest. Local: hardlink (cheap,
	// same inode). Remote: streamed copy of the actual bytes (dstPath has no content of
	// its own yet).
	PromoteCandidate(srcPath, dstPath string) error

	// RemoveMigratedRepoBlob runs once per pre-existing repo blob during the
	// one-time upgrade to the global blobstore (see upgradeToGlobalBlobstore): after
	// PromoteCandidate has copied one repo's blob into the global blobstore as the new
	// canonical copy, every *other* repo that already held a full, real copy of the same
	// digest must have that copy removed, so the content only exists once.
	// Local: no-op - local repos already dedupe via hardlinks to a shared inode, so there
	// is nothing to convert. Remote: deletes repoBlobPath after promotion is verified.
	RemoveMigratedRepoBlob(globalBlobPath, repoBlobPath string) error

	// LinkBlob links repoBlobPath (dstPath) to existing content at srcPath during normal
	// dedupe. Local: hardlink. Remote: no-op; the caller records logical ownership.
	LinkBlob(srcPath, dstPath string) error

	// ResolveReadPath picks which path a read should actually use for blobPath. Local:
	// delegates to resolveReadPathWithCache, using blobSize to tell a real hardlink with
	// content apart from a zero-byte stub left by an interrupted or legacy write (see
	// that function's comment for the full case breakdown). Remote: prefers
	// globalBlobPath if it exists (the usual case, since content lives centrally there),
	// falling back to blobPath only for blobs that predate the global blobstore or are
	// mid-upload; ignores fallbackResolverFunc entirely.
	ResolveReadPath(blobPath, globalBlobPath string, digest godigest.Digest, blobSize int64,
		fallbackResolverFunc func(godigest.Digest) (string, error),
	) (string, error)

	// ShouldDeleteGlobalBlob reports whether the global blobstore's copy of digest is
	// safe to delete now that globalBlobPath's caller-side reference is gone. Local: uses
	// the filesystem's hardlink count (nlink) when the platform reports it - if this was
	// the last link, it's safe; falls back to isDigestReferenced (a cache-based scan)
	// otherwise. Remote: always uses isDigestReferenced, since there is no hardlink count
	// to consult. isDigestReferenced is a parameter rather than a field on blobLifecycle
	// because it needs ImageStore's cache (blobRefsForDigest) - a blobLifecycle is
	// constructed from just a storeDriver (see newBlobLifecycle) and has no reference
	// back to the ImageStore that owns it.
	ShouldDeleteGlobalBlob(globalBlobPath string, digest godigest.Digest,
		isDigestReferenced func(godigest.Digest) (bool, error),
	) (bool, error)

	// UsesLogicalRepoRefs reports whether dedupe ownership is represented only in
	// metadata. Local storage returns false because each repo has a hardlink.
	UsesLogicalRepoRefs() bool

	// IncludeRepoInMountCandidates reports whether repo should be considered a candidate
	// source for cross-repo blob mount/dedupe lookups (see GetAllDedupeReposCandidates).
	// Both implementations exclude the global blobstore repo itself (_blobstore/), an
	// internal implementation detail rather than a real repo a mount could come from.
	IncludeRepoInMountCandidates(repo string) bool
}

// resolveReadPathWithCache is localHardlinkBlobLifecycle.ResolveReadPath's body; remote
// shared storage resolves directly from the global blob path.
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
//     fallbackResolverFunc (checkCacheBlob), which looks up a path elsewhere in the store that
//     actually has the bytes for this digest, rather than serving up the empty stub.
//
// fallbackResolverFunc is a parameter, not a call to is.checkCacheBlob directly, because this
// is a plain package-level function with no ImageStore reference - the same reason
// ShouldDeleteGlobalBlob takes isDigestReferenced as a parameter. It also keeps this function
// unit-testable with a stub resolver, independent of any real cache driver.
func resolveReadPathWithCache(blobPath string, digest godigest.Digest, blobSize int64,
	fallbackResolverFunc func(godigest.Digest) (string, error),
) (string, error) {
	if blobSize > 0 {
		return blobPath, nil
	}

	if digest.Algorithm().FromBytes(nil) == digest {
		return blobPath, nil
	}

	return fallbackResolverFunc(digest)
}

func newBlobLifecycle(storeDriver storageTypes.Driver) blobLifecycle {
	if storeDriver.Name() == constants.LocalStorageDriverName {
		return &localHardlinkBlobLifecycle{storeDriver: storeDriver, statFn: os.Stat}
	}

	return &remoteSharedBlobLifecycle{storeDriver: storeDriver}
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

func (l *localHardlinkBlobLifecycle) RemoveMigratedRepoBlob(_, _ string) error {
	// Local filesystem keeps hardlinks in repos; no marker conversion is needed.
	return nil
}

func (l *localHardlinkBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return l.storeDriver.Link(srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) ResolveReadPath(blobPath, _ string, digest godigest.Digest, blobSize int64,
	fallbackResolverFunc func(godigest.Digest) (string, error),
) (string, error) {
	return resolveReadPathWithCache(blobPath, digest, blobSize, fallbackResolverFunc)
}

// isDigestReferenced stays a parameter here too, even though this method is already
// local-specific: newBlobLifecycle(storeDriver) runs inside NewImageStore's own struct
// literal (see the lifecycle field there), before the *ImageStore value it would need to
// close over exists, so there's no is.isDigestReferencedAcrossRepos to capture at
// construction time without a second, later wiring step.
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

// hardLinkCount reads Nlink off fileInfo.Sys() via reflection since its static type is
// platform-specific: on linux/darwin/freebsd it's *syscall.Stat_t, which does have an
// Nlink field (an unsigned int of varying width per platform/arch, but always something
// CanUint() accepts). On windows, Sys() is *syscall.Win32FileAttributeData, which has no
// Nlink field at all - FieldByName returns an invalid reflect.Value there, so this
// returns (0, false) rather than panicking, and the caller falls back to a
// cache-based isDigestReferenced check instead of trusting a link count.
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

func (l *localHardlinkBlobLifecycle) UsesLogicalRepoRefs() bool {
	return false
}

func (l *localHardlinkBlobLifecycle) IncludeRepoInMountCandidates(repo string) bool {
	return repo != constants.GlobalBlobsRepo
}

type remoteSharedBlobLifecycle struct {
	storeDriver storageTypes.Driver
}

func (r *remoteSharedBlobLifecycle) PromoteCandidate(srcPath, dstPath string) error {
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

func (r *remoteSharedBlobLifecycle) RemoveMigratedRepoBlob(globalBlobPath, repoBlobPath string) error {
	return r.storeDriver.Delete(repoBlobPath)
}

func (r *remoteSharedBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return nil
}

func (r *remoteSharedBlobLifecycle) ResolveReadPath(blobPath, globalBlobPath string, digest godigest.Digest,
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

func (r *remoteSharedBlobLifecycle) ShouldDeleteGlobalBlob(_ string, digest godigest.Digest,
	isDigestReferenced func(godigest.Digest) (bool, error),
) (bool, error) {
	isReferenced, err := isDigestReferenced(digest)
	if err != nil {
		return false, err
	}

	return !isReferenced, nil
}

func (r *remoteSharedBlobLifecycle) UsesLogicalRepoRefs() bool {
	return true
}

func (r *remoteSharedBlobLifecycle) IncludeRepoInMountCandidates(repo string) bool {
	return repo != constants.GlobalBlobsRepo
}
