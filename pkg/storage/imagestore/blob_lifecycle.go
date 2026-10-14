package imagestore

import (
	"errors"
	"net/http"
	"path"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// blobLifecycle holds everything the image store does differently on local storage and on
// remote (object) storage. The image store asks it, and never checks which driver it runs on:
// newBlobLifecycle makes that choice once, when the store is created.
//
// The differences come from two places. Local storage is a filesystem the store owns: it has
// real directories, and dedupe makes each copy of a blob a hardlink to the same inode. Remote
// storage keeps no empty directories, and dedupe leaves a zero-byte placeholder at each copy,
// which reads resolve to the stored content through the cache.
type blobLifecycle interface {
	// LinkBlob makes dstPath stand for the content at srcPath, during dedupe.
	// Local: a hardlink. Remote: a zero-byte placeholder at dstPath.
	LinkBlob(srcPath, dstPath string) error

	// ResolveReadPath returns the path a read of blobPath should use, given its size as
	// already stat'd. Local: blobPath itself, since a hardlink holds the content. Remote: a
	// zero-byte blobPath for a digest that is not the empty one is a placeholder, so the
	// content's path comes from fallbackResolverFunc; otherwise blobPath itself.
	ResolveReadPath(blobPath string, digest godigest.Digest, blobSize int64,
		fallbackResolverFunc func(godigest.Digest) (string, error),
	) (string, error)

	// ValidateBlobsDir reports whether the repo at repoDir has the blobs directory an image
	// layout needs. Local: blobs/ must exist and be a directory. Remote: object stores keep
	// no empty directories, so there is nothing to check.
	ValidateBlobsDir(repoDir string) (bool, error)

	// RedirectURL returns a URL a client can fetch a blob from directly, or "" when blobs are
	// served by zot itself. blobPath is called only when a URL can be made, to find the path
	// holding the blob's content. Local: always "". Remote: the driver's URL for that path.
	RedirectURL(r *http.Request, blobPath func() (string, error)) (string, error)

	// UpdateStorageUsage refreshes the storage-usage metric for repo. Local: measures the repo
	// directory. Remote: nothing, since measuring would mean listing every object in the repo.
	UpdateStorageUsage(repo string)

	// DeletesCanDestroySharedContent reports whether deleting a blob the cache does not know
	// about can remove content other repos still use, so that such deletes have to wait for
	// the dedupe walk to have recorded every blob (see RunDedupeBlobs and deleteBlob).
	// Local: no, an inode with several hard links outlives any one of them. Remote: yes, a
	// placeholder does not hold the content, which is stored once.
	DeletesCanDestroySharedContent() bool
}

func newBlobLifecycle(storeDriver storageTypes.Driver, rootDir string,
	metrics monitoring.MetricServer,
) blobLifecycle {
	if storeDriver.Name() == storageConstants.LocalStorageDriverName {
		return &localHardlinkBlobLifecycle{storeDriver: storeDriver, rootDir: rootDir, metrics: metrics}
	}

	return &remoteSharedBlobLifecycle{storeDriver: storeDriver}
}

type localHardlinkBlobLifecycle struct {
	storeDriver storageTypes.Driver
	rootDir     string
	metrics     monitoring.MetricServer
}

func (l *localHardlinkBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return l.storeDriver.Link(srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) ResolveReadPath(blobPath string, _ godigest.Digest, _ int64,
	_ func(godigest.Digest) (string, error),
) (string, error) {
	return blobPath, nil
}

func (l *localHardlinkBlobLifecycle) ValidateBlobsDir(repoDir string) (bool, error) {
	// Stat, not DirExists: DirExists collapses Transient/Permanent into false, which would
	// soft-skip a live repo from inventory walks as (false, nil).
	blobsInfo, err := l.storeDriver.Stat(path.Join(repoDir, ispec.ImageBlobsDir))
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return false, nil
		}

		if errors.Is(err, zerr.ErrStorageTransient) || errors.Is(err, zerr.ErrStoragePermanent) {
			return false, err
		}

		return false, errclass.MarkTransient(err)
	}

	return blobsInfo.IsDir(), nil
}

func (l *localHardlinkBlobLifecycle) RedirectURL(_ *http.Request, _ func() (string, error)) (string, error) {
	// zot serves local blobs itself; there is no external URL to send a client to
	return "", nil
}

func (l *localHardlinkBlobLifecycle) UpdateStorageUsage(repo string) {
	monitoring.SetStorageUsage(l.metrics, l.rootDir, repo)
}

func (l *localHardlinkBlobLifecycle) DeletesCanDestroySharedContent() bool {
	return false
}

type remoteSharedBlobLifecycle struct {
	storeDriver storageTypes.Driver
}

func (r *remoteSharedBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return r.storeDriver.Link(srcPath, dstPath)
}

func (r *remoteSharedBlobLifecycle) ResolveReadPath(blobPath string, digest godigest.Digest, blobSize int64,
	fallbackResolverFunc func(godigest.Digest) (string, error),
) (string, error) {
	if blobSize == 0 && !isEmptyContentDigest(digest) {
		return fallbackResolverFunc(digest)
	}

	return blobPath, nil
}

func (r *remoteSharedBlobLifecycle) ValidateBlobsDir(_ string) (bool, error) {
	return true, nil
}

func (r *remoteSharedBlobLifecycle) RedirectURL(req *http.Request, blobPath func() (string, error)) (string, error) {
	contentPath, err := blobPath()
	if err != nil {
		return "", err
	}

	redirectURL, err := r.storeDriver.RedirectURL(req, contentPath)
	if err != nil {
		return "", mapStorageErr(err)
	}

	return redirectURL, nil
}

func (r *remoteSharedBlobLifecycle) UpdateStorageUsage(_ string) {}

func (r *remoteSharedBlobLifecycle) DeletesCanDestroySharedContent() bool {
	return true
}
