package imagestore

import (
	"errors"
	"net/http"
	"path"

	"github.com/distribution/distribution/v3/registry/storage/driver"
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
// real directories, and dedupe makes each copy of a blob a hardlink to the same inode, so
// every copy holds the content. Remote storage keeps no empty directories, and dedupe leaves
// a zero-byte placeholder at each copy except the one holding the content.
//
// Local storage relies on one more driver property: WriteFile rewrites a file in place, so a
// copy repaired by rewriting it is repaired for every hardlink to it as well.
//
// The lifecycle owns the placeholder model, so the image store never assumes it:
//   - IsPlaceholder decides whether a read has to go through the cache to find the content,
//     and which copies the dedupe and restore walks treat as placeholders.
//   - HandOffContent keeps the content alive when the copy holding it is deleted.
//   - DeletesCanDestroySharedContent decides whether deletes wait for the dedupe walk.
//
// What stays in the image store is the driver-independent integrity rule: a zero-byte file
// for a digest that is not the empty one is never served, and never used as a dedupe origin.
type blobLifecycle interface {
	// IsPlaceholder reports whether the file at a copy of digest, as already stat'd, is a
	// dedupe placeholder whose content is at the path the cache records.
	// Local: never, since a hardlink holds the content. Remote: a zero-byte file for a
	// digest that is not the empty one.
	IsPlaceholder(digest godigest.Digest, binfo driver.FileInfo) bool

	// LinkBlob makes dstPath stand for the content at srcPath, during dedupe. Linking a path
	// onto itself does nothing.
	// Local: a hardlink. Remote: a zero-byte placeholder at dstPath.
	LinkBlob(srcPath, dstPath string) error

	// HandOffContent is called when fromPath, the copy holding digest's content (fromSize
	// bytes), is about to be deleted and toPath is the copy that is to become the origin. It
	// makes sure toPath holds the content, and reports whether doing so removed fromPath; if
	// not, the caller still has to delete it. A toPath missing from storage is reported as the
	// driver's missing error, so that the caller can drop it and try another copy.
	// Local: a hardlink already holds the content, unless toPath is a corrupt zero-size copy
	// (older dedupe walks recorded them without repair); fromPath is moved onto such a copy.
	// Nothing is moved for the empty digest, or when fromPath is empty too, as when both are
	// links to one truncated inode, where a rename would succeed without removing either.
	// Remote: if toPath is zero-size (a placeholder, or a copy of the empty digest), fromPath
	// is moved onto it; a toPath that already holds the content is left alone.
	HandOffContent(digest godigest.Digest, fromPath string, fromSize int64, toPath string) (removedFrom bool, err error)

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

// isEmptyContentDigest reports whether digest is the algorithm's hash of zero bytes.
func isEmptyContentDigest(digest godigest.Digest) bool {
	return digest.Algorithm().FromBytes(nil) == digest
}

// linkDistinct links dstPath to srcPath unless both name the same path. Remote drivers
// implement Link as writing empty bytes to dstPath, so a self-link would replace the only
// content copy with a placeholder.
func linkDistinct(storeDriver storageTypes.Driver, srcPath, dstPath string) error {
	if path.Clean(srcPath) == path.Clean(dstPath) {
		return nil
	}

	return storeDriver.Link(srcPath, dstPath)
}

type localHardlinkBlobLifecycle struct {
	storeDriver storageTypes.Driver
	rootDir     string
	metrics     monitoring.MetricServer
}

func (l *localHardlinkBlobLifecycle) IsPlaceholder(_ godigest.Digest, _ driver.FileInfo) bool {
	return false
}

func (l *localHardlinkBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return linkDistinct(l.storeDriver, srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) HandOffContent(digest godigest.Digest, fromPath string, fromSize int64,
	toPath string,
) (bool, error) {
	binfo, err := l.storeDriver.Stat(toPath)
	if err != nil {
		return false, err
	}

	// a hardlink keeps the content when another link is deleted
	if !lacksContent(digest, binfo.Size()) || fromSize == 0 {
		return false, nil
	}

	if err := l.storeDriver.Move(fromPath, toPath); err != nil {
		return false, err
	}

	return true, nil
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

func (r *remoteSharedBlobLifecycle) IsPlaceholder(digest godigest.Digest, binfo driver.FileInfo) bool {
	return lacksContent(digest, binfo.Size())
}

func (r *remoteSharedBlobLifecycle) LinkBlob(srcPath, dstPath string) error {
	return linkDistinct(r.storeDriver, srcPath, dstPath)
}

func (r *remoteSharedBlobLifecycle) HandOffContent(_ godigest.Digest, fromPath string, _ int64,
	toPath string,
) (bool, error) {
	binfo, err := r.storeDriver.Stat(toPath)
	if err != nil {
		return false, err
	}

	// Any zero-size copy, not only a placeholder: moving onto a copy of the empty digest is
	// as good as deleting fromPath, and saves the separate delete.
	if binfo.Size() != 0 {
		return false, nil
	}

	if err := r.storeDriver.Move(fromPath, toPath); err != nil {
		return false, err
	}

	return true, nil
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
