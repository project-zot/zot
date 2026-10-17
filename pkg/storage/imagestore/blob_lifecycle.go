package imagestore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"reflect"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
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
//   - RepairSharedContent replaces wrong shared content with a verified upload.
//   - DeletesCanDestroySharedContent decides whether deletes wait for the dedupe walk.
//
// What stays in the image store is the driver-independent integrity rule: a zero-byte file
// for a digest that is not the empty one is never served, and never used as a dedupe origin.
type blobLifecycle interface { //nolint:interfacebloat
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

	// RepairSharedContent overwrites the content at originPath, which every deduped copy of the
	// blob shares, with the verified upload at uploadPath, and consumes uploadPath. It is used
	// when a blob is pushed and the shared content does not match the upload; the cache is not
	// changed.
	// Local: copies share one inode, so originPath is rewritten in place (Writer without append
	// truncates the existing file), which repairs every hardlink to it, and uploadPath is then
	// deleted. A rename would repair only the path it lands on. If the rewrite fails, originPath
	// may be left partly written; it was already wrong, the upload is still in place, and the
	// error reaches the client, so a retry repeats the repair.
	// Remote: placeholders resolve to originPath, so uploadPath is moved onto it.
	RepairSharedContent(uploadPath, originPath string) error

	// The methods below serve the global blobstore (GlobalBlobsRepo), which holds the one
	// copy of each deduped blob.

	// PromoteCandidate makes the global blobstore copy at dstPath out of a repo's copy at
	// srcPath, making it the canonical copy for that digest. Local: hardlink (cheap, same
	// inode). Remote: streamed copy of the actual bytes (dstPath has no content of its own
	// yet).
	PromoteCandidate(srcPath, dstPath string) error

	// RemoveMigratedRepoBlob runs once per pre-existing repo copy during the one-time
	// upgrade to the global blobstore, after PromoteCandidate has made the canonical copy and
	// the repo copy is recorded as an owner: every repo copy that holds the content itself
	// must give it up, so the content exists once. Local: no-op, repo copies are hardlinks of
	// the canonical copy's inode. Remote: a copy with content is replaced by a placeholder;
	// one already a placeholder, or gone, is left as it is.
	RemoveMigratedRepoBlob(globalBlobPath, repoBlobPath string) error

	// ShouldDeleteGlobalBlob reports whether the global blobstore copy of digest at
	// globalBlobPath is to be deleted now, once a repo's copy is gone and DeleteBlobRef has run.
	// Local: when no repo uses it, by the copy's hardlink count, which is 1 when only the
	// blobstore's own link remains; where the platform does not report one,
	// isDigestReferenced (a cache-based scan) decides. Remote: never, since another instance
	// may be linking the digest; the reclaim sweep deletes it under a claim. A copy already
	// gone is never to be deleted again.
	ShouldDeleteGlobalBlob(globalBlobPath string, digest godigest.Digest,
		isDigestReferenced func(godigest.Digest) (bool, error),
	) (bool, error)

	// IncludeRepoInMountCandidates reports whether repo may be a source for cross-repo blob
	// mounts. Both exclude the global blobstore, which is never a repository.
	IncludeRepoInMountCandidates(repo string) bool

	// KeepsContentInGlobalBlobstore reports whether deduped content lives in the global
	// blobstore, with repo copies only referring to it. Both do now (local repo copies are
	// hardlinks of the payload, remote ones placeholders); this goes away once nothing still
	// handles the earlier remote layout, where the origin was a repo's copy.
	KeepsContentInGlobalBlobstore() bool

	// PutBlobRef records blobPath in the reference index for the global blobstore payload of
	// digest. For the payload's own path, it records that the payload is there, which a reclaim
	// sweep requires before it deletes one. For a repo copy, it records that repo as an owner;
	// this runs before anything relies on the payload, so that from then on no sweep deletes
	// it, and while a sweep holds a claim on digest it waits for the claim to clear, up to
	// linkerClaimWait, then fails with a transient error for the client to retry.
	// Local: nothing to record, a hardlink keeps the payload.
	PutBlobRef(digest godigest.Digest, blobPath string) error

	// ReclaimGlobalBlobs deletes the global blobstore payloads no repo has owned for at least
	// delay. Local: nothing to do, a payload goes with its last repo copy. Remote: the reclaim
	// sweep (see reclaim.go).
	ReclaimGlobalBlobs(ctx context.Context, delay time.Duration) error

	// DeleteBlobRef drops repoPath's ownership of the global blobstore payload of digest, once its
	// repo copy is gone. Local: nothing to drop, the hardlink went with the copy. Remote: the
	// reference is removed, and once nothing owns digest, a reclaim marker tells the sweep to
	// look at the payload.
	DeleteBlobRef(digest godigest.Digest, repoPath string) error
}

const (
	// linkerClaimWait bounds how long PutBlobRef waits for a reclaim sweep's claim to clear. A sweep
	// holds one for as long as its payload delete may take, which is well under this.
	linkerClaimWait = 30 * time.Second
	// linkerClaimPoll is how often PutBlobRef retries meanwhile.
	linkerClaimPoll = 250 * time.Millisecond
)

// blobLifecycleDeps is what a blob lifecycle is built with.
type blobLifecycleDeps struct {
	storeDriver storageTypes.Driver
	rootDir     string
	metrics     monitoring.MetricServer
	log         zlog.Logger
	// refs is the store's cache, nil without one. Only the remote lifecycle uses it: there a
	// repo copy is a placeholder, so ownership of a payload is recorded in the cache's reference
	// index, and the reclaim sweep forgets a payload it deleted.
	refs storageTypes.Cache
}

func newBlobLifecycle(deps blobLifecycleDeps) blobLifecycle {
	if deps.storeDriver.Name() == storageConstants.LocalStorageDriverName {
		return &localHardlinkBlobLifecycle{
			storeDriver: deps.storeDriver, rootDir: deps.rootDir, metrics: deps.metrics, statFn: os.Stat,
		}
	}

	return &remoteSharedBlobLifecycle{
		storeDriver: deps.storeDriver, rootDir: deps.rootDir, log: deps.log, refs: deps.refs,
		claimWait: linkerClaimWait,
	}
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
	// statFn reads the hardlink count; os.Stat, overridable in tests so the fallback for
	// platforms that report no count can be driven.
	statFn func(name string) (os.FileInfo, error)
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

func (l *localHardlinkBlobLifecycle) RepairSharedContent(uploadPath, originPath string) error {
	if err := l.rewriteInPlace(uploadPath, originPath); err != nil {
		return err
	}

	// the upload is closed by now: Windows cannot delete a file that is still open
	return l.storeDriver.Delete(uploadPath)
}

// rewriteInPlace copies the file at srcPath over the file at dstPath without replacing it, so
// that every hardlink to dstPath sees the new content.
func (l *localHardlinkBlobLifecycle) rewriteInPlace(srcPath, dstPath string) error {
	reader, err := l.storeDriver.Reader(srcPath, 0)
	if err != nil {
		return err
	}

	defer reader.Close()

	// not Cancel on failure: it removes the file, which here is a link to the shared content
	writer, err := l.storeDriver.Writer(dstPath, false)
	if err != nil {
		return err
	}

	if _, err := io.Copy(writer, reader); err != nil {
		_ = writer.Close()

		return err
	}

	if err := writer.Commit(context.Background()); err != nil {
		_ = writer.Close()

		return err
	}

	return writer.Close()
}

func (l *localHardlinkBlobLifecycle) PromoteCandidate(srcPath, dstPath string) error {
	return linkDistinct(l.storeDriver, srcPath, dstPath)
}

func (l *localHardlinkBlobLifecycle) RemoveMigratedRepoBlob(_, _ string) error {
	// repo copies are hardlinks of the canonical copy's inode: nothing to remove
	return nil
}

func (l *localHardlinkBlobLifecycle) ShouldDeleteGlobalBlob(globalBlobPath string, digest godigest.Digest,
	isDigestReferenced func(godigest.Digest) (bool, error),
) (bool, error) {
	fileInfo, err := l.statFn(globalBlobPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, err
	}

	if nLink, ok := hardLinkCount(fileInfo); ok {
		// the blobstore's own link is the last one left
		return nLink <= 1, nil
	}

	if isDigestReferenced == nil {
		return false, nil
	}

	referenced, err := isDigestReferenced(digest)
	if err != nil {
		return false, err
	}

	return !referenced, nil
}

func (l *localHardlinkBlobLifecycle) IncludeRepoInMountCandidates(repo string) bool {
	return repo != storageConstants.GlobalBlobsRepo
}

func (l *localHardlinkBlobLifecycle) KeepsContentInGlobalBlobstore() bool {
	return true
}

func (l *localHardlinkBlobLifecycle) PutBlobRef(_ godigest.Digest, _ string) error {
	return nil
}

func (l *localHardlinkBlobLifecycle) DeleteBlobRef(_ godigest.Digest, _ string) error {
	return nil
}

func (l *localHardlinkBlobLifecycle) ReclaimGlobalBlobs(_ context.Context, _ time.Duration) error {
	return nil
}

// hardLinkCount returns a file's hardlink count where the platform reports one. It reads the
// Nlink field of the platform's stat structure by reflection, so it builds everywhere; where
// there is no such field (Windows) it reports none, and callers fall back to the cache.
func hardLinkCount(fileInfo os.FileInfo) (uint64, bool) {
	stat := reflect.Indirect(reflect.ValueOf(fileInfo.Sys()))
	if !stat.IsValid() || stat.Kind() != reflect.Struct {
		return 0, false
	}

	nLink := stat.FieldByName("Nlink")
	if !nLink.IsValid() || !nLink.CanUint() {
		return 0, false
	}

	return nLink.Uint(), true
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
	rootDir     string
	log         zlog.Logger
	refs        storageTypes.Cache
	claimWait   time.Duration // linkerClaimWait, shorter in tests
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

func (r *remoteSharedBlobLifecycle) RepairSharedContent(uploadPath, originPath string) error {
	// every placeholder resolves to originPath through the cache, so replacing it repairs them all
	return r.storeDriver.Move(uploadPath, originPath)
}

func (r *remoteSharedBlobLifecycle) PromoteCandidate(srcPath, dstPath string) error {
	// a copy, not a Move: the repo copy at srcPath is still served until it is replaced
	blobReader, err := r.storeDriver.Reader(srcPath, 0)
	if err != nil {
		return err
	}

	blobWriter, err := r.storeDriver.Writer(dstPath, false)
	if err != nil {
		if closeErr := blobReader.Close(); closeErr != nil {
			r.log.Error().Err(closeErr).Msg("failed to close blob reader")
		}

		return err
	}

	if _, err := io.Copy(blobWriter, blobReader); err != nil {
		r.abortWrite(blobWriter, blobReader)

		return err
	}

	if err := blobWriter.Commit(context.Background()); err != nil {
		r.abortWrite(blobWriter, blobReader)

		return err
	}

	if err := blobReader.Close(); err != nil {
		if closeErr := blobWriter.Close(); closeErr != nil {
			r.log.Error().Err(closeErr).Msg("failed to close blob writer")
		}

		return err
	}

	return blobWriter.Close()
}

// abortWrite cleans up after PromoteCandidate's copy or commit failed. Every step is best
// effort, but a failure is logged, since it can leave a partial object behind.
func (r *remoteSharedBlobLifecycle) abortWrite(blobWriter driver.FileWriter, blobReader io.ReadCloser) {
	if err := blobWriter.Cancel(context.Background()); err != nil {
		r.log.Error().Err(err).Msg("failed to cancel blob writer")
	}

	if err := blobReader.Close(); err != nil {
		r.log.Error().Err(err).Msg("failed to close blob reader")
	}

	if err := blobWriter.Close(); err != nil {
		r.log.Error().Err(err).Msg("failed to close blob writer")
	}
}

func (r *remoteSharedBlobLifecycle) RemoveMigratedRepoBlob(globalBlobPath, repoBlobPath string) error {
	binfo, err := r.storeDriver.Stat(repoBlobPath)
	if err != nil {
		// A migration re-run after a crash, or a repo deleted meanwhile, may find the copy gone,
		// which a driver may report as a plain PathNotFoundError: there is nothing to give up.
		if errclass.IsStorageObjectMissing(err) {
			return nil
		}

		if _, ok := errors.AsType[driver.PathNotFoundError](err); ok {
			return nil
		}

		return err
	}

	// already a placeholder, as later copies of an earlier release, or a re-run, left it
	if binfo.Size() == 0 {
		return nil
	}

	return linkDistinct(r.storeDriver, globalBlobPath, repoBlobPath)
}

func (r *remoteSharedBlobLifecycle) ShouldDeleteGlobalBlob(_ string, _ godigest.Digest,
	_ func(godigest.Digest) (bool, error),
) (bool, error) {
	return false, nil
}

func (r *remoteSharedBlobLifecycle) IncludeRepoInMountCandidates(repo string) bool {
	return repo != storageConstants.GlobalBlobsRepo
}

func (r *remoteSharedBlobLifecycle) KeepsContentInGlobalBlobstore() bool {
	return true
}

func (r *remoteSharedBlobLifecycle) PutBlobRef(digest godigest.Digest, blobPath string) error {
	// without a cache there is no index, and no other instance to coordinate with
	if r.refs == nil {
		return nil
	}

	if blobPath == path.Join(r.rootDir, storageConstants.GlobalBlobsRepo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded()) {
		return r.refs.RecordGlobal(digest)
	}

	deadline := time.Now().Add(r.claimWait)

	for {
		err := r.refs.AddReference(digest, blobPath)
		if !errors.Is(err, zerr.ErrDigestClaimed) {
			return err
		}

		// a sweep is deleting the payload: once it finishes, the push promotes its own upload
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %w", zerr.ErrStorageTransient, err)
		}

		time.Sleep(linkerClaimPoll)
	}
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
