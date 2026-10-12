package types

import (
	"context"
	"io"
	"net/http"
	"time"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/v2/pkg/scheduler"
)

type FilterRepoFunc func(repo string) (bool, error)

type StoreController interface {
	GetImageStore(name string) ImageStore
	GetDefaultImageStore() ImageStore
	GetImageSubStores() map[string]ImageStore
}

type ImageStore interface { //nolint:interfacebloat
	Name() string
	DirExists(d string) bool
	RootDir() string
	RepoExists(repo string) bool
	// StatRepo is RepoExists with the reason kept: nil if repo exists, an error wrapping
	// zerr.ErrRepoNotFound if it does not, and the storage error itself if the backend could
	// not say. Callers answering a client must use this, or an outage reads as "no such repo".
	StatRepo(repo string) error
	// WithRepoLock and WithRepoReadLock hold repo's lock for wrappedFunc's duration. repo
	// need not exist: callers such as CheckBlob lock names a request merely mentions.
	// Implementations must therefore not keep a lock around per name ever seen; the default
	// store reference-counts its entries and drops each one when its last holder or waiter
	// leaves (imagestore.repoLockMap), so memory tracks in-flight operations only.
	WithRepoLock(repo string, wrappedFunc func() error) error
	WithRepoReadLock(repo string, wrappedFunc func() error) error
	// WithBlobstoreLock holds the shared global blobstore's write lock for wrappedFunc's
	// duration. Must be acquired before any repo lock, never after - use
	// WithBlobstoreAndRepoLock when both are needed.
	//
	// This and the other locks here are process-local: they serialise goroutines of one zot
	// instance and are not what protects a store shared by several instances. Nothing relies
	// on them for that. On such stores (remote backends with a Redis/DynamoDB blob-ref index)
	// dropping a blob's last reference never deletes the global payload under these locks; it
	// only writes a reclaim marker, and the payload is deleted later by a sweep that
	// coordinates with linkers on every instance through marker, claim and pin objects in the
	// bucket plus a per-digest lock in the shared cache. See imagestore/reclaim.go.
	WithBlobstoreLock(wrappedFunc func() error) error
	// WithBlobstoreReadLock is WithBlobstoreLock's read-lock counterpart; same ordering rule.
	WithBlobstoreReadLock(wrappedFunc func() error) error
	// WithBlobstoreAndRepoLock acquires both locks in the mandated blobstore-before-repo
	// order, so callers don't have to get it right themselves.
	WithBlobstoreAndRepoLock(repo string, wrappedFunc func() error) error
	// WithRepoCleanupLock holds what deleting blobs out of repo requires: its write lock,
	// plus the blobstore write lock only on stores where such a delete can remove the shared
	// payload right away. Long repo-wide passes (GC, repo removal) must use this rather than
	// WithBlobstoreAndRepoLock so they do not stall every other repository without need.
	WithRepoCleanupLock(repo string, wrappedFunc func() error) error
	// WithBlobstoreReadAndRepoLock is WithBlobstoreAndRepoLock's read-lock counterpart.
	WithBlobstoreReadAndRepoLock(repo string, wrappedFunc func() error) error
	InitRepo(ctx context.Context, name string) error
	ValidateRepo(name string) (bool, error)
	GetRepositories() ([]string, error)
	GetNextRepository(processedRepos map[string]struct{}) (string, error)
	GetNextRepositories(repo string, maxEntries int, fn FilterRepoFunc) ([]string, bool, error)
	GetImageTags(repo string) ([]string, error)
	GetImageManifest(repo, reference string) ([]byte, godigest.Digest, string, error)
	PutImageManifest(ctx context.Context, repo, reference, mediaType string, body []byte, extraTags []string) (
		godigest.Digest, godigest.Digest, error)
	DeleteImageManifest(ctx context.Context, repo, reference string, detectCollision bool) error
	BlobUploadPath(repo, uuid string) string
	StatBlobUpload(repo, uuid string) (bool, int64, time.Time, error)
	ListBlobUploads(repo string) ([]string, error)
	NewBlobUpload(ctx context.Context, repo string) (string, error)
	GetBlobUpload(repo, uuid string) (int64, error)
	PutBlobChunkStreamed(ctx context.Context, repo, uuid string, body io.Reader) (int64, error)
	PutBlobChunk(ctx context.Context, repo, uuid string, from, to int64, body io.Reader) (int64, error)
	BlobUploadInfo(repo, uuid string) (int64, error)
	FinishBlobUpload(repo, uuid string, body io.Reader, digest godigest.Digest) error
	FullBlobUpload(ctx context.Context, repo string, body io.Reader, digest godigest.Digest) (string, int64, error)
	DedupeBlob(src string, dstDigest godigest.Digest, dstRepo, dst string) error
	DeleteBlobUpload(repo, uuid string) error
	BlobPath(repo string, digest godigest.Digest) string
	CheckBlob(ctx context.Context, repo string, digest godigest.Digest) (bool, int64, error)
	StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error)
	GetBlob(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error)
	GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
	) (io.ReadCloser, int64, int64, error)
	DeleteBlob(repo string, digest godigest.Digest) error
	CleanupRepo(repo string, blobs []godigest.Digest) (int, error)
	RemoveIdleRepository(repo string, maxBlobAge time.Duration) (bool, error)
	GetIndexContent(repo string) ([]byte, error)
	PutIndexContent(repo string, index ispec.Index) error
	StatIndex(repo string) (bool, int64, time.Time, error)
	GetBlobContent(repo string, digest godigest.Digest) ([]byte, error)
	GetReferrers(repo string, digest godigest.Digest, artifactTypes []string) (ispec.Index, error)
	RunDedupeBlobs(interval time.Duration, sch *scheduler.Scheduler)
	RunDedupeForDigest(ctx context.Context, digest godigest.Digest, dedupe bool, duplicateBlobs []string) error
	GetNextDigestWithBlobPaths(repos []string, lastDigests []godigest.Digest) (godigest.Digest, []string, error)
	GetAllBlobs(repo string) ([]godigest.Digest, error)
	PopulateStorageMetrics(interval time.Duration, sch *scheduler.Scheduler)
	VerifyBlobDigestValue(repo string, digest godigest.Digest) error
	GetAllDedupeReposCandidates(digest godigest.Digest) ([]string, error)
	GetBlobRedirectURL(r *http.Request, repo string, digest godigest.Digest) (string, error)
}

type Driver interface { //nolint:interfacebloat
	Name() string
	EnsureDir(path string) error
	DirExists(path string) bool
	Reader(path string, offset int64) (io.ReadCloser, error)
	ReadFile(path string) ([]byte, error)
	Delete(path string) error
	Stat(path string) (storagedriver.FileInfo, error)
	Writer(filepath string, isAppend bool) (storagedriver.FileWriter, error)
	WriteFile(filepath string, content []byte) (int, error)
	Walk(path string, f storagedriver.WalkFn) error
	List(fullpath string) ([]string, error)
	Move(sourcePath string, destPath string) error
	SameFile(path1, path2 string) bool
	Link(src, dest string) error
	RedirectURL(r *http.Request, path string) (string, error)
}
