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
	// WithRepoLock and WithRepoReadLock run wrappedFunc while holding the write, respectively
	// read, lock for work on repo, and return its error.
	//
	// The repo argument names the repository the caller works on. It is not a promise that
	// only that repository is touched: with dedupe, a blob in one repo can be a link to, or
	// a placeholder for, content stored under another repo, so reads and writes made under
	// these locks can reach other repositories' blobs. That is safe only because the default
	// store has a single lock, which every repo maps to. Locking per repo is therefore not a
	// change that can be made behind these two methods alone: content shared between
	// repositories first needs a lock of its own.
	WithRepoLock(repo string, wrappedFunc func() error) error
	WithRepoReadLock(repo string, wrappedFunc func() error) error
	// WithBlobstoreLock and WithBlobstoreReadLock run wrappedFunc while holding the write,
	// respectively read, lock for the blob content repositories share, and return its error.
	// This is the lock of its own that shared content needs before repos can be locked
	// separately. Callers that work on a repo and can also reach shared content name both,
	// through the three methods below, instead of nesting the two kinds of lock themselves.
	//
	// The default store still has its single lock, and all of these methods take it, once.
	// They are therefore not reentrant: wrappedFunc must not call another of them.
	WithBlobstoreLock(wrappedFunc func() error) error
	WithBlobstoreReadLock(wrappedFunc func() error) error
	// WithBlobstoreAndRepoLock holds the write lock on both the shared content and repo.
	WithBlobstoreAndRepoLock(repo string, wrappedFunc func() error) error
	// WithBlobstoreReadAndRepoLock holds repo's write lock and reads shared content.
	WithBlobstoreReadAndRepoLock(repo string, wrappedFunc func() error) error
	// WithRepoCleanupLock holds what deleting blobs out of repo requires. Passes that remove
	// a repo's blobs (GC, removal of an emptied repo) use it rather than choosing a lock
	// themselves: whether such a delete can touch shared content is for the store to know.
	WithRepoCleanupLock(repo string, wrappedFunc func() error) error
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
