package types

import (
	"context"
	"io"
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
	RLock(*time.Time)
	RUnlock(*time.Time)
	Lock(*time.Time)
	Unlock(*time.Time)
	InitRepo(name string) error
	ValidateRepo(name string) (bool, error)
	GetRepositories() ([]string, error)
	GetNextRepository(processedRepos map[string]struct{}) (string, error)
	GetNextRepositories(repo string, maxEntries int, fn FilterRepoFunc) ([]string, bool, error)
	GetImageTags(repo string) ([]string, error)
	GetImageManifest(repo, reference string) ([]byte, godigest.Digest, string, error)
	PutImageManifest(repo, reference, mediaType string, body []byte) (godigest.Digest, godigest.Digest, error)
	DeleteImageManifest(repo, reference string, detectCollision bool) error
	BlobUploadPath(repo, uuid string) string
	StatBlobUpload(repo, uuid string) (bool, int64, time.Time, error)
	ListBlobUploads(repo string) ([]string, error)
	NewBlobUpload(repo string) (string, error)
	GetBlobUpload(repo, uuid string) (int64, error)
	PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error)
	PutBlobChunk(repo, uuid string, from, to int64, body io.Reader) (int64, error)
	BlobUploadInfo(repo, uuid string) (int64, error)
	FinishBlobUpload(repo, uuid string, body io.Reader, digest godigest.Digest) error
	FullBlobUpload(repo string, body io.Reader, digest godigest.Digest) (string, int64, error)
	DedupeBlob(src string, dstDigest godigest.Digest, dstRepo, dst string) error
	DeleteBlobUpload(repo, uuid string) error
	BlobPath(repo string, digest godigest.Digest) string
	CheckBlob(repo string, digest godigest.Digest) (bool, int64, error)
	CheckBlobForMount(repo string, digest godigest.Digest) (bool, int64, error)
	StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error)
	GetBlob(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error)
	GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
	) (io.ReadCloser, int64, int64, error)
	DeleteBlob(repo string, digest godigest.Digest) error
	CleanupRepo(repo string, blobs []godigest.Digest, removeRepo bool) (int, error)
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
}

type Driver interface { //nolint:interfacebloat
	Name() string
	EnsureDir(path string) error
	DirExists(path string) bool
	Reader(path string, offset int64) (io.ReadCloser, error)
	ReadFile(path string) ([]byte, error)
	Delete(path string) error
	Stat(path string) (storagedriver.FileInfo, error)
	Writer(filepath string, append bool) (storagedriver.FileWriter, error) //nolint: predeclared
	WriteFile(filepath string, content []byte) (int, error)
	Walk(path string, f storagedriver.WalkFn) error
	List(fullpath string) ([]string, error)
	Move(sourcePath string, destPath string) error
	SameFile(path1, path2 string) bool
	Link(src, dest string) error
}
