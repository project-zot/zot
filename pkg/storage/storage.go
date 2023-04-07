package storage

import (
	"io"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"

	"zotregistry.io/zot/pkg/scheduler"
)

const (
	S3StorageDriverName = "s3"
)

type ImageStore interface { //nolint:interfacebloat
	DirExists(d string) bool
	RootDir() string
	RLock(*time.Time)
	RUnlock(*time.Time)
	Lock(*time.Time)
	Unlock(*time.Time)
	InitRepo(name string) error
	ValidateRepo(name string) (bool, error)
	GetRepositories() ([]string, error)
	GetNextRepository(repo string) (string, error)
	GetImageTags(repo string) ([]string, error)
	GetImageManifest(repo, reference string) ([]byte, godigest.Digest, string, error)
	PutImageManifest(repo, reference, mediaType string, body []byte) (godigest.Digest, error)
	DeleteImageManifest(repo, reference string, detectCollision bool) error
	BlobUploadPath(repo, uuid string) string
	NewBlobUpload(repo string) (string, error)
	GetBlobUpload(repo, uuid string) (int64, error)
	PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error)
	PutBlobChunk(repo, uuid string, from, to int64, body io.Reader) (int64, error)
	BlobUploadInfo(repo, uuid string) (int64, error)
	FinishBlobUpload(repo, uuid string, body io.Reader, digest godigest.Digest) error
	FullBlobUpload(repo string, body io.Reader, digest godigest.Digest) (string, int64, error)
	DedupeBlob(src string, dstDigest godigest.Digest, dst string) error
	DeleteBlobUpload(repo, uuid string) error
	BlobPath(repo string, digest godigest.Digest) string
	CheckBlob(repo string, digest godigest.Digest) (bool, int64, error)
	GetBlob(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error)
	GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
	) (io.ReadCloser, int64, int64, error)
	DeleteBlob(repo string, digest godigest.Digest) error
	GetIndexContent(repo string) ([]byte, error)
	GetBlobContent(repo string, digest godigest.Digest) ([]byte, error)
	GetReferrers(repo string, digest godigest.Digest, artifactTypes []string) (ispec.Index, error)
	GetOrasReferrers(repo string, digest godigest.Digest, artifactType string) ([]artifactspec.Descriptor, error)
	RunGCRepo(repo string) error
	RunGCPeriodically(interval time.Duration, sch *scheduler.Scheduler)
	RunDedupeBlobs(interval time.Duration, sch *scheduler.Scheduler)
	RunDedupeForDigest(digest godigest.Digest, dedupe bool, duplicateBlobs []string) error
	GetNextDigestWithBlobPaths(lastDigests []godigest.Digest) (godigest.Digest, []string, error)
}
