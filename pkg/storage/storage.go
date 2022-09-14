package storage

import (
	"io"
	"time"

	"github.com/opencontainers/go-digest"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"zotregistry.io/zot/pkg/scheduler"
)

const (
	S3StorageDriverName = "s3"
)

type ImageStore interface {
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
	GetImageManifest(repo, reference string) ([]byte, string, string, error)
	PutImageManifest(repo, reference, mediaType string, body []byte) (string, error)
	DeleteImageManifest(repo, reference string) error
	BlobUploadPath(repo, uuid string) string
	NewBlobUpload(repo string) (string, error)
	GetBlobUpload(repo, uuid string) (int64, error)
	PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error)
	PutBlobChunk(repo, uuid string, from, to int64, body io.Reader) (int64, error)
	BlobUploadInfo(repo, uuid string) (int64, error)
	FinishBlobUpload(repo, uuid string, body io.Reader, digest string) error
	FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error)
	DedupeBlob(src string, dstDigest digest.Digest, dst string) error
	DeleteBlobUpload(repo, uuid string) error
	BlobPath(repo string, digest digest.Digest) string
	CheckBlob(repo, digest string) (bool, int64, error)
	GetBlob(repo, digest, mediaType string) (io.ReadCloser, int64, error)
	GetBlobPartial(repo, digest, mediaType string, from, to int64) (io.ReadCloser, int64, int64, error)
	DeleteBlob(repo, digest string) error
	GetIndexContent(repo string) ([]byte, error)
	GetBlobContent(repo, digest string) ([]byte, error)
	GetReferrers(repo, digest string, mediaType string) ([]artifactspec.Descriptor, error)
	RunGCRepo(repo string) error
	RunGCPeriodically(interval time.Duration, sch *scheduler.Scheduler)
}
