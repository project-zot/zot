package storage

import (
	"io"
	"time"

	"github.com/opencontainers/go-digest"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
)

const (
	S3StorageDriverName = "s3"
	DefaultGCDelay      = 1 * time.Hour
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
	GetImageTags(repo string) ([]string, error)
	GetImageManifest(repo string, reference string) ([]byte, string, string, error)
	PutImageManifest(repo string, reference string, mediaType string, body []byte) (string, error)
	DeleteImageManifest(repo string, reference string) error
	BlobUploadPath(repo string, uuid string) string
	NewBlobUpload(repo string) (string, error)
	GetBlobUpload(repo string, uuid string) (int64, error)
	PutBlobChunkStreamed(repo string, uuid string, body io.Reader) (int64, error)
	PutBlobChunk(repo string, uuid string, from int64, to int64, body io.Reader) (int64, error)
	BlobUploadInfo(repo string, uuid string) (int64, error)
	FinishBlobUpload(repo string, uuid string, body io.Reader, digest string) error
	FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error)
	DedupeBlob(src string, dstDigest digest.Digest, dst string) error
	DeleteBlobUpload(repo string, uuid string) error
	BlobPath(repo string, digest digest.Digest) string
	CheckBlob(repo string, digest string) (bool, int64, error)
	GetBlob(repo string, digest string, mediaType string) (io.Reader, int64, error)
	DeleteBlob(repo string, digest string) error
	GetIndexContent(repo string) ([]byte, error)
	GetBlobContent(repo, digest string) ([]byte, error)
	GetReferrers(repo, digest string, mediaType string) ([]artifactspec.Descriptor, error)
	RunGCPeriodically(gcInterval time.Duration)
}
