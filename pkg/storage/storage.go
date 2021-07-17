package storage

import (
	"io"

	"github.com/opencontainers/go-digest"
)

const (
	S3StorageDriverName = "s3"
)

type ImageStore interface {
	DirExists(d string) bool
	RootDir() string
	RLock()
	RUnlock()
	Lock()
	Unlock()
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
}
