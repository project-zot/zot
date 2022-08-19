package mocks

import (
	"io"
	"time"

	"github.com/opencontainers/go-digest"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
)

type MockedImageStore struct {
	DirExistsFn            func(d string) bool
	RootDirFn              func() string
	InitRepoFn             func(name string) error
	ValidateRepoFn         func(name string) (bool, error)
	GetRepositoriesFn      func() ([]string, error)
	GetImageTagsFn         func(repo string) ([]string, error)
	GetImageManifestFn     func(repo string, reference string) ([]byte, string, string, error)
	PutImageManifestFn     func(repo string, reference string, mediaType string, body []byte) (string, error)
	DeleteImageManifestFn  func(repo string, reference string) error
	BlobUploadPathFn       func(repo string, uuid string) string
	NewBlobUploadFn        func(repo string) (string, error)
	GetBlobUploadFn        func(repo string, uuid string) (int64, error)
	BlobUploadInfoFn       func(repo string, uuid string) (int64, error)
	PutBlobChunkStreamedFn func(repo string, uuid string, body io.Reader) (int64, error)
	PutBlobChunkFn         func(repo string, uuid string, from int64, to int64, body io.Reader) (int64, error)
	FinishBlobUploadFn     func(repo string, uuid string, body io.Reader, digest string) error
	FullBlobUploadFn       func(repo string, body io.Reader, digest string) (string, int64, error)
	DedupeBlobFn           func(src string, dstDigest digest.Digest, dst string) error
	DeleteBlobUploadFn     func(repo string, uuid string) error
	BlobPathFn             func(repo string, digest digest.Digest) string
	CheckBlobFn            func(repo string, digest string) (bool, int64, error)
	GetBlobFn              func(repo string, digest string, mediaType string) (io.ReadCloser, int64, error)
	DeleteBlobFn           func(repo string, digest string) error
	GetIndexContentFn      func(repo string) ([]byte, error)
	GetBlobContentFn       func(repo, digest string) ([]byte, error)
	GetReferrersFn         func(repo, digest string, mediaType string) ([]artifactspec.Descriptor, error)
	URLForPathFn           func(path string) (string, error)
	RunGCRepoFn            func(repo string)
}

func (is MockedImageStore) Lock(t *time.Time) {
}

func (is MockedImageStore) Unlock(t *time.Time) {
}

func (is MockedImageStore) RUnlock(t *time.Time) {
}

func (is MockedImageStore) RLock(t *time.Time) {
}

func (is MockedImageStore) DirExists(d string) bool {
	if is.DirExistsFn != nil {
		return is.DirExistsFn(d)
	}

	return true
}

func (is MockedImageStore) RootDir() string {
	if is.RootDirFn != nil {
		return is.RootDirFn()
	}

	return ""
}

func (is MockedImageStore) InitRepo(name string) error {
	if is.InitRepoFn != nil {
		return is.InitRepoFn(name)
	}

	return nil
}

func (is MockedImageStore) ValidateRepo(name string) (bool, error) {
	if is.ValidateRepoFn != nil {
		return is.ValidateRepoFn(name)
	}

	return true, nil
}

func (is MockedImageStore) GetRepositories() ([]string, error) {
	if is.GetRepositoriesFn != nil {
		return is.GetRepositoriesFn()
	}

	return []string{}, nil
}

func (is MockedImageStore) GetImageManifest(repo string, reference string) ([]byte, string, string, error) {
	if is.GetImageManifestFn != nil {
		return is.GetImageManifestFn(repo, reference)
	}

	return []byte{}, "", "", nil
}

func (is MockedImageStore) PutImageManifest(
	repo string,
	reference string,
	mediaType string,
	body []byte,
) (string, error) {
	if is.PutImageManifestFn != nil {
		return is.PutImageManifestFn(repo, reference, mediaType, body)
	}

	return "", nil
}

func (is MockedImageStore) GetImageTags(name string) ([]string, error) {
	if is.GetImageTagsFn != nil {
		return is.GetImageTagsFn(name)
	}

	return []string{}, nil
}

func (is MockedImageStore) DeleteImageManifest(name string, reference string) error {
	if is.DeleteImageManifestFn != nil {
		return is.DeleteImageManifestFn(name, reference)
	}

	return nil
}

func (is MockedImageStore) NewBlobUpload(repo string) (string, error) {
	if is.NewBlobUploadFn != nil {
		return is.NewBlobUploadFn(repo)
	}

	return "", nil
}

func (is MockedImageStore) GetBlobUpload(repo string, uuid string) (int64, error) {
	if is.GetBlobUploadFn != nil {
		return is.GetBlobUploadFn(repo, uuid)
	}

	return 0, nil
}

func (is MockedImageStore) BlobUploadInfo(repo string, uuid string) (int64, error) {
	if is.BlobUploadInfoFn != nil {
		return is.BlobUploadInfoFn(repo, uuid)
	}

	return 0, nil
}

func (is MockedImageStore) BlobUploadPath(repo string, uuid string) string {
	if is.BlobUploadPathFn != nil {
		return is.BlobUploadPathFn(repo, uuid)
	}

	return ""
}

func (is MockedImageStore) PutBlobChunkStreamed(repo string, uuid string, body io.Reader) (int64, error) {
	if is.PutBlobChunkStreamedFn != nil {
		return is.PutBlobChunkStreamedFn(repo, uuid, body)
	}

	return 0, nil
}

func (is MockedImageStore) PutBlobChunk(
	repo string,
	uuid string,
	from int64,
	to int64,
	body io.Reader,
) (int64, error) {
	if is.PutBlobChunkFn != nil {
		return is.PutBlobChunkFn(repo, uuid, from, to, body)
	}

	return 0, nil
}

func (is MockedImageStore) FinishBlobUpload(repo string, uuid string, body io.Reader, digest string) error {
	if is.FinishBlobUploadFn != nil {
		return is.FinishBlobUploadFn(repo, uuid, body, digest)
	}

	return nil
}

func (is MockedImageStore) FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error) {
	if is.FullBlobUploadFn != nil {
		return is.FullBlobUploadFn(repo, body, digest)
	}

	return "", 0, nil
}

func (is MockedImageStore) DedupeBlob(src string, dstDigest digest.Digest, dst string) error {
	if is.DedupeBlobFn != nil {
		return is.DedupeBlobFn(src, dstDigest, dst)
	}

	return nil
}

func (is MockedImageStore) DeleteBlob(repo string, digest string) error {
	if is.DeleteBlobFn != nil {
		return is.DeleteBlobFn(repo, digest)
	}

	return nil
}

func (is MockedImageStore) BlobPath(repo string, digest digest.Digest) string {
	if is.BlobPathFn != nil {
		return is.BlobPathFn(repo, digest)
	}

	return ""
}

func (is MockedImageStore) CheckBlob(repo string, digest string) (bool, int64, error) {
	if is.CheckBlobFn != nil {
		return is.CheckBlobFn(repo, digest)
	}

	return true, 0, nil
}

func (is MockedImageStore) GetBlob(repo string, digest string, mediaType string) (io.ReadCloser, int64, error) {
	if is.GetBlobFn != nil {
		return is.GetBlobFn(repo, digest, mediaType)
	}

	return io.NopCloser(&io.LimitedReader{}), 0, nil
}

func (is MockedImageStore) DeleteBlobUpload(repo string, digest string) error {
	if is.DeleteBlobUploadFn != nil {
		return is.DeleteBlobUploadFn(repo, digest)
	}

	return nil
}

func (is MockedImageStore) GetIndexContent(repo string) ([]byte, error) {
	if is.GetIndexContentFn != nil {
		return is.GetIndexContentFn(repo)
	}

	return []byte{}, nil
}

func (is MockedImageStore) GetBlobContent(repo string, digest string) ([]byte, error) {
	if is.GetBlobContentFn != nil {
		return is.GetBlobContentFn(repo, digest)
	}

	return []byte{}, nil
}

func (is MockedImageStore) GetReferrers(
	repo string,
	digest string,
	mediaType string,
) ([]artifactspec.Descriptor, error) {
	if is.GetReferrersFn != nil {
		return is.GetReferrersFn(repo, digest, mediaType)
	}

	return []artifactspec.Descriptor{}, nil
}

func (is MockedImageStore) URLForPath(path string) (string, error) {
	if is.URLForPathFn != nil {
		return is.URLForPathFn(path)
	}

	return "", nil
}

func (is MockedImageStore) RunGCRepo(repo string) {
	if is.RunGCRepoFn != nil {
		is.RunGCRepoFn(repo)
	}
}
