package mocks

import (
	"context"
	"io"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/v2/pkg/scheduler"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type MockedImageStore struct {
	NameFn                func() string
	DirExistsFn           func(d string) bool
	RootDirFn             func() string
	InitRepoFn            func(name string) error
	ValidateRepoFn        func(name string) (bool, error)
	GetRepositoriesFn     func() ([]string, error)
	GetNextRepositoryFn   func(processedRepos map[string]struct{}) (string, error)
	GetNextRepositoriesFn func(lastRepo string, maxEntries int, fn storageTypes.FilterRepoFunc) ([]string, bool, error)
	GetImageTagsFn        func(repo string) ([]string, error)
	GetImageManifestFn    func(repo string, reference string) ([]byte, godigest.Digest, string, error)
	PutImageManifestFn    func(repo string, reference string, mediaType string, body []byte) (godigest.Digest,
		godigest.Digest, error)
	DeleteImageManifestFn  func(repo string, reference string, detectCollision bool) error
	BlobUploadPathFn       func(repo string, uuid string) string
	StatBlobUploadFn       func(repo string, uuid string) (bool, int64, time.Time, error)
	ListBlobUploadsFn      func(repo string) ([]string, error)
	NewBlobUploadFn        func(repo string) (string, error)
	GetBlobUploadFn        func(repo string, uuid string) (int64, error)
	BlobUploadInfoFn       func(repo string, uuid string) (int64, error)
	PutBlobChunkStreamedFn func(repo string, uuid string, body io.Reader) (int64, error)
	PutBlobChunkFn         func(repo string, uuid string, from int64, to int64, body io.Reader) (int64, error)
	FinishBlobUploadFn     func(repo string, uuid string, body io.Reader, digest godigest.Digest) error
	FullBlobUploadFn       func(repo string, body io.Reader, digest godigest.Digest) (string, int64, error)
	DedupeBlobFn           func(src string, dstDigest godigest.Digest, dstRepo, dst string) error
	DeleteBlobUploadFn     func(repo string, uuid string) error
	BlobPathFn             func(repo string, digest godigest.Digest) string
	CheckBlobFn            func(repo string, digest godigest.Digest) (bool, int64, error)
	CheckBlobForMountFn    func(repo string, digest godigest.Digest) (bool, int64, error)
	StatBlobFn             func(repo string, digest godigest.Digest) (bool, int64, time.Time, error)
	GetBlobPartialFn       func(repo string, digest godigest.Digest, mediaType string, from, to int64,
	) (io.ReadCloser, int64, int64, error)
	GetBlobFn            func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error)
	DeleteBlobFn         func(repo string, digest godigest.Digest) error
	GetIndexContentFn    func(repo string) ([]byte, error)
	GetBlobContentFn     func(repo string, digest godigest.Digest) ([]byte, error)
	GetReferrersFn       func(repo string, digest godigest.Digest, artifactTypes []string) (ispec.Index, error)
	URLForPathFn         func(path string) (string, error)
	RunGCRepoFn          func(repo string) error
	RunGCPeriodicallyFn  func(interval time.Duration, sch *scheduler.Scheduler)
	RunDedupeBlobsFn     func(interval time.Duration, sch *scheduler.Scheduler)
	RunDedupeForDigestFn func(ctx context.Context, digest godigest.Digest, dedupe bool,
		duplicateBlobs []string) error
	GetNextDigestWithBlobPathsFn  func(repos []string, lastDigests []godigest.Digest) (godigest.Digest, []string, error)
	GetAllBlobsFn                 func(repo string) ([]godigest.Digest, error)
	CleanupRepoFn                 func(repo string, blobs []godigest.Digest, removeRepo bool) (int, error)
	PutIndexContentFn             func(repo string, index ispec.Index) error
	PopulateStorageMetricsFn      func(interval time.Duration, sch *scheduler.Scheduler)
	StatIndexFn                   func(repo string) (bool, int64, time.Time, error)
	VerifyBlobDigestValueFn       func(repo string, digest godigest.Digest) error
	GetAllDedupeReposCandidatesFn func(digest godigest.Digest) ([]string, error)
}

func (is MockedImageStore) StatIndex(repo string) (bool, int64, time.Time, error) {
	if is.StatIndexFn != nil {
		return is.StatIndexFn(repo)
	}

	return true, 0, time.Time{}, nil
}

func (is MockedImageStore) Lock(t *time.Time) {
}

func (is MockedImageStore) Unlock(t *time.Time) {
}

func (is MockedImageStore) RUnlock(t *time.Time) {
}

func (is MockedImageStore) RLock(t *time.Time) {
}

func (is MockedImageStore) Name() string {
	if is.NameFn != nil {
		return is.NameFn()
	}

	return ""
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

func (is MockedImageStore) GetNextRepository(processedRepos map[string]struct{}) (string, error) {
	if is.GetNextRepositoryFn != nil {
		return is.GetNextRepositoryFn(processedRepos)
	}

	return "", nil
}

func (is MockedImageStore) GetNextRepositories(lastRepo string, maxEntries int,
	fn storageTypes.FilterRepoFunc,
) ([]string, bool, error) {
	if is.GetNextRepositoriesFn != nil {
		return is.GetNextRepositoriesFn(lastRepo, maxEntries, fn)
	}

	return []string{}, false, nil
}

func (is MockedImageStore) GetImageManifest(repo string, reference string) ([]byte, godigest.Digest, string, error) {
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
) (godigest.Digest, godigest.Digest, error) {
	if is.PutImageManifestFn != nil {
		return is.PutImageManifestFn(repo, reference, mediaType, body)
	}

	return "", "", nil
}

func (is MockedImageStore) GetImageTags(name string) ([]string, error) {
	if is.GetImageTagsFn != nil {
		return is.GetImageTagsFn(name)
	}

	return []string{}, nil
}

func (is MockedImageStore) GetAllBlobs(repo string) ([]godigest.Digest, error) {
	if is.GetAllBlobsFn != nil {
		return is.GetAllBlobsFn(repo)
	}

	return []godigest.Digest{}, nil
}

func (is MockedImageStore) DeleteImageManifest(name string, reference string, detectCollision bool) error {
	if is.DeleteImageManifestFn != nil {
		return is.DeleteImageManifestFn(name, reference, detectCollision)
	}

	return nil
}

func (is MockedImageStore) ListBlobUploads(repo string) ([]string, error) {
	if is.ListBlobUploadsFn != nil {
		return is.ListBlobUploadsFn(repo)
	}

	return []string{}, nil
}

func (is MockedImageStore) StatBlobUpload(repo string, uuid string) (bool, int64, time.Time, error) {
	if is.StatBlobUploadFn != nil {
		return is.StatBlobUploadFn(repo, uuid)
	}

	return true, 0, time.Time{}, nil
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

func (is MockedImageStore) FinishBlobUpload(repo string, uuid string, body io.Reader, digest godigest.Digest) error {
	if is.FinishBlobUploadFn != nil {
		return is.FinishBlobUploadFn(repo, uuid, body, digest)
	}

	return nil
}

func (is MockedImageStore) FullBlobUpload(repo string, body io.Reader, digest godigest.Digest) (string, int64, error) {
	if is.FullBlobUploadFn != nil {
		return is.FullBlobUploadFn(repo, body, digest)
	}

	return "", 0, nil
}

func (is MockedImageStore) DedupeBlob(src string, dstDigest godigest.Digest, dstRepo, dst string) error {
	if is.DedupeBlobFn != nil {
		return is.DedupeBlobFn(src, dstDigest, dstRepo, dst)
	}

	return nil
}

func (is MockedImageStore) DeleteBlob(repo string, digest godigest.Digest) error {
	if is.DeleteBlobFn != nil {
		return is.DeleteBlobFn(repo, digest)
	}

	return nil
}

func (is MockedImageStore) BlobPath(repo string, digest godigest.Digest) string {
	if is.BlobPathFn != nil {
		return is.BlobPathFn(repo, digest)
	}

	return ""
}

func (is MockedImageStore) CheckBlob(repo string, digest godigest.Digest) (bool, int64, error) {
	if is.CheckBlobFn != nil {
		return is.CheckBlobFn(repo, digest)
	}

	return true, 0, nil
}

func (is MockedImageStore) CheckBlobForMount(repo string, digest godigest.Digest) (bool, int64, error) {
	if is.CheckBlobForMountFn != nil {
		return is.CheckBlobForMountFn(repo, digest)
	}

	return true, 0, nil
}

func (is MockedImageStore) StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	if is.StatBlobFn != nil {
		return is.StatBlobFn(repo, digest)
	}

	return true, 0, time.Time{}, nil
}

func (is MockedImageStore) GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
) (io.ReadCloser, int64, int64, error) {
	if is.GetBlobPartialFn != nil {
		return is.GetBlobPartialFn(repo, digest, mediaType, from, to)
	}

	return io.NopCloser(&io.LimitedReader{}), 0, 0, nil
}

func (is MockedImageStore) GetBlob(repo string, digest godigest.Digest, mediaType string,
) (io.ReadCloser, int64, error) {
	if is.GetBlobFn != nil {
		return is.GetBlobFn(repo, digest, mediaType)
	}

	return io.NopCloser(&io.LimitedReader{}), 0, nil
}

func (is MockedImageStore) DeleteBlobUpload(repo string, uuid string) error {
	if is.DeleteBlobUploadFn != nil {
		return is.DeleteBlobUploadFn(repo, uuid)
	}

	return nil
}

func (is MockedImageStore) GetIndexContent(repo string) ([]byte, error) {
	if is.GetIndexContentFn != nil {
		return is.GetIndexContentFn(repo)
	}

	return []byte{}, nil
}

func (is MockedImageStore) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	if is.GetBlobContentFn != nil {
		return is.GetBlobContentFn(repo, digest)
	}

	return []byte{}, nil
}

func (is MockedImageStore) GetReferrers(
	repo string, digest godigest.Digest,
	artifactTypes []string,
) (ispec.Index, error) {
	if is.GetReferrersFn != nil {
		return is.GetReferrersFn(repo, digest, artifactTypes)
	}

	return ispec.Index{}, nil
}

func (is MockedImageStore) URLForPath(path string) (string, error) {
	if is.URLForPathFn != nil {
		return is.URLForPathFn(path)
	}

	return "", nil
}

func (is MockedImageStore) RunGCRepo(repo string) error {
	if is.RunGCRepoFn != nil {
		return is.RunGCRepoFn(repo)
	}

	return nil
}

func (is MockedImageStore) RunGCPeriodically(interval time.Duration, sch *scheduler.Scheduler) {
	if is.RunGCPeriodicallyFn != nil {
		is.RunGCPeriodicallyFn(interval, sch)
	}
}

func (is MockedImageStore) RunDedupeBlobs(interval time.Duration, sch *scheduler.Scheduler) {
	if is.RunDedupeBlobsFn != nil {
		is.RunDedupeBlobsFn(interval, sch)
	}
}

func (is MockedImageStore) RunDedupeForDigest(ctx context.Context, digest godigest.Digest, dedupe bool,
	duplicateBlobs []string,
) error {
	if is.RunDedupeForDigestFn != nil {
		return is.RunDedupeForDigestFn(ctx, digest, dedupe, duplicateBlobs)
	}

	return nil
}

func (is MockedImageStore) GetNextDigestWithBlobPaths(repos []string, lastDigests []godigest.Digest,
) (godigest.Digest, []string, error) {
	if is.GetNextDigestWithBlobPathsFn != nil {
		return is.GetNextDigestWithBlobPathsFn(repos, lastDigests)
	}

	return "", []string{}, nil
}

func (is MockedImageStore) CleanupRepo(repo string, blobs []godigest.Digest, removeRepo bool) (int, error) {
	if is.CleanupRepoFn != nil {
		return is.CleanupRepoFn(repo, blobs, removeRepo)
	}

	return 0, nil
}

func (is MockedImageStore) PutIndexContent(repo string, index ispec.Index) error {
	if is.PutIndexContentFn != nil {
		return is.PutIndexContentFn(repo, index)
	}

	return nil
}

func (is MockedImageStore) PopulateStorageMetrics(interval time.Duration, sch *scheduler.Scheduler) {
	if is.PopulateStorageMetricsFn != nil {
		is.PopulateStorageMetricsFn(interval, sch)
	}
}

func (is MockedImageStore) VerifyBlobDigestValue(repo string, digest godigest.Digest) error {
	if is.VerifyBlobDigestValueFn != nil {
		return is.VerifyBlobDigestValueFn(repo, digest)
	}

	return nil
}

func (is MockedImageStore) GetAllDedupeReposCandidates(digest godigest.Digest) ([]string, error) {
	if is.GetAllBlobsFn != nil {
		return is.GetAllDedupeReposCandidatesFn(digest)
	}

	return []string{}, nil
}
