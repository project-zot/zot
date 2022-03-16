package storage

import (
	"io"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
)

type regulator struct {
	imageStore ImageStore
	*sync.Cond

	available uint64
}

/* NewRegulator wraps ImageStore in order to regulate concurrent calls
to ImageStore, useful for filesystem storage which can reach maximum open file descriptors. */
func NewRegulator(imageStore ImageStore, limit uint64) ImageStore {
	return &regulator{
		imageStore: imageStore,
		Cond:       sync.NewCond(&sync.Mutex{}),
		available:  limit,
	}
}

func (r *regulator) enter() {
	r.L.Lock()
	for r.available == 0 {
		// limit reach
		r.Wait()
	}
	r.available--
	r.L.Unlock()
}

func (r *regulator) exit() {
	r.L.Lock()
	// signal waiting go routines
	r.Signal()
	r.available++
	r.L.Unlock()
}

func (r *regulator) DirExists(d string) bool {
	r.enter()
	defer r.exit()

	return r.imageStore.DirExists(d)
}

func (r *regulator) RootDir() string {
	return r.imageStore.RootDir()
}

func (r *regulator) RLock(lockStart *time.Time) {
	r.imageStore.RLock(lockStart)
}

func (r *regulator) RUnlock(lockStart *time.Time) {
	r.imageStore.RUnlock(lockStart)
}

func (r *regulator) Lock(lockStart *time.Time) {
	r.imageStore.Lock(lockStart)
}

func (r *regulator) Unlock(lockStart *time.Time) {
	r.imageStore.Unlock(lockStart)
}

func (r *regulator) InitRepo(repo string) error {
	r.enter()
	defer r.exit()

	return r.imageStore.InitRepo(repo)
}

func (r *regulator) ValidateRepo(repo string) (bool, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.ValidateRepo(repo)
}

func (r *regulator) GetRepositories() ([]string, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetRepositories()
}

func (r *regulator) GetImageTags(repo string) ([]string, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetImageTags(repo)
}

func (r *regulator) GetImageManifest(repo, reference string) ([]byte, string, string, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetImageManifest(repo, reference)
}

func (r *regulator) PutImageManifest(repo, reference, mediatype string, body []byte) (string, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.PutImageManifest(repo, reference, mediatype, body)
}

func (r *regulator) DeleteImageManifest(repo, reference string) error {
	r.enter()
	defer r.exit()

	return r.imageStore.DeleteImageManifest(repo, reference)
}

func (r *regulator) BlobUploadPath(repo, uuid string) string {
	r.enter()
	defer r.exit()

	return r.imageStore.BlobUploadPath(repo, uuid)
}

func (r *regulator) NewBlobUpload(repo string) (string, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.NewBlobUpload(repo)
}

func (r *regulator) GetBlobUpload(repo string, uuid string) (int64, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetBlobUpload(repo, uuid)
}

func (r *regulator) PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.PutBlobChunkStreamed(repo, uuid, body)
}

func (r *regulator) PutBlobChunk(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.PutBlobChunk(repo, uuid, from, to, body)
}

func (r *regulator) BlobUploadInfo(repo, uuid string) (int64, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.BlobUploadInfo(repo, uuid)
}

func (r *regulator) FinishBlobUpload(repo, uuid string, body io.Reader, digest string) error {
	r.enter()
	defer r.exit()

	return r.imageStore.FinishBlobUpload(repo, uuid, body, digest)
}

func (r *regulator) FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.FullBlobUpload(repo, body, digest)
}

func (r *regulator) DedupeBlob(src string, dstDigest digest.Digest, dst string) error {
	r.enter()
	defer r.exit()

	return r.imageStore.DedupeBlob(src, dstDigest, dst)
}

func (r *regulator) DeleteBlobUpload(repo, uuid string) error {
	r.enter()
	defer r.exit()

	return r.imageStore.DeleteBlobUpload(repo, uuid)
}

func (r *regulator) BlobPath(repo string, digest digest.Digest) string {
	r.enter()
	defer r.exit()

	return r.imageStore.BlobPath(repo, digest)
}

func (r *regulator) CheckBlob(repo, digest string) (bool, int64, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.CheckBlob(repo, digest)
}

func (r *regulator) GetBlob(repo, digest, mediaType string) (io.Reader, int64, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetBlob(repo, digest, mediaType)
}

func (r *regulator) DeleteBlob(repo, digest string) error {
	r.enter()
	defer r.exit()

	return r.imageStore.DeleteBlob(repo, digest)
}

func (r *regulator) GetIndexContent(repo string) ([]byte, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetIndexContent(repo)
}

func (r *regulator) GetBlobContent(repo, digest string) ([]byte, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetBlobContent(repo, digest)
}

func (r *regulator) GetReferrers(repo, digest, mediaType string) ([]artifactspec.Descriptor, error) {
	r.enter()
	defer r.exit()

	return r.imageStore.GetReferrers(repo, digest, mediaType)
}
