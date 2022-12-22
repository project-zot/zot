package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sync"
	"time"

	// Add s3 support.
	"github.com/docker/distribution/registry/storage/driver"
	// Load s3 driver.
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/test"
)

const (
	CacheDBName = "s3_cache"
)

// ObjectStorage provides the image storage operations.
type ObjectStorage struct {
	rootDir     string
	store       driver.StorageDriver
	lock        *sync.RWMutex
	blobUploads map[string]storage.BlobUpload
	log         zerolog.Logger
	metrics     monitoring.MetricServer
	cache       cache.Cache
	dedupe      bool
	linter      storage.Lint
}

func (is *ObjectStorage) RootDir() string {
	return is.rootDir
}

func (is *ObjectStorage) DirExists(d string) bool {
	if fi, err := is.store.Stat(context.Background(), d); err == nil && fi.IsDir() {
		return true
	}

	return false
}

// NewObjectStorage returns a new image store backed by cloud storages.
// see https://github.com/docker/docker.github.io/tree/master/registry/storage-drivers
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, cacheDir string, gc bool, gcDelay time.Duration, dedupe, commit bool,
	log zlog.Logger, metrics monitoring.MetricServer, linter storage.Lint,
	store driver.StorageDriver, cacheDriver cache.Cache,
) storage.ImageStore {
	imgStore := &ObjectStorage{
		rootDir:     rootDir,
		store:       store,
		lock:        &sync.RWMutex{},
		blobUploads: make(map[string]storage.BlobUpload),
		log:         log.With().Caller().Logger(),
		metrics:     metrics,
		dedupe:      dedupe,
		linter:      linter,
	}

	imgStore.cache = cacheDriver

	return imgStore
}

// RLock read-lock.
func (is *ObjectStorage) RLock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.RLock()
}

// RUnlock read-unlock.
func (is *ObjectStorage) RUnlock(lockStart *time.Time) {
	is.lock.RUnlock()

	lockEnd := time.Now()
	// includes time spent in acquiring and holding a lock
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RLOCK) // histogram
}

// Lock write-lock.
func (is *ObjectStorage) Lock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.Lock()
}

// Unlock write-unlock.
func (is *ObjectStorage) Unlock(lockStart *time.Time) {
	is.lock.Unlock()

	lockEnd := time.Now()
	// includes time spent in acquiring and holding a lock
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RWLOCK) // histogram
}

func (is *ObjectStorage) initRepo(name string) error {
	repoDir := path.Join(is.rootDir, name)

	// "oci-layout" file - create if it doesn't exist
	ilPath := path.Join(repoDir, ispec.ImageLayoutFile)
	if _, err := is.store.Stat(context.Background(), ilPath); err != nil {
		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}

		buf, err := json.Marshal(il)
		if err != nil {
			is.log.Error().Err(err).Msg("unable to marshal JSON")

			return err
		}

		if _, err := writeFile(is.store, ilPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("unable to write file")

			return err
		}
	}

	// "index.json" file - create if it doesn't exist
	indexPath := path.Join(repoDir, "index.json")
	if _, err := is.store.Stat(context.Background(), indexPath); err != nil {
		index := ispec.Index{}
		index.SchemaVersion = 2

		buf, err := json.Marshal(index)
		if err != nil {
			is.log.Error().Err(err).Msg("unable to marshal JSON")

			return err
		}

		if _, err := writeFile(is.store, indexPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("unable to write file")

			return err
		}
	}

	return nil
}

// InitRepo creates an image repository under this store.
func (is *ObjectStorage) InitRepo(name string) error {
	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	return is.initRepo(name)
}

// ValidateRepo validates that the repository layout is complaint with the OCI repo layout.
func (is *ObjectStorage) ValidateRepo(name string) (bool, error) {
	// https://github.com/opencontainers/image-spec/blob/master/image-layout.md#content
	// at least, expect at least 3 entries - ["blobs", "oci-layout", "index.json"]
	// and an additional/optional BlobUploadDir in each image store
	// for objects storage we can not create empty dirs, so we check only against index.json and oci-layout
	dir := path.Join(is.rootDir, name)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return false, zerr.ErrRepoNotFound
	}

	files, err := is.store.List(context.Background(), dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")

		return false, zerr.ErrRepoNotFound
	}

	//nolint:gomnd
	if len(files) < 2 {
		return false, zerr.ErrRepoBadVersion
	}

	found := map[string]bool{
		ispec.ImageLayoutFile: false,
		"index.json":          false,
	}

	for _, file := range files {
		_, err := is.store.Stat(context.Background(), file)
		if err != nil {
			return false, err
		}

		filename, err := filepath.Rel(dir, file)
		if err != nil {
			return false, err
		}

		found[filename] = true
	}

	for k, v := range found {
		if !v && k != storageConstants.BlobUploadDir {
			return false, nil
		}
	}

	buf, err := is.store.GetContent(context.Background(), path.Join(dir, ispec.ImageLayoutFile))
	if err != nil {
		return false, err
	}

	var il ispec.ImageLayout
	if err := json.Unmarshal(buf, &il); err != nil {
		return false, err
	}

	if il.Version != ispec.ImageLayoutVersion {
		return false, zerr.ErrRepoBadVersion
	}

	return true, nil
}

// GetRepositories returns a list of all the repositories under this store.
func (is *ObjectStorage) GetRepositories() ([]string, error) {
	var lockLatency time.Time

	dir := is.rootDir

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	stores := make([]string, 0)
	err := is.store.Walk(context.Background(), dir, func(fileInfo driver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil || rel == "." {
			return nil //nolint:nilerr // ignore paths not relative to root dir
		}

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

		is.log.Debug().Str("name", fileInfo.Path()).Msg("found image store")
		stores = append(stores, rel)

		return nil
	})

	// if the root directory is not yet created then return an empty slice of repositories
	var perr driver.PathNotFoundError
	if errors.As(err, &perr) {
		return stores, nil
	}

	return stores, err
}

// GetNextRepository returns next repository under this store.
func (is *ObjectStorage) GetNextRepository(repo string) (string, error) {
	return "", nil
}

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ObjectStorage) GetImageTags(repo string) ([]string, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return nil, zerr.ErrRepoNotFound
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	index, err := storage.GetIndex(is, repo, is.log)
	if err != nil {
		return nil, err
	}

	return storage.GetTagsByIndex(index), nil
}

// GetImageManifest returns the image manifest of an image in the specific repository.
func (is *ObjectStorage) GetImageManifest(repo, reference string) ([]byte, godigest.Digest, string, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return nil, "", "", zerr.ErrRepoNotFound
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	index, err := storage.GetIndex(is, repo, is.log)
	if err != nil {
		return nil, "", "", zerr.ErrRepoNotFound
	}

	manifestDesc, found := storage.GetManifestDescByReference(index, reference)
	if !found {
		return nil, "", "", zerr.ErrManifestNotFound
	}

	buf, err := is.GetBlobContent(repo, manifestDesc.Digest)
	if err != nil {
		if errors.Is(err, zerr.ErrBlobNotFound) {
			return nil, "", "", zerr.ErrManifestNotFound
		}

		return nil, "", "", err
	}

	var manifest ispec.Manifest
	if err := json.Unmarshal(buf, &manifest); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return nil, "", "", err
	}

	monitoring.IncDownloadCounter(is.metrics, repo)

	return buf, manifestDesc.Digest, manifestDesc.MediaType, nil
}

// PutImageManifest adds an image manifest to the repository.
func (is *ObjectStorage) PutImageManifest(repo, reference, mediaType string, //nolint: gocyclo
	body []byte,
) (godigest.Digest, error) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")

		return "", err
	}

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	dig, err := storage.ValidateManifest(is, repo, reference, mediaType, body, is.log)
	if err != nil {
		return dig, err
	}

	refIsDigest := true

	mDigest, err := storage.GetAndValidateRequestDigest(body, reference, is.log)
	if err != nil {
		if errors.Is(err, zerr.ErrBadManifest) {
			return mDigest, err
		}

		refIsDigest = false
	}

	index, err := storage.GetIndex(is, repo, is.log)
	if err != nil {
		return "", err
	}

	// create a new descriptor
	desc := ispec.Descriptor{
		MediaType: mediaType, Size: int64(len(body)), Digest: mDigest,
	}

	if !refIsDigest {
		desc.Annotations = map[string]string{ispec.AnnotationRefName: reference}
	}

	updateIndex, oldDgst, err := storage.CheckIfIndexNeedsUpdate(&index, &desc, is.log)
	if err != nil {
		return "", err
	}

	if !updateIndex {
		return desc.Digest, nil
	}

	// write manifest to "blobs"
	dir := path.Join(is.rootDir, repo, "blobs", mDigest.Algorithm().String())
	manifestPath := path.Join(dir, mDigest.Encoded())

	if err = is.store.PutContent(context.Background(), manifestPath, body); err != nil {
		is.log.Error().Err(err).Str("file", manifestPath).Msg("unable to write")

		return "", err
	}

	err = storage.UpdateIndexWithPrunedImageManifests(is, &index, repo, desc, oldDgst, is.log)
	if err != nil {
		return "", err
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	indexPath := path.Join(dir, "index.json")

	buf, err := json.Marshal(index)
	if err != nil {
		is.log.Error().Err(err).Str("file", indexPath).Msg("unable to marshal JSON")

		return "", err
	}

	// apply linter only on images, not signatures
	pass, err := storage.ApplyLinter(is, is.linter, repo, desc)
	if !pass {
		is.log.Error().Err(err).Str("repo", repo).Str("reference", reference).Msg("linter didn't pass")

		return "", err
	}

	if err = is.store.PutContent(context.Background(), indexPath, buf); err != nil {
		is.log.Error().Err(err).Str("file", manifestPath).Msg("unable to write")

		return "", err
	}

	monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
	monitoring.IncUploadCounter(is.metrics, repo)

	return desc.Digest, nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ObjectStorage) DeleteImageManifest(repo, reference string, detectCollisions bool) error {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return zerr.ErrRepoNotFound
	}

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	index, err := storage.GetIndex(is, repo, is.log)
	if err != nil {
		return err
	}

	manifestDesc, err := storage.RemoveManifestDescByReference(&index, reference, detectCollisions)
	if err != nil {
		return err
	}

	err = storage.UpdateIndexWithPrunedImageManifests(is, &index, repo, manifestDesc, manifestDesc.Digest, is.log)
	if err != nil {
		return err
	}

	// now update "index.json"
	dir = path.Join(is.rootDir, repo)
	file := path.Join(dir, "index.json")

	buf, err := json.Marshal(index)
	if err != nil {
		return err
	}

	if _, err := writeFile(is.store, file, buf); err != nil {
		is.log.Debug().Str("deleting reference", reference).Msg("")

		return err
	}

	// Delete blob only when blob digest not present in manifest entry.
	// e.g. 1.0.1 & 1.0.2 have same blob digest so if we delete 1.0.1, blob should not be removed.
	toDelete := true

	for _, manifest := range index.Manifests {
		if manifestDesc.Digest.String() == manifest.Digest.String() {
			toDelete = false

			break
		}
	}

	if toDelete {
		p := path.Join(dir, "blobs", manifestDesc.Digest.Algorithm().String(), manifestDesc.Digest.Encoded())

		err = is.store.Delete(context.Background(), p)
		if err != nil {
			return err
		}
	}

	monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ObjectStorage) BlobUploadPath(repo, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, storageConstants.BlobUploadDir, uuid)

	return blobUploadPath
}

// NewBlobUpload returns the unique ID for an upload in progress.
func (is *ObjectStorage) NewBlobUpload(repo string) (string, error) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Error().Err(err).Msg("error initializing repo")

		return "", err
	}

	uuid, err := guuid.NewV4()
	if err != nil {
		return "", err
	}

	uid := uuid.String()

	blobUploadPath := is.BlobUploadPath(repo, uid)

	// create multipart upload (append false)
	_, err = is.store.Writer(context.Background(), blobUploadPath, false)
	if err != nil {
		return "", err
	}

	return uid, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ObjectStorage) GetBlobUpload(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	writer, err := is.store.Writer(context.Background(), blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		return -1, err
	}

	return writer.Size(), nil
}

// PutBlobChunkStreamed appends another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ObjectStorage) PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	file, err := is.store.Writer(context.Background(), blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		is.log.Error().Err(err).Msg("failed to continue multipart upload")

		return -1, err
	}

	defer file.Close()

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(body)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to read blob")

		return -1, err
	}

	nbytes, err := file.Write(buf.Bytes())
	if err != nil {
		is.log.Error().Err(err).Msg("failed to append to file")

		return -1, err
	}

	return int64(nbytes), err
}

// PutBlobChunk writes another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ObjectStorage) PutBlobChunk(repo, uuid string, from, to int64,
	body io.Reader,
) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	file, err := is.store.Writer(context.Background(), blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		is.log.Error().Err(err).Msg("failed to continue multipart upload")

		return -1, err
	}

	defer file.Close()

	if from != file.Size() {
		is.log.Error().Int64("expected", from).Int64("actual", file.Size()).
			Msg("invalid range start for blob upload")

		return -1, zerr.ErrBadUploadRange
	}

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(body)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to read blob")

		return -1, err
	}

	nbytes, err := file.Write(buf.Bytes())
	if err != nil {
		is.log.Error().Err(err).Msg("failed to append to file")

		return -1, err
	}

	return int64(nbytes), err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ObjectStorage) BlobUploadInfo(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	writer, err := is.store.Writer(context.Background(), blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		return -1, err
	}

	return writer.Size(), nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ObjectStorage) FinishBlobUpload(repo, uuid string, body io.Reader, dstDigest godigest.Digest) error {
	if err := dstDigest.Validate(); err != nil {
		return err
	}

	src := is.BlobUploadPath(repo, uuid)

	// complete multiUploadPart
	fileWriter, err := is.store.Writer(context.Background(), src, true)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return zerr.ErrBadBlobDigest
	}

	if err := fileWriter.Commit(); err != nil {
		is.log.Error().Err(err).Msg("failed to commit file")

		return err
	}

	if err := fileWriter.Close(); err != nil {
		is.log.Error().Err(err).Msg("failed to close file")

		return err
	}

	fileReader, err := is.store.Reader(context.Background(), src, 0)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open file")

		return zerr.ErrUploadNotFound
	}

	defer fileReader.Close()

	srcDigest, err := godigest.FromReader(fileReader)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return zerr.ErrBadBlobDigest
	}

	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return zerr.ErrBadBlobDigest
	}

	dst := is.BlobPath(repo, dstDigest)

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		if err := is.DedupeBlob(src, dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to dedupe blob")

			return err
		}
	} else {
		if err := is.store.Move(context.Background(), src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to finish blob")

			return err
		}
	}

	return nil
}

// FullBlobUpload handles a full blob upload, and no partial session is created.
func (is *ObjectStorage) FullBlobUpload(repo string, body io.Reader, dstDigest godigest.Digest) (string, int64, error) {
	if err := dstDigest.Validate(); err != nil {
		return "", -1, err
	}

	if err := is.InitRepo(repo); err != nil {
		return "", -1, err
	}

	u, err := guuid.NewV4()
	if err != nil {
		return "", -1, err
	}

	uuid := u.String()
	src := is.BlobUploadPath(repo, uuid)
	digester := sha256.New()
	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(body)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to read blob")

		return "", -1, err
	}

	nbytes, err := writeFile(is.store, src, buf.Bytes())
	if err != nil {
		is.log.Error().Err(err).Msg("failed to write blob")

		return "", -1, err
	}

	_, err = digester.Write(buf.Bytes())
	if err != nil {
		is.log.Error().Err(err).Msg("digester failed to write")

		return "", -1, err
	}

	srcDigest := godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil)))
	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return "", -1, zerr.ErrBadBlobDigest
	}

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		if err := is.DedupeBlob(src, dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to dedupe blob")

			return "", -1, err
		}
	} else {
		if err := is.store.Move(context.Background(), src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to finish blob")

			return "", -1, err
		}
	}

	return uuid, int64(nbytes), nil
}

func (is *ObjectStorage) DedupeBlob(src string, dstDigest godigest.Digest, dst string) error {
retry:
	is.log.Debug().Str("src", src).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: enter")

	dstRecord, err := is.cache.GetBlob(dstDigest)
	if err := test.Error(err); err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to lookup blob record")

		return err
	}

	if dstRecord == "" {
		// cache record doesn't exist, so first disk and cache entry for this digest
		if err := is.cache.PutBlob(dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to insert blob record")

			return err
		}

		// move the blob from uploads to final dest
		if err := is.store.Move(context.Background(), src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dst", dst).Msg("dedupe: unable to rename blob")

			return err
		}

		is.log.Debug().Str("src", src).Str("dst", dst).Msg("dedupe: rename")
	} else {
		// cache record exists, but due to GC and upgrades from older versions,
		// disk content and cache records may go out of sync
		_, err := is.store.Stat(context.Background(), dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to stat")
			// the actual blob on disk may have been removed by GC, so sync the cache
			err := is.cache.DeleteBlob(dstDigest, dstRecord)
			if err = test.Error(err); err != nil {
				//nolint:lll
				is.log.Error().Err(err).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: unable to delete blob record")

				return err
			}

			goto retry
		}

		fileInfo, err := is.store.Stat(context.Background(), dst)
		if err != nil && !errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to stat")

			return err
		}

		// prevent overwrite original blob
		if fileInfo == nil && dstRecord != dst {
			// put empty file so that we are compliant with oci layout, this will act as a deduped blob
			err = is.store.PutContent(context.Background(), dst, []byte{})
			if err != nil {
				is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to write empty file")

				return err
			}

			if err := is.cache.PutBlob(dstDigest, dst); err != nil {
				is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to insert blob record")

				return err
			}
		}

		// remove temp blobupload
		if err := is.store.Delete(context.Background(), src); err != nil {
			is.log.Error().Err(err).Str("src", src).Msg("dedupe: unable to remove blob")

			return err
		}

		is.log.Debug().Str("src", src).Msg("dedupe: remove")
	}

	return nil
}

func (is *ObjectStorage) RunGCRepo(repo string) error {
	return nil
}

func (is *ObjectStorage) RunGCPeriodically(interval time.Duration, sch *scheduler.Scheduler) {
}

// DeleteBlobUpload deletes an existing blob upload that is currently in progress.
func (is *ObjectStorage) DeleteBlobUpload(repo, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	writer, err := is.store.Writer(context.Background(), blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return zerr.ErrUploadNotFound
		}

		return err
	}

	defer writer.Close()

	if err := writer.Cancel(); err != nil {
		is.log.Error().Err(err).Str("blobUploadPath", blobUploadPath).Msg("error deleting blob upload")

		return err
	}

	return nil
}

// BlobPath returns the repository path of a blob.
func (is *ObjectStorage) BlobPath(repo string, digest godigest.Digest) string {
	return path.Join(is.rootDir, repo, "blobs", digest.Algorithm().String(), digest.Encoded())
}

// CheckBlob verifies a blob and returns true if the blob is correct.
func (is *ObjectStorage) CheckBlob(repo string, digest godigest.Digest) (bool, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return false, -1, err
	}

	blobPath := is.BlobPath(repo, digest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		is.Lock(&lockLatency)
		defer is.Unlock(&lockLatency)
	} else {
		is.RLock(&lockLatency)
		defer is.RUnlock(&lockLatency)
	}

	binfo, err := is.store.Stat(context.Background(), blobPath)
	if err == nil && binfo.Size() > 0 {
		is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

		return true, binfo.Size(), nil
	}
	// otherwise is a 'deduped' blob (empty file)

	// Check blobs in cache
	dstRecord, err := is.checkCacheBlob(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest.String()).Msg("cache: not found")

		return false, -1, zerr.ErrBlobNotFound
	}

	blobSize, err := is.copyBlob(repo, blobPath, dstRecord)
	if err != nil {
		return false, -1, zerr.ErrBlobNotFound
	}

	// put deduped blob in cache
	if err := is.cache.PutBlob(digest, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("dedupe: unable to insert blob record")

		return false, -1, err
	}

	return true, blobSize, nil
}

func (is *ObjectStorage) checkCacheBlob(digest godigest.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}

	if fmt.Sprintf("%v", is.cache) == fmt.Sprintf("%v", nil) {
		return "", zerr.ErrBlobNotFound
	}

	dstRecord, err := is.cache.GetBlob(digest)
	if err != nil {
		return "", err
	}

	if _, err := is.store.Stat(context.Background(), dstRecord); err != nil {
		is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

		// the actual blob on disk may have been removed by GC, so sync the cache
		if err := is.cache.DeleteBlob(digest, dstRecord); err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", dstRecord).
				Msg("unable to remove blob path from cache")

			return "", err
		}

		return "", zerr.ErrBlobNotFound
	}

	is.log.Debug().Str("digest", digest.String()).Str("dstRecord", dstRecord).Msg("cache: found dedupe record")

	return dstRecord, nil
}

func (is *ObjectStorage) copyBlob(repo string, blobPath string, dstRecord string) (int64, error) {
	if err := is.initRepo(repo); err != nil {
		is.log.Error().Err(err).Str("repo", repo).Msg("unable to initialize an empty repo")

		return -1, err
	}

	if err := is.store.PutContent(context.Background(), blobPath, []byte{}); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Str("link", dstRecord).Msg("dedupe: unable to link")

		return -1, zerr.ErrBlobNotFound
	}

	// return original blob with content instead of the deduped one (blobPath)
	binfo, err := is.store.Stat(context.Background(), dstRecord)
	if err == nil {
		return binfo.Size(), nil
	}

	return -1, zerr.ErrBlobNotFound
}

// blobStream is using to serve blob range requests.
type blobStream struct {
	reader io.Reader
	closer io.Closer
}

func NewBlobStream(readCloser io.ReadCloser, from, to int64) (io.ReadCloser, error) {
	return &blobStream{reader: io.LimitReader(readCloser, to-from+1), closer: readCloser}, nil
}

func (bs *blobStream) Read(buf []byte) (int, error) {
	return bs.reader.Read(buf)
}

func (bs *blobStream) Close() error {
	return bs.closer.Close()
}

// GetBlobPartial returns a partial stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ObjectStorage) GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
) (io.ReadCloser, int64, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return nil, -1, -1, err
	}

	blobPath := is.BlobPath(repo, digest)

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	binfo, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return nil, -1, -1, zerr.ErrBlobNotFound
	}

	end := to

	if to < 0 || to >= binfo.Size() {
		end = binfo.Size() - 1
	}

	blobHandle, err := is.store.Reader(context.Background(), blobPath, from)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")

		return nil, -1, -1, err
	}

	blobReadCloser, err := NewBlobStream(blobHandle, from, end)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob stream")

		return nil, -1, -1, err
	}

	// is a 'deduped' blob?
	if binfo.Size() == 0 {
		defer blobReadCloser.Close()

		// Check blobs in cache
		dstRecord, err := is.checkCacheBlob(digest)
		if err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Msg("cache: not found")

			return nil, -1, -1, zerr.ErrBlobNotFound
		}

		binfo, err := is.store.Stat(context.Background(), dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

			return nil, -1, -1, zerr.ErrBlobNotFound
		}

		end := to

		if to < 0 || to >= binfo.Size() {
			end = binfo.Size() - 1
		}

		blobHandle, err := is.store.Reader(context.Background(), dstRecord, from)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to open blob")

			return nil, -1, -1, err
		}

		blobReadCloser, err := NewBlobStream(blobHandle, from, end)
		if err != nil {
			is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob stream")

			return nil, -1, -1, err
		}

		return blobReadCloser, end - from + 1, binfo.Size(), nil
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, end - from + 1, binfo.Size(), nil
}

// GetBlob returns a stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ObjectStorage) GetBlob(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return nil, -1, err
	}

	blobPath := is.BlobPath(repo, digest)

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	binfo, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return nil, -1, zerr.ErrBlobNotFound
	}

	blobReadCloser, err := is.store.Reader(context.Background(), blobPath, 0)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")

		return nil, -1, err
	}

	// is a 'deduped' blob?
	if binfo.Size() == 0 && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		// Check blobs in cache
		dstRecord, err := is.checkCacheBlob(digest)
		if err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Msg("cache: not found")

			return nil, -1, zerr.ErrBlobNotFound
		}

		binfo, err := is.store.Stat(context.Background(), dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

			return nil, -1, zerr.ErrBlobNotFound
		}

		blobReadCloser, err := is.store.Reader(context.Background(), dstRecord, 0)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to open blob")

			return nil, -1, err
		}

		return blobReadCloser, binfo.Size(), nil
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, binfo.Size(), nil
}

// GetBlobContent returns blob contents, SHOULD lock from outside.
func (is *ObjectStorage) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	if err := digest.Validate(); err != nil {
		return []byte{}, err
	}

	blobPath := is.BlobPath(repo, digest)

	binfo, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return []byte{}, zerr.ErrBlobNotFound
	}

	blobBuf, err := is.store.GetContent(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")

		return nil, err
	}

	// is a 'deduped' blob?
	if binfo.Size() == 0 && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		// Check blobs in cache
		dstRecord, err := is.checkCacheBlob(digest)
		if err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Msg("cache: not found")

			return nil, zerr.ErrBlobNotFound
		}

		blobBuf, err := is.store.GetContent(context.Background(), dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to open blob")

			return nil, err
		}

		return blobBuf, nil
	}

	return blobBuf, nil
}

func (is *ObjectStorage) GetReferrers(repo string, gdigest godigest.Digest, artifactType string,
) (ispec.Index, error) {
	var lockLatency time.Time

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	return storage.GetReferrers(is, repo, gdigest, artifactType, is.log)
}

func (is *ObjectStorage) GetOrasReferrers(repo string, gdigest godigest.Digest, artifactType string,
) ([]artifactspec.Descriptor, error) {
	var lockLatency time.Time

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	return storage.GetOrasReferrers(is, repo, gdigest, artifactType, is.log)
}

// GetIndexContent returns index.json contents, SHOULD lock from outside.
func (is *ObjectStorage) GetIndexContent(repo string) ([]byte, error) {
	dir := path.Join(is.rootDir, repo)

	buf, err := is.store.GetContent(context.Background(), path.Join(dir, "index.json"))
	if err != nil {
		if errors.Is(err, driver.PathNotFoundError{}) {
			is.log.Error().Err(err).Str("dir", dir).Msg("index.json doesn't exist")

			return []byte{}, zerr.ErrRepoNotFound
		}

		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return []byte{}, err
	}

	return buf, nil
}

// DeleteBlob removes the blob from the repository.
func (is *ObjectStorage) DeleteBlob(repo string, digest godigest.Digest) error {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return err
	}

	blobPath := is.BlobPath(repo, digest)

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	_, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return zerr.ErrBlobNotFound
	}

	if fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		dstRecord, err := is.cache.GetBlob(digest)
		if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to lookup blob record")

			return err
		}

		// remove cache entry and move blob contents to the next candidate if there is any
		if err := is.cache.DeleteBlob(digest, blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", blobPath).
				Msg("unable to remove blob path from cache")

			return err
		}

		// if the deleted blob is one with content
		if dstRecord == blobPath {
			// get next candidate
			dstRecord, err := is.cache.GetBlob(digest)
			if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
				is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to lookup blob record")

				return err
			}

			// if we have a new candidate move the blob content to it
			if dstRecord != "" {
				if err := is.store.Move(context.Background(), blobPath, dstRecord); err != nil {
					is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to remove blob path")

					return err
				}

				return nil
			}
		}
	}

	if err := is.store.Delete(context.Background(), blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to remove blob path")

		return err
	}

	return nil
}

// Do not use for multipart upload, buf must not be empty.
// If you want to create an empty file use is.store.PutContent().
func writeFile(store driver.StorageDriver, filepath string, buf []byte) (int, error) {
	var n int

	if stwr, err := store.Writer(context.Background(), filepath, false); err == nil {
		defer stwr.Close()

		if n, err = stwr.Write(buf); err != nil {
			return -1, err
		}

		if err := stwr.Commit(); err != nil {
			return -1, err
		}
	} else {
		return -1, err
	}

	return n, nil
}
