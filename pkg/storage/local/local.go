package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	apexlog "github.com/apex/log"
	guuid "github.com/gofrs/uuid"
	"github.com/minio/sha256-simd"
	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/casext"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	"github.com/sigstore/cosign/pkg/oci/remote"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	zlog "zotregistry.io/zot/pkg/log"
	zreg "zotregistry.io/zot/pkg/regexp"
	"zotregistry.io/zot/pkg/scheduler"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/test"
)

const (
	DefaultFilePerms     = 0o600
	DefaultDirPerms      = 0o700
	defaultSchemaVersion = 2
)

// BlobUpload models and upload request.
type BlobUpload struct {
	StoreName string
	ID        string
}

// ImageStoreLocal provides the image storage operations.
type ImageStoreLocal struct {
	rootDir     string
	lock        *sync.RWMutex
	blobUploads map[string]storage.BlobUpload
	cache       cache.Cache
	gc          bool
	dedupe      bool
	commit      bool
	gcDelay     time.Duration
	log         zerolog.Logger
	metrics     monitoring.MetricServer
	linter      storage.Lint
}

func (is *ImageStoreLocal) RootDir() string {
	return is.rootDir
}

func (is *ImageStoreLocal) DirExists(d string) bool {
	return common.DirExists(d)
}

// NewImageStore returns a new image store backed by a file storage.
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, gc bool, gcDelay time.Duration, dedupe, commit bool,
	log zlog.Logger, metrics monitoring.MetricServer, linter storage.Lint, cacheDriver cache.Cache,
) storage.ImageStore {
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		if err := os.MkdirAll(rootDir, DefaultDirPerms); err != nil {
			log.Error().Err(err).Str("rootDir", rootDir).Msg("unable to create root dir")

			return nil
		}
	}

	imgStore := &ImageStoreLocal{
		rootDir:     rootDir,
		lock:        &sync.RWMutex{},
		blobUploads: make(map[string]storage.BlobUpload),
		gc:          gc,
		gcDelay:     gcDelay,
		dedupe:      dedupe,
		commit:      commit,
		log:         log.With().Caller().Logger(),
		metrics:     metrics,
		linter:      linter,
	}

	imgStore.cache = cacheDriver

	if gc {
		// we use umoci GC to perform garbage-collection, but it uses its own logger.
		// - so capture those logs, could be useful.
		apexlog.SetLevel(apexlog.DebugLevel)
		apexlog.SetHandler(apexlog.HandlerFunc(func(entry *apexlog.Entry) error {
			e := log.Debug()
			for k, v := range entry.Fields {
				e = e.Interface(k, v)
			}
			e.Msg(entry.Message)

			return nil
		}))
	}

	return imgStore
}

// RLock read-lock.
func (is *ImageStoreLocal) RLock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.RLock()
}

// RUnlock read-unlock.
func (is *ImageStoreLocal) RUnlock(lockStart *time.Time) {
	is.lock.RUnlock()

	lockEnd := time.Now()
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RLOCK) // histogram
}

// Lock write-lock.
func (is *ImageStoreLocal) Lock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.Lock()
}

// Unlock write-unlock.
func (is *ImageStoreLocal) Unlock(lockStart *time.Time) {
	is.lock.Unlock()

	lockEnd := time.Now()
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RWLOCK) // histogram
}

func (is *ImageStoreLocal) initRepo(name string) error {
	repoDir := path.Join(is.rootDir, name)

	if !utf8.ValidString(name) {
		is.log.Error().Msg("input is not valid UTF-8")

		return zerr.ErrInvalidRepositoryName
	}

	if !zreg.FullNameRegexp.MatchString(name) {
		is.log.Error().Str("repo", name).Msg("invalid repository name")

		return zerr.ErrInvalidRepositoryName
	}

	// create "blobs" subdir
	err := ensureDir(path.Join(repoDir, "blobs"), is.log)
	if err != nil {
		is.log.Error().Err(err).Msg("error creating blobs subdir")

		return err
	}
	// create BlobUploadDir subdir
	err = ensureDir(path.Join(repoDir, storageConstants.BlobUploadDir), is.log)
	if err != nil {
		is.log.Error().Err(err).Msg("error creating blob upload subdir")

		return err
	}

	// "oci-layout" file - create if it doesn't exist
	ilPath := path.Join(repoDir, ispec.ImageLayoutFile)
	if _, err := os.Stat(ilPath); err != nil {
		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}

		buf, err := json.Marshal(il)
		if err != nil {
			is.log.Panic().Err(err).Msg("unable to marshal JSON")
		}

		if err := is.writeFile(ilPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("unable to write file")

			return err
		}
	}

	// "index.json" file - create if it doesn't exist
	indexPath := path.Join(repoDir, "index.json")
	if _, err := os.Stat(indexPath); err != nil {
		index := ispec.Index{Versioned: imeta.Versioned{SchemaVersion: defaultSchemaVersion}}

		buf, err := json.Marshal(index)
		if err != nil {
			is.log.Panic().Err(err).Msg("unable to marshal JSON")
		}

		if err := is.writeFile(indexPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", indexPath).Msg("unable to write file")

			return err
		}
	}

	return nil
}

// InitRepo creates an image repository under this store.
func (is *ImageStoreLocal) InitRepo(name string) error {
	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	return is.initRepo(name)
}

// ValidateRepo validates that the repository layout is complaint with the OCI repo layout.
func (is *ImageStoreLocal) ValidateRepo(name string) (bool, error) {
	// https://github.com/opencontainers/image-spec/blob/master/image-layout.md#content
	// at least, expect at least 3 entries - ["blobs", "oci-layout", "index.json"]
	// and an additional/optional BlobUploadDir in each image store
	if !zreg.FullNameRegexp.MatchString(name) {
		return false, zerr.ErrInvalidRepositoryName
	}

	dir := path.Join(is.rootDir, name)
	if !is.DirExists(dir) {
		return false, zerr.ErrRepoNotFound
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")

		return false, zerr.ErrRepoNotFound
	}

	if len(files) < 3 { //nolint:gomnd
		return false, zerr.ErrRepoBadVersion
	}

	found := map[string]bool{
		"blobs":               false,
		ispec.ImageLayoutFile: false,
		"index.json":          false,
	}

	for _, file := range files {
		if file.Name() == "blobs" && !file.IsDir() {
			return false, nil
		}

		found[file.Name()] = true
	}

	for k, v := range found {
		if !v && k != storageConstants.BlobUploadDir {
			return false, nil
		}
	}

	buf, err := os.ReadFile(path.Join(dir, ispec.ImageLayoutFile))
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
func (is *ImageStoreLocal) GetRepositories() ([]string, error) {
	var lockLatency time.Time

	dir := is.rootDir

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	_, err := os.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Msg("failure walking storage root-dir")

		return nil, err
	}

	stores := make([]string, 0)
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(is.rootDir, path)
		if err != nil {
			return nil //nolint:nilerr // ignore paths not relative to root dir
		}

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

		// is.log.Debug().Str("dir", path).Str("name", info.Name()).Msg("found image store")
		stores = append(stores, rel)

		return nil
	})

	return stores, err
}

// GetNextRepository returns next repository under this store.
func (is *ImageStoreLocal) GetNextRepository(repo string) (string, error) {
	var lockLatency time.Time

	dir := is.rootDir

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	_, err := os.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Msg("failure walking storage root-dir")

		return "", err
	}

	found := false
	store := ""
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(is.rootDir, path)
		if err != nil {
			return nil //nolint:nilerr // ignore paths not relative to root dir
		}

		ok, err := is.ValidateRepo(rel)
		if !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

		if repo == "" && ok && err == nil {
			store = rel

			return io.EOF
		}

		if found {
			store = rel

			return io.EOF
		}

		if rel == repo {
			found = true
		}

		return nil
	})

	return store, err
}

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ImageStoreLocal) GetImageTags(repo string) ([]string, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if !is.DirExists(dir) {
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
func (is *ImageStoreLocal) GetImageManifest(repo, reference string) ([]byte, godigest.Digest, string, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if !is.DirExists(dir) {
		return nil, "", "", zerr.ErrRepoNotFound
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	index, err := storage.GetIndex(is, repo, is.log)
	if err != nil {
		return nil, "", "", err
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
func (is *ImageStoreLocal) PutImageManifest(repo, reference, mediaType string, //nolint: gocyclo
	body []byte,
) (godigest.Digest, error) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")

		return "", err
	}

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	digest, err := storage.ValidateManifest(is, repo, reference, mediaType, body, is.log)
	if err != nil {
		return digest, err
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
	_ = ensureDir(dir, is.log)
	file := path.Join(dir, mDigest.Encoded())

	// in case the linter will not pass, it will be garbage collected
	if err := is.writeFile(file, body); err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to write")

		return "", err
	}

	err = storage.UpdateIndexWithPrunedImageManifests(is, &index, repo, desc, oldDgst, is.log)
	if err != nil {
		return "", err
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	file = path.Join(dir, "index.json")

	buf, err := json.Marshal(index)
	if err := test.Error(err); err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to marshal JSON")

		return "", err
	}

	// apply linter only on images, not signatures
	pass, err := storage.ApplyLinter(is, is.linter, repo, desc)
	if !pass {
		is.log.Error().Err(err).Str("repo", repo).Str("reference", reference).Msg("linter didn't pass")

		return "", err
	}

	err = is.writeFile(file, buf)
	if err := test.Error(err); err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to write")

		return "", err
	}

	if is.gc {
		if err := is.garbageCollect(dir, repo); err != nil {
			return "", err
		}
	}

	monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
	monitoring.IncUploadCounter(is.metrics, repo)

	return desc.Digest, nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ImageStoreLocal) DeleteImageManifest(repo, reference string, detectCollision bool) error {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if !is.DirExists(dir) {
		return zerr.ErrRepoNotFound
	}

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	index, err := storage.GetIndex(is, repo, is.log)
	if err != nil {
		return err
	}

	manifestDesc, err := storage.RemoveManifestDescByReference(&index, reference, detectCollision)
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

	if err := is.writeFile(file, buf); err != nil {
		return err
	}

	if is.gc {
		if err := is.garbageCollect(dir, repo); err != nil {
			return err
		}
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

		_ = os.Remove(p)
	}

	monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ImageStoreLocal) BlobUploadPath(repo, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, storageConstants.BlobUploadDir, uuid)

	return blobUploadPath
}

// NewBlobUpload returns the unique ID for an upload in progress.
func (is *ImageStoreLocal) NewBlobUpload(repo string) (string, error) {
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

	file, err := os.OpenFile(blobUploadPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, DefaultFilePerms)
	if err != nil {
		return "", zerr.ErrRepoNotFound
	}

	defer file.Close()

	return uid, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ImageStoreLocal) GetBlobUpload(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	if !utf8.ValidString(blobUploadPath) {
		is.log.Error().Msg("input is not valid UTF-8")

		return -1, zerr.ErrInvalidRepositoryName
	}

	binfo, err := os.Stat(blobUploadPath)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, zerr.ErrUploadNotFound
		}

		return -1, err
	}

	return binfo.Size(), nil
}

// PutBlobChunkStreamed appends another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStoreLocal) PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	_, err := os.Stat(blobUploadPath)
	if err != nil {
		return -1, zerr.ErrUploadNotFound
	}

	file, err := os.OpenFile(blobUploadPath, os.O_WRONLY|os.O_CREATE, DefaultFilePerms)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to open file")

		return -1, err
	}

	defer func() {
		if is.commit {
			_ = file.Sync()
		}

		_ = file.Close()
	}()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		is.log.Error().Err(err).Msg("failed to seek file")

		return -1, err
	}

	n, err := io.Copy(file, body)

	return n, err
}

// PutBlobChunk writes another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStoreLocal) PutBlobChunk(repo, uuid string, from, to int64,
	body io.Reader,
) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	binfo, err := os.Stat(blobUploadPath)
	if err != nil {
		return -1, zerr.ErrUploadNotFound
	}

	if from != binfo.Size() {
		is.log.Error().Int64("expected", from).Int64("actual", binfo.Size()).
			Msg("invalid range start for blob upload")

		return -1, zerr.ErrBadUploadRange
	}

	file, err := os.OpenFile(blobUploadPath, os.O_WRONLY|os.O_CREATE, DefaultFilePerms)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to open file")

		return -1, err
	}

	defer func() {
		if is.commit {
			_ = file.Sync()
		}

		_ = file.Close()
	}()

	if _, err := file.Seek(from, io.SeekStart); err != nil {
		is.log.Error().Err(err).Msg("failed to seek file")

		return -1, err
	}

	n, err := io.Copy(file, body)

	return n, err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ImageStoreLocal) BlobUploadInfo(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	binfo, err := os.Stat(blobUploadPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")

		return -1, err
	}

	size := binfo.Size()

	return size, nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ImageStoreLocal) FinishBlobUpload(repo, uuid string, body io.Reader, dstDigest godigest.Digest) error {
	if err := dstDigest.Validate(); err != nil {
		return err
	}

	src := is.BlobUploadPath(repo, uuid)

	_, err := os.Stat(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to stat blob")

		return zerr.ErrUploadNotFound
	}

	blobFile, err := os.Open(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return zerr.ErrUploadNotFound
	}

	defer blobFile.Close()

	digester := sha256.New()

	_, err = io.Copy(digester, blobFile)
	if err != nil {
		is.log.Error().Err(err).Str("repo", repo).Str("blob", src).Str("digest", dstDigest.String()).
			Msg("unable to compute hash")

		return err
	}

	srcDigest := godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil)))

	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return zerr.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	err = ensureDir(dir, is.log)
	if err != nil {
		is.log.Error().Err(err).Msg("error creating blobs/sha256 dir")

		return err
	}

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		err = is.DedupeBlob(src, dstDigest, dst)
		if err := test.Error(err); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to dedupe blob")

			return err
		}
	} else {
		if err := os.Rename(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to finish blob")

			return err
		}
	}

	return nil
}

// FullBlobUpload handles a full blob upload, and no partial session is created.
func (is *ImageStoreLocal) FullBlobUpload(repo string, body io.Reader, dstDigest godigest.Digest,
) (string, int64, error) {
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

	blobFile, err := os.Create(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return "", -1, zerr.ErrUploadNotFound
	}

	defer func() {
		if is.commit {
			_ = blobFile.Sync()
		}

		_ = blobFile.Close()
	}()

	digester := sha256.New()
	mw := io.MultiWriter(blobFile, digester)

	nbytes, err := io.Copy(mw, body)
	if err != nil {
		return "", -1, err
	}

	srcDigest := godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil)))
	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return "", -1, zerr.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	_ = ensureDir(dir, is.log)
	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		if err := is.DedupeBlob(src, dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to dedupe blob")

			return "", -1, err
		}
	} else {
		if err := os.Rename(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("unable to finish blob")

			return "", -1, err
		}
	}

	return uuid, nbytes, nil
}

func (is *ImageStoreLocal) DedupeBlob(src string, dstDigest godigest.Digest, dst string) error {
retry:
	is.log.Debug().Str("src", src).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: enter")

	dstRecord, err := is.cache.GetBlob(dstDigest)

	if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to lookup blob record")

		return err
	}

	if dstRecord == "" {
		// cache record doesn't exist, so first disk and cache entry for this diges
		if err := is.cache.PutBlob(dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to insert blob record")

			return err
		}

		// move the blob from uploads to final dest
		if err := os.Rename(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dst", dst).Msg("dedupe: unable to rename blob")

			return err
		}

		is.log.Debug().Str("src", src).Str("dst", dst).Msg("dedupe: rename")
	} else {
		// cache record exists, but due to GC and upgrades from older versions,
		// disk content and cache records may go out of sync
		dstRecord = path.Join(is.rootDir, dstRecord)

		dstRecordFi, err := os.Stat(dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to stat")
			// the actual blob on disk may have been removed by GC, so sync the cache
			if err := is.cache.DeleteBlob(dstDigest, dstRecord); err != nil {
				//nolint:lll // gofumpt conflicts with lll
				is.log.Error().Err(err).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: unable to delete blob record")

				return err
			}

			goto retry
		}

		dstFi, err := os.Stat(dst)
		if err != nil && !os.IsNotExist(err) {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to stat")

			return err
		}

		if !os.SameFile(dstFi, dstRecordFi) {
			// blob lookup cache out of sync with actual disk contents
			if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
				is.log.Error().Err(err).Str("dst", dst).Msg("dedupe: unable to remove blob")

				return err
			}

			is.log.Debug().Str("blobPath", dst).Str("dstRecord", dstRecord).Msg("dedupe: creating hard link")

			if err := os.Link(dstRecord, dst); err != nil {
				is.log.Error().Err(err).Str("blobPath", dst).Str("link", dstRecord).Msg("dedupe: unable to hard link")

				return err
			}
		}

		if err := os.Remove(src); err != nil {
			is.log.Error().Err(err).Str("src", src).Msg("dedupe: uname to remove blob")

			return err
		}

		is.log.Debug().Str("src", src).Msg("dedupe: remove")
	}

	return nil
}

// DeleteBlobUpload deletes an existing blob upload that is currently in progress.
func (is *ImageStoreLocal) DeleteBlobUpload(repo, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	if err := os.Remove(blobUploadPath); err != nil {
		is.log.Error().Err(err).Str("blobUploadPath", blobUploadPath).Msg("error deleting blob upload")

		return err
	}

	return nil
}

// BlobPath returns the repository path of a blob.
func (is *ImageStoreLocal) BlobPath(repo string, digest godigest.Digest) string {
	return path.Join(is.rootDir, repo, "blobs", digest.Algorithm().String(), digest.Encoded())
}

// CheckBlob verifies a blob and returns true if the blob is correct.
func (is *ImageStoreLocal) CheckBlob(repo string, digest godigest.Digest) (bool, int64, error) {
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

	binfo, err := os.Stat(blobPath)
	if err == nil {
		is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

		return true, binfo.Size(), nil
	}

	is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

	// Check blobs in cache
	dstRecord, err := is.checkCacheBlob(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest.String()).Msg("cache: not found")

		return false, -1, zerr.ErrBlobNotFound
	}

	// If found copy to location
	blobSize, err := is.copyBlob(repo, blobPath, dstRecord)
	if err != nil {
		return false, -1, zerr.ErrBlobNotFound
	}

	if err := is.cache.PutBlob(digest, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("dedupe: unable to insert blob record")

		return false, -1, err
	}

	return true, blobSize, nil
}

func (is *ImageStoreLocal) checkCacheBlob(digest godigest.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}

	if !is.dedupe || fmt.Sprintf("%v", is.cache) == fmt.Sprintf("%v", nil) {
		return "", zerr.ErrBlobNotFound
	}

	dstRecord, err := is.cache.GetBlob(digest)
	if err != nil {
		return "", err
	}

	dstRecord = path.Join(is.rootDir, dstRecord)

	if _, err := os.Stat(dstRecord); err != nil {
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

func (is *ImageStoreLocal) copyBlob(repo, blobPath, dstRecord string) (int64, error) {
	if err := is.initRepo(repo); err != nil {
		is.log.Error().Err(err).Str("repo", repo).Msg("unable to initialize an empty repo")

		return -1, err
	}

	_ = ensureDir(filepath.Dir(blobPath), is.log)

	if err := os.Link(dstRecord, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Str("link", dstRecord).Msg("dedupe: unable to hard link")

		return -1, zerr.ErrBlobNotFound
	}

	binfo, err := os.Stat(blobPath)
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

func newBlobStream(blobPath string, from, to int64) (io.ReadCloser, error) {
	blobFile, err := os.Open(blobPath)
	if err != nil {
		return nil, err
	}

	if from > 0 {
		_, err = blobFile.Seek(from, io.SeekStart)
		if err != nil {
			return nil, err
		}
	}

	if from < 0 || to < from {
		return nil, zerr.ErrBadRange
	}

	blobstrm := blobStream{reader: blobFile, closer: blobFile}

	blobstrm.reader = io.LimitReader(blobFile, to-from+1)

	return &blobstrm, nil
}

func (bs *blobStream) Read(buf []byte) (int, error) {
	return bs.reader.Read(buf)
}

func (bs *blobStream) Close() error {
	return bs.closer.Close()
}

// GetBlobPartial returns a partial stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ImageStoreLocal) GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
) (io.ReadCloser, int64, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return nil, -1, -1, err
	}

	blobPath := is.BlobPath(repo, digest)

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	binfo, err := os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return nil, -1, -1, zerr.ErrBlobNotFound
	}

	if to < 0 || to >= binfo.Size() {
		to = binfo.Size() - 1
	}

	blobReadCloser, err := newBlobStream(blobPath, from, to)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")

		return nil, -1, -1, err
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, to - from + 1, binfo.Size(), nil
}

// GetBlob returns a stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ImageStoreLocal) GetBlob(repo string, digest godigest.Digest, mediaType string,
) (io.ReadCloser, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return nil, -1, err
	}

	blobPath := is.BlobPath(repo, digest)

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	binfo, err := os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return nil, -1, zerr.ErrBlobNotFound
	}

	blobReadCloser, err := os.Open(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")

		return nil, -1, err
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, binfo.Size(), nil
}

// GetBlobContent returns blob contents, SHOULD lock from outside.
func (is *ImageStoreLocal) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	if err := digest.Validate(); err != nil {
		return []byte{}, err
	}

	blobPath := is.BlobPath(repo, digest)

	blob, err := os.ReadFile(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			is.log.Error().Err(err).Str("blob", blobPath).Msg("blob doesn't exist")

			return []byte{}, zerr.ErrBlobNotFound
		}

		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to read blob")

		return []byte{}, err
	}

	return blob, nil
}

// GetIndexContent returns index.json contents, SHOULD lock from outside.
func (is *ImageStoreLocal) GetIndexContent(repo string) ([]byte, error) {
	dir := path.Join(is.rootDir, repo)

	buf, err := os.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		if os.IsNotExist(err) {
			is.log.Error().Err(err).Str("dir", dir).Msg("index.json doesn't exist")

			return []byte{}, zerr.ErrRepoNotFound
		}

		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return []byte{}, err
	}

	return buf, nil
}

// DeleteBlob removes the blob from the repository.
func (is *ImageStoreLocal) DeleteBlob(repo string, digest godigest.Digest) error {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return err
	}

	blobPath := is.BlobPath(repo, digest)

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	_, err := os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return zerr.ErrBlobNotFound
	}

	if fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		if err := is.cache.DeleteBlob(digest, blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", blobPath).
				Msg("unable to remove blob path from cache")

			return err
		}
	}

	if err := os.Remove(blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to remove blob path")

		return err
	}

	return nil
}

func (is *ImageStoreLocal) GetReferrers(repo string, gdigest godigest.Digest, artifactTypes []string,
) (ispec.Index, error) {
	var lockLatency time.Time

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	return storage.GetReferrers(is, repo, gdigest, artifactTypes, is.log)
}

func (is *ImageStoreLocal) GetOrasReferrers(repo string, gdigest godigest.Digest, artifactType string,
) ([]oras.Descriptor, error) {
	var lockLatency time.Time

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	return storage.GetOrasReferrers(is, repo, gdigest, artifactType, is.log)
}

func (is *ImageStoreLocal) writeFile(filename string, data []byte) error {
	if !is.commit {
		return os.WriteFile(filename, data, DefaultFilePerms)
	}

	fhandle, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, DefaultFilePerms)
	if err != nil {
		return err
	}

	_, err = fhandle.Write(data)

	if err1 := test.Error(fhandle.Sync()); err1 != nil && err == nil {
		err = err1
		is.log.Error().Err(err).Str("filename", filename).Msg("unable to sync file")
	}

	if err1 := test.Error(fhandle.Close()); err1 != nil && err == nil {
		err = err1
	}

	return err
}

// utility routines

func ValidateHardLink(rootDir string) error {
	if err := os.MkdirAll(rootDir, DefaultDirPerms); err != nil {
		return err
	}

	err := os.WriteFile(path.Join(rootDir, "hardlinkcheck.txt"),
		[]byte("check whether hardlinks work on filesystem"), DefaultFilePerms)
	if err != nil {
		return err
	}

	err = os.Link(path.Join(rootDir, "hardlinkcheck.txt"), path.Join(rootDir, "duphardlinkcheck.txt"))
	if err != nil {
		// Remove hardlinkcheck.txt if hardlink fails
		zerr := os.RemoveAll(path.Join(rootDir, "hardlinkcheck.txt"))
		if zerr != nil {
			return zerr
		}

		return err
	}

	err = os.RemoveAll(path.Join(rootDir, "hardlinkcheck.txt"))
	if err != nil {
		return err
	}

	return os.RemoveAll(path.Join(rootDir, "duphardlinkcheck.txt"))
}

func ensureDir(dir string, log zerolog.Logger) error {
	if err := os.MkdirAll(dir, DefaultDirPerms); err != nil {
		log.Error().Err(err).Str("dir", dir).Msg("unable to create dir")

		return err
	}

	return nil
}

func (is *ImageStoreLocal) garbageCollect(dir string, repo string) error {
	oci, err := umoci.OpenLayout(dir)
	if err := test.Error(err); err != nil {
		return err
	}
	defer oci.Close()

	// gc untagged manifests and signatures
	index, err := oci.GetIndex(context.Background())
	if err != nil {
		return err
	}

	referencedByImageIndex := []string{}
	cosignDescriptors := []ispec.Descriptor{}
	notationDescriptors := []ispec.Descriptor{}

	/* gather manifests references by multiarch images (to skip gc)
	gather cosign and notation signatures descriptors */
	for _, desc := range index.Manifests {
		switch desc.MediaType {
		case ispec.MediaTypeImageIndex:
			indexImage, err := storage.GetImageIndex(is, repo, desc.Digest, is.log)
			if err != nil {
				is.log.Error().Err(err).Str("repo", repo).Str("digest", desc.Digest.String()).
					Msg("gc: failed to read multiarch(index) image")

				return err
			}

			for _, indexDesc := range indexImage.Manifests {
				referencedByImageIndex = append(referencedByImageIndex, indexDesc.Digest.String())
			}
		case ispec.MediaTypeImageManifest:
			tag, ok := desc.Annotations[ispec.AnnotationRefName]
			if ok {
				// gather cosign signatures
				if strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, remote.SignatureTagSuffix) {
					cosignDescriptors = append(cosignDescriptors, desc)
				}
			}
		case oras.MediaTypeArtifactManifest:
			notationDescriptors = append(notationDescriptors, desc)
		}
	}

	is.log.Info().Msg("gc: untagged manifests")

	if err := gcUntaggedManifests(is, oci, &index, repo, referencedByImageIndex); err != nil {
		return err
	}

	is.log.Info().Msg("gc: cosign signatures")

	if err := gcCosignSignatures(is, oci, &index, repo, cosignDescriptors); err != nil {
		return err
	}

	is.log.Info().Msg("gc: notation signatures")

	if err := gcNotationSignatures(is, oci, &index, repo, notationDescriptors); err != nil {
		return err
	}

	is.log.Info().Msg("gc: blobs")

	err = oci.GC(context.Background(), ifOlderThan(is, repo, is.gcDelay))
	if err := test.Error(err); err != nil {
		return err
	}

	return nil
}

func gcUntaggedManifests(imgStore *ImageStoreLocal, oci casext.Engine, index *ispec.Index, repo string,
	referencedByImageIndex []string,
) error {
	for _, desc := range index.Manifests {
		// skip manifests referenced in image indexex
		if common.Contains(referencedByImageIndex, desc.Digest.String()) {
			continue
		}

		// remove untagged images
		if desc.MediaType == ispec.MediaTypeImageManifest {
			_, ok := desc.Annotations[ispec.AnnotationRefName]
			if !ok {
				// check if is indeed an image and not an artifact by checking it's config blob
				buf, err := imgStore.GetBlobContent(repo, desc.Digest)
				if err != nil {
					imgStore.log.Error().Err(err).Str("repo", repo).Str("digest", desc.Digest.String()).
						Msg("gc: failed to read image manifest")

					return err
				}

				manifest := ispec.Manifest{}

				err = json.Unmarshal(buf, &manifest)
				if err != nil {
					return err
				}

				// skip manifests which are not of type image
				if manifest.Config.MediaType != ispec.MediaTypeImageConfig {
					imgStore.log.Info().Str("config mediaType", manifest.Config.MediaType).
						Msg("skipping gc untagged manifest, because config blob is not application/vnd.oci.image.config.v1+json")

					continue
				}

				// remove manifest if it's older than gc.delay
				canGC, err := isBlobOlderThan(imgStore, repo, desc.Digest, imgStore.gcDelay)
				if err != nil {
					imgStore.log.Error().Err(err).Str("repo", repo).Str("digest", desc.Digest.String()).
						Msgf("gc: failed to check if blob is older than %s", imgStore.gcDelay.String())

					return err
				}

				if canGC {
					imgStore.log.Info().Str("repo", repo).Str("digest", desc.Digest.String()).Msg("gc: removing manifest without tag")

					_, err = storage.RemoveManifestDescByReference(index, desc.Digest.String(), true)
					if errors.Is(err, zerr.ErrManifestConflict) {
						imgStore.log.Info().Str("repo", repo).Str("digest", desc.Digest.String()).
							Msg("gc: skipping removing manifest due to conflict")

						continue
					}

					err := oci.PutIndex(context.Background(), *index)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func gcCosignSignatures(imgStore *ImageStoreLocal, oci casext.Engine, index *ispec.Index, repo string,
	cosignDescriptors []ispec.Descriptor,
) error {
	for _, cosignDesc := range cosignDescriptors {
		foundSubject := false
		// check if we can find the manifest which the signature points to
		for _, desc := range index.Manifests {
			subject := fmt.Sprintf("sha256-%s.%s", desc.Digest.Encoded(), remote.SignatureTagSuffix)
			if subject == cosignDesc.Annotations[ispec.AnnotationRefName] {
				foundSubject = true
			}
		}

		if !foundSubject {
			// remove manifest
			imgStore.log.Info().Str("repo", repo).Str("digest", cosignDesc.Digest.String()).
				Msg("gc: removing cosign signature without subject")

			// no need to check for manifest conflict, if one doesn't have a subject, then none with same digest will have
			_, _ = storage.RemoveManifestDescByReference(index, cosignDesc.Digest.String(), false)

			err := oci.PutIndex(context.Background(), *index)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func gcNotationSignatures(imgStore *ImageStoreLocal, oci casext.Engine, index *ispec.Index, repo string,
	notationDescriptors []ispec.Descriptor,
) error {
	for _, notationDesc := range notationDescriptors {
		foundSubject := false
		// check if we can find the manifest which the signature points to
		artManifest, err := storage.GetOrasManifestByDigest(imgStore, repo, notationDesc.Digest, imgStore.log)
		if err != nil {
			imgStore.log.Error().Err(err).Str("repo", repo).Str("digest", notationDesc.Digest.String()).
				Msg("gc: failed to get oras artifact manifest")

			return err
		}

		// skip oras artifacts which are not signatures
		if artManifest.ArtifactType != notreg.ArtifactTypeNotation {
			continue
		}

		for _, desc := range index.Manifests {
			if desc.Digest == artManifest.Subject.Digest {
				foundSubject = true
			}
		}

		if !foundSubject {
			// remove manifest
			imgStore.log.Info().Str("repo", repo).Str("digest", notationDesc.Digest.String()).
				Msg("gc: removing notation signature without subject")

			// no need to check for manifest conflict, if one doesn't have a subject, then none with same digest will have
			_, _ = storage.RemoveManifestDescByReference(index, notationDesc.Digest.String(), false)

			err := oci.PutIndex(context.Background(), *index)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func ifOlderThan(imgStore *ImageStoreLocal, repo string, delay time.Duration) casext.GCPolicy {
	return func(ctx context.Context, digest godigest.Digest) (bool, error) {
		return isBlobOlderThan(imgStore, repo, digest, delay)
	}
}

func isBlobOlderThan(imgStore *ImageStoreLocal, repo string, digest godigest.Digest, delay time.Duration,
) (bool, error) {
	blobPath := imgStore.BlobPath(repo, digest)

	fileInfo, err := os.Stat(blobPath)
	if err != nil {
		imgStore.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", blobPath).
			Msg("gc: failed to stat blob")

		return false, err
	}

	if fileInfo.ModTime().Add(delay).After(time.Now()) {
		return false, nil
	}

	imgStore.log.Info().Str("digest", digest.String()).Str("blobPath", blobPath).Msg("perform GC on blob")

	return true, nil
}

func (is *ImageStoreLocal) gcRepo(repo string) error {
	dir := path.Join(is.RootDir(), repo)

	var lockLatency time.Time

	is.Lock(&lockLatency)
	err := is.garbageCollect(dir, repo)
	is.Unlock(&lockLatency)

	if err != nil {
		return err
	}

	return nil
}

func (is *ImageStoreLocal) RunGCRepo(repo string) error {
	is.log.Info().Msg(fmt.Sprintf("executing GC of orphaned blobs for %s", path.Join(is.RootDir(), repo)))

	if err := is.gcRepo(repo); err != nil {
		errMessage := fmt.Sprintf("error while running GC for %s", path.Join(is.RootDir(), repo))
		is.log.Error().Err(err).Msg(errMessage)
		is.log.Info().Msg(fmt.Sprintf("GC unsuccessfully completed for %s", path.Join(is.RootDir(), repo)))

		return err
	}

	is.log.Info().Msg(fmt.Sprintf("GC successfully completed for %s", path.Join(is.RootDir(), repo)))

	return nil
}

func (is *ImageStoreLocal) RunGCPeriodically(interval time.Duration, sch *scheduler.Scheduler) {
	generator := &taskGenerator{
		imgStore: is,
	}
	sch.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

type taskGenerator struct {
	imgStore *ImageStoreLocal
	lastRepo string
	done     bool
}

func (gen *taskGenerator) GenerateTask() (scheduler.Task, error) {
	repo, err := gen.imgStore.GetNextRepository(gen.lastRepo)

	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	if repo == "" {
		gen.done = true

		return nil, nil
	}

	gen.lastRepo = repo

	return newGCTask(gen.imgStore, repo), nil
}

func (gen *taskGenerator) IsDone() bool {
	return gen.done
}

func (gen *taskGenerator) Reset() {
	gen.lastRepo = ""
	gen.done = false
}

type gcTask struct {
	imgStore *ImageStoreLocal
	repo     string
}

func newGCTask(imgStore *ImageStoreLocal, repo string) *gcTask {
	return &gcTask{imgStore, repo}
}

func (gcT *gcTask) DoWork() error {
	return gcT.imgStore.RunGCRepo(gcT.repo)
}
