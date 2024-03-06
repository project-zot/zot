package imagestore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/docker/distribution/registry/storage/driver"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	syncConstants "zotregistry.dev/zot/pkg/extensions/sync/constants"
	zlog "zotregistry.dev/zot/pkg/log"
	zreg "zotregistry.dev/zot/pkg/regexp"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage/cache"
	common "zotregistry.dev/zot/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
	"zotregistry.dev/zot/pkg/test/inject"
)

const (
	cosignSignatureTagSuffix = "sig"
	SBOMTagSuffix            = "sbom"
)

// ImageStore provides the image storage operations.
type ImageStore struct {
	rootDir     string
	storeDriver storageTypes.Driver
	lock        *sync.RWMutex
	log         zlog.Logger
	metrics     monitoring.MetricServer
	cache       cache.Cache
	dedupe      bool
	linter      common.Lint
	commit      bool
}

func (is *ImageStore) Name() string {
	return is.storeDriver.Name()
}

func (is *ImageStore) RootDir() string {
	return is.rootDir
}

func (is *ImageStore) DirExists(d string) bool {
	return is.storeDriver.DirExists(d)
}

// NewImageStore returns a new image store backed by cloud storages.
// see https://github.com/docker/docker.github.io/tree/master/registry/storage-drivers
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, cacheDir string, dedupe, commit bool, log zlog.Logger,
	metrics monitoring.MetricServer, linter common.Lint, storeDriver storageTypes.Driver, cacheDriver cache.Cache,
) storageTypes.ImageStore {
	if err := storeDriver.EnsureDir(rootDir); err != nil {
		log.Error().Err(err).Str("rootDir", rootDir).Msg("failed to create root dir")

		return nil
	}

	imgStore := &ImageStore{
		rootDir:     rootDir,
		storeDriver: storeDriver,
		lock:        &sync.RWMutex{},
		log:         log,
		metrics:     metrics,
		dedupe:      dedupe,
		linter:      linter,
		commit:      commit,
		cache:       cacheDriver,
	}

	return imgStore
}

// RLock read-lock.
func (is *ImageStore) RLock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.RLock()
}

// RUnlock read-unlock.
func (is *ImageStore) RUnlock(lockStart *time.Time) {
	is.lock.RUnlock()

	lockEnd := time.Now()
	// includes time spent in acquiring and holding a lock
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RLOCK) // histogram
}

// Lock write-lock.
func (is *ImageStore) Lock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.Lock()
}

// Unlock write-unlock.
func (is *ImageStore) Unlock(lockStart *time.Time) {
	is.lock.Unlock()

	lockEnd := time.Now()
	// includes time spent in acquiring and holding a lock
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RWLOCK) // histogram
}

func (is *ImageStore) initRepo(name string) error {
	repoDir := path.Join(is.rootDir, name)

	if !utf8.ValidString(name) {
		is.log.Error().Msg("invalid UTF-8 input")

		return zerr.ErrInvalidRepositoryName
	}

	if !zreg.FullNameRegexp.MatchString(name) {
		is.log.Error().Str("repository", name).Msg("invalid repository name")

		return zerr.ErrInvalidRepositoryName
	}

	// create "blobs" subdir
	err := is.storeDriver.EnsureDir(path.Join(repoDir, "blobs"))
	if err != nil {
		is.log.Error().Err(err).Str("repository", name).Str("dir", repoDir).Msg("failed to create blobs subdir")

		return err
	}
	// create BlobUploadDir subdir
	err = is.storeDriver.EnsureDir(path.Join(repoDir, storageConstants.BlobUploadDir))
	if err != nil {
		is.log.Error().Err(err).Msg("failed to create blob upload subdir")

		return err
	}

	// "oci-layout" file - create if it doesn't exist
	ilPath := path.Join(repoDir, ispec.ImageLayoutFile)
	if _, err := is.storeDriver.Stat(ilPath); err != nil {
		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}

		buf, err := json.Marshal(il)
		if err != nil {
			is.log.Error().Err(err).Msg("failed to marshal JSON")

			return err
		}

		if _, err := is.storeDriver.WriteFile(ilPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("failed to write file")

			return err
		}
	}

	// "index.json" file - create if it doesn't exist
	indexPath := path.Join(repoDir, "index.json")
	if _, err := is.storeDriver.Stat(indexPath); err != nil {
		index := ispec.Index{}
		index.SchemaVersion = 2

		buf, err := json.Marshal(index)
		if err != nil {
			is.log.Error().Err(err).Msg("failed to marshal JSON")

			return err
		}

		if _, err := is.storeDriver.WriteFile(indexPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("failed to write file")

			return err
		}
	}

	return nil
}

// InitRepo creates an image repository under this store.
func (is *ImageStore) InitRepo(name string) error {
	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	return is.initRepo(name)
}

// ValidateRepo validates that the repository layout is complaint with the OCI repo layout.
func (is *ImageStore) ValidateRepo(name string) (bool, error) {
	if !zreg.FullNameRegexp.MatchString(name) {
		return false, zerr.ErrInvalidRepositoryName
	}

	// https://github.com/opencontainers/image-spec/blob/master/image-layout.md#content
	// at least, expect at least 3 entries - ["blobs", "oci-layout", "index.json"]
	// and an additional/optional BlobUploadDir in each image store
	// for s3 we can not create empty dirs, so we check only against index.json and oci-layout
	dir := path.Join(is.rootDir, name)
	if fi, err := is.storeDriver.Stat(dir); err != nil || !fi.IsDir() {
		return false, zerr.ErrRepoNotFound
	}

	files, err := is.storeDriver.List(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read directory")

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
		fileInfo, err := is.storeDriver.Stat(file)
		if err != nil {
			return false, err
		}

		filename, err := filepath.Rel(dir, file)
		if err != nil {
			return false, err
		}

		if filename == "blobs" && !fileInfo.IsDir() {
			return false, nil
		}

		found[filename] = true
	}

	// check blobs dir exists only for filesystem, in s3 we can't have empty dirs
	if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
		if !is.storeDriver.DirExists(path.Join(dir, "blobs")) {
			return false, nil
		}
	}

	for k, v := range found {
		if !v && k != storageConstants.BlobUploadDir {
			return false, nil
		}
	}

	buf, err := is.storeDriver.ReadFile(path.Join(dir, ispec.ImageLayoutFile))
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
func (is *ImageStore) GetRepositories() ([]string, error) {
	var lockLatency time.Time

	dir := is.rootDir

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	stores := make([]string, 0)

	err := is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		// skip .sync and .uploads dirs no need to try to validate them
		if strings.HasSuffix(fileInfo.Path(), syncConstants.SyncBlobUploadDir) ||
			strings.HasSuffix(fileInfo.Path(), storageConstants.BlobUploadDir) {
			return driver.ErrSkipDir
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil {
			return nil //nolint:nilerr // ignore paths that are not under root dir
		}

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

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
func (is *ImageStore) GetNextRepository(repo string) (string, error) {
	var lockLatency time.Time

	dir := is.rootDir

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	_, err := is.storeDriver.List(dir)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Debug().Msg("empty rootDir")

			return "", nil
		}

		is.log.Error().Err(err).Str("root-dir", dir).Msg("failed to walk storage root-dir")

		return "", err
	}

	found := false
	store := ""
	err = is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
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

	driverErr := &driver.Error{}

	// some s3 implementations (eg, digitalocean spaces) will return pathnotfounderror for walk but not list
	// therefore, we must also catch that error here.
	if errors.As(err, &driver.PathNotFoundError{}) {
		is.log.Debug().Msg("empty rootDir")

		return "", nil
	}

	if errors.Is(err, io.EOF) ||
		(errors.As(err, driverErr) && errors.Is(driverErr.Enclosed, io.EOF)) {
		return store, nil
	}

	return store, err
}

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ImageStore) GetImageTags(repo string) ([]string, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if fi, err := is.storeDriver.Stat(dir); err != nil || !fi.IsDir() {
		return nil, zerr.ErrRepoNotFound
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	index, err := common.GetIndex(is, repo, is.log)
	if err != nil {
		return nil, err
	}

	return common.GetTagsByIndex(index), nil
}

// GetImageManifest returns the image manifest of an image in the specific repository.
func (is *ImageStore) GetImageManifest(repo, reference string) ([]byte, godigest.Digest, string, error) {
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.storeDriver.Stat(dir); err != nil || !fi.IsDir() {
		return nil, "", "", zerr.ErrRepoNotFound
	}

	var lockLatency time.Time

	var err error

	is.RLock(&lockLatency)
	defer func() {
		is.RUnlock(&lockLatency)

		if err == nil {
			monitoring.IncDownloadCounter(is.metrics, repo)
		}
	}()

	index, err := common.GetIndex(is, repo, is.log)
	if err != nil {
		return nil, "", "", err
	}

	manifestDesc, found := common.GetManifestDescByReference(index, reference)
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

	return buf, manifestDesc.Digest, manifestDesc.MediaType, nil
}

// PutImageManifest adds an image manifest to the repository.
func (is *ImageStore) PutImageManifest(repo, reference, mediaType string, //nolint: gocyclo
	body []byte,
) (godigest.Digest, godigest.Digest, error) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")

		return "", "", err
	}

	var lockLatency time.Time

	var err error

	is.Lock(&lockLatency)
	defer func() {
		is.Unlock(&lockLatency)

		if err == nil {
			if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
				monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
			}

			monitoring.IncUploadCounter(is.metrics, repo)
		}
	}()

	refIsDigest := true

	mDigest, err := common.GetAndValidateRequestDigest(body, reference, is.log)
	if err != nil {
		if errors.Is(err, zerr.ErrBadManifest) {
			return mDigest, "", err
		}

		refIsDigest = false
	}

	dig, err := common.ValidateManifest(is, repo, reference, mediaType, body, is.log)
	if err != nil {
		return dig, "", err
	}

	index, err := common.GetIndex(is, repo, is.log)
	if err != nil {
		return "", "", err
	}

	// create a new descriptor
	desc := ispec.Descriptor{
		MediaType: mediaType, Size: int64(len(body)), Digest: mDigest,
	}

	if !refIsDigest {
		desc.Annotations = map[string]string{ispec.AnnotationRefName: reference}
	}

	var subjectDigest godigest.Digest

	artifactType := ""

	if mediaType == ispec.MediaTypeImageManifest {
		var manifest ispec.Manifest

		err := json.Unmarshal(body, &manifest)
		if err != nil {
			return "", "", err
		}

		if manifest.Subject != nil {
			subjectDigest = manifest.Subject.Digest
		}

		artifactType = zcommon.GetManifestArtifactType(manifest)
	} else if mediaType == ispec.MediaTypeImageIndex {
		var index ispec.Index

		err := json.Unmarshal(body, &index)
		if err != nil {
			return "", "", err
		}

		if index.Subject != nil {
			subjectDigest = index.Subject.Digest
		}

		artifactType = zcommon.GetIndexArtifactType(index)
	}

	updateIndex, oldDgst, err := common.CheckIfIndexNeedsUpdate(&index, &desc, is.log)
	if err != nil {
		return "", "", err
	}

	if !updateIndex {
		return desc.Digest, subjectDigest, nil
	}

	// write manifest to "blobs"
	dir := path.Join(is.rootDir, repo, "blobs", mDigest.Algorithm().String())
	manifestPath := path.Join(dir, mDigest.Encoded())

	if _, err = is.storeDriver.WriteFile(manifestPath, body); err != nil {
		is.log.Error().Err(err).Str("file", manifestPath).Msg("failed to write")

		return "", "", err
	}

	err = common.UpdateIndexWithPrunedImageManifests(is, &index, repo, desc, oldDgst, is.log)
	if err != nil {
		return "", "", err
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)

	// update the descriptors artifact type in order to check for signatures when applying the linter
	desc.ArtifactType = artifactType

	// apply linter only on images, not signatures
	pass, err := common.ApplyLinter(is, is.linter, repo, desc)
	if !pass {
		is.log.Error().Err(err).Str("repository", repo).Str("reference", reference).
			Msg("linter didn't pass")

		return "", "", err
	}

	if err := is.PutIndexContent(repo, index); err != nil {
		return "", "", err
	}

	return desc.Digest, subjectDigest, nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ImageStore) DeleteImageManifest(repo, reference string, detectCollisions bool) error {
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.storeDriver.Stat(dir); err != nil || !fi.IsDir() {
		return zerr.ErrRepoNotFound
	}

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	err := is.deleteImageManifest(repo, reference, detectCollisions)
	if err != nil {
		return err
	}

	return nil
}

func (is *ImageStore) deleteImageManifest(repo, reference string, detectCollisions bool) error {
	defer func() {
		if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
			monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
		}
	}()

	index, err := common.GetIndex(is, repo, is.log)
	if err != nil {
		return err
	}

	manifestDesc, err := common.RemoveManifestDescByReference(&index, reference, detectCollisions)
	if err != nil {
		return err
	}

	/* check if manifest is referenced in image indexes, do not allow index images manipulations
	(ie. remove manifest being part of an image index)	*/
	if manifestDesc.MediaType == ispec.MediaTypeImageManifest {
		for _, mDesc := range index.Manifests {
			if mDesc.MediaType == ispec.MediaTypeImageIndex {
				if ok, _ := common.IsBlobReferencedInImageIndex(is, repo, manifestDesc.Digest, ispec.Index{
					Manifests: []ispec.Descriptor{mDesc},
				}, is.log); ok {
					return zerr.ErrManifestReferenced
				}
			}
		}
	}

	err = common.UpdateIndexWithPrunedImageManifests(is, &index, repo, manifestDesc, manifestDesc.Digest, is.log)
	if err != nil {
		return err
	}

	// now update "index.json"
	dir := path.Join(is.rootDir, repo)
	file := path.Join(dir, "index.json")

	buf, err := json.Marshal(index)
	if err != nil {
		return err
	}

	if _, err := is.storeDriver.WriteFile(file, buf); err != nil {
		is.log.Debug().Str("reference", reference).Str("repository", repo).Msg("failed to update index.json")

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

		err = is.storeDriver.Delete(p)
		if err != nil {
			return err
		}
	}

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ImageStore) BlobUploadPath(repo, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, storageConstants.BlobUploadDir, uuid)

	return blobUploadPath
}

// NewBlobUpload returns the unique ID for an upload in progress.
func (is *ImageStore) NewBlobUpload(repo string) (string, error) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Error().Err(err).Msg("failed to initialize repo")

		return "", err
	}

	uuid, err := guuid.NewV4()
	if err != nil {
		return "", err
	}

	uid := uuid.String()

	blobUploadPath := is.BlobUploadPath(repo, uid)

	// create multipart upload (append false)
	writer, err := is.storeDriver.Writer(blobUploadPath, false)
	if err != nil {
		is.log.Debug().Err(err).Str("blob", blobUploadPath).Msg("failed to start multipart writer")

		return "", zerr.ErrRepoNotFound
	}

	defer writer.Close()

	return uid, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ImageStore) GetBlobUpload(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	if !utf8.ValidString(blobUploadPath) {
		is.log.Error().Msg("invalid UTF-8 input")

		return -1, zerr.ErrInvalidRepositoryName
	}

	writer, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		return -1, err
	}

	defer writer.Close()

	return writer.Size(), nil
}

// PutBlobChunkStreamed appends another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	file, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		is.log.Error().Err(err).Msg("failed to continue multipart upload")

		return -1, err
	}

	var n int64 //nolint: varnamelen

	defer func() {
		err = file.Close()
	}()

	n, err = io.Copy(file, body)

	return n, err
}

// PutBlobChunk writes another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunk(repo, uuid string, from, to int64,
	body io.Reader,
) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	file, err := is.storeDriver.Writer(blobUploadPath, true)
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

	n, err := io.Copy(file, body)

	return n, err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ImageStore) BlobUploadInfo(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	writer, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		return -1, err
	}

	defer writer.Close()

	return writer.Size(), nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ImageStore) FinishBlobUpload(repo, uuid string, body io.Reader, dstDigest godigest.Digest) error {
	if err := dstDigest.Validate(); err != nil {
		return err
	}

	src := is.BlobUploadPath(repo, uuid)

	// complete multiUploadPart
	fileWriter, err := is.storeDriver.Writer(src, true)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return zerr.ErrUploadNotFound
	}

	if err := fileWriter.Commit(); err != nil {
		is.log.Error().Err(err).Msg("failed to commit file")

		return err
	}

	if err := fileWriter.Close(); err != nil {
		is.log.Error().Err(err).Msg("failed to close file")

		return err
	}

	srcDigest, err := getBlobDigest(is, src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return err
	}

	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return zerr.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())

	err = is.storeDriver.EnsureDir(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to create dir")

		return err
	}

	dst := is.BlobPath(repo, dstDigest)

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		err = is.DedupeBlob(src, dstDigest, repo, dst)
		if err := inject.Error(err); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to dedupe blob")

			return err
		}
	} else {
		if err := is.storeDriver.Move(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to finish blob")

			return err
		}
	}

	return nil
}

// FullBlobUpload handles a full blob upload, and no partial session is created.
func (is *ImageStore) FullBlobUpload(repo string, body io.Reader, dstDigest godigest.Digest) (string, int64, error) {
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

	blobFile, err := is.storeDriver.Writer(src, false)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return "", -1, zerr.ErrUploadNotFound
	}

	defer blobFile.Close()

	mw := io.MultiWriter(blobFile, digester)

	nbytes, err := io.Copy(mw, body)
	if err != nil {
		return "", -1, err
	}

	if err := blobFile.Commit(); err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to commit blob")

		return "", -1, err
	}

	srcDigest := godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil)))
	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return "", -1, zerr.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())
	_ = is.storeDriver.EnsureDir(dir)

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		if err := is.DedupeBlob(src, dstDigest, repo, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to dedupe blob")

			return "", -1, err
		}
	} else {
		if err := is.storeDriver.Move(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to finish blob")

			return "", -1, err
		}
	}

	return uuid, nbytes, nil
}

func (is *ImageStore) DedupeBlob(src string, dstDigest godigest.Digest, dstRepo string, dst string) error {
retry:
	is.log.Debug().Str("src", src).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe begin")

	dstRecord, err := is.cache.GetBlob(dstDigest)
	if err := inject.Error(err); err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		is.log.Error().Err(err).Str("blobPath", dst).Str("component", "dedupe").Msg("failed to lookup blob record")

		return err
	}

	if dstRecord == "" {
		// cache record doesn't exist, so first disk and cache entry for this digest
		if err := is.cache.PutBlob(dstDigest, dst); err != nil {
			is.log.Error().Err(err).Str("blobPath", dst).Str("component", "dedupe").
				Msg("failed to insert blob record")

			return err
		}

		// move the blob from uploads to final dest
		if err := is.storeDriver.Move(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dst", dst).Str("component", "dedupe").
				Msg("failed to rename blob")

			return err
		}

		is.log.Debug().Str("src", src).Str("dst", dst).Str("component", "dedupe").Msg("rename")
	} else {
		// cache record exists, but due to GC and upgrades from older versions,
		// disk content and cache records may go out of sync
		if is.cache.UsesRelativePaths() {
			dstRecord = path.Join(is.rootDir, dstRecord)
		}

		blobInfo, err := is.storeDriver.Stat(dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Str("component", "dedupe").Msg("failed to stat")
			// the actual blob on disk may have been removed by GC, so sync the cache
			err := is.cache.DeleteBlob(dstDigest, dstRecord)
			if err = inject.Error(err); err != nil {
				//nolint:lll
				is.log.Error().Err(err).Str("dstDigest", dstDigest.String()).Str("dst", dst).
					Str("component", "dedupe").Msg("failed to delete blob record")

				return err
			}

			goto retry
		}

		// prevent overwrite original blob
		if !is.storeDriver.SameFile(dst, dstRecord) {
			if err := is.storeDriver.Link(dstRecord, dst); err != nil {
				is.log.Error().Err(err).Str("blobPath", dstRecord).Str("component", "dedupe").
					Msg("failed to link blobs")

				return err
			}

			if err := is.cache.PutBlob(dstDigest, dst); err != nil {
				is.log.Error().Err(err).Str("blobPath", dst).Str("component", "dedupe").
					Msg("failed to insert blob record")

				return err
			}
		} else {
			// if it's same file then it was already uploaded, check if blob is corrupted
			if desc, err := common.GetBlobDescriptorFromRepo(is, dstRepo, dstDigest, is.log); err == nil {
				// blob corrupted, replace content
				if desc.Size != blobInfo.Size() {
					if err := is.storeDriver.Move(src, dst); err != nil {
						is.log.Error().Err(err).Str("src", src).Str("dst", dst).Str("component", "dedupe").
							Msg("failed to rename blob")

						return err
					}

					is.log.Debug().Str("src", src).Str("component", "dedupe").Msg("remove")

					return nil
				}
			}
		}

		// remove temp blobupload
		if err := is.storeDriver.Delete(src); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("component", "dedupe").
				Msg("failed to remove blob")

			return err
		}

		is.log.Debug().Str("src", src).Str("component", "dedupe").Msg("remove")
	}

	return nil
}

// DeleteBlobUpload deletes an existing blob upload that is currently in progress.
func (is *ImageStore) DeleteBlobUpload(repo, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	writer, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return zerr.ErrUploadNotFound
		}

		return err
	}

	defer writer.Close()

	if err := writer.Cancel(); err != nil {
		is.log.Error().Err(err).Str("blobUploadPath", blobUploadPath).Msg("failed to delete blob upload")

		return err
	}

	return nil
}

// BlobPath returns the repository path of a blob.
func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
	return path.Join(is.rootDir, repo, "blobs", digest.Algorithm().String(), digest.Encoded())
}

/*
	CheckBlob verifies a blob and returns true if the blob is correct

If the blob is not found but it's found in cache then it will be copied over.
*/
func (is *ImageStore) CheckBlob(repo string, digest godigest.Digest) (bool, int64, error) {
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

	binfo, err := is.storeDriver.Stat(blobPath)
	if err == nil && binfo.Size() > 0 {
		// try to find blob size in blob descriptors, if blob can not be found
		desc, err := common.GetBlobDescriptorFromRepo(is, repo, digest, is.log)
		if err != nil || desc.Size == binfo.Size() {
			// blob not found in descriptors, can not compare, just return
			is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

			return true, binfo.Size(), nil //nolint: nilerr
		}

		if desc.Size != binfo.Size() {
			is.log.Debug().Str("blob path", blobPath).Msg("blob path found, but it's corrupted")

			return false, -1, zerr.ErrBlobNotFound
		}
	}
	// otherwise is a 'deduped' blob (empty file)

	// Check blobs in cache
	dstRecord, err := is.checkCacheBlob(digest)
	if err != nil {
		is.log.Warn().Err(err).Str("digest", digest.String()).Msg("not found in cache")

		return false, -1, zerr.ErrBlobNotFound
	}

	blobSize, err := is.copyBlob(repo, blobPath, dstRecord)
	if err != nil {
		return false, -1, zerr.ErrBlobNotFound
	}

	// put deduped blob in cache
	if err := is.cache.PutBlob(digest, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Str("component", "dedupe").Msg("failed to insert blob record")

		return false, -1, err
	}

	return true, blobSize, nil
}

// StatBlob verifies if a blob is present inside a repository. The caller function MUST lock from outside.
func (is *ImageStore) StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	if err := digest.Validate(); err != nil {
		return false, -1, time.Time{}, err
	}

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return false, -1, time.Time{}, err
	}

	return true, binfo.Size(), binfo.ModTime(), nil
}

func (is *ImageStore) checkCacheBlob(digest godigest.Digest) (string, error) {
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

	if is.cache.UsesRelativePaths() {
		dstRecord = path.Join(is.rootDir, dstRecord)
	}

	if _, err := is.storeDriver.Stat(dstRecord); err != nil {
		is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

		// the actual blob on disk may have been removed by GC, so sync the cache
		if err := is.cache.DeleteBlob(digest, dstRecord); err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", dstRecord).
				Msg("failed to remove blob path from cache")

			return "", err
		}

		return "", zerr.ErrBlobNotFound
	}

	is.log.Debug().Str("digest", digest.String()).Str("dstRecord", dstRecord).Str("component", "cache").
		Msg("found dedupe record")

	return dstRecord, nil
}

func (is *ImageStore) copyBlob(repo string, blobPath, dstRecord string) (int64, error) {
	if err := is.initRepo(repo); err != nil {
		is.log.Error().Err(err).Str("repository", repo).Msg("failed to initialize an empty repo")

		return -1, err
	}

	_ = is.storeDriver.EnsureDir(filepath.Dir(blobPath))

	if err := is.storeDriver.Link(dstRecord, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Str("link", dstRecord).Str("component", "dedupe").
			Msg("failed to hard link")

		return -1, zerr.ErrBlobNotFound
	}

	// return original blob with content instead of the deduped one (blobPath)
	binfo, err := is.storeDriver.Stat(dstRecord)
	if err == nil {
		return binfo.Size(), nil
	}

	return -1, zerr.ErrBlobNotFound
}

// GetBlobPartial returns a partial stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ImageStore) GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
) (io.ReadCloser, int64, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return nil, -1, -1, err
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return nil, -1, -1, err
	}

	end := to

	if to < 0 || to >= binfo.Size() {
		end = binfo.Size() - 1
	}

	blobHandle, err := is.storeDriver.Reader(binfo.Path(), from)
	if err != nil {
		is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob")

		return nil, -1, -1, err
	}

	blobReadCloser, err := newBlobStream(blobHandle, from, end)
	if err != nil {
		is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob stream")

		return nil, -1, -1, err
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, end - from + 1, binfo.Size(), nil
}

/*
	In the case of s3(which doesn't support links) we link them in our cache by
	keeping a reference to the original blob and its duplicates

On the storage, original blobs are those with contents, and duplicates one are just empty files.
This function helps handling this situation, by using this one you can make sure you always get the original blob.
*/
func (is *ImageStore) originalBlobInfo(repo string, digest godigest.Digest) (driver.FileInfo, error) {
	blobPath := is.BlobPath(repo, digest)

	binfo, err := is.storeDriver.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return nil, zerr.ErrBlobNotFound
	}

	if binfo.Size() == 0 {
		dstRecord, err := is.checkCacheBlob(digest)
		if err != nil {
			is.log.Debug().Err(err).Str("digest", digest.String()).Msg("not found in cache")

			return nil, zerr.ErrBlobNotFound
		}

		binfo, err = is.storeDriver.Stat(dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

			return nil, zerr.ErrBlobNotFound
		}
	}

	return binfo, nil
}

// GetBlob returns a stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ImageStore) GetBlob(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return nil, -1, err
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return nil, -1, err
	}

	blobReadCloser, err := is.storeDriver.Reader(binfo.Path(), 0)
	if err != nil {
		is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob")

		return nil, -1, err
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, binfo.Size(), nil
}

// GetBlobContent returns blob contents, the caller function MUST lock from outside.
// Should be used for small files(manifests/config blobs).
func (is *ImageStore) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	if err := digest.Validate(); err != nil {
		return []byte{}, err
	}

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return nil, err
	}

	blobBuf, err := is.storeDriver.ReadFile(binfo.Path())
	if err != nil {
		is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob")

		return nil, err
	}

	return blobBuf, nil
}

// VerifyBlobDigestValue verifies that the blob which is addressed by given digest has a equivalent computed digest.
func (is *ImageStore) VerifyBlobDigestValue(repo string, digest godigest.Digest) error {
	if err := digest.Validate(); err != nil {
		return err
	}

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return err
	}

	blobReadCloser, err := is.storeDriver.Reader(binfo.Path(), 0)
	if err != nil {
		return err
	}

	defer blobReadCloser.Close()

	// compute its real digest
	computedDigest, err := godigest.FromReader(blobReadCloser)
	if err != nil {
		return err
	}

	// if the computed digest is different than the blob name(its initial digest) then the blob has been corrupted.
	if computedDigest != digest {
		return zerr.ErrBadBlobDigest
	}

	return nil
}

func (is *ImageStore) GetReferrers(repo string, gdigest godigest.Digest, artifactTypes []string,
) (ispec.Index, error) {
	var lockLatency time.Time

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	return common.GetReferrers(is, repo, gdigest, artifactTypes, is.log)
}

// GetIndexContent returns index.json contents, the caller function MUST lock from outside.
func (is *ImageStore) GetIndexContent(repo string) ([]byte, error) {
	dir := path.Join(is.rootDir, repo)

	buf, err := is.storeDriver.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		if errors.Is(err, driver.PathNotFoundError{}) {
			is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

			return []byte{}, zerr.ErrRepoNotFound
		}

		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return []byte{}, err
	}

	return buf, nil
}

func (is *ImageStore) StatIndex(repo string) (bool, int64, time.Time, error) {
	repoIndexPath := path.Join(is.rootDir, repo, "index.json")

	fileInfo, err := is.storeDriver.Stat(repoIndexPath)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Error().Err(err).Str("indexFile", repoIndexPath).Msg("failed to stat index.json")

			return false, 0, time.Time{}, zerr.ErrRepoNotFound
		}

		is.log.Error().Err(err).Str("indexFile", repoIndexPath).Msg("failed to read index.json")

		return false, 0, time.Time{}, err
	}

	return true, fileInfo.Size(), fileInfo.ModTime(), nil
}

func (is *ImageStore) PutIndexContent(repo string, index ispec.Index) error {
	dir := path.Join(is.rootDir, repo)

	indexPath := path.Join(dir, "index.json")

	buf, err := json.Marshal(index)
	if err != nil {
		is.log.Error().Err(err).Str("file", indexPath).Msg("failed to marshal JSON")

		return err
	}

	if _, err = is.storeDriver.WriteFile(indexPath, buf); err != nil {
		is.log.Error().Err(err).Str("file", indexPath).Msg("failed to write")

		return err
	}

	return nil
}

// DeleteBlob removes the blob from the repository.
func (is *ImageStore) DeleteBlob(repo string, digest godigest.Digest) error {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return err
	}

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	return is.deleteBlob(repo, digest)
}

/*
CleanupRepo removes blobs from the repository and removes repo if flag is true and all blobs were removed
the caller function MUST lock from outside.
*/
func (is *ImageStore) CleanupRepo(repo string, blobs []godigest.Digest, removeRepo bool) (int, error) {
	count := 0

	for _, digest := range blobs {
		is.log.Debug().Str("repository", repo).
			Str("digest", digest.String()).Msg("perform GC on blob")

		if err := is.deleteBlob(repo, digest); err != nil {
			if errors.Is(err, zerr.ErrBlobReferenced) {
				if err := is.deleteImageManifest(repo, digest.String(), true); err != nil {
					if errors.Is(err, zerr.ErrManifestConflict) || errors.Is(err, zerr.ErrManifestReferenced) {
						continue
					}

					is.log.Error().Err(err).Str("repository", repo).Str("digest", digest.String()).Msg("failed to delete manifest")

					return count, err
				}

				count++
			} else {
				is.log.Error().Err(err).Str("repository", repo).Str("digest", digest.String()).Msg("failed to delete blob")

				return count, err
			}
		} else {
			count++
		}
	}

	blobUploads, err := is.storeDriver.List(path.Join(is.RootDir(), repo, storageConstants.BlobUploadDir))
	if err != nil {
		is.log.Debug().Str("repository", repo).Msg("failed to list .uploads/ dir")
	}

	// if removeRepo flag is true and we cleanup all blobs and there are no blobs currently being uploaded.
	if removeRepo && count == len(blobs) && count > 0 && len(blobUploads) == 0 {
		is.log.Info().Str("repository", repo).Msg("removed all blobs, removing repo")

		if err := is.storeDriver.Delete(path.Join(is.rootDir, repo)); err != nil {
			is.log.Error().Err(err).Str("repository", repo).Msg("failed to remove repo")

			return count, err
		}
	}

	return count, nil
}

func (is *ImageStore) deleteBlob(repo string, digest godigest.Digest) error {
	blobPath := is.BlobPath(repo, digest)

	_, err := is.storeDriver.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return zerr.ErrBlobNotFound
	}

	// first check if this blob is not currently in use
	if ok, _ := common.IsBlobReferenced(is, repo, digest, is.log); ok {
		return zerr.ErrBlobReferenced
	}

	if fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		dstRecord, err := is.cache.GetBlob(digest)
		if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Str("component", "dedupe").
				Msg("failed to lookup blob record")

			return err
		}

		// remove cache entry and move blob contents to the next candidate if there is any
		if ok := is.cache.HasBlob(digest, blobPath); ok {
			if err := is.cache.DeleteBlob(digest, blobPath); err != nil {
				is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", blobPath).
					Msg("failed to remove blob path from cache")

				return err
			}
		}

		// if the deleted blob is one with content
		if dstRecord == blobPath {
			// get next candidate
			dstRecord, err := is.cache.GetBlob(digest)
			if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
				is.log.Error().Err(err).Str("blobPath", dstRecord).Str("component", "dedupe").
					Msg("failed to lookup blob record")

				return err
			}

			// if we have a new candidate move the blob content to it
			if dstRecord != "" {
				/* check to see if we need to move the content from original blob to duplicate one
				(in case of filesystem, this should not be needed */
				binfo, err := is.storeDriver.Stat(dstRecord)
				if err != nil {
					is.log.Error().Err(err).Str("path", blobPath).Str("component", "dedupe").
						Msg("failed to stat blob")

					return err
				}

				if binfo.Size() == 0 {
					if err := is.storeDriver.Move(blobPath, dstRecord); err != nil {
						is.log.Error().Err(err).Str("blobPath", blobPath).Str("component", "dedupe").
							Msg("failed to remove blob path")

						return err
					}
				}

				return nil
			}
		}
	}

	if err := is.storeDriver.Delete(blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("failed to remove blob path")

		return err
	}

	return nil
}

func getBlobDigest(imgStore *ImageStore, path string) (godigest.Digest, error) {
	fileReader, err := imgStore.storeDriver.Reader(path, 0)
	if err != nil {
		return "", zerr.ErrUploadNotFound
	}

	defer fileReader.Close()

	digest, err := godigest.FromReader(fileReader)
	if err != nil {
		return "", zerr.ErrBadBlobDigest
	}

	return digest, nil
}

func (is *ImageStore) GetAllBlobs(repo string) ([]string, error) {
	dir := path.Join(is.rootDir, repo, "blobs", "sha256")

	files, err := is.storeDriver.List(dir)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Debug().Msg("empty rootDir")

			return []string{}, nil
		}

		return []string{}, err
	}

	ret := []string{}

	for _, file := range files {
		ret = append(ret, filepath.Base(file))
	}

	return ret, nil
}

func (is *ImageStore) GetNextDigestWithBlobPaths(repos []string, lastDigests []godigest.Digest,
) (godigest.Digest, []string, error) {
	var lockLatency time.Time

	dir := is.rootDir

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	var duplicateBlobs []string

	var digest godigest.Digest

	err := is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		// skip blobs under .sync and .uploads
		if strings.HasSuffix(fileInfo.Path(), syncConstants.SyncBlobUploadDir) ||
			strings.HasSuffix(fileInfo.Path(), storageConstants.BlobUploadDir) {
			return driver.ErrSkipDir
		}

		if fileInfo.IsDir() {
			// skip repositories not found in repos
			repo := path.Base(fileInfo.Path())

			if !zcommon.Contains(repos, repo) && repo != "blobs" && repo != "sha256" {
				return driver.ErrSkipDir
			}
		}

		blobDigest := godigest.NewDigestFromEncoded("sha256", path.Base(fileInfo.Path()))
		if err := blobDigest.Validate(); err != nil { //nolint: nilerr
			return nil //nolint: nilerr // ignore files which are not blobs
		}

		if digest == "" && !zcommon.Contains(lastDigests, blobDigest) {
			digest = blobDigest
		}

		if blobDigest == digest {
			duplicateBlobs = append(duplicateBlobs, fileInfo.Path())
		}

		return nil
	})

	// if the root directory is not yet created
	var perr driver.PathNotFoundError

	if errors.As(err, &perr) {
		return digest, duplicateBlobs, nil
	}

	return digest, duplicateBlobs, err
}

func (is *ImageStore) getOriginalBlobFromDisk(duplicateBlobs []string) (string, error) {
	for _, blobPath := range duplicateBlobs {
		binfo, err := is.storeDriver.Stat(blobPath)
		if err != nil {
			is.log.Error().Err(err).Str("path", blobPath).Str("component", "storage").Msg("failed to stat blob")

			return "", zerr.ErrBlobNotFound
		}

		if binfo.Size() > 0 {
			return blobPath, nil
		}
	}

	return "", zerr.ErrBlobNotFound
}

func (is *ImageStore) getOriginalBlob(digest godigest.Digest, duplicateBlobs []string) (string, error) {
	var originalBlob string

	var err error

	originalBlob, err = is.checkCacheBlob(digest)
	if err != nil && !errors.Is(err, zerr.ErrBlobNotFound) && !errors.Is(err, zerr.ErrCacheMiss) {
		is.log.Error().Err(err).Str("component", "dedupe").Msg("failed to find blob in cache")

		return originalBlob, err
	}

	// if we still don't have, search it
	if originalBlob == "" {
		is.log.Warn().Str("component", "dedupe").Msg("failed to find blob in cache, searching it in storage...")
		// a rebuild dedupe was attempted in the past
		// get original blob, should be found otherwise exit with error

		originalBlob, err = is.getOriginalBlobFromDisk(duplicateBlobs)
		if err != nil {
			return originalBlob, err
		}
	}

	is.log.Info().Str("originalBlob", originalBlob).Str("component", "dedupe").Msg("found original blob")

	return originalBlob, nil
}

func (is *ImageStore) dedupeBlobs(ctx context.Context, digest godigest.Digest, duplicateBlobs []string) error {
	if fmt.Sprintf("%v", is.cache) == fmt.Sprintf("%v", nil) {
		is.log.Error().Err(zerr.ErrDedupeRebuild).Msg("failed to dedupe blobs, no cache driver found")

		return zerr.ErrDedupeRebuild
	}

	is.log.Info().Str("digest", digest.String()).Str("component", "dedupe").Msg("deduping blobs for digest")

	var originalBlob string

	// rebuild from dedupe false to true
	for _, blobPath := range duplicateBlobs {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		binfo, err := is.storeDriver.Stat(blobPath)
		if err != nil {
			is.log.Error().Err(err).Str("path", blobPath).Str("component", "dedupe").Msg("failed to stat blob")

			return err
		}

		if binfo.Size() == 0 {
			is.log.Warn().Str("component", "dedupe").Msg("found file without content, trying to find the original blob")
			// a rebuild dedupe was attempted in the past
			// get original blob, should be found otherwise exit with error
			if originalBlob == "" {
				originalBlob, err = is.getOriginalBlob(digest, duplicateBlobs)
				if err != nil {
					is.log.Error().Err(err).Str("component", "dedupe").Msg("failed to find original blob")

					return zerr.ErrDedupeRebuild
				}

				// cache original blob
				if ok := is.cache.HasBlob(digest, originalBlob); !ok {
					if err := is.cache.PutBlob(digest, originalBlob); err != nil {
						return err
					}
				}
			}

			// cache dedupe blob
			if ok := is.cache.HasBlob(digest, blobPath); !ok {
				if err := is.cache.PutBlob(digest, blobPath); err != nil {
					return err
				}
			}
		} else {
			// if we have an original blob cached then we can safely dedupe the rest of them
			if originalBlob != "" {
				if err := is.storeDriver.Link(originalBlob, blobPath); err != nil {
					is.log.Error().Err(err).Str("path", blobPath).Str("component", "dedupe").Msg("failed to dedupe blob")

					return err
				}
			}

			// cache it
			if ok := is.cache.HasBlob(digest, blobPath); !ok {
				if err := is.cache.PutBlob(digest, blobPath); err != nil {
					return err
				}
			}

			// mark blob as preserved
			originalBlob = blobPath
		}
	}

	is.log.Info().Str("digest", digest.String()).Str("component", "dedupe").
		Msg("deduping blobs for digest finished successfully")

	return nil
}

func (is *ImageStore) restoreDedupedBlobs(ctx context.Context, digest godigest.Digest, duplicateBlobs []string) error {
	is.log.Info().Str("digest", digest.String()).Str("component", "dedupe").Msg("restoring deduped blobs for digest")

	// first we need to find the original blob, either in cache or by checking each blob size
	originalBlob, err := is.getOriginalBlob(digest, duplicateBlobs)
	if err != nil {
		is.log.Error().Err(err).Str("component", "dedupe").Msg("failed to find original blob")

		return zerr.ErrDedupeRebuild
	}

	for _, blobPath := range duplicateBlobs {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		binfo, err := is.storeDriver.Stat(blobPath)
		if err != nil {
			is.log.Error().Err(err).Str("path", blobPath).Str("component", "dedupe").Msg("failed to stat blob")

			return err
		}

		// if we find a deduped blob, then copy original blob content to deduped one
		if binfo.Size() == 0 {
			// move content from original blob to deduped one
			buf, err := is.storeDriver.ReadFile(originalBlob)
			if err != nil {
				is.log.Error().Err(err).Str("path", originalBlob).Str("component", "dedupe").
					Msg("failed to get original blob content")

				return err
			}

			_, err = is.storeDriver.WriteFile(blobPath, buf)
			if err != nil {
				return err
			}
		}
	}

	is.log.Info().Str("digest", digest.String()).
		Str("component", "dedupe").Msg("restoring deduped blobs for digest finished successfully")

	return nil
}

func (is *ImageStore) RunDedupeForDigest(ctx context.Context, digest godigest.Digest, dedupe bool,
	duplicateBlobs []string,
) error {
	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	if dedupe {
		return is.dedupeBlobs(ctx, digest, duplicateBlobs)
	}

	return is.restoreDedupedBlobs(ctx, digest, duplicateBlobs)
}

func (is *ImageStore) RunDedupeBlobs(interval time.Duration, sch *scheduler.Scheduler) {
	generator := &common.DedupeTaskGenerator{
		ImgStore: is,
		Dedupe:   is.dedupe,
		Log:      is.log,
	}

	sch.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

func (is *ImageStore) PopulateStorageMetrics(interval time.Duration, sch *scheduler.Scheduler) {
	generator := &common.StorageMetricsInitGenerator{
		ImgStore: is,
		Metrics:  is.metrics,
		Log:      is.log,
		MaxDelay: 15, //nolint:gomnd
	}

	sch.SubmitGenerator(generator, interval, scheduler.HighPriority)
}

type blobStream struct {
	reader io.Reader
	closer io.Closer
}

func newBlobStream(readCloser io.ReadCloser, from, to int64) (io.ReadCloser, error) {
	if from < 0 || to < from {
		return nil, zerr.ErrBadRange
	}

	return &blobStream{reader: io.LimitReader(readCloser, to-from+1), closer: readCloser}, nil
}

func (bs *blobStream) Read(buf []byte) (int, error) {
	return bs.reader.Read(buf)
}

func (bs *blobStream) Close() error {
	return bs.closer.Close()
}
