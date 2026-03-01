package imagestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/inject"
)

const (
	cosignSignatureTagSuffix = "sig"
	SBOMTagSuffix            = "sbom"
)

// ImageStore provides the image storage operations.
type ImageStore struct {
	rootDir          string
	storeDriver      storageTypes.Driver
	lock             *sync.RWMutex
	log              zlog.Logger
	metrics          monitoring.MetricServer
	events           events.Recorder
	cache            storageTypes.Cache
	dedupe           bool
	linter           common.Lint
	commit           bool
	compat           []compat.MediaCompatibility
	emptyDigestCache *zcommon.EmptyDigestCache
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
	metrics monitoring.MetricServer, linter common.Lint, storeDriver storageTypes.Driver,
	cacheDriver storageTypes.Cache, compat []compat.MediaCompatibility, recorder events.Recorder,
) storageTypes.ImageStore {
	if err := storeDriver.EnsureDir(rootDir); err != nil {
		log.Error().Err(err).Str("rootDir", rootDir).Msg("failed to create root dir")

		return nil
	}

	imgStore := &ImageStore{
		rootDir:          rootDir,
		storeDriver:      storeDriver,
		lock:             &sync.RWMutex{},
		log:              log,
		metrics:          metrics,
		dedupe:           dedupe,
		linter:           linter,
		commit:           commit,
		cache:            cacheDriver,
		compat:           compat,
		events:           recorder,
		emptyDigestCache: zcommon.NewEmptyDigestCache(),
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
	err := is.storeDriver.EnsureDir(path.Join(repoDir, ispec.ImageBlobsDir))
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
	indexPath := path.Join(repoDir, ispec.ImageIndexFile)
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

		if is.events != nil {
			is.events.RepositoryCreated(name)
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

	files, err := is.storeDriver.List(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read directory")

		return false, zerr.ErrRepoNotFound
	}

	//nolint:mnd
	if len(files) < 2 {
		return false, zerr.ErrRepoBadVersion
	}

	found := map[string]bool{
		ispec.ImageLayoutFile: false,
		ispec.ImageIndexFile:  false,
	}

	for _, file := range files {
		if path.Base(file) == ispec.ImageIndexFile {
			found[ispec.ImageIndexFile] = true
		}

		if strings.HasSuffix(file, ispec.ImageLayoutFile) {
			found[ispec.ImageLayoutFile] = true
		}
	}

	// check blobs dir exists only for filesystem, in s3 we can't have empty dirs
	if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
		if !is.storeDriver.DirExists(path.Join(dir, ispec.ImageBlobsDir)) {
			return false, nil
		}
	}

	for _, v := range found {
		if !v {
			return false, nil
		}
	}

	return true, nil
}

func (is *ImageStore) GetNextRepositories(lastRepo string, maxEntries int, filterFn storageTypes.FilterRepoFunc,
) ([]string, bool, error) {
	var lockLatency time.Time

	dir := is.rootDir

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	stores := make([]string, 0)

	moreEntries := false
	entries := 0
	found := false
	err := is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if entries == maxEntries {
			moreEntries = true

			return io.EOF
		}

		if !fileInfo.IsDir() {
			return nil
		}

		// skip .sync and .uploads dirs no need to try to validate them
		if strings.HasSuffix(fileInfo.Path(), syncConstants.SyncBlobUploadDir) ||
			strings.HasSuffix(fileInfo.Path(), ispec.ImageBlobsDir) ||
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

		if lastRepo == rel {
			found = true

			return nil
		}

		if lastRepo == "" {
			found = true
		}

		ok, err := filterFn(rel)
		if err != nil {
			return err
		}

		if found && ok {
			entries++

			stores = append(stores, rel)
		}

		return nil
	})

	// if the root directory is not yet created then return an empty slice of repositories

	driverErr := &driver.Error{}

	if errors.As(err, &driver.PathNotFoundError{}) {
		is.log.Debug().Msg("empty rootDir")

		return stores, false, nil
	}

	if errors.Is(err, io.EOF) ||
		(errors.As(err, driverErr) && errors.Is(driverErr.Detail, io.EOF)) {
		return stores, moreEntries, nil
	}

	return stores, moreEntries, err
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
			strings.HasSuffix(fileInfo.Path(), ispec.ImageBlobsDir) ||
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
func (is *ImageStore) GetNextRepository(processedRepos map[string]struct{}) (string, error) {
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

	store := ""
	err = is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil {
			return nil //nolint:nilerr // ignore paths not relative to root dir
		}

		if _, ok := processedRepos[rel]; ok {
			return nil // repo already processed
		}

		ok, err := is.ValidateRepo(rel)
		if !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

		store = rel

		return io.EOF
	})

	driverErr := &driver.Error{}

	// some s3 implementations (eg, digitalocean spaces) will return pathnotfounderror for walk but not list
	// therefore, we must also catch that error here.
	if errors.As(err, &driver.PathNotFoundError{}) {
		is.log.Debug().Msg("empty rootDir")

		return "", nil
	}

	if errors.Is(err, io.EOF) ||
		(errors.As(err, driverErr) && errors.Is(driverErr.Detail, io.EOF)) {
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

	err = common.ValidateManifest(is, repo, reference, mediaType, body, is.compat, is.log)
	if err != nil {
		return mDigest, "", err
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
		return mDigest, subjectDigest, nil
	}

	// write manifest to "blobs"
	dir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir, mDigest.Algorithm().String())
	manifestPath := path.Join(dir, mDigest.Encoded())

	binfo, err := is.storeDriver.Stat(manifestPath)
	if err != nil || binfo.Size() != desc.Size {
		// The blob isn't already there, or it is corrupted, and needs a correction
		if _, err = is.storeDriver.WriteFile(manifestPath, body); err != nil {
			is.log.Error().Err(err).Str("file", manifestPath).Msg("failed to write")

			return "", "", err
		}
	}

	err = common.UpdateIndexWithPrunedImageManifests(is, &index, repo, desc, oldDgst, is.log)
	if err != nil {
		return "", "", err
	}

	// now update "index.json"
	for midx, manifest := range index.Manifests {
		_, ok := manifest.Annotations[ispec.AnnotationRefName]
		if !ok && manifest.Digest.String() == desc.Digest.String() {
			// matching descriptor does not have a tag, we need to remove it and add the new descriptor
			index.Manifests = append(index.Manifests[:midx], index.Manifests[midx+1:]...)
		}
	}

	index.Manifests = append(index.Manifests, desc)

	// update the descriptors artifact type in order to check for signatures when applying the linter
	desc.ArtifactType = artifactType

	// apply linter only on images, not signatures
	pass, err := common.ApplyLinter(is, is.linter, repo, desc)
	if !pass {
		is.log.Error().Err(err).Str("repository", repo).Str("reference", reference).
			Msg("linter didn't pass")

		if is.events != nil {
			is.events.ImageLintFailed(repo, reference, mDigest.String(), mediaType, string(body))
		}

		return "", "", err
	}

	if err := is.PutIndexContent(repo, index); err != nil {
		return "", "", err
	}

	if is.events != nil {
		is.events.ImageUpdated(repo, reference, mDigest.String(), mediaType, string(body))
	}

	return mDigest, subjectDigest, nil
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
	if zcommon.IsDigest(reference) &&
		(manifestDesc.MediaType == ispec.MediaTypeImageManifest || manifestDesc.MediaType == ispec.MediaTypeImageIndex) {
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
	file := path.Join(dir, ispec.ImageIndexFile)

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
		p := path.Join(dir, ispec.ImageBlobsDir, manifestDesc.Digest.Algorithm().String(),
			manifestDesc.Digest.Encoded())

		err = is.storeDriver.Delete(p)
		if err != nil {
			return err
		}
	}

	if is.events != nil {
		is.events.ImageDeleted(repo, reference, manifestDesc.Digest.String(), manifestDesc.MediaType)
	}

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ImageStore) BlobUploadPath(repo, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, storageConstants.BlobUploadDir, uuid)

	return blobUploadPath
}

/*
ListBlobUploads returns all blob uploads present in the repository. The caller function MUST lock from outside.
*/
func (is *ImageStore) ListBlobUploads(repo string) ([]string, error) {
	blobUploadPaths, err := is.storeDriver.List(path.Join(is.RootDir(), repo, storageConstants.BlobUploadDir))
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			// blobs uploads folder does not exist
			return []string{}, nil
		}

		is.log.Debug().Str("repository", repo).Msg("failed to list .uploads/ dir")
	}

	blobUploads := []string{}
	for _, blobUploadPath := range blobUploadPaths {
		blobUploads = append(blobUploads, path.Base(blobUploadPath))
	}

	return blobUploads, err
}

// StatBlobUpload verifies if a blob upload is present inside a repository. The caller function MUST lock from outside.
func (is *ImageStore) StatBlobUpload(repo, uuid string) (bool, int64, time.Time, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	binfo, err := is.storeDriver.Stat(blobUploadPath)
	if err != nil {
		is.log.Error().Err(err).Str("blobUpload", blobUploadPath).Msg("failed to stat blob upload")

		return false, -1, time.Time{}, err
	}

	return true, binfo.Size(), binfo.ModTime(), nil
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

	fsize := file.Size()

	if from != fsize {
		is.log.Error().Int64("expected", from).Int64("actual", file.Size()).
			Msg("invalid range start for blob upload")

		return -1, zerr.ErrBadUploadRange
	}

	n, err := io.Copy(file, body)

	return n + fsize, err
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

	// Verify digest for empty blobs before committing
	if fileWriter.Size() == 0 {
		if !is.emptyDigestCache.IsEmptyDigest(dstDigest) {
			_ = fileWriter.Close()
			is.log.Error().Str("dstDigest", dstDigest.String()).Msg("invalid empty blob digest")

			return zerr.ErrBadBlobDigest
		}
	}

	// Commit the file
	if err := fileWriter.Commit(context.Background()); err != nil {
		is.log.Error().Err(err).Msg("failed to commit file")

		return err
	}

	if err := fileWriter.Close(); err != nil {
		is.log.Error().Err(err).Msg("failed to close file")

		return err
	}

	// Verify digest for non-empty blobs after committing
	if fileWriter.Size() != 0 {
		srcDigest, err := getBlobDigest(is, src, dstDigest.Algorithm())
		if err != nil {
			is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

			return err
		}

		if srcDigest != dstDigest {
			is.log.Error().Str("srcDigest", srcDigest.String()).
				Str("dstDigest", dstDigest.String()).Msg("invalid blob digest")

			return zerr.ErrBadBlobDigest
		}
	}

	dir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir, dstDigest.Algorithm().String())

	err = is.storeDriver.EnsureDir(dir)
	if err != nil {
		is.log.Error().Str("directory", dir).Err(err).Msg("failed to create dir")

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

	dstDigestAlgorithm := dstDigest.Algorithm()

	digester := dstDigestAlgorithm.Hash()

	blobFile, err := is.storeDriver.Writer(src, false)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return "", -1, zerr.ErrUploadNotFound
	}

	mw := io.MultiWriter(blobFile, digester)

	nbytes, err := io.Copy(mw, body)
	if err != nil {
		_ = blobFile.Close()

		is.log.Error().Err(err).Str("blob", src).Msg("failed to write blob")

		return "", -1, err
	}

	if err := blobFile.Commit(context.Background()); err != nil {
		_ = blobFile.Close()

		is.log.Error().Err(err).Str("blob", src).Msg("failed to commit blob")

		return "", -1, err
	}

	// Close explicitly before returning so the subsequent move/rename can succeed on Windows.
	// - Windows does not allow renaming/moving a file while there is any open handle to it.
	// - If we relied on a deferred close, the handle would be released only when the function returns,
	// which would prevent the move/rename operation from succeeding on Windows.
	if err := blobFile.Close(); err != nil {
		is.log.Error().Err(err).Msg("failed to close blob")

		return "", -1, err
	}

	srcDigest := godigest.NewDigestFromEncoded(dstDigestAlgorithm, hex.EncodeToString(digester.Sum(nil)))
	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return "", -1, zerr.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir, dstDigestAlgorithm.String())
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
	if dst == "" {
		is.log.Error().Str("blobPath", dst).Str("component", "dedupe").
			Msg("failed to dedupe blob: empty destination path")

		return zerr.ErrBadBlobDigest
	}

	for {
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

			return nil
		}

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

			continue
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

		return nil
	}
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

	if err := writer.Cancel(context.Background()); err != nil {
		is.log.Error().Err(err).Str("blobUploadPath", blobUploadPath).Msg("failed to delete blob upload")

		return err
	}

	return nil
}

// BlobPath returns the repository path of a blob.
func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
	return path.Join(is.rootDir, repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
}

func (is *ImageStore) GetAllDedupeReposCandidates(digest godigest.Digest) ([]string, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return nil, err
	}

	if is.cache == nil {
		return nil, nil //nolint:nilnil
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	blobsPaths, err := is.cache.GetAllBlobs(digest)
	if err != nil {
		return nil, err
	}

	repos := []string{}

	for _, blobPath := range blobsPaths {
		// these can be both full paths or relative paths depending on the cache options
		if !is.cache.UsesRelativePaths() && path.IsAbs(blobPath) {
			blobPath, _ = filepath.Rel(is.rootDir, blobPath)
		}

		blobPath = filepath.ToSlash(blobPath)
		blobsDirIndex := strings.LastIndex(blobPath, "/blobs/")

		repos = append(repos, blobPath[:blobsDirIndex])
	}

	return repos, nil
}

// checkBlobInternal is the shared implementation for CheckBlob and CheckBlobForMount.
// If checkCacheOnNotFound is true, it will check the cache when the blob is not found in the repository.
func (is *ImageStore) checkBlobInternal(
	repo string, digest godigest.Digest, checkCacheOnNotFound bool,
) (bool, int64, error) {
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
	if err != nil {
		// Blob not found at blob path
		if checkCacheOnNotFound {
			// Check cache for deduped blob (for mounting)
			return is.linkBlobFromCache(repo, digest, blobPath)
		}

		// Do NOT check cache - per spec, blob must exist "in the repository"
		return false, -1, zerr.ErrBlobNotFound
	}

	// File exists at blob path - handle based on size
	if binfo.Size() == 0 {
		// Empty blob - check if it's a valid empty blob or deduped placeholder
		if is.emptyDigestCache.IsEmptyDigest(digest) {
			// Valid empty blob (digest matches)
			is.log.Debug().Str("blob path", blobPath).Msg("empty blob found")

			return true, 0, nil
		}

		// Empty file exists but it's a deduped placeholder (digest doesn't match)
		// For S3, deduped placeholders are valid and blob is accessible via cache
		// For local storage, deduped placeholders mean the blob doesn't exist at this location
		if (is.storeDriver.Name() == storageConstants.S3StorageDriverName) || checkCacheOnNotFound {
			// S3: get actual blob size from cache
			dstRecord, err := is.checkCacheBlob(digest)
			if err == nil && dstRecord != blobPath {
				originalInfo, err := is.storeDriver.Stat(dstRecord)
				if err == nil {
					is.log.Debug().Str("blob path", blobPath).Msg("deduped placeholder found, using original blob size")

					return true, originalInfo.Size(), nil
				}
			}
		}

		// Deduped placeholder - check cache if allowed (for mounting, which copies the blob)
		if checkCacheOnNotFound {
			return is.linkBlobFromCache(repo, digest, blobPath)
		}

		// Do NOT check cache - per spec, blob must exist "in the repository"
		// The empty file is a placeholder, not the actual blob
		return false, -1, zerr.ErrBlobNotFound
	}

	// Non-empty blob - verify integrity via descriptor
	desc, err := common.GetBlobDescriptorFromRepo(is, repo, digest, is.log)
	if err != nil || desc.Size == binfo.Size() {
		// Blob size matches descriptor or descriptor not found (can't verify)
		is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

		return true, binfo.Size(), nil //nolint: nilerr
	}

	// Size mismatch - blob is corrupted
	is.log.Debug().Str("blob path", blobPath).Msg("blob path found, but it's corrupted")

	return false, -1, zerr.ErrBlobNotFound
}

// CheckBlob verifies a blob and returns true if the blob is correct.
// It only checks if the blob exists in the specified repository, not in other repositories.
// For mount operations, use CheckBlobForMount which also checks the cache.
func (is *ImageStore) CheckBlob(repo string, digest godigest.Digest) (bool, int64, error) {
	return is.checkBlobInternal(repo, digest, false)
}

// CheckBlobForMount checks if a blob exists in the repository or can be mounted from cache.
// This is used for mount operations where we want to check if a blob exists in any repository.
func (is *ImageStore) CheckBlobForMount(repo string, digest godigest.Digest) (bool, int64, error) {
	return is.checkBlobInternal(repo, digest, true)
}

// linkBlobFromCache attempts to find a deduped blob in cache and link it to the target repository.
// Returns error if blob is not found in cache.
func (is *ImageStore) linkBlobFromCache(repo string, digest godigest.Digest, blobPath string) (bool, int64, error) {
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

// isDedupeablePlaceholder checks if a zero-byte file is a deduped placeholder vs a real empty blob.
func (is *ImageStore) isDedupeablePlaceholder(digest godigest.Digest, size int64) bool {
	return size == 0 && !is.emptyDigestCache.IsEmptyDigest(digest)
}

// statBlobInRepo checks if a blob exists in the repository and returns its file info.
// This is a helper used by StatBlob and originalBlobInfo.
// The caller MUST handle locking.
func (is *ImageStore) statBlobInRepo(repo string, digest godigest.Digest) (driver.FileInfo, error) {
	blobPath := is.BlobPath(repo, digest)

	binfo, err := is.storeDriver.Stat(blobPath)
	if err != nil {
		// Blob not found at blob path - do NOT check cache
		// Per spec, blob must exist "in the repository"
		return nil, zerr.ErrBlobNotFound
	}

	// File exists at blob path - handle deduped placeholders
	if !is.isDedupeablePlaceholder(digest, binfo.Size()) {
		return binfo, nil
	}

	// Empty file exists but it's probably a deduped placeholder (digest doesn't match)
	// For S3, deduped placeholders are valid because blob is accessible via cache
	// For local storage, deduped placeholders mean blob doesn't exist at this location
	if is.storeDriver.Name() == storageConstants.S3StorageDriverName {
		// S3: deduped placeholder is valid (blob accessible via cache)
		// Return the empty file info - originalBlobInfo will handle getting the actual blob
		return binfo, nil
	}

	// Local storage: deduped placeholder means blob doesn't exist at this location
	// Do NOT check cache - per spec, blob must exist "in the repository"
	return nil, zerr.ErrBlobNotFound
}

// StatBlob verifies if a blob is present inside a repository. The caller function MUST lock from outside.
// This function only checks if the blob exists in the specific repository, not in other repositories via cache.
// For deduped placeholders (empty files), it returns error because the blob doesn't actually exist "in the repository".
func (is *ImageStore) StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	if err := digest.Validate(); err != nil {
		return false, -1, time.Time{}, err
	}

	binfo, err := is.statBlobInRepo(repo, digest)
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

	// Try all cache entries until we find one that exists
	allBlobPaths, err := is.cache.GetAllBlobs(digest)
	if err != nil {
		return "", err
	}

	for _, dstRecord := range allBlobPaths {
		if is.cache.UsesRelativePaths() {
			dstRecord = path.Join(is.rootDir, dstRecord)
		}

		binfo, statErr := is.storeDriver.Stat(dstRecord)
		if statErr == nil {
			// Check if this is a deduped placeholder (empty file that's not the canonical empty blob)
			if is.isDedupeablePlaceholder(digest, binfo.Size()) {
				// This is a placeholder, not the original - skip it
				continue
			}

			// Found a valid blob with actual content
			is.log.Debug().Str("digest", digest.String()).Str("dstRecord", dstRecord).Str("component", "cache").
				Msg("found dedupe record")

			return dstRecord, nil
		}

		// This entry is stale, remove it
		is.log.Warn().Str("blob", dstRecord).Msg("removing stale cache entry")

		if err := is.cache.DeleteBlob(digest, dstRecord); err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", dstRecord).
				Msg("failed to remove stale blob path from cache")
		}
	}

	return "", zerr.ErrBlobNotFound
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
	binfo, err := is.statBlobInRepo(repo, digest)
	if err != nil {
		is.log.Error().Err(err).Str("blob", is.BlobPath(repo, digest)).Msg("failed to stat blob")

		return nil, err
	}

	// If it's a deduped placeholder, find the original blob
	if is.isDedupeablePlaceholder(digest, binfo.Size()) && is.cache != nil {
		// For S3, check cache even when dedupe is disabled (for backward compatibility)
		// For local storage, only check cache when dedupe is enabled
		if is.dedupe || is.storeDriver.Name() == storageConstants.S3StorageDriverName {
			dstRecord, err := is.checkCacheBlob(digest)
			if err != nil {
				return nil, zerr.ErrBlobNotFound
			}

			if dstRecord != binfo.Path() {
				if originalInfo, err := is.storeDriver.Stat(dstRecord); err == nil {
					return originalInfo, nil
				}
			}
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

	buf, err := is.storeDriver.ReadFile(path.Join(dir, ispec.ImageIndexFile))
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
	repoIndexPath := path.Join(is.rootDir, repo, ispec.ImageIndexFile)

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

	indexPath := path.Join(dir, ispec.ImageIndexFile)

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

	blobUploads, _ := is.ListBlobUploads(repo)

	// if removeRepo flag is true and we cleanup all blobs and there are no blobs currently being uploaded.
	if removeRepo && count == len(blobs) && count > 0 && len(blobUploads) == 0 {
		is.log.Info().Str("repository", repo).Msg("removed all blobs, removing repo")

		if err := is.storeDriver.Delete(path.Join(is.rootDir, repo)); err != nil {
			is.log.Error().Err(err).Str("repository", repo).Msg("failed to remove repo")

			return count, err
		}
	}

	// finally update metrics
	if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
		monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
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

				if is.isDedupeablePlaceholder(digest, binfo.Size()) {
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

func getBlobDigest(imgStore *ImageStore, path string, digestAlgorithm godigest.Algorithm,
) (godigest.Digest, error) {
	fileReader, err := imgStore.storeDriver.Reader(path, 0)
	if err != nil {
		return "", zerr.ErrUploadNotFound
	}

	defer fileReader.Close()

	digest, err := digestAlgorithm.FromReader(fileReader)
	if err != nil {
		return "", zerr.ErrBadBlobDigest
	}

	return digest, nil
}

func (is *ImageStore) GetAllBlobs(repo string) ([]godigest.Digest, error) {
	blobsDir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir)

	ret := []godigest.Digest{}

	algorithmPaths, err := is.storeDriver.List(blobsDir)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Debug().Str("directory", blobsDir).Msg("empty blobs directory")

			return ret, nil
		}

		return ret, err
	}

	for _, algorithmPath := range algorithmPaths {
		algorithm := godigest.Algorithm(path.Base(algorithmPath))

		if !algorithm.Available() {
			continue
		}

		digestPaths, err := is.storeDriver.List(algorithmPath)
		if err != nil {
			// algorithmPath was obtained by looking up under the blobs directory
			// we are sure it already exists, so PathNotFoundError does not need to be checked
			return []godigest.Digest{}, err
		}

		for _, file := range digestPaths {
			digest := godigest.NewDigestFromEncoded(algorithm, filepath.Base(file))
			ret = append(ret, digest)
		}
	}

	if len(ret) == 0 {
		is.log.Debug().Str("directory", blobsDir).Msg("empty blobs directory")
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
			baseName := path.Base(fileInfo.Path())
			if slices.Contains(repos, baseName) || baseName == ispec.ImageBlobsDir {
				return nil
			}

			candidateAlgorithm := godigest.Algorithm(baseName)

			if !candidateAlgorithm.Available() {
				return driver.ErrSkipDir
			}

			return nil
		}

		baseName := path.Base(fileInfo.Path())

		skippedFiles := []string{ispec.ImageLayoutFile, ispec.ImageIndexFile, "meta.db", "cache.db"}
		if slices.Contains(skippedFiles, baseName) {
			return nil
		}

		// Verify path structure follows standard OCI: rootDir/repo/blobs/algorithm/digest
		parentDir := path.Clean(path.Dir(fileInfo.Path()))
		grandparentDir := path.Clean(path.Dir(parentDir))

		// Require grandparent directory to be ImageBlobsDir (standard OCI structure)
		if path.Base(grandparentDir) != ispec.ImageBlobsDir {
			return nil
		}

		// Verify parent directory is a valid digest algorithm (e.g., sha256, sha512)
		digestAlgorithm := godigest.Algorithm(path.Base(parentDir))
		if !digestAlgorithm.Available() {
			return nil
		}

		digestHash := baseName

		blobDigest := godigest.NewDigestFromEncoded(digestAlgorithm, digestHash)
		if err := blobDigest.Validate(); err != nil { //nolint: nilerr
			is.log.Debug().Str("path", fileInfo.Path()).Str("digestHash", digestHash).
				Str("digestAlgorithm", digestAlgorithm.String()).
				Msg("digest validation failed when walking blob paths")

			return nil //nolint: nilerr // ignore files which are not blobs
		}

		if digest == "" && !slices.Contains(lastDigests, blobDigest) {
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

		if is.isDedupeablePlaceholder(digest, binfo.Size()) {
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
				if _, err := is.cache.GetBlob(digest); err != nil {
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
		if is.isDedupeablePlaceholder(digest, binfo.Size()) {
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
	generator := common.NewStorageMetricsInitGenerator(is, is.metrics, is.log)

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
