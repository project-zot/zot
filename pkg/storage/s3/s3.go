package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
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

	// Add s3 support.
	"github.com/docker/distribution/registry/storage/driver"
	// Load s3 driver.
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	"github.com/sigstore/cosign/pkg/oci/remote"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

const (
	RLOCK       = "RLock"
	RWLOCK      = "RWLock"
	CacheDBName = "s3_cache"
)

// ObjectStorage provides the image storage operations.
type ObjectStorage struct {
	rootDir     string
	store       driver.StorageDriver
	lock        *sync.RWMutex
	blobUploads map[string]storage.BlobUpload
	log         zerolog.Logger
	// We must keep track of multi part uploads to s3, because the lib
	// which we are using doesn't cancel multiparts uploads
	// see: https://github.com/distribution/distribution/blob/main/registry/storage/driver/s3-aws/s3.go#L545
	multiPartUploads sync.Map
	metrics          monitoring.MetricServer
	cache            *storage.Cache
	dedupe           bool
	linter           storage.Lint
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
func NewImageStore(rootDir string, cacheDir string, gc bool, gcDelay time.Duration, dedupe, commit bool,
	log zlog.Logger, metrics monitoring.MetricServer, linter storage.Lint,
	store driver.StorageDriver,
) storage.ImageStore {
	imgStore := &ObjectStorage{
		rootDir:          rootDir,
		store:            store,
		lock:             &sync.RWMutex{},
		blobUploads:      make(map[string]storage.BlobUpload),
		log:              log.With().Caller().Logger(),
		multiPartUploads: sync.Map{},
		metrics:          metrics,
		dedupe:           dedupe,
		linter:           linter,
	}

	cachePath := path.Join(cacheDir, CacheDBName+storage.DBExtensionName)

	if dedupe {
		imgStore.cache = storage.NewCache(cacheDir, CacheDBName, false, log)
	} else {
		// if dedupe was used in previous runs use it to serve blobs correctly
		if _, err := os.Stat(cachePath); err == nil {
			log.Info().Str("cache path", cachePath).Msg("found cache database")
			imgStore.cache = storage.NewCache(cacheDir, CacheDBName, false, log)
		}
	}

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
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), RLOCK) // histogram
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
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), RWLOCK) // histogram
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

	// nolint:gomnd
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
		if !v && k != storage.BlobUploadDir {
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

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ObjectStorage) GetImageTags(repo string) ([]string, error) {
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return nil, zerr.ErrRepoNotFound
	}

	buf, err := is.GetIndexContent(repo)
	if err != nil {
		return nil, err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return nil, zerr.ErrRepoNotFound
	}

	tags := make([]string, 0)

	for _, manifest := range index.Manifests {
		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			tags = append(tags, v)
		}
	}

	return tags, nil
}

// GetImageManifest returns the image manifest of an image in the specific repository.
func (is *ObjectStorage) GetImageManifest(repo, reference string) ([]byte, string, string, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return nil, "", "", zerr.ErrRepoNotFound
	}

	buf, err := is.GetIndexContent(repo)
	if err != nil {
		return nil, "", "", err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return nil, "", "", err
	}

	found := false

	var digest godigest.Digest

	mediaType := ""

	for _, manifest := range index.Manifests {
		if reference == manifest.Digest.String() {
			digest = manifest.Digest
			mediaType = manifest.MediaType
			found = true

			break
		}

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			digest = manifest.Digest
			mediaType = manifest.MediaType
			found = true

			break
		}
	}

	if !found {
		return nil, "", "", zerr.ErrManifestNotFound
	}

	manifestPath := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	buf, err = is.store.GetContent(context.Background(), manifestPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", manifestPath).Msg("failed to read manifest")

		return nil, "", "", err
	}

	var manifest ispec.Manifest
	if err := json.Unmarshal(buf, &manifest); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return nil, "", "", err
	}

	monitoring.IncDownloadCounter(is.metrics, repo)

	return buf, digest.String(), mediaType, nil
}

/**
before an image index manifest is pushed to a repo, its constituent manifests
are pushed first, so when updating/removing this image index manifest, we also
need to determine if there are other image index manifests which refer to the
same constitutent manifests so that they can be garbage-collected correctly

pruneImageManifestsFromIndex is a helper routine to achieve this.
*/
func (is *ObjectStorage) pruneImageManifestsFromIndex(dir string, digest godigest.Digest, // nolint: gocyclo
	outIndex ispec.Index, otherImgIndexes []ispec.Descriptor, log zerolog.Logger,
) ([]ispec.Descriptor, error) {
	indexPath := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	buf, err := is.store.GetContent(context.Background(), indexPath)
	if err != nil {
		log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return nil, err
	}

	var imgIndex ispec.Index
	if err := json.Unmarshal(buf, &imgIndex); err != nil {
		log.Error().Err(err).Str("path", indexPath).Msg("invalid JSON")

		return nil, err
	}

	inUse := map[string]uint{}

	for _, manifest := range imgIndex.Manifests {
		inUse[manifest.Digest.Encoded()]++
	}

	for _, otherIndex := range otherImgIndexes {
		indexPath := path.Join(dir, "blobs", otherIndex.Digest.Algorithm().String(), otherIndex.Digest.Encoded())

		buf, err := is.store.GetContent(context.Background(), indexPath)
		if err != nil {
			log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

			return nil, err
		}

		var oindex ispec.Index
		if err := json.Unmarshal(buf, &oindex); err != nil {
			log.Error().Err(err).Str("path", indexPath).Msg("invalid JSON")

			return nil, err
		}

		for _, omanifest := range oindex.Manifests {
			_, ok := inUse[omanifest.Digest.Encoded()]
			if ok {
				inUse[omanifest.Digest.Encoded()]++
			}
		}
	}

	prunedManifests := []ispec.Descriptor{}

	// for all manifests in the index, skip those that either have a tag or
	// are used in other imgIndexes
	for _, outManifest := range outIndex.Manifests {
		if outManifest.MediaType != ispec.MediaTypeImageManifest {
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}

		_, ok := outManifest.Annotations[ispec.AnnotationRefName]
		if ok {
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}

		count, ok := inUse[outManifest.Digest.Encoded()]
		if !ok {
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}

		if count != 1 {
			// this manifest is in use in other image indexes
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}
	}

	return prunedManifests, nil
}

// PutImageManifest adds an image manifest to the repository.
func (is *ObjectStorage) PutImageManifest(repo, reference, mediaType string, //nolint: gocyclo
	body []byte) (string, error,
) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")

		return "", err
	}

	// validate the manifest
	if !storage.IsSupportedMediaType(mediaType) {
		is.log.Debug().Interface("actual", mediaType).
			Msg("bad manifest media type")

		return "", zerr.ErrBadManifest
	}

	if len(body) == 0 {
		is.log.Debug().Int("len", len(body)).Msg("invalid body length")

		return "", zerr.ErrBadManifest
	}

	var imageManifest ispec.Manifest
	if err := json.Unmarshal(body, &imageManifest); err != nil {
		is.log.Error().Err(err).Msg("unable to unmarshal JSON")

		return "", zerr.ErrBadManifest
	}

	if imageManifest.SchemaVersion != storage.SchemaVersion {
		is.log.Error().Int("SchemaVersion", imageManifest.SchemaVersion).Msg("invalid manifest")

		return "", zerr.ErrBadManifest
	}

	for _, l := range imageManifest.Layers {
		digest := l.Digest
		blobPath := is.BlobPath(repo, digest)
		is.log.Info().Str("blobPath", blobPath).Str("reference", reference).Msg("manifest layers")

		if _, err := is.store.Stat(context.Background(), blobPath); err != nil {
			is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to find blob")

			return digest.String(), zerr.ErrBlobNotFound
		}
	}

	mDigest := godigest.FromBytes(body)
	refIsDigest := false
	dgst, err := godigest.Parse(reference)

	if err == nil {
		if dgst.String() != mDigest.String() {
			is.log.Error().Str("actual", mDigest.String()).Str("expected", dgst.String()).
				Msg("manifest digest is not valid")

			return "", zerr.ErrBadManifest
		}

		refIsDigest = true
	}

	dir := path.Join(is.rootDir, repo)

	buf, err := is.GetIndexContent(repo)
	if err != nil {
		return "", err
	}

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return "", zerr.ErrRepoBadVersion
	}

	updateIndex := true
	// create a new descriptor
	desc := ispec.Descriptor{
		MediaType: mediaType, Size: int64(len(body)), Digest: mDigest,
		Platform: &ispec.Platform{Architecture: "amd64", OS: "linux"},
	}
	if !refIsDigest {
		desc.Annotations = map[string]string{ispec.AnnotationRefName: reference}
	}

	var oldDgst godigest.Digest

	for midx, manifest := range index.Manifests {
		if reference == manifest.Digest.String() {
			// nothing changed, so don't update
			desc = manifest
			updateIndex = false

			break
		}

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			if manifest.Digest.String() == mDigest.String() {
				// nothing changed, so don't update
				desc = manifest
				updateIndex = false

				break
			}
			// manifest contents have changed for the same tag,
			// so update index.json descriptor

			is.log.Info().
				Int64("old size", desc.Size).
				Int64("new size", int64(len(body))).
				Str("old digest", desc.Digest.String()).
				Str("new digest", mDigest.String()).
				Str("old digest", desc.Digest.String()).
				Str("new digest", mDigest.String()).
				Msg("updating existing tag with new manifest contents")

			// changing media-type is disallowed!
			if manifest.MediaType != mediaType {
				err = zerr.ErrBadManifest
				is.log.Error().Err(err).
					Str("old mediaType", manifest.MediaType).
					Str("new mediaType", mediaType).Msg("cannot change media-type")

				return "", err
			}

			desc = manifest
			oldDgst = manifest.Digest
			desc.Size = int64(len(body))
			desc.Digest = mDigest

			index.Manifests = append(index.Manifests[:midx], index.Manifests[midx+1:]...)

			break
		}
	}

	if !updateIndex {
		return desc.Digest.String(), nil
	}

	// write manifest to "blobs"
	dir = path.Join(is.rootDir, repo, "blobs", mDigest.Algorithm().String())
	manifestPath := path.Join(dir, mDigest.Encoded())

	if err = is.store.PutContent(context.Background(), manifestPath, body); err != nil {
		is.log.Error().Err(err).Str("file", manifestPath).Msg("unable to write")

		return "", err
	}

	/* additionally, unmarshal an image index and for all manifests in that
	index, ensure that they do not have a name or they are not in other
	manifest indexes else GC can never clean them */
	if (mediaType == ispec.MediaTypeImageIndex) && (oldDgst != "") {
		otherImgIndexes := []ispec.Descriptor{}

		for _, manifest := range index.Manifests {
			if manifest.MediaType == ispec.MediaTypeImageIndex {
				otherImgIndexes = append(otherImgIndexes, manifest)
			}
		}

		otherImgIndexes = append(otherImgIndexes, desc)

		dir := path.Join(is.rootDir, repo)

		prunedManifests, err := is.pruneImageManifestsFromIndex(dir, oldDgst, index, otherImgIndexes, is.log)
		if err != nil {
			return "", err
		}

		index.Manifests = prunedManifests
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	indexPath := path.Join(dir, "index.json")
	buf, err = json.Marshal(index)

	if err != nil {
		is.log.Error().Err(err).Str("file", indexPath).Msg("unable to marshal JSON")

		return "", err
	}

	// apply linter only on images, not signatures
	if is.linter != nil {
		if mediaType == ispec.MediaTypeImageManifest &&
			// check that image manifest is not cosign signature
			!strings.HasPrefix(reference, "sha256-") &&
			!strings.HasSuffix(reference, remote.SignatureTagSuffix) {
			// lint new index with new manifest before writing to disk
			pass, err := is.linter.Lint(repo, mDigest, is)
			if err != nil {
				is.log.Error().Err(err).Msg("linter error")

				return "", err
			}

			if !pass {
				return "", zerr.ErrImageLintAnnotations
			}
		}
	}

	if err = is.store.PutContent(context.Background(), indexPath, buf); err != nil {
		is.log.Error().Err(err).Str("file", manifestPath).Msg("unable to write")

		return "", err
	}

	monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
	monitoring.IncUploadCounter(is.metrics, repo)

	return desc.Digest.String(), nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ObjectStorage) DeleteImageManifest(repo, reference string) error {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return zerr.ErrRepoNotFound
	}

	isTag := false

	// as per spec "reference" can only be a digest and not a tag
	dgst, err := godigest.Parse(reference)
	if err != nil {
		is.log.Debug().Str("invalid digest: ", reference).Msg("storage: assuming tag")

		isTag = true
	}

	buf, err := is.GetIndexContent(repo)
	if err != nil {
		return err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return err
	}

	found := false

	isImageIndex := false

	var manifest ispec.Descriptor

	// we are deleting, so keep only those manifests that don't match
	outIndex := index
	outIndex.Manifests = []ispec.Descriptor{}

	otherImgIndexes := []ispec.Descriptor{}

	for _, manifest = range index.Manifests {
		if isTag {
			tag, ok := manifest.Annotations[ispec.AnnotationRefName]
			if ok && tag == reference {
				is.log.Debug().Str("deleting tag", tag).Msg("")

				dgst = manifest.Digest

				found = true

				if manifest.MediaType == ispec.MediaTypeImageIndex {
					isImageIndex = true
				}

				continue
			}
		} else if reference == manifest.Digest.String() {
			is.log.Debug().Str("deleting reference", reference).Msg("")
			found = true

			if manifest.MediaType == ispec.MediaTypeImageIndex {
				isImageIndex = true
			}

			continue
		}

		outIndex.Manifests = append(outIndex.Manifests, manifest)

		if manifest.MediaType == ispec.MediaTypeImageIndex {
			otherImgIndexes = append(otherImgIndexes, manifest)
		}
	}

	if !found {
		return zerr.ErrManifestNotFound
	}

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	/* additionally, unmarshal an image index and for all manifests in that
	index, ensure that they do not have a name or they are not in other
	manifest indexes else GC can never clean them */
	if isImageIndex {
		prunedManifests, err := is.pruneImageManifestsFromIndex(dir, dgst, outIndex, otherImgIndexes, is.log)
		if err != nil {
			return err
		}

		outIndex.Manifests = prunedManifests
	}

	// now update "index.json"
	dir = path.Join(is.rootDir, repo)
	file := path.Join(dir, "index.json")
	buf, err = json.Marshal(outIndex)

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

	for _, manifest = range outIndex.Manifests {
		if dgst.String() == manifest.Digest.String() {
			toDelete = false

			break
		}
	}

	if toDelete {
		p := path.Join(dir, "blobs", dgst.Algorithm().String(), dgst.Encoded())

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
	blobUploadPath := path.Join(dir, storage.BlobUploadDir, uuid)

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

	// here we should create an empty multi part upload, but that's not possible
	// so we just create a regular empty file which will be overwritten by FinishBlobUpload
	err = is.store.PutContent(context.Background(), blobUploadPath, []byte{})
	if err != nil {
		return "", zerr.ErrRepoNotFound
	}

	return uid, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ObjectStorage) GetBlobUpload(repo, uuid string) (int64, error) {
	var fileSize int64

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	// if it's not a multipart upload check for the regular empty file
	// created by NewBlobUpload, it should have 0 size every time
	_, hasStarted := is.multiPartUploads.Load(blobUploadPath)
	if !hasStarted {
		binfo, err := is.store.Stat(context.Background(), blobUploadPath)
		if err != nil {
			var perr driver.PathNotFoundError
			if errors.As(err, &perr) {
				return -1, zerr.ErrUploadNotFound
			}

			return -1, err
		}

		fileSize = binfo.Size()
	} else {
		// otherwise get the size of multi parts upload
		fi, err := getMultipartFileWriter(is, blobUploadPath)
		if err != nil {
			return -1, err
		}

		fileSize = fi.Size()
	}

	return fileSize, nil
}

// PutBlobChunkStreamed appends another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ObjectStorage) PutBlobChunkStreamed(repo, uuid string, body io.Reader) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	_, err := is.store.Stat(context.Background(), blobUploadPath)
	if err != nil {
		return -1, zerr.ErrUploadNotFound
	}

	file, err := getMultipartFileWriter(is, blobUploadPath)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to create multipart upload")

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

	_, err := is.store.Stat(context.Background(), blobUploadPath)
	if err != nil {
		return -1, zerr.ErrUploadNotFound
	}

	file, err := getMultipartFileWriter(is, blobUploadPath)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to create multipart upload")

		return -1, err
	}

	defer file.Close()

	if from != file.Size() {
		// cancel multipart upload
		is.multiPartUploads.Delete(blobUploadPath)

		err := file.Cancel()
		if err != nil {
			is.log.Error().Err(err).Msg("failed to cancel multipart upload")

			return -1, err
		}

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
	var fileSize int64

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	// if it's not a multipart upload check for the regular empty file
	// created by NewBlobUpload, it should have 0 size every time
	_, hasStarted := is.multiPartUploads.Load(blobUploadPath)
	if !hasStarted {
		uploadInfo, err := is.store.Stat(context.Background(), blobUploadPath)
		if err != nil {
			is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")

			return -1, err
		}

		fileSize = uploadInfo.Size()
	} else {
		// otherwise get the size of multi parts upload
		binfo, err := getMultipartFileWriter(is, blobUploadPath)
		if err != nil {
			is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")

			return -1, err
		}

		fileSize = binfo.Size()
	}

	return fileSize, nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ObjectStorage) FinishBlobUpload(repo, uuid string, body io.Reader, digest string) error {
	dstDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return zerr.ErrBadBlobDigest
	}

	src := is.BlobUploadPath(repo, uuid)

	// complete multiUploadPart
	fileWriter, err := is.store.Writer(context.Background(), src, true)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return zerr.ErrBadBlobDigest
	}

	defer fileWriter.Close()

	if err := fileWriter.Commit(); err != nil {
		is.log.Error().Err(err).Msg("failed to commit file")

		return err
	}

	if err := fileWriter.Close(); err != nil {
		is.log.Error().Err(err).Msg("failed to close file")
	}

	fileReader, err := is.store.Reader(context.Background(), src, 0)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open file")

		return zerr.ErrUploadNotFound
	}

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

	fileReader.Close()

	dst := is.BlobPath(repo, dstDigest)

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	if is.dedupe && is.cache != nil {
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

	is.multiPartUploads.Delete(src)

	return nil
}

// FullBlobUpload handles a full blob upload, and no partial session is created.
func (is *ObjectStorage) FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return "", -1, err
	}

	dstDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return "", -1, zerr.ErrBadBlobDigest
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

	if is.dedupe && is.cache != nil {
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

	dstRecord, err := is.cache.GetBlob(dstDigest.String())
	if err := test.Error(err); err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to lookup blob record")

		return err
	}

	if dstRecord == "" {
		// cache record doesn't exist, so first disk and cache entry for this digest
		if err := is.cache.PutBlob(dstDigest.String(), dst); err != nil {
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
			err := is.cache.DeleteBlob(dstDigest.String(), dstRecord)
			if err = test.Error(err); err != nil {
				// nolint:lll
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

			if err := is.cache.PutBlob(dstDigest.String(), dst); err != nil {
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

func (is *ObjectStorage) RunGCRepo(repo string) {
}

// DeleteBlobUpload deletes an existing blob upload that is currently in progress.
func (is *ObjectStorage) DeleteBlobUpload(repo, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	if err := is.store.Delete(context.Background(), blobUploadPath); err != nil {
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
func (is *ObjectStorage) CheckBlob(repo, digest string) (bool, int64, error) {
	var lockLatency time.Time

	dgst, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return false, -1, zerr.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, dgst)

	if is.dedupe && is.cache != nil {
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
		is.log.Error().Err(err).Str("digest", digest).Msg("cache: not found")

		return false, -1, zerr.ErrBlobNotFound
	}

	// If found copy to location
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

func (is *ObjectStorage) checkCacheBlob(digest string) (string, error) {
	if is.cache == nil {
		return "", zerr.ErrBlobNotFound
	}

	dstRecord, err := is.cache.GetBlob(digest)
	if err != nil {
		return "", err
	}

	is.log.Debug().Str("digest", digest).Str("dstRecord", dstRecord).Msg("cache: found dedupe record")

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
func (is *ObjectStorage) GetBlobPartial(repo, digest, mediaType string, from, to int64,
) (io.ReadCloser, int64, int64, error) {
	var lockLatency time.Time

	dgst, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return nil, -1, -1, zerr.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, dgst)

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
			is.log.Error().Err(err).Str("digest", digest).Msg("cache: not found")

			return nil, -1, -1, zerr.ErrBlobNotFound
		}

		binfo, err := is.store.Stat(context.Background(), dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

			// the actual blob on disk may have been removed by GC, so sync the cache
			if err := is.cache.DeleteBlob(digest, dstRecord); err != nil {
				is.log.Error().Err(err).Str("dstDigest", digest).Str("dst", dstRecord).Msg("dedupe: unable to delete blob record")

				return nil, -1, -1, err
			}

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
func (is *ObjectStorage) GetBlob(repo, digest, mediaType string) (io.ReadCloser, int64, error) {
	var lockLatency time.Time

	dgst, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return nil, -1, zerr.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, dgst)

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
	if binfo.Size() == 0 {
		// Check blobs in cache
		dstRecord, err := is.checkCacheBlob(digest)
		if err != nil {
			is.log.Error().Err(err).Str("digest", digest).Msg("cache: not found")

			return nil, -1, zerr.ErrBlobNotFound
		}

		binfo, err := is.store.Stat(context.Background(), dstRecord)
		if err != nil {
			is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

			// the actual blob on disk may have been removed by GC, so sync the cache
			if err := is.cache.DeleteBlob(digest, dstRecord); err != nil {
				is.log.Error().Err(err).Str("dstDigest", digest).Str("dst", dstRecord).Msg("dedupe: unable to delete blob record")

				return nil, -1, err
			}

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

func (is *ObjectStorage) GetBlobContent(repo, digest string) ([]byte, error) {
	blob, _, err := is.GetBlob(repo, digest, ispec.MediaTypeImageManifest)
	if err != nil {
		return []byte{}, err
	}
	defer blob.Close()

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(blob)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to read blob")

		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func (is *ObjectStorage) GetReferrers(repo, digest, mediaType string) ([]artifactspec.Descriptor, error) {
	return nil, zerr.ErrMethodNotSupported
}

func (is *ObjectStorage) GetIndexContent(repo string) ([]byte, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	buf, err := is.store.GetContent(context.Background(), path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return []byte{}, zerr.ErrRepoNotFound
	}

	return buf, nil
}

// DeleteBlob removes the blob from the repository.
func (is *ObjectStorage) DeleteBlob(repo, digest string) error {
	var lockLatency time.Time

	dgst, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return zerr.ErrBlobNotFound
	}

	blobPath := is.BlobPath(repo, dgst)

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	_, err = is.store.Stat(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return zerr.ErrBlobNotFound
	}

	if is.cache != nil {
		dstRecord, err := is.cache.GetBlob(digest)
		if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			is.log.Error().Err(err).Str("blobPath", dstRecord).Msg("dedupe: unable to lookup blob record")

			return err
		}

		// remove cache entry and move blob contents to the next candidate if there is any
		if err := is.cache.DeleteBlob(digest, blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", digest).Str("blobPath", blobPath).Msg("unable to remove blob path from cache")

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

// get a multipart upload FileWriter based on wheather or not one has already been started.
func getMultipartFileWriter(imgStore *ObjectStorage, filepath string) (driver.FileWriter, error) {
	var file driver.FileWriter

	var err error

	_, hasStarted := imgStore.multiPartUploads.Load(filepath)
	if !hasStarted {
		// start multipart upload
		file, err = imgStore.store.Writer(context.Background(), filepath, false)
		if err != nil {
			return file, err
		}

		imgStore.multiPartUploads.Store(filepath, true)
	} else {
		// continue multipart upload
		file, err = imgStore.store.Writer(context.Background(), filepath, true)
		if err != nil {
			return file, err
		}
	}

	return file, nil
}
