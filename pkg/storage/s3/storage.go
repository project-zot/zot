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
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

const (
	RLOCK  = "RLock"
	RWLOCK = "RWLock"
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
func NewImageStore(rootDir string, gc bool, gcDelay time.Duration, dedupe, commit bool,
	log zlog.Logger, metrics monitoring.MetricServer,
	store driver.StorageDriver) storage.ImageStore {
	imgStore := &ObjectStorage{
		rootDir:          rootDir,
		store:            store,
		lock:             &sync.RWMutex{},
		blobUploads:      make(map[string]storage.BlobUpload),
		log:              log.With().Caller().Logger(),
		multiPartUploads: sync.Map{},
		metrics:          metrics,
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

	if fi, err := is.store.Stat(context.Background(), repoDir); err == nil && fi.IsDir() {
		return nil
	}

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
		f, err := is.store.Stat(context.Background(), file)
		if err != nil {
			return false, err
		}

		if strings.HasSuffix(file, "blobs") && !f.IsDir() {
			return false, nil
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
func (is *ObjectStorage) GetImageManifest(repo string, reference string) ([]byte, string, string, error) {
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

// PutImageManifest adds an image manifest to the repository.
func (is *ObjectStorage) PutImageManifest(repo string, reference string, mediaType string,
	body []byte) (string, error) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")

		return "", err
	}

	if mediaType != ispec.MediaTypeImageManifest {
		is.log.Debug().Interface("actual", mediaType).
			Interface("expected", ispec.MediaTypeImageManifest).Msg("bad manifest media type")

		return "", zerr.ErrBadManifest
	}

	if len(body) == 0 {
		is.log.Debug().Int("len", len(body)).Msg("invalid body length")

		return "", zerr.ErrBadManifest
	}

	var m ispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		is.log.Error().Err(err).Msg("unable to unmarshal JSON")

		return "", zerr.ErrBadManifest
	}

	if m.SchemaVersion != storage.SchemaVersion {
		is.log.Error().Int("SchemaVersion", m.SchemaVersion).Msg("invalid manifest")

		return "", zerr.ErrBadManifest
	}

	for _, l := range m.Layers {
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
				Msg("updating existing tag with new manifest contents")

			desc = manifest
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

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	indexPath := path.Join(dir, "index.json")
	buf, err = json.Marshal(index)

	if err != nil {
		is.log.Error().Err(err).Str("file", indexPath).Msg("unable to marshal JSON")

		return "", err
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
func (is *ObjectStorage) DeleteImageManifest(repo string, reference string) error {
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

	var manifest ispec.Descriptor

	// we are deleting, so keep only those manifests that don't match
	outIndex := index
	outIndex.Manifests = []ispec.Descriptor{}

	for _, manifest = range index.Manifests {
		if isTag {
			tag, ok := manifest.Annotations[ispec.AnnotationRefName]
			if ok && tag == reference {
				is.log.Debug().Str("deleting tag", tag).Msg("")

				dgst = manifest.Digest

				found = true

				continue
			}
		} else if reference == manifest.Digest.String() {
			is.log.Debug().Str("deleting reference", reference).Msg("")
			found = true

			continue
		}

		outIndex.Manifests = append(outIndex.Manifests, manifest)
	}

	if !found {
		return zerr.ErrManifestNotFound
	}

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

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
func (is *ObjectStorage) BlobUploadPath(repo string, uuid string) string {
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
func (is *ObjectStorage) GetBlobUpload(repo string, uuid string) (int64, error) {
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
func (is *ObjectStorage) PutBlobChunkStreamed(repo string, uuid string, body io.Reader) (int64, error) {
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
func (is *ObjectStorage) PutBlobChunk(repo string, uuid string, from int64, to int64,
	body io.Reader) (int64, error) {
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
func (is *ObjectStorage) BlobUploadInfo(repo string, uuid string) (int64, error) {
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
func (is *ObjectStorage) FinishBlobUpload(repo string, uuid string, body io.Reader, digest string) error {
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

	if err := is.store.Move(context.Background(), src, dst); err != nil {
		is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
			Str("dst", dst).Msg("unable to finish blob")

		return err
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

	if err := is.store.Move(context.Background(), src, dst); err != nil {
		is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
			Str("dst", dst).Msg("unable to finish blob")

		return "", -1, err
	}

	return uuid, int64(nbytes), nil
}

func (is *ObjectStorage) DedupeBlob(src string, dstDigest godigest.Digest, dst string) error {
	return nil
}

// DeleteBlobUpload deletes an existing blob upload that is currently in progress.
func (is *ObjectStorage) DeleteBlobUpload(repo string, uuid string) error {
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
func (is *ObjectStorage) CheckBlob(repo string, digest string) (bool, int64, error) {
	var lockLatency time.Time

	dgst, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return false, -1, zerr.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, dgst)

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	binfo, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		var perr driver.PathNotFoundError
		if errors.As(err, &perr) {
			return false, -1, zerr.ErrBlobNotFound
		}

		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return false, -1, err
	}

	is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

	return true, binfo.Size(), nil
}

// GetBlob returns a stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ObjectStorage) GetBlob(repo string, digest string, mediaType string) (io.Reader, int64, error) {
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

	blobReader, err := is.store.Reader(context.Background(), blobPath, 0)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")

		return nil, -1, err
	}

	return blobReader, binfo.Size(), nil
}

func (is *ObjectStorage) GetBlobContent(repo string, digest string) ([]byte, error) {
	blob, _, err := is.GetBlob(repo, digest, ispec.MediaTypeImageManifest)
	if err != nil {
		return []byte{}, err
	}

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(blob)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to read blob")

		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func (is *ObjectStorage) GetReferrers(repo, digest string, mediaType string) ([]artifactspec.Descriptor, error) {
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
func (is *ObjectStorage) DeleteBlob(repo string, digest string) error {
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
