package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/extensions/monitoring"
	zlog "github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	guuid "github.com/gofrs/uuid"
	"github.com/opencontainers/go-digest"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"

	// Add s3 support
	storageDriver "github.com/docker/distribution/registry/storage/driver"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws" // Load s3 driver
)

const (
	actualBlobUploadDir = "/BLOBS/"
	linkedBlobsFilePath = "/linked_blobs.json"
)

type LinkedBlobs struct {
	Links map[string][]string `json:"links,omitempty"`
}

// ObjectStorage provides the image storage operations.
type ObjectStorage struct {
	rootDir     string
	store       storageDriver.StorageDriver
	lock        *sync.RWMutex
	blobUploads map[string]storage.BlobUpload
	dedupe      bool
	log         zerolog.Logger
	// We must keep track of multi part uploads to s3, because the lib
	// which we are using doesn't cancel multiparts uploads
	// see: https://github.com/distribution/distribution/blob/main/registry/storage/driver/s3-aws/s3.go#L545
	isMultiPartUpload map[string]bool
	metrics           monitoring.MetricServer
}

// because s3 doesn't support symlinks, we store the real blobs in actualBlobPath
// and the images blobs are just files with content being the path to real blobs.
// actualBlobPath returns the real repository path of a blob.
func actualBlobPath(rootDir string, digest godigest.Digest) string {
	return path.Join(rootDir, actualBlobUploadDir, digest.Algorithm().String(), digest.Encoded())
}

func newLinkedBlobs(is *ObjectStorage) error {
	l := path.Join(is.rootDir, linkedBlobsFilePath)

	err := is.store.PutContent(context.Background(), l, []byte{})
	if err != nil {
		is.log.Error().Err(err).Str("path", l).Msg("couldn't unmarshal linked blobs")
		return err
	}

	return nil
}

func loadLinkedBlobs(is *ObjectStorage) (LinkedBlobs, error) {
	l := path.Join(is.rootDir, linkedBlobsFilePath)

	buf, err := is.store.GetContent(context.Background(), l)
	if err != nil {
		if isPathNotFoundErr(err) {
			err = newLinkedBlobs(is)
			if err != nil {
				return LinkedBlobs{}, err
			}

			return LinkedBlobs{}, nil
		}

		is.log.Error().Err(err).Str("path", l).Msg("couldn't read linked blobs")

		return LinkedBlobs{}, err
	}

	lb := LinkedBlobs{}

	if err := json.Unmarshal(buf, &lb); err != nil {
		is.log.Error().Err(err).Str("path", l).Msg("couldn't unmarshal linked blobs")
		return LinkedBlobs{}, err
	}

	return lb, nil
}

func dumpLinkedBlobs(is *ObjectStorage, lb LinkedBlobs) error {
	l := path.Join(is.rootDir, linkedBlobsFilePath)

	buf, err := json.Marshal(lb)
	if err != nil {
		is.log.Error().Err(err).Msg("couldn't unmarhsal linked blobs")
		return err
	}

	err = is.store.PutContent(context.Background(), l, buf)
	if err != nil {
		is.log.Error().Err(err).Str("path", l).Msg("couldn't unmarhsal linked blobs")
		return err
	}

	return nil
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
func NewImageStore(rootDir string, gc bool, dedupe bool, log zlog.Logger, m monitoring.MetricServer,
	store storageDriver.StorageDriver) storage.ImageStore {
	is := &ObjectStorage{
		rootDir:           rootDir,
		store:             store,
		lock:              &sync.RWMutex{},
		dedupe:            dedupe,
		blobUploads:       make(map[string]storage.BlobUpload),
		log:               log.With().Caller().Logger(),
		isMultiPartUpload: make(map[string]bool),
		metrics:           m,
	}

	return is
}

// RLock read-lock.
func (is *ObjectStorage) RLock() {
	is.lock.RLock()
}

// RUnlock read-unlock.
func (is *ObjectStorage) RUnlock() {
	is.lock.RUnlock()
}

// Lock write-lock.
func (is *ObjectStorage) Lock() {
	is.lock.Lock()
}

// Unlock write-unlock.
func (is *ObjectStorage) Unlock() {
	is.lock.Unlock()
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
	is.Lock()
	defer is.Unlock()

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
		return false, errors.ErrRepoNotFound
	}

	files, err := is.store.List(context.Background(), dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")
		return false, errors.ErrRepoNotFound
	}

	// nolint:gomnd
	if len(files) < 2 {
		return false, errors.ErrRepoBadVersion
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
		return false, errors.ErrRepoBadVersion
	}

	return true, nil
}

// GetRepositories returns a list of all the repositories under this store.
func (is *ObjectStorage) GetRepositories() ([]string, error) {
	dir := is.rootDir

	is.RLock()
	defer is.RUnlock()

	stores := make([]string, 0)
	err := is.store.Walk(context.Background(), dir, func(fileInfo storageDriver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil {
			return nil
		}

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil
		}

		stores = append(stores, rel)

		return nil
	})

	// if the root directory is not yet created then return an empty slice of repositories
	if isPathNotFoundErr(err) {
		return stores, nil
	}

	return stores, err
}

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ObjectStorage) GetImageTags(repo string) ([]string, error) {
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return nil, errors.ErrRepoNotFound
	}

	is.RLock()
	defer is.RUnlock()

	buf, err := is.GetIndexContent(repo)
	if err != nil {
		return nil, err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return nil, errors.ErrRepoNotFound
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
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return nil, "", "", errors.ErrRepoNotFound
	}

	is.RLock()
	defer is.RUnlock()

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

	for _, m := range index.Manifests {
		if reference == m.Digest.String() {
			digest = m.Digest
			mediaType = m.MediaType
			found = true

			break
		}

		v, ok := m.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			digest = m.Digest
			mediaType = m.MediaType
			found = true

			break
		}
	}

	if !found {
		return nil, "", "", errors.ErrManifestNotFound
	}

	p := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	buf, err = is.store.GetContent(context.Background(), p)
	if err != nil {
		is.log.Error().Err(err).Str("blob", p).Msg("failed to read manifest")
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
		return "", errors.ErrBadManifest
	}

	if len(body) == 0 {
		is.log.Debug().Int("len", len(body)).Msg("invalid body length")
		return "", errors.ErrBadManifest
	}

	var m ispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		is.log.Error().Err(err).Msg("unable to unmarshal JSON")
		return "", errors.ErrBadManifest
	}

	if m.SchemaVersion != storage.SchemaVersion {
		is.log.Error().Int("SchemaVersion", m.SchemaVersion).Msg("invalid manifest")
		return "", errors.ErrBadManifest
	}

	for _, l := range m.Layers {
		digest := l.Digest
		blobPath := is.BlobPath(repo, digest)
		is.log.Info().Str("blobPath", blobPath).Str("reference", reference).Msg("manifest layers")

		if _, err := is.store.Stat(context.Background(), blobPath); err != nil {
			is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to find blob")
			return digest.String(), errors.ErrBlobNotFound
		}
	}

	mDigest := godigest.FromBytes(body)
	refIsDigest := false
	d, err := godigest.Parse(reference)

	if err == nil {
		if d.String() != mDigest.String() {
			is.log.Error().Str("actual", mDigest.String()).Str("expected", d.String()).
				Msg("manifest digest is not valid")
			return "", errors.ErrBadManifest
		}

		refIsDigest = true
	}

	is.Lock()
	defer is.Unlock()

	dir := path.Join(is.rootDir, repo)

	buf, err := is.GetIndexContent(repo)
	if err != nil {
		return "", err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return "", errors.ErrRepoBadVersion
	}

	updateIndex := true
	// create a new descriptor
	desc := ispec.Descriptor{MediaType: mediaType, Size: int64(len(body)), Digest: mDigest,
		Platform: &ispec.Platform{Architecture: "amd64", OS: "linux"}}
	if !refIsDigest {
		desc.Annotations = map[string]string{ispec.AnnotationRefName: reference}
	}

	for i, m := range index.Manifests {
		if reference == m.Digest.String() {
			// nothing changed, so don't update
			desc = m
			updateIndex = false

			break
		}

		v, ok := m.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			if m.Digest.String() == mDigest.String() {
				// nothing changed, so don't update
				desc = m
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

			desc = m
			desc.Size = int64(len(body))
			desc.Digest = mDigest

			index.Manifests = append(index.Manifests[:i], index.Manifests[i+1:]...)

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
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return errors.ErrRepoNotFound
	}

	isTag := false

	// as per spec "reference" can only be a digest and not a tag
	digest, err := godigest.Parse(reference)
	if err != nil {
		is.log.Debug().Str("invalid digest: ", reference).Msg("storage: assuming tag")

		isTag = true
	}

	is.Lock()
	defer is.Unlock()

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

	var m ispec.Descriptor

	// we are deleting, so keep only those manifests that don't match
	outIndex := index
	outIndex.Manifests = []ispec.Descriptor{}

	for _, m = range index.Manifests {
		if isTag {
			tag, ok := m.Annotations[ispec.AnnotationRefName]
			if ok && tag == reference {
				is.log.Debug().Str("deleting tag", tag).Msg("")

				digest = m.Digest

				found = true

				continue
			}
		} else if reference == m.Digest.String() {
			is.log.Debug().Str("deleting reference", reference).Msg("")
			found = true
			continue
		}

		outIndex.Manifests = append(outIndex.Manifests, m)
	}

	if !found {
		return errors.ErrManifestNotFound
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

	for _, m = range outIndex.Manifests {
		if digest.String() == m.Digest.String() {
			toDelete = false
			break
		}
	}

	if toDelete {
		p := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

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

	u := uuid.String()

	blobUploadPath := is.BlobUploadPath(repo, u)

	// here we should create an empty multi part upload, but that's not possible
	// so we just create a regular empty file which will be overwritten by FinishBlobUpload
	err = is.store.PutContent(context.Background(), blobUploadPath, []byte{})
	if err != nil {
		return "", errors.ErrRepoNotFound
	}

	return u, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ObjectStorage) GetBlobUpload(repo string, uuid string) (int64, error) {
	var fileSize int64

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	// if it's not a multipart upload check for the regular empty file
	// created by NewBlobUpload, it should have 0 size every time
	isMultiPartStarted, ok := is.isMultiPartUpload[blobUploadPath]
	if !isMultiPartStarted || !ok {
		fi, err := is.store.Stat(context.Background(), blobUploadPath)
		if err != nil {
			_, ok := err.(storageDriver.PathNotFoundError)
			if ok {
				return -1, errors.ErrUploadNotFound
			}

			return -1, err
		}

		fileSize = fi.Size()
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
		return -1, errors.ErrUploadNotFound
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

	n, err := file.Write(buf.Bytes())
	if err != nil {
		is.log.Error().Err(err).Msg("failed to append to file")
		return -1, err
	}

	return int64(n), err
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
		return -1, errors.ErrUploadNotFound
	}

	file, err := getMultipartFileWriter(is, blobUploadPath)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to create multipart upload")
		return -1, err
	}

	defer file.Close()

	if from != file.Size() {
		// cancel multipart upload created earlier
		err := file.Cancel()
		if err != nil {
			is.log.Error().Err(err).Msg("failed to cancel multipart upload")
			return -1, err
		}

		is.log.Error().Int64("expected", from).Int64("actual", file.Size()).
			Msg("invalid range start for blob upload")

		return -1, errors.ErrBadUploadRange
	}

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(body)
	if err != nil {
		is.log.Error().Err(err).Msg("failed to read blob")
		return -1, err
	}

	n, err := file.Write(buf.Bytes())
	if err != nil {
		is.log.Error().Err(err).Msg("failed to append to file")
		return -1, err
	}

	is.isMultiPartUpload[blobUploadPath] = true

	return int64(n), err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ObjectStorage) BlobUploadInfo(repo string, uuid string) (int64, error) {
	var fileSize int64

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	// if it's not a multipart upload check for the regular empty file
	// created by NewBlobUpload, it should have 0 size every time
	isMultiPartStarted, ok := is.isMultiPartUpload[blobUploadPath]
	if !isMultiPartStarted || !ok {
		fi, err := is.store.Stat(context.Background(), blobUploadPath)
		if err != nil {
			is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")
			return -1, err
		}

		fileSize = fi.Size()
	} else {
		// otherwise get the size of multi parts upload
		fi, err := getMultipartFileWriter(is, blobUploadPath)
		if err != nil {
			is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")
			return -1, err
		}

		fileSize = fi.Size()
	}

	return fileSize, nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ObjectStorage) FinishBlobUpload(repo string, uuid string, body io.Reader, digest string) error {
	dstDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return errors.ErrBadBlobDigest
	}

	src := is.BlobUploadPath(repo, uuid)

	// complete multiUploadPart
	fileWriter, err := is.store.Writer(context.Background(), src, true)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return errors.ErrBadBlobDigest
	}

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
		return errors.ErrUploadNotFound
	}

	srcDigest, err := godigest.FromReader(fileReader)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return errors.ErrBadBlobDigest
	}

	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")
		return errors.ErrBadBlobDigest
	}

	fileReader.Close()

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe {
		actualdst := actualBlobPath(is.RootDir(), dstDigest)

		// check if same file before continuing, otherwise rewrite file
		_, err = is.store.Stat(context.Background(), actualdst)
		if err != nil {
			if !isPathNotFoundErr(err) {
				return err
			}

			if err := is.store.Move(context.Background(), src, actualdst); err != nil {
				is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
					Str("dst", dst).Msg("unable to finish blob")
				return err
			}
		} else {
			err := is.store.Delete(context.Background(), src)
			if err != nil {
				is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
					Msg("unable to remove blob upload")
				return err
			}
		}

		// write file containing the path to the actual blob
		if err := is.store.PutContent(context.Background(), dst, []byte(actualdst)); err != nil {
			is.log.Error().Err(err).Str("dst", dst).Msg("unable to write blob")
			return err
		}

		err = is.putBlobsLink(dstDigest, dst)
		if err != nil {
			is.log.Error().Err(err).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("unable to store blob links info")
			return err
		}
	} else if err := is.store.Move(context.Background(), src, dst); err != nil {
		is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
			Str("dst", dst).Msg("unable to finish blob")
		return err
	}

	// remove multipart upload, not needed anymore
	delete(is.isMultiPartUpload, src)

	return nil
}

func (is *ObjectStorage) deleteBlobsLink(actualBlobDigest godigest.Digest, blobPath string) error {
	lb, err := loadLinkedBlobs(is)
	if err != nil {
		return err
	}

	d := actualBlobDigest.String()

	linkedBlobs := lb.Links[d]

	j := 0

	for _, path := range linkedBlobs {
		if blobPath != path {
			linkedBlobs[j] = path
			j++
		}
	}

	linkedBlobs = linkedBlobs[:j]
	lb.Links[d] = linkedBlobs

	if len(lb.Links[d]) == 0 {
		// remove entry
		err := is.store.Delete(context.Background(), actualBlobPath(is.rootDir, actualBlobDigest))
		if err != nil {
			is.log.Error().Err(err).Str("path", actualBlobPath(is.rootDir, actualBlobDigest)).Msg("couldn't delete blob")
			return err
		}
	}

	err = dumpLinkedBlobs(is, lb)
	if err != nil {
		return err
	}

	return nil
}

func (is *ObjectStorage) putBlobsLink(actualBlobDigest godigest.Digest, blobPath string) error {
	lb, err := loadLinkedBlobs(is)
	if err != nil {
		return err
	}

	d := actualBlobDigest.String()

	if len(lb.Links) == 0 {
		lb.Links = make(map[string][]string)
	}

	if len(lb.Links[d]) == 0 {
		lb.Links[d] = []string{blobPath}
	} else {
		lb.Links[d] = append(lb.Links[d], blobPath)
	}

	err = dumpLinkedBlobs(is, lb)
	if err != nil {
		return err
	}

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
		return "", -1, errors.ErrBadBlobDigest
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

	n, err := writeFile(is.store, src, buf.Bytes())
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
		return "", -1, errors.ErrBadBlobDigest
	}

	is.Lock()
	defer is.Unlock()

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe {
		actualdst := actualBlobPath(is.RootDir(), dstDigest)

		// check if same file before continuing, otherwise rewrite file
		_, err = is.store.Stat(context.Background(), actualdst)
		if err != nil {
			if isPathNotFoundErr(err) {
				if err := is.store.Move(context.Background(), src, actualdst); err != nil {
					is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
						Str("dst", dst).Msg("unable to finish blob")
					return "", -1, err
				}
			} else {
				return "", -1, err
			}
		} else {
			err := is.store.Delete(context.Background(), src)
			if err != nil {
				is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
					Msg("unable to remove blob upload")
				return "", -1, err
			}
		}

		// write file containing the path to the actual blob
		if err := is.store.PutContent(context.Background(), dst, []byte(actualdst)); err != nil {
			is.log.Error().Err(err).Str("dst", dst).Msg("unable to write blob")
			return "", -1, err
		}

		err = is.putBlobsLink(dstDigest, dst)
		if err != nil {
			is.log.Error().Err(err).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("unable to store blobs links info")
			return "", -1, err
		}
	} else if err := is.store.Move(context.Background(), src, dst); err != nil {
		is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
			Str("dst", dst).Msg("unable to finish blob")
		return "", -1, err
	}

	return uuid, int64(n), nil
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

func (is *ObjectStorage) checkDedupedBlob(repo string, d digest.Digest) (bool, int64, error) {
	is.Lock()
	defer is.Unlock()

	if !is.dedupe {
		return false, -1, errors.ErrBlobNotFound
	}

	blobPath := is.BlobPath(repo, d)

	buf, err := is.store.GetContent(context.Background(), blobPath)
	if err != nil {
		if !isPathNotFoundErr(err) {
			return false, -1, err
		}

		realBlobPath := actualBlobPath(is.rootDir, d)

		// if  blob not found, we may find it in cache
		blobInfo, err := is.store.Stat(context.Background(), realBlobPath)
		if err != nil {
			if isPathNotFoundErr(err) {
				return false, -1, errors.ErrBlobNotFound
			}

			return false, -1, err
		}

		err = is.store.PutContent(context.Background(), blobPath, []byte(blobPath))
		if err != nil {
			return false, -1, err
		}

		err = is.putBlobsLink(d, blobPath)
		if err != nil {
			is.log.Error().Err(err).Str("dstDigest", d.String()).Str("dst", blobPath).Msg("unable to write liked blobs info")
			return false, -1, err
		}

		return true, blobInfo.Size(), nil
	}

	realBlobPath := string(buf)

	blobInfo, err := is.store.Stat(context.Background(), realBlobPath)
	if err != nil {
		if isPathNotFoundErr(err) {
			// remove out-of-sync blobPath
			err := is.store.Delete(context.Background(), blobPath)
			if err != nil {
				return false, -1, err
			}

			// remove out-of-sync link
			err = is.deleteBlobsLink(d, blobPath)
			if err != nil {
				return false, -1, err
			}

			return false, -1, errors.ErrBlobNotFound
		}

		return false, -1, err
	}

	return true, blobInfo.Size(), nil
}

// CheckBlob verifies a blob and returns true if the blob is correct.
func (is *ObjectStorage) CheckBlob(repo string, digest string) (bool, int64, error) {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return false, -1, errors.ErrBadBlobDigest
	}

	if is.dedupe {
		return is.checkDedupedBlob(repo, d)
	}

	blobPath := is.BlobPath(repo, d)

	is.RLock()
	defer is.RUnlock()

	blobInfo, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		if isPathNotFoundErr(err) {
			return false, -1, errors.ErrBlobNotFound
		}

		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return false, -1, err
	}

	is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

	return true, blobInfo.Size(), nil
}

// GetBlob returns a stream to read the blob.
// FIXME: we should probably parse the manifest and use (digest, mediaType) as a
// blob selector instead of directly downloading the blob.
func (is *ObjectStorage) GetBlob(repo string, digest string, mediaType string) (io.Reader, int64, error) {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return nil, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

	is.RLock()
	defer is.RUnlock()

	if is.dedupe {
		buf, err := is.store.GetContent(context.Background(), blobPath)
		if err != nil {
			if isPathNotFoundErr(err) {
				return nil, -1, errors.ErrBlobNotFound
			}

			return nil, -1, err
		}

		realBlobPath := string(buf)

		blobInfo, err := is.store.Stat(context.Background(), realBlobPath)
		if err != nil {
			if isPathNotFoundErr(err) {
				// remove blob which points to realBlob
				err := is.store.Delete(context.Background(), blobPath)
				if err != nil {
					return nil, -1, err
				}

				return nil, -1, errors.ErrBlobNotFound
			}

			return nil, -1, err
		}

		blobReader, err := is.store.Reader(context.Background(), realBlobPath, 0)
		if err != nil {
			is.log.Error().Err(err).Str("blob", realBlobPath).Msg("failed to open blob")
			return nil, -1, err
		}

		return blobReader, blobInfo.Size(), nil
	}

	blobInfo, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return nil, -1, errors.ErrBlobNotFound
	}

	blobReader, err := is.store.Reader(context.Background(), blobPath, 0)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")
		return nil, -1, err
	}

	return blobReader, blobInfo.Size(), nil
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

func (is *ObjectStorage) GetIndexContent(repo string) ([]byte, error) {
	dir := path.Join(is.rootDir, repo)

	buf, err := is.store.GetContent(context.Background(), path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
		return []byte{}, errors.ErrRepoNotFound
	}

	return buf, nil
}

// DeleteBlob removes the blob from the repository.
func (is *ObjectStorage) DeleteBlob(repo string, digest string) error {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return errors.ErrBlobNotFound
	}

	blobPath := is.BlobPath(repo, d)

	is.Lock()
	defer is.Unlock()

	_, err = is.store.Stat(context.Background(), blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return errors.ErrBlobNotFound
	}

	if err := is.store.Delete(context.Background(), blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to remove blob path")
		return err
	}

	if is.dedupe {
		if err := is.deleteBlobsLink(d, blobPath); err != nil {
			return err
		}
	}

	return nil
}

// Do not use for multipart upload, buf must not be empty.
// If you want to create an empty file use is.store.PutContent().
func writeFile(store storageDriver.StorageDriver, filepath string, buf []byte) (int, error) {
	var n int

	if fw, err := store.Writer(context.Background(), filepath, false); err == nil {
		defer fw.Close()

		if n, err = fw.Write(buf); err != nil {
			return -1, err
		}

		if err := fw.Commit(); err != nil {
			return -1, err
		}
	} else {
		return -1, err
	}

	return n, nil
}

// Because we can not create an empty multipart upload, we store multi part uploads
// so that we know when to create a fileWriter with append=true or with append=false.
func getMultipartFileWriter(is *ObjectStorage, filepath string) (storageDriver.FileWriter, error) {
	var file storageDriver.FileWriter

	var err error

	isMultiPartStarted, ok := is.isMultiPartUpload[filepath]
	if !isMultiPartStarted || !ok {
		file, err = is.store.Writer(context.Background(), filepath, false)
		if err != nil {
			return file, err
		}
	} else {
		file, err = is.store.Writer(context.Background(), filepath, true)
		if err != nil {
			return file, err
		}
	}

	return file, nil
}

func isPathNotFoundErr(err error) bool {
	_, ok := err.(storageDriver.PathNotFoundError)
	return ok
}
