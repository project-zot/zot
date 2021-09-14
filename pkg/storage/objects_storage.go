package storage

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
	zlog "github.com/anuvu/zot/pkg/log"
	"github.com/docker/distribution/registry/storage/driver/factory"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"

	// Add s3 support
	storageDriver "github.com/docker/distribution/registry/storage/driver"
	_ "github.com/docker/distribution/registry/storage/driver/s3-aws" // Load s3 driver
)

// ObjectStorage provides the image storage operations.
type ObjectStorage struct {
	rootDir     string
	store       storageDriver.StorageDriver
	lock        *sync.RWMutex
	blobUploads map[string]BlobUpload
	log         zerolog.Logger
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

// NewObjectStorage returns a new image store backed by a file storage.
func NewObjectStorage(rootDir string, gc bool, dedupe bool, log zlog.Logger,
	objectStoreParams map[string]interface{}) ImageStore {
	storeName := fmt.Sprintf("%v", objectStoreParams["name"])

	// Init a Storager from connection string.
	store, err := factory.Create(storeName, objectStoreParams)
	if err != nil {
		log.Error().Err(err).Str("rootDir", rootDir).Msg("Unable to create s3 service")
		return nil
	}

	is := &ObjectStorage{
		rootDir:     rootDir,
		store:       store,
		lock:        &sync.RWMutex{},
		blobUploads: make(map[string]BlobUpload),
		log:         log.With().Caller().Logger(),
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

	if fi, err := is.store.Stat(context.Background(), repoDir); err == nil && fi.IsDir() {
		return nil
	}

	// "oci-layout" file - create if it doesn't exist
	ilPath := path.Join(repoDir, ispec.ImageLayoutFile)
	if _, err := is.store.Stat(context.Background(), ilPath); err != nil {
		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}
		buf, err := json.Marshal(il)

		if err != nil {
			is.log.Panic().Err(err).Msg("unable to marshal JSON")
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
			is.log.Panic().Err(err).Msg("unable to marshal JSON")
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
	dir := path.Join(is.rootDir, name)
	if fi, err := is.store.Stat(context.Background(), dir); err != nil || !fi.IsDir() {
		return false, errors.ErrRepoNotFound
	}

	files, err := is.store.List(context.Background(), dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")
		return false, errors.ErrRepoNotFound
	}

	is.log.Info().Msgf("files : %v", files)

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
		if !v && k != BlobUploadDir {
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
	_, ok := err.(storageDriver.PathNotFoundError)
	if ok {
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

	if m.SchemaVersion != schemaVersion {
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
	}

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

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ObjectStorage) BlobUploadPath(repo string, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, BlobUploadDir, uuid)

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

	err = is.store.PutContent(context.Background(), blobUploadPath, []byte{})
	if err != nil {
		return "", errors.ErrRepoNotFound
	}

	return u, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ObjectStorage) GetBlobUpload(repo string, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	fi, err := is.store.Stat(context.Background(), blobUploadPath)

	if err != nil {
		return -1, err
	}

	return fi.Size(), nil
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

	file, err := getMultipartFileWriter(is.store, blobUploadPath)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to create multipart upload")
		return -1, err
	}

	defer file.Close()

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(body)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to read blob")
	}

	n, err := file.Write(buf.Bytes())
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to append to file")
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

	fi, err := is.store.Stat(context.Background(), blobUploadPath)
	if err != nil {
		return -1, errors.ErrUploadNotFound
	}

	if from != fi.Size() {
		is.log.Error().Int64("expected", from).Int64("actual", fi.Size()).
			Msg("invalid range start for blob upload")
		return -1, errors.ErrBadUploadRange
	}

	file, err := getMultipartFileWriter(is.store, blobUploadPath)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to create multipart upload")
		return -1, err
	}

	defer file.Close()

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(body)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to read blob")
	}

	n, err := file.Write(buf.Bytes())
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to append to file")
	}

	return int64(n), err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ObjectStorage) BlobUploadInfo(repo string, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	fi, err := is.store.Stat(context.Background(), blobUploadPath)

	if err != nil {
		is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")
		return -1, err
	}

	size := fi.Size()

	return size, nil
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
		return err
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

	err = fileReader.Close()
	if err != nil {
		return err
	}

	dst := is.BlobPath(repo, dstDigest)

	if err := is.store.Move(context.Background(), src, dst); err != nil {
		is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
			Str("dst", dst).Msg("unable to finish blob")
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
		is.log.Fatal().Err(err).Msg("failed to read blob")
	}

	n, err := writeFile(is.store, src, buf.Bytes())
	if err != nil {
		return "", -1, err
	}

	_, err = digester.Write(buf.Bytes())
	if err != nil {
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

	if err := is.store.Move(context.Background(), src, dst); err != nil {
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

// CheckBlob verifies a blob and returns true if the blob is correct.
func (is *ObjectStorage) CheckBlob(repo string, digest string) (bool, int64, error) {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return false, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

	is.RLock()
	defer is.RUnlock()

	blobInfo, err := is.store.Stat(context.Background(), blobPath)
	if err != nil {
		_, ok := err.(storageDriver.PathNotFoundError)
		if ok {
			return false, -1, errors.ErrBlobNotFound
		}

		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return false, -1, errors.ErrBadBlobDigest
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
		is.log.Fatal().Err(err).Msg("failed to read blob")
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

// Because we can not create an empty multipart upload, we first try to get a multipart upload session,
// otherwise we create it.
func getMultipartFileWriter(store storageDriver.StorageDriver, filepath string) (storageDriver.FileWriter, error) {
	file, err := store.Writer(context.Background(), filepath, false)
	if err != nil {
		// multipart upload already created
		file, err = store.Writer(context.Background(), filepath, true)
		if err != nil {
			return file, err
		}
	}

	return file, nil
}
