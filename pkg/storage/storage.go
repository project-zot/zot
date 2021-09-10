package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"	
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anuvu/zot/pkg/extensions/monitoring"
	"github.com/anuvu/zot/errors"
	zlog "github.com/anuvu/zot/pkg/log"
	apexlog "github.com/apex/log"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/casext"
	"github.com/rs/zerolog"
)

const (
	// BlobUploadDir defines the upload directory for blob uploads.
	BlobUploadDir = ".uploads"
	schemaVersion = 2
	gcDelay       = 1 * time.Hour
)

// BlobUpload models and upload request.
type BlobUpload struct {
	StoreName string
	ID        string
}

type StoreController struct {
	DefaultStore *ImageStore
	SubStore     map[string]*ImageStore
}

// ImageStore provides the image storage operations.
type ImageStore struct {
	rootDir     string
	lock        *sync.RWMutex
	blobUploads map[string]BlobUpload
	cache       *Cache
	gc          bool
	dedupe      bool
	log         zerolog.Logger
}

func (is *ImageStore) RootDir() string {
	return is.rootDir
}

func getRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2)

	if len(names) != 2 { // nolint: gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

func (sc StoreController) GetImageStore(name string) *ImageStore {
	if sc.SubStore != nil {
		// SubStore is being provided, now we need to find equivalent image store and this will be found by splitting name
		prefixName := getRoutePrefix(name)

		imgStore, ok := sc.SubStore[prefixName]
		if !ok {
			imgStore = sc.DefaultStore
		}

		return imgStore
	}

	return sc.DefaultStore
}

// NewImageStore returns a new image store backed by a file storage.
func NewImageStore(rootDir string, gc bool, dedupe bool, log zlog.Logger) *ImageStore {
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		if err := os.MkdirAll(rootDir, 0700); err != nil {
			log.Error().Err(err).Str("rootDir", rootDir).Msg("unable to create root dir")
			return nil
		}
	}

	is := &ImageStore{
		rootDir:     rootDir,
		lock:        &sync.RWMutex{},
		blobUploads: make(map[string]BlobUpload),
		gc:          gc,
		dedupe:      dedupe,
		log:         log.With().Caller().Logger(),
	}

	if dedupe {
		is.cache = NewCache(rootDir, "cache", log)
	}

	if gc {
		// we use umoci GC to perform garbage-collection, but it uses its own logger
		// - so capture those logs, could be useful
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

	return is
}

// RLock read-lock.
func (is *ImageStore) RLock() {
	is.lock.RLock()
}

// RUnlock read-unlock.
func (is *ImageStore) RUnlock() {
	is.lock.RUnlock()
}

// Lock write-lock.
func (is *ImageStore) Lock() {
	is.lock.Lock()
}

// Unlock write-unlock.
func (is *ImageStore) Unlock() {
	is.lock.Unlock()
}
func (is *ImageStore) initRepo(name string) error {
	repoDir := path.Join(is.rootDir, name)

	// create "blobs" subdir
	err := ensureDir(path.Join(repoDir, "blobs"), is.log)
	if err != nil {
		is.log.Error().Err(err).Msg("error creating blobs subdir")

		return err
	}
	// create BlobUploadDir subdir
	err = ensureDir(path.Join(repoDir, BlobUploadDir), is.log)
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

		if err := ioutil.WriteFile(ilPath, buf, 0644); err != nil { //nolint: gosec
			is.log.Error().Err(err).Str("file", ilPath).Msg("unable to write file")
			return err
		}
	}

	// "index.json" file - create if it doesn't exist
	indexPath := path.Join(repoDir, "index.json")
	if _, err := os.Stat(indexPath); err != nil {
		index := ispec.Index{}
		index.SchemaVersion = 2
		buf, err := json.Marshal(index)

		if err != nil {
			is.log.Panic().Err(err).Msg("unable to marshal JSON")
		}

		if err := ioutil.WriteFile(indexPath, buf, 0644); err != nil { //nolint: gosec
			is.log.Error().Err(err).Str("file", indexPath).Msg("unable to write file")
			return err
		}
	}

	return nil
}

// InitRepo creates an image repository under this store.
func (is *ImageStore) InitRepo(name string) error {
	is.Lock()
	defer is.Unlock()

	return is.initRepo(name)
}

// ValidateRepo validates that the repository layout is complaint with the OCI repo layout.
func (is *ImageStore) ValidateRepo(name string) (bool, error) {
	// https://github.com/opencontainers/image-spec/blob/master/image-layout.md#content
	// at least, expect at least 3 entries - ["blobs", "oci-layout", "index.json"]
	// and an additional/optional BlobUploadDir in each image store
	dir := path.Join(is.rootDir, name)
	if !dirExists(dir) {
		return false, errors.ErrRepoNotFound
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")
		return false, errors.ErrRepoNotFound
	}
	// nolint:gomnd
	if len(files) < 3 {
		return false, errors.ErrRepoBadVersion
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
		if !v && k != BlobUploadDir {
			return false, nil
		}
	}

	buf, err := ioutil.ReadFile(path.Join(dir, ispec.ImageLayoutFile))
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
func (is *ImageStore) GetRepositories() ([]string, error) {
	dir := is.rootDir

	is.RLock()
	defer is.RUnlock()

	_, err := ioutil.ReadDir(dir)
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
			return nil
		}

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil
		}

		//is.log.Debug().Str("dir", path).Str("name", info.Name()).Msg("found image store")
		stores = append(stores, rel)

		return nil
	})

	return stores, err
}

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ImageStore) GetImageTags(repo string) ([]string, error) {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return nil, errors.ErrRepoNotFound
	}

	is.RLock()
	defer is.RUnlock()

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
		return nil, errors.ErrRepoNotFound
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
func (is *ImageStore) GetImageManifest(repo string, reference string) ([]byte, string, string, error) {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return nil, "", "", errors.ErrRepoNotFound
	}

	is.RLock()
	defer is.RUnlock()

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		if os.IsNotExist(err) {
			return nil, "", "", errors.ErrRepoNotFound
		}

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

	buf, err = ioutil.ReadFile(p)

	if err != nil {
		is.log.Error().Err(err).Str("blob", p).Msg("failed to read manifest")

		if os.IsNotExist(err) {
			return nil, "", "", errors.ErrManifestNotFound
		}

		return nil, "", "", err
	}

	var manifest ispec.Manifest
	if err := json.Unmarshal(buf, &manifest); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return nil, "", "", err
	}

	monitoring.IncDownloadCounter(repo)

	return buf, digest.String(), mediaType, nil
}

// PutImageManifest adds an image manifest to the repository.
func (is *ImageStore) PutImageManifest(repo string, reference string, mediaType string,
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

		if _, err := os.Stat(blobPath); err != nil {
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
	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
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
	_ = ensureDir(dir, is.log)
	file := path.Join(dir, mDigest.Encoded())

	if err := ioutil.WriteFile(file, body, 0600); err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to write")
		return "", err
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	file = path.Join(dir, "index.json")
	buf, err = json.Marshal(index)

	if err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to marshal JSON")
		return "", err
	}

	if err := ioutil.WriteFile(file, buf, 0644); err != nil { //nolint: gosec
		is.log.Error().Err(err).Str("file", file).Msg("unable to write")
		return "", err
	}

	if is.gc {
		oci, err := umoci.OpenLayout(dir)
		if err != nil {
			return "", err
		}
		defer oci.Close()

		if err := oci.GC(context.Background(), ifOlderThan(is, repo, gcDelay)); err != nil {
			return "", err
		}
	}

	monitoring.SetStorageUsage(repo, is.rootDir)
	monitoring.IncUploadCounter(repo)

	return desc.Digest.String(), nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ImageStore) DeleteImageManifest(repo string, reference string) error {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return errors.ErrRepoNotFound
	}

	isTag := false

	// as per spec "reference" can be a digest and a tag
	digest, err := godigest.Parse(reference)
	if err != nil {
		is.log.Debug().Str("invalid digest: ", reference).Msg("storage: assuming tag")

		isTag = true
	}

	is.Lock()
	defer is.Unlock()

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))

	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
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

	if err := ioutil.WriteFile(file, buf, 0644); err != nil { //nolint: gosec
		return err
	}

	if is.gc {
		oci, err := umoci.OpenLayout(dir)
		if err != nil {
			return err
		}
		defer oci.Close()

		if err := oci.GC(context.Background(), ifOlderThan(is, repo, gcDelay)); err != nil {
			return err
		}
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

		_ = os.Remove(p)
	}

	monitoring.SetStorageUsage(repo, is.rootDir)

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ImageStore) BlobUploadPath(repo string, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, BlobUploadDir, uuid)

	return blobUploadPath
}

// NewBlobUpload returns the unique ID for an upload in progress.
func (is *ImageStore) NewBlobUpload(repo string) (string, error) {
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

	file, err := os.OpenFile(blobUploadPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return "", errors.ErrRepoNotFound
	}
	defer file.Close()

	return u, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ImageStore) GetBlobUpload(repo string, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	fi, err := os.Stat(blobUploadPath)

	if err != nil {
		if os.IsNotExist(err) {
			return -1, errors.ErrUploadNotFound
		}

		return -1, err
	}

	return fi.Size(), nil
}

// PutBlobChunkStreamed appends another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunkStreamed(repo string, uuid string, body io.Reader) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	_, err := os.Stat(blobUploadPath)
	if err != nil {
		return -1, errors.ErrUploadNotFound
	}

	file, err := os.OpenFile(
		blobUploadPath,
		os.O_WRONLY|os.O_CREATE,
		0600,
	)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to open file")
	}
	defer file.Close()

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		is.log.Fatal().Err(err).Msg("failed to seek file")
	}

	n, err := io.Copy(file, body)

	return n, err
}

// PutBlobChunk writes another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunk(repo string, uuid string, from int64, to int64,
	body io.Reader) (int64, error) {
	if err := is.InitRepo(repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	fi, err := os.Stat(blobUploadPath)
	if err != nil {
		return -1, errors.ErrUploadNotFound
	}

	if from != fi.Size() {
		is.log.Error().Int64("expected", from).Int64("actual", fi.Size()).
			Msg("invalid range start for blob upload")
		return -1, errors.ErrBadUploadRange
	}

	file, err := os.OpenFile(
		blobUploadPath,
		os.O_WRONLY|os.O_CREATE,
		0600,
	)
	if err != nil {
		is.log.Fatal().Err(err).Msg("failed to open file")
	}
	defer file.Close()

	if _, err := file.Seek(from, io.SeekStart); err != nil {
		is.log.Fatal().Err(err).Msg("failed to seek file")
	}

	n, err := io.Copy(file, body)

	return n, err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ImageStore) BlobUploadInfo(repo string, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	fi, err := os.Stat(blobUploadPath)

	if err != nil {
		is.log.Error().Err(err).Str("blob", blobUploadPath).Msg("failed to stat blob")
		return -1, err
	}

	size := fi.Size()

	return size, nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ImageStore) FinishBlobUpload(repo string, uuid string, body io.Reader, digest string) error {
	dstDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return errors.ErrBadBlobDigest
	}

	src := is.BlobUploadPath(repo, uuid)

	_, err = os.Stat(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to stat blob")
		return errors.ErrUploadNotFound
	}

	f, err := os.Open(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return errors.ErrUploadNotFound
	}

	srcDigest, err := godigest.FromReader(f)
	f.Close()

	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return errors.ErrBadBlobDigest
	}

	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")
		return errors.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())

	is.Lock()
	defer is.Unlock()

	err = ensureDir(dir, is.log)
	if err != nil {
		is.log.Error().Err(err).Msg("error creating blobs/sha256 dir")

		return err
	}

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && is.cache != nil {
		if err := is.DedupeBlob(src, dstDigest, dst); err != nil {
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
func (is *ImageStore) FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error) {
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

	f, err := os.Create(src)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")
		return "", -1, errors.ErrUploadNotFound
	}

	defer f.Close()

	digester := sha256.New()
	mw := io.MultiWriter(f, digester)
	n, err := io.Copy(mw, body)

	if err != nil {
		return "", -1, err
	}

	srcDigest := godigest.NewDigestFromEncoded(godigest.SHA256, fmt.Sprintf("%x", digester.Sum(nil)))
	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")
		return "", -1, errors.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, "blobs", dstDigest.Algorithm().String())

	is.Lock()
	defer is.Unlock()

	_ = ensureDir(dir, is.log)
	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && is.cache != nil {
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

	return uuid, n, nil
}

// nolint:interfacer
func (is *ImageStore) DedupeBlob(src string, dstDigest godigest.Digest, dst string) error {
retry:
	is.log.Debug().Str("src", src).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: ENTER")

	dstRecord, err := is.cache.GetBlob(dstDigest.String())

	// nolint:goerr113
	if err != nil && err != errors.ErrCacheMiss {
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
			if err := is.cache.DeleteBlob(dstDigest.String(), dstRecord); err != nil {
				// nolint:lll
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

			is.log.Debug().Str("blobPath", dst).Msg("dedupe: creating hard link")

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
func (is *ImageStore) DeleteBlobUpload(repo string, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	if err := os.Remove(blobUploadPath); err != nil {
		is.log.Error().Err(err).Str("blobUploadPath", blobUploadPath).Msg("error deleting blob upload")
		return err
	}

	return nil
}

// BlobPath returns the repository path of a blob.
func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
	return path.Join(is.rootDir, repo, "blobs", digest.Algorithm().String(), digest.Encoded())
}

// CheckBlob verifies a blob and returns true if the blob is correct.
func (is *ImageStore) CheckBlob(repo string, digest string) (bool, int64, error) {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return false, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

	if is.dedupe && is.cache != nil {
		is.Lock()
		defer is.Unlock()
	} else {
		is.RLock()
		defer is.RUnlock()
	}

	blobInfo, err := os.Stat(blobPath)
	if err == nil {
		is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

		return true, blobInfo.Size(), nil
	}

	is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

	// Check blobs in cache
	dstRecord, err := is.checkCacheBlob(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("cache: not found")

		return false, -1, errors.ErrBlobNotFound
	}

	// If found copy to location
	blobSize, err := is.copyBlob(repo, blobPath, dstRecord)
	if err != nil {
		return false, -1, errors.ErrBlobNotFound
	}

	if err := is.cache.PutBlob(digest, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("dedupe: unable to insert blob record")

		return false, -1, err
	}

	return true, blobSize, nil
}

func (is *ImageStore) checkCacheBlob(digest string) (string, error) {
	if !is.dedupe || is.cache == nil {
		return "", errors.ErrBlobNotFound
	}

	dstRecord, err := is.cache.GetBlob(digest)
	if err != nil {
		return "", err
	}

	dstRecord = path.Join(is.rootDir, dstRecord)

	is.log.Debug().Str("digest", digest).Str("dstRecord", dstRecord).Msg("cache: found dedupe record")

	return dstRecord, nil
}

func (is *ImageStore) copyBlob(repo string, blobPath string, dstRecord string) (int64, error) {
	if err := is.initRepo(repo); err != nil {
		is.log.Error().Err(err).Str("repo", repo).Msg("unable to initialize an empty repo")
		return -1, err
	}

	_ = ensureDir(filepath.Dir(blobPath), is.log)

	if err := os.Link(dstRecord, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Str("link", dstRecord).Msg("dedupe: unable to hard link")

		return -1, errors.ErrBlobNotFound
	}

	blobInfo, err := os.Stat(blobPath)
	if err == nil {
		return blobInfo.Size(), nil
	}

	return -1, errors.ErrBlobNotFound
}

// GetBlob returns a stream to read the blob.
// FIXME: we should probably parse the manifest and use (digest, mediaType) as a
// blob selector instead of directly downloading the blob.
func (is *ImageStore) GetBlob(repo string, digest string, mediaType string) (io.Reader, int64, error) {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return nil, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

	is.RLock()
	defer is.RUnlock()

	blobInfo, err := os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return nil, -1, errors.ErrBlobNotFound
	}

	blobReader, err := os.Open(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to open blob")
		return nil, -1, err
	}

	return blobReader, blobInfo.Size(), nil
}

// DeleteBlob removes the blob from the repository.
func (is *ImageStore) DeleteBlob(repo string, digest string) error {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return errors.ErrBlobNotFound
	}

	blobPath := is.BlobPath(repo, d)

	is.Lock()
	defer is.Unlock()

	_, err = os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return errors.ErrBlobNotFound
	}

	if is.cache != nil {
		if err := is.cache.DeleteBlob(digest, blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", digest).Str("blobPath", blobPath).Msg("unable to remove blob path from cache")
			return err
		}
	}

	if err := os.Remove(blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to remove blob path")
		return err
	}

	return nil
}

// garbage collection

// Scrub will clean up all unreferenced blobs.
// TODO.
func Scrub(dir string, fix bool) error {
	return nil
}

// utility routines

func CheckHardLink(srcFileName string, destFileName string) error {
	return os.Link(srcFileName, destFileName)
}

func ValidateHardLink(rootDir string) error {
	err := ioutil.WriteFile(path.Join(rootDir, "hardlinkcheck.txt"), //nolint: gosec
		[]byte("check whether hardlinks work on filesystem"), 0644)
	if err != nil {
		return err
	}

	err = CheckHardLink(path.Join(rootDir, "hardlinkcheck.txt"), path.Join(rootDir, "duphardlinkcheck.txt"))
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

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fi.IsDir() {
		return false
	}

	return true
}

func ensureDir(dir string, log zerolog.Logger) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Error().Err(err).Str("dir", dir).Msg("unable to create dir")

		return err
	}

	return nil
}

func ifOlderThan(is *ImageStore, repo string, delay time.Duration) casext.GCPolicy {
	return func(ctx context.Context, digest godigest.Digest) (bool, error) {
		blobPath := is.BlobPath(repo, digest)
		fi, err := os.Stat(blobPath)

		if err != nil {
			return false, err
		}

		if fi.ModTime().Add(delay).After(time.Now()) {
			return false, nil
		}

		is.log.Info().Str("digest", digest.String()).Str("blobPath", blobPath).Msg("perform GC on blob")

		return true, nil
	}
}
