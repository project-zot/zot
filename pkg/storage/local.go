package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	apexlog "github.com/apex/log"
	guuid "github.com/gofrs/uuid"
	"github.com/minio/sha256-simd"
	"github.com/notaryproject/notation-go-lib"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/opencontainers/umoci/oci/casext"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	"github.com/sigstore/cosign/pkg/oci/remote"
	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/test"
)

const (
	// BlobUploadDir defines the upload directory for blob uploads.
	BlobUploadDir    = ".uploads"
	SchemaVersion    = 2
	DefaultFilePerms = 0o600
	DefaultDirPerms  = 0o700
	RLOCK            = "RLock"
	RWLOCK           = "RWLock"
)

// BlobUpload models and upload request.
type BlobUpload struct {
	StoreName string
	ID        string
}

type StoreController struct {
	DefaultStore ImageStore
	SubStore     map[string]ImageStore
}

// ImageStoreLocal provides the image storage operations.
type ImageStoreLocal struct {
	rootDir     string
	lock        *sync.RWMutex
	blobUploads map[string]BlobUpload
	cache       *Cache
	gc          bool
	dedupe      bool
	commit      bool
	gcDelay     time.Duration
	log         zerolog.Logger
	metrics     monitoring.MetricServer
	linter      Lint
}

func (is *ImageStoreLocal) RootDir() string {
	return is.rootDir
}

func (is *ImageStoreLocal) DirExists(d string) bool {
	return DirExists(d)
}

func getRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2) //nolint:gomnd

	if len(names) != 2 { //nolint:gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

func (sc StoreController) GetImageStore(name string) ImageStore {
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
func NewImageStore(rootDir string, gc bool, gcDelay time.Duration, dedupe, commit bool,
	log zlog.Logger, metrics monitoring.MetricServer, linter Lint,
) ImageStore {
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		if err := os.MkdirAll(rootDir, DefaultDirPerms); err != nil {
			log.Error().Err(err).Str("rootDir", rootDir).Msg("unable to create root dir")

			return nil
		}
	}

	imgStore := &ImageStoreLocal{
		rootDir:     rootDir,
		lock:        &sync.RWMutex{},
		blobUploads: make(map[string]BlobUpload),
		gc:          gc,
		gcDelay:     gcDelay,
		dedupe:      dedupe,
		commit:      commit,
		log:         log.With().Caller().Logger(),
		metrics:     metrics,
		linter:      linter,
	}

	if dedupe {
		imgStore.cache = NewCache(rootDir, "cache", true, log)
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
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), RLOCK) // histogram
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
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), RWLOCK) // histogram
}

func (is *ImageStoreLocal) initRepo(name string) error {
	repoDir := path.Join(is.rootDir, name)

	if !utf8.ValidString(name) {
		is.log.Error().Msg("input is not valid UTF-8")

		return zerr.ErrInvalidRepositoryName
	}

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

		if err := is.writeFile(ilPath, buf); err != nil {
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
	dir := path.Join(is.rootDir, name)
	if !is.DirExists(dir) {
		return false, zerr.ErrRepoNotFound
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")

		return false, zerr.ErrRepoNotFound
	}

	if len(files) < 3 { // nolint:gomnd
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
			return nil // nolint:nilerr // ignore paths not relative to root dir
		}

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil // nolint:nilerr // ignore invalid repos
		}

		// is.log.Debug().Str("dir", path).Str("name", info.Name()).Msg("found image store")
		stores = append(stores, rel)

		return nil
	})

	return stores, err
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

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return nil, zerr.ErrRepoNotFound
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
func (is *ImageStoreLocal) GetImageManifest(repo, reference string) ([]byte, string, string, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if !is.DirExists(dir) {
		return nil, "", "", zerr.ErrRepoNotFound
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		if os.IsNotExist(err) {
			return nil, "", "", zerr.ErrRepoNotFound
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

	p := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	buf, err = ioutil.ReadFile(p)

	if err != nil {
		is.log.Error().Err(err).Str("blob", p).Msg("failed to read manifest")

		if os.IsNotExist(err) {
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

	return buf, digest.String(), mediaType, nil
}

func (is *ImageStoreLocal) validateOCIManifest(repo, reference string, manifest *ispec.Manifest) (string, error) {
	if manifest.SchemaVersion != SchemaVersion {
		is.log.Error().Int("SchemaVersion", manifest.SchemaVersion).Msg("invalid manifest")

		return "", zerr.ErrBadManifest
	}

	// validate image config
	config := manifest.Config
	if config.MediaType != ispec.MediaTypeImageConfig {
		return "", zerr.ErrBadManifest
	}

	digest := config.Digest

	blobPath := is.BlobPath(repo, digest)
	if _, err := os.Stat(blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to find blob")

		return digest.String(), zerr.ErrBlobNotFound
	}

	blobFile, err := os.Open(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to find blob")

		return digest.String(), zerr.ErrBlobNotFound
	}

	defer blobFile.Close()

	dec := json.NewDecoder(blobFile)

	var cspec ispec.Image
	if err := dec.Decode(&cspec); err != nil {
		return "", zerr.ErrBadManifest
	}

	// validate the layers
	for _, l := range manifest.Layers {
		digest = l.Digest
		blobPath = is.BlobPath(repo, digest)
		is.log.Info().Str("blobPath", blobPath).Str("reference", reference).Msg("manifest layers")

		if _, err := os.Stat(blobPath); err != nil {
			is.log.Error().Err(err).Str("blobPath", blobPath).Msg("unable to find blob")

			return digest.String(), zerr.ErrBlobNotFound
		}
	}

	return "", nil
}

/**
before an image index manifest is pushed to a repo, its constituent manifests
are pushed first, so when updating/removing this image index manifest, we also
need to determine if there are other image index manifests which refer to the
same constitutent manifests so that they can be garbage-collected correctly

pruneImageManifestsFromIndex is a helper routine to achieve this.
*/
func pruneImageManifestsFromIndex(dir string, digest godigest.Digest, // nolint: gocyclo
	outIndex ispec.Index, otherImgIndexes []ispec.Descriptor, log zerolog.Logger,
) ([]ispec.Descriptor, error) {
	indexPath := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	buf, err := ioutil.ReadFile(indexPath)
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

		buf, err := ioutil.ReadFile(indexPath)
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
func (is *ImageStoreLocal) PutImageManifest(repo, reference, mediaType string, // nolint: gocyclo
	body []byte,
) (string, error) {
	if err := is.InitRepo(repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")

		return "", err
	}

	// validate the manifest
	if !IsSupportedMediaType(mediaType) {
		is.log.Debug().Interface("actual", mediaType).
			Msg("bad manifest media type")

		return "", zerr.ErrBadManifest
	}

	if len(body) == 0 {
		is.log.Debug().Int("len", len(body)).Msg("invalid body length")

		return "", zerr.ErrBadManifest
	}

	dig, err := validateManifest(is, repo, reference, mediaType, body)
	if err != nil {
		return dig, err
	}

	mDigest := godigest.FromBytes(body)
	refIsDigest := false
	d, err := godigest.Parse(reference)

	if err == nil {
		if d.String() != mDigest.String() {
			is.log.Error().Str("actual", mDigest.String()).Str("expected", d.String()).
				Msg("manifest digest is not valid")

			return "", zerr.ErrBadManifest
		}

		refIsDigest = true
	}

	var lockLatency time.Time

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	dir := path.Join(is.rootDir, repo)

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return "", err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return "", zerr.ErrRepoBadVersion
	}

	updateIndex := true
	// create a new descriptor
	desc := ispec.Descriptor{
		MediaType: mediaType, Size: int64(len(body)), Digest: mDigest,
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
				Str("old mediaType", manifest.MediaType).
				Str("new mediaType", mediaType).
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
	_ = ensureDir(dir, is.log)
	file := path.Join(dir, mDigest.Encoded())

	// in case the linter will not pass, it will be garbage collected
	if err := is.writeFile(file, body); err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to write")

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

		prunedManifests, err := pruneImageManifestsFromIndex(dir, oldDgst, index, otherImgIndexes, is.log)
		if err != nil {
			return "", err
		}

		index.Manifests = prunedManifests
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	file = path.Join(dir, "index.json")
	buf, err = json.Marshal(index)

	if err := test.Error(err); err != nil {
		is.log.Error().Err(err).Str("file", file).Msg("unable to marshal JSON")

		return "", err
	}

	// apply linter only on images, not signatures
	if is.linter != nil {
		if mediaType == ispec.MediaTypeImageManifest &&
			// check that image manifest is not cosign signature
			!strings.HasPrefix(reference, "sha256-") &&
			!strings.HasSuffix(reference, remote.SignatureTagSuffix) {
			// lint new index with new manifest before writing to disk
			is.Unlock(&lockLatency)
			pass, err := is.linter.Lint(repo, mDigest, is)
			is.Lock(&lockLatency)
			if err != nil {
				is.log.Error().Err(err).Msg("linter error")

				return "", err
			}

			if !pass {
				return "", zerr.ErrImageLintAnnotations
			}
		}
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

	return desc.Digest.String(), nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ImageStoreLocal) DeleteImageManifest(repo, reference string) error {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if !is.DirExists(dir) {
		return zerr.ErrRepoNotFound
	}

	isTag := false

	// as per spec "reference" can be a digest and a tag
	dgst, err := godigest.Parse(reference)
	if err != nil {
		is.log.Debug().Str("invalid digest: ", reference).Msg("storage: assuming tag")

		isTag = true
	}

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

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

	/* additionally, unmarshal an image index and for all manifests in that
	index, ensure that they do not have a name or they are not in other
	manifest indexes else GC can never clean them */
	if isImageIndex {
		prunedManifests, err := pruneImageManifestsFromIndex(dir, dgst, outIndex, otherImgIndexes, is.log)
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

	for _, manifest = range outIndex.Manifests {
		if dgst.String() == manifest.Digest.String() {
			toDelete = false

			break
		}
	}

	if toDelete {
		p := path.Join(dir, "blobs", dgst.Algorithm().String(), dgst.Encoded())

		_ = os.Remove(p)
	}

	monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ImageStoreLocal) BlobUploadPath(repo, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, BlobUploadDir, uuid)

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
func (is *ImageStoreLocal) FinishBlobUpload(repo, uuid string, body io.Reader, digest string) error {
	dstDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return zerr.ErrBadBlobDigest
	}

	src := is.BlobUploadPath(repo, uuid)

	_, err = os.Stat(src)
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
		is.log.Error().Err(err).Str("repo", repo).Str("blob", src).Str("digest", digest).Msg("unable to compute hash")

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

	if is.dedupe && is.cache != nil {
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
func (is *ImageStoreLocal) FullBlobUpload(repo string, body io.Reader, digest string) (string, int64, error) {
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

	return uuid, nbytes, nil
}

func (is *ImageStoreLocal) DedupeBlob(src string, dstDigest godigest.Digest, dst string) error {
retry:
	is.log.Debug().Str("src", src).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe: enter")

	dstRecord, err := is.cache.GetBlob(dstDigest.String())

	if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		is.log.Error().Err(err).Str("blobPath", dst).Msg("dedupe: unable to lookup blob record")

		return err
	}

	if dstRecord == "" {
		// cache record doesn't exist, so first disk and cache entry for this diges
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
func (is *ImageStoreLocal) CheckBlob(repo, digest string) (bool, int64, error) {
	var lockLatency time.Time

	parsedDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return false, -1, zerr.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, parsedDigest)

	if is.dedupe && is.cache != nil {
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
		is.log.Error().Err(err).Str("digest", digest).Msg("cache: not found")

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

func (is *ImageStoreLocal) checkCacheBlob(digest string) (string, error) {
	if !is.dedupe || is.cache == nil {
		return "", zerr.ErrBlobNotFound
	}

	dstRecord, err := is.cache.GetBlob(digest)
	if err != nil {
		return "", err
	}

	dstRecord = path.Join(is.rootDir, dstRecord)

	is.log.Debug().Str("digest", digest).Str("dstRecord", dstRecord).Msg("cache: found dedupe record")

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

// GetBlob returns a stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ImageStoreLocal) GetBlob(repo, digest, mediaType string) (io.ReadCloser, int64, error) {
	var lockLatency time.Time

	parsedDigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return nil, -1, zerr.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, parsedDigest)

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

func (is *ImageStoreLocal) GetBlobContent(repo, digest string) ([]byte, error) {
	blob, _, err := is.GetBlob(repo, digest, ispec.MediaTypeImageManifest)
	if err != nil {
		return []byte{}, err
	}
	defer blob.Close()

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(blob)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to read blob")

		return []byte{}, err
	}

	return buf.Bytes(), nil
}

func (is *ImageStoreLocal) GetIndexContent(repo string) ([]byte, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
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
func (is *ImageStoreLocal) DeleteBlob(repo, digest string) error {
	var lockLatency time.Time

	dgst, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return zerr.ErrBlobNotFound
	}

	blobPath := is.BlobPath(repo, dgst)

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	_, err = os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return zerr.ErrBlobNotFound
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

func (is *ImageStoreLocal) GetReferrers(repo, digest, artifactType string) ([]artifactspec.Descriptor, error) {
	var lockLatency time.Time

	dir := path.Join(is.rootDir, repo)
	if !is.DirExists(dir) {
		return nil, zerr.ErrRepoNotFound
	}

	gdigest, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")

		return nil, zerr.ErrBadBlobDigest
	}

	is.RLock(&lockLatency)
	defer is.RUnlock(&lockLatency)

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		if os.IsNotExist(err) {
			return nil, zerr.ErrRepoNotFound
		}

		return nil, err
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

		return nil, err
	}

	found := false

	result := []artifactspec.Descriptor{}

	for _, manifest := range index.Manifests {
		if manifest.MediaType != artifactspec.MediaTypeArtifactManifest {
			continue
		}

		p := path.Join(dir, "blobs", manifest.Digest.Algorithm().String(), manifest.Digest.Encoded())

		buf, err = ioutil.ReadFile(p)

		if err != nil {
			is.log.Error().Err(err).Str("blob", p).Msg("failed to read manifest")

			if os.IsNotExist(err) {
				return nil, zerr.ErrManifestNotFound
			}

			return nil, err
		}

		var artManifest artifactspec.Manifest
		if err := json.Unmarshal(buf, &artManifest); err != nil {
			is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

			return nil, err
		}

		if artifactType != artManifest.ArtifactType || gdigest != artManifest.Subject.Digest {
			continue
		}

		result = append(result, artifactspec.Descriptor{
			MediaType:    manifest.MediaType,
			ArtifactType: artManifest.ArtifactType,
			Digest:       manifest.Digest,
			Size:         manifest.Size,
			Annotations:  manifest.Annotations,
		})

		found = true
	}

	if !found {
		return nil, zerr.ErrManifestNotFound
	}

	return result, nil
}

func (is *ImageStoreLocal) writeFile(filename string, data []byte) error {
	if !is.commit {
		return ioutil.WriteFile(filename, data, DefaultFilePerms)
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

func IsSupportedMediaType(mediaType string) bool {
	return mediaType == ispec.MediaTypeImageIndex ||
		mediaType == ispec.MediaTypeImageManifest ||
		mediaType == artifactspec.MediaTypeArtifactManifest
}

// utility routines

func ValidateHardLink(rootDir string) error {
	if err := os.MkdirAll(rootDir, DefaultDirPerms); err != nil {
		return err
	}

	err := ioutil.WriteFile(path.Join(rootDir, "hardlinkcheck.txt"),
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

	err = oci.GC(context.Background(), ifOlderThan(is, repo, is.gcDelay))
	if err := test.Error(err); err != nil {
		return err
	}

	return nil
}

func validateManifest(imgStore *ImageStoreLocal, repo, reference,
	mediaType string, body []byte,
) (string, error) {
	if mediaType == ispec.MediaTypeImageManifest {
		var manifest ispec.Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			imgStore.log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}

		if manifest.Config.MediaType == ispec.MediaTypeImageConfig {
			digest, err := imgStore.validateOCIManifest(repo, reference, &manifest)
			if err != nil {
				imgStore.log.Error().Err(err).Msg("invalid oci image manifest")

				return digest, err
			}
		}
	} else if mediaType == artifactspec.MediaTypeArtifactManifest {
		var m notation.Descriptor
		if err := json.Unmarshal(body, &m); err != nil {
			imgStore.log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}
	}

	return "", nil
}

func ifOlderThan(imgStore *ImageStoreLocal, repo string, delay time.Duration) casext.GCPolicy {
	return func(ctx context.Context, digest godigest.Digest) (bool, error) {
		blobPath := imgStore.BlobPath(repo, digest)

		fi, err := os.Stat(blobPath)
		if err != nil {
			return false, err
		}

		if fi.ModTime().Add(delay).After(time.Now()) {
			return false, nil
		}

		imgStore.log.Info().Str("digest", digest.String()).Str("blobPath", blobPath).Msg("perform GC on blob")

		return true, nil
	}
}

func DirExists(d string) bool {
	if !utf8.ValidString(d) {
		return false
	}

	fileInfo, err := os.Stat(d)
	if err != nil {
		if e, ok := err.(*fs.PathError); ok && errors.Is(e.Err, syscall.ENAMETOOLONG) || //nolint: errorlint
			errors.Is(e.Err, syscall.EINVAL) {
			return false
		}
	}

	if err != nil && os.IsNotExist(err) {
		return false
	}

	if !fileInfo.IsDir() {
		return false
	}

	return true
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

func (is *ImageStoreLocal) RunGCRepo(repo string) {
	is.log.Info().Msg(fmt.Sprintf("executing GC of orphaned blobs for %s", path.Join(is.RootDir(), repo)))

	if err := is.gcRepo(repo); err != nil {
		errMessage := fmt.Sprintf("error while running GC for %s", path.Join(is.RootDir(), repo))
		is.log.Error().Err(err).Msg(errMessage)
	}

	is.log.Info().Msg(fmt.Sprintf("GC completed for %s", path.Join(is.RootDir(), repo)))
}
