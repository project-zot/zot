package storage

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sync"

	"github.com/anuvu/zot/errors"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
)

const (
	BlobUploadDir = ".uploads"
)

type BlobUpload struct {
	StoreName string
	ID        string
}

type ImageStore struct {
	rootDir     string
	lock        *sync.Mutex
	blobUploads map[string]BlobUpload
	log         zerolog.Logger
}

func NewImageStore(rootDir string, log zerolog.Logger) *ImageStore {
	is := &ImageStore{rootDir: rootDir,
		lock:        &sync.Mutex{},
		blobUploads: make(map[string]BlobUpload),
		log:         log.With().Caller().Logger(),
	}
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		_ = os.MkdirAll(rootDir, 0700)
	} else if _, err := is.Validate(); err != nil {
		panic(err)
	}
	return is
}

func (is *ImageStore) Validate() (bool, error) {
	dir := is.rootDir
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")
		return false, errors.ErrRepoNotFound
	}

	for _, file := range files {
		if !file.IsDir() {
			is.log.Error().Err(err).Str("file", file.Name()).Msg("not a directory")
			return false, errors.ErrRepoIsNotDir
		}

		v, err := is.ValidateRepo(file.Name())
		if !v {
			return v, err
		}
	}

	return true, nil
}

func (is *ImageStore) InitRepo(name string) error {
	repoDir := path.Join(is.rootDir, name)

	if fi, err := os.Stat(repoDir); err == nil && fi.IsDir() {
		return nil
	}

	// create repo dir
	ensureDir(repoDir)

	// create "blobs" subdir
	dir := path.Join(repoDir, "blobs")
	ensureDir(dir)

	// create BlobUploadDir subdir
	dir = path.Join(repoDir, BlobUploadDir)
	ensureDir(dir)

	// "oci-layout" file - create if it doesn't exist
	ilPath := path.Join(repoDir, ispec.ImageLayoutFile)
	if _, err := os.Stat(ilPath); err != nil {
		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}
		buf, err := json.Marshal(il)
		if err != nil {
			panic(err)
		}
		if err := ioutil.WriteFile(ilPath, buf, 0644); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("unable to write file")
			panic(err)
		}
	}

	// "index.json" file - create if it doesn't exist
	indexPath := path.Join(repoDir, "index.json")
	if _, err := os.Stat(indexPath); err != nil {
		index := ispec.Index{}
		index.SchemaVersion = 2
		buf, err := json.Marshal(index)
		if err != nil {
			panic(err)
		}
		if err := ioutil.WriteFile(indexPath, buf, 0644); err != nil {
			is.log.Error().Err(err).Str("file", indexPath).Msg("unable to write file")
			panic(err)
		}
	}

	return nil
}

func (is *ImageStore) ValidateRepo(name string) (bool, error) {
	// https://github.com/opencontainers/image-spec/blob/master/image-layout.md#content
	// at least, expect exactly 4 entries - ["blobs", "oci-layout", "index.json"] and BlobUploadDir
	// in each image store
	dir := path.Join(is.rootDir, name)
	if !dirExists(dir) {
		return false, errors.ErrRepoNotFound
	}

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("unable to read directory")
		return false, errors.ErrRepoNotFound
	}

	if len(files) != 4 {
		return false, nil
	}

	found := map[string]bool{
		"blobs":               false,
		ispec.ImageLayoutFile: false,
		"index.json":          false,
		BlobUploadDir:         false,
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

func (is *ImageStore) GetRepositories() ([]string, error) {
	dir := is.rootDir
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		is.log.Error().Err(err).Msg("failure walking storage root-dir")
		return nil, err
	}

	stores := make([]string, 0)
	for _, file := range files {
		p := path.Join(dir, file.Name())
		is.log.Debug().Str("dir", p).Str("name", file.Name()).Msg("found image store")
		stores = append(stores, file.Name())
	}
	return stores, nil
}

func (is *ImageStore) GetImageTags(repo string) ([]string, error) {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return nil, errors.ErrRepoNotFound
	}
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

func (is *ImageStore) GetImageManifest(repo string, reference string) ([]byte, string, string, error) {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return nil, "", "", errors.ErrRepoNotFound
	}
	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
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

	p := path.Join(dir, "blobs")
	p = path.Join(p, digest.Algorithm().String())
	p = path.Join(p, digest.Encoded())

	buf, err = ioutil.ReadFile(p)
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

func (is *ImageStore) PutImageManifest(repo string, reference string,
	mediaType string, body []byte) (string, error) {

	if err := is.InitRepo(repo); err != nil {
		return "", err
	}

	if mediaType != ispec.MediaTypeImageManifest {
		return "", errors.ErrBadManifest
	}

	if len(body) == 0 {
		return "", errors.ErrBadManifest
	}

	var m ispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return "", errors.ErrBadManifest
	}

	for _, l := range m.Layers {
		digest := l.Digest
		blobPath := is.BlobPath(repo, digest)
		if _, err := os.Stat(blobPath); err != nil {
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
			// manifest contents have changed for the same tag
			desc = m
			desc.Digest = mDigest
			index.Manifests = append(index.Manifests[:i], index.Manifests[1+1:]...)
			break
		}
	}

	if !updateIndex {
		return desc.Digest.String(), nil
	}

	// write manifest to "blobs"
	dir = path.Join(is.rootDir, repo)
	dir = path.Join(dir, "blobs")
	dir = path.Join(dir, mDigest.Algorithm().String())
	_ = os.MkdirAll(dir, 0755)
	file := path.Join(dir, mDigest.Encoded())
	if err := ioutil.WriteFile(file, body, 0644); err != nil {
		return "", err
	}

	// now update "index.json"
	index.Manifests = append(index.Manifests, desc)
	dir = path.Join(is.rootDir, repo)
	file = path.Join(dir, "index.json")
	buf, err = json.Marshal(index)
	if err != nil {
		return "", err
	}
	if err := ioutil.WriteFile(file, buf, 0644); err != nil {
		return "", err
	}

	return desc.Digest.String(), nil
}

func (is *ImageStore) DeleteImageManifest(repo string, reference string) error {
	dir := path.Join(is.rootDir, repo)
	if !dirExists(dir) {
		return errors.ErrRepoNotFound
	}
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
	var digest godigest.Digest
	var i int
	var m ispec.Descriptor
	for i, m = range index.Manifests {
		if reference == m.Digest.String() {
			digest = m.Digest
			found = true
			break
		}

		v, ok := m.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			digest = m.Digest
			found = true
			break
		}
	}

	if !found {
		return errors.ErrManifestNotFound
	}

	// remove the manifest entry, not preserving order
	index.Manifests[i] = index.Manifests[len(index.Manifests)-1]
	index.Manifests = index.Manifests[:len(index.Manifests)-1]

	// now update "index.json"
	dir = path.Join(is.rootDir, repo)
	file := path.Join(dir, "index.json")
	buf, err = json.Marshal(index)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(file, buf, 0644); err != nil {
		return err
	}

	p := path.Join(dir, "blobs")
	p = path.Join(p, digest.Algorithm().String())
	p = path.Join(p, digest.Encoded())

	_ = os.Remove(p)

	return nil
}

func (is *ImageStore) BlobUploadPath(repo string, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, BlobUploadDir)
	blobUploadPath = path.Join(blobUploadPath, uuid)
	return blobUploadPath
}

func (is *ImageStore) NewBlobUpload(repo string) (string, error) {
	if err := is.InitRepo(repo); err != nil {
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

func (is *ImageStore) PutBlobChunk(repo string, uuid string,
	from int64, to int64, body io.Reader) (int64, error) {

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

	if _, err := file.Seek(from, 0); err != nil {
		is.log.Fatal().Err(err).Msg("failed to seek file")
	}

	n, err := io.Copy(file, body)
	return n, err
}

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

func (is *ImageStore) FinishBlobUpload(repo string, uuid string,
	body io.Reader, digest string) error {

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

	dir := path.Join(is.rootDir, repo)
	dir = path.Join(dir, "blobs")
	dir = path.Join(dir, dstDigest.Algorithm().String())
	_ = os.MkdirAll(dir, 0755)
	dst := is.BlobPath(repo, dstDigest)

	// move the blob from uploads to final dest
	_ = os.Rename(src, dst)

	return err
}

func (is *ImageStore) DeleteBlobUpload(repo string, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)
	_ = os.Remove(blobUploadPath)
	return nil
}

func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
	dir := path.Join(is.rootDir, repo)
	blobPath := path.Join(dir, "blobs")
	blobPath = path.Join(blobPath, digest.Algorithm().String())
	blobPath = path.Join(blobPath, digest.Encoded())
	return blobPath
}

func (is *ImageStore) CheckBlob(repo string, digest string,
	mediaType string) (bool, int64, error) {

	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return false, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

	blobInfo, err := os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return false, -1, errors.ErrBlobNotFound
	}

	return true, blobInfo.Size(), nil
}

// FIXME: we should probably parse the manifest and use (digest, mediaType) as a
// blob selector instead of directly downloading the blob
func (is *ImageStore) GetBlob(repo string, digest string,
	mediaType string) (io.Reader, int64, error) {

	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return nil, -1, errors.ErrBadBlobDigest
	}

	blobPath := is.BlobPath(repo, d)

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

func (is *ImageStore) DeleteBlob(repo string, digest string) error {
	d, err := godigest.Parse(digest)
	if err != nil {
		is.log.Error().Err(err).Str("digest", digest).Msg("failed to parse digest")
		return errors.ErrBlobNotFound
	}

	blobPath := is.BlobPath(repo, d)

	_, err = os.Stat(blobPath)
	if err != nil {
		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		return errors.ErrBlobNotFound
	}

	_ = os.Remove(blobPath)

	return nil
}

// garbage collection

// TODO

func Scrub(dir string, fix bool) error {
	return nil
}

// utility routines

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

func ensureDir(dir string) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}
}
