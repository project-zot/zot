package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type mapBackedCache struct {
	mu         sync.Mutex
	entries    map[string]map[string]struct{}
	putCalls   int
	failOnCall int
}

// stickyOriginalCache simulates cache drivers that keep the original path while
// duplicates still exist, even when DeleteBlob is called on the original path.
type stickyOriginalCache struct {
	mu         sync.Mutex
	original   map[string]string
	duplicates map[string]map[string]struct{}
}

func newStickyOriginalCache() *stickyOriginalCache {
	return &stickyOriginalCache{
		original:   map[string]string{},
		duplicates: map[string]map[string]struct{}{},
	}
}

func (cache *stickyOriginalCache) Name() string {
	return "sticky-original-cache"
}

func (cache *stickyOriginalCache) UsesRelativePaths() bool {
	return false
}

func (cache *stickyOriginalCache) GetBlob(digest godigest.Digest) (string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	original, ok := cache.original[digest.String()]
	if !ok || original == "" {
		return "", zerr.ErrCacheMiss
	}

	return original, nil
}

func (cache *stickyOriginalCache) GetAllBlobs(digest godigest.Digest) ([]string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	original, ok := cache.original[digest.String()]
	if !ok || original == "" {
		return nil, zerr.ErrCacheMiss
	}

	ret := []string{original}
	for dup := range cache.duplicates[digest.String()] {
		ret = append(ret, dup)
	}

	sort.Strings(ret)

	return ret, nil
}

func (cache *stickyOriginalCache) PutBlob(digest godigest.Digest, blobPath string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if current, ok := cache.original[digest.String()]; !ok || current == "" {
		cache.original[digest.String()] = blobPath

		return nil
	}

	if cache.original[digest.String()] == blobPath {
		return nil
	}

	if _, ok := cache.duplicates[digest.String()]; !ok {
		cache.duplicates[digest.String()] = map[string]struct{}{}
	}

	cache.duplicates[digest.String()][blobPath] = struct{}{}

	return nil
}

func (cache *stickyOriginalCache) HasBlob(digest godigest.Digest, blobPath string) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.original[digest.String()] == blobPath {
		return true
	}

	_, ok := cache.duplicates[digest.String()][blobPath]

	return ok
}

func (cache *stickyOriginalCache) DeleteBlob(digest godigest.Digest, blobPath string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	dgst := digest.String()

	if _, ok := cache.duplicates[dgst][blobPath]; ok {
		delete(cache.duplicates[dgst], blobPath)

		return nil
	}

	if cache.original[dgst] != blobPath {
		return zerr.ErrCacheMiss
	}

	// Intentionally keep original when duplicates exist.
	if len(cache.duplicates[dgst]) > 0 {
		return nil
	}

	delete(cache.original, dgst)

	return nil
}

func newMapBackedCache() *mapBackedCache {
	return &mapBackedCache{entries: map[string]map[string]struct{}{}}
}

func (cache *mapBackedCache) Name() string {
	return "mock-cache"
}

func (cache *mapBackedCache) GetBlob(digest godigest.Digest) (string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	pathsMap, ok := cache.entries[digest.String()]
	if !ok || len(pathsMap) == 0 {
		return "", zerr.ErrCacheMiss
	}

	paths := make([]string, 0, len(pathsMap))
	for blobPath := range pathsMap {
		paths = append(paths, blobPath)
	}

	sort.Strings(paths)

	return paths[0], nil
}

func (cache *mapBackedCache) GetAllBlobs(digest godigest.Digest) ([]string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	pathsMap, ok := cache.entries[digest.String()]
	if !ok || len(pathsMap) == 0 {
		return nil, zerr.ErrCacheMiss
	}

	paths := make([]string, 0, len(pathsMap))
	for blobPath := range pathsMap {
		paths = append(paths, blobPath)
	}

	sort.Strings(paths)

	return paths, nil
}

func (cache *mapBackedCache) PutBlob(digest godigest.Digest, blobPath string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	cache.putCalls++
	if cache.failOnCall > 0 && cache.putCalls == cache.failOnCall {
		return errors.New("injected cache put failure")
	}

	if _, ok := cache.entries[digest.String()]; !ok {
		cache.entries[digest.String()] = map[string]struct{}{}
	}

	cache.entries[digest.String()][blobPath] = struct{}{}

	return nil
}

func (cache *mapBackedCache) HasBlob(digest godigest.Digest, blobPath string) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	pathsMap, ok := cache.entries[digest.String()]
	if !ok {
		return false
	}

	_, ok = pathsMap[blobPath]

	return ok
}

func (cache *mapBackedCache) DeleteBlob(digest godigest.Digest, blobPath string) error {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	pathsMap, ok := cache.entries[digest.String()]
	if !ok {
		return zerr.ErrCacheMiss
	}

	if _, ok := pathsMap[blobPath]; !ok {
		return zerr.ErrCacheMiss
	}

	delete(pathsMap, blobPath)
	if len(pathsMap) == 0 {
		delete(cache.entries, digest.String())
	}

	return nil
}

func (cache *mapBackedCache) UsesRelativePaths() bool {
	return false
}

func makeStatefulMigrationStoreMock(rootDir, repo, blobPath string, blobContent []byte) *mocks.StorageDriverMock {
	files := map[string][]byte{
		blobPath: append([]byte(nil), blobContent...),
		path.Join(rootDir, repo, ispec.ImageIndexFile):  []byte("{}"),
		path.Join(rootDir, repo, ispec.ImageLayoutFile): []byte("{}"),
	}

	dirs := map[string]struct{}{}
	ensureDir := func(p string) {
		clean := strings.TrimSuffix(p, "/")
		if clean == "" {
			clean = "/"
		}

		dirs[clean] = struct{}{}
	}

	ensureParents := func(p string) {
		cur := path.Dir(p)
		for cur != "." && cur != "/" {
			ensureDir(cur)
			cur = path.Dir(cur)
		}

		ensureDir(rootDir)
	}

	for fpath := range files {
		ensureParents(fpath)
	}

	listUnder := func(prefix string) []string {
		seen := map[string]struct{}{}
		ret := []string{}

		for d := range dirs {
			if path.Dir(d) == prefix {
				if _, ok := seen[d]; !ok {
					seen[d] = struct{}{}
					ret = append(ret, d)
				}
			}
		}

		for f := range files {
			if path.Dir(f) == prefix {
				if _, ok := seen[f]; !ok {
					seen[f] = struct{}{}
					ret = append(ret, f)
				}
			}
		}

		sort.Strings(ret)

		return ret
	}

	var mu sync.Mutex

	return &mocks.StorageDriverMock{
		GetContentFn: func(_ context.Context, filePath string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()

			content, ok := files[filePath]
			if !ok {
				return nil, driver.PathNotFoundError{Path: filePath}
			}

			return append([]byte(nil), content...), nil
		},
		StatFn: func(_ context.Context, filePath string) (driver.FileInfo, error) {
			mu.Lock()
			defer mu.Unlock()

			if content, ok := files[filePath]; ok {
				size := int64(len(content))

				return &mocks.FileInfoMock{
					IsDirFn: func() bool { return false },
					PathFn:  func() string { return filePath },
					SizeFn:  func() int64 { return size },
				}, nil
			}

			if _, ok := dirs[filePath]; ok {
				return &mocks.FileInfoMock{
					IsDirFn: func() bool { return true },
					PathFn:  func() string { return filePath },
					SizeFn:  func() int64 { return 0 },
				}, nil
			}

			return nil, driver.PathNotFoundError{Path: filePath}
		},
		ListFn: func(_ context.Context, fullPath string) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()

			if _, ok := dirs[fullPath]; !ok {
				return nil, driver.PathNotFoundError{Path: fullPath}
			}

			return listUnder(fullPath), nil
		},
		WalkFn: func(_ context.Context, fullPath string, walkFn driver.WalkFn,
			_ ...func(*driver.WalkOptions),
		) error {
			if fullPath != rootDir {
				return nil
			}

			return walkFn(&mocks.FileInfoMock{
				IsDirFn: func() bool { return true },
				PathFn:  func() string { return path.Join(rootDir, repo) },
				SizeFn:  func() int64 { return 0 },
			})
		},
		ReaderFn: func(_ context.Context, filePath string, _ int64) (io.ReadCloser, error) {
			mu.Lock()
			defer mu.Unlock()

			content, ok := files[filePath]
			if !ok {
				return nil, driver.PathNotFoundError{Path: filePath}
			}

			return io.NopCloser(bytes.NewReader(content)), nil
		},
		WriterFn: func(_ context.Context, filePath string, isAppend bool) (driver.FileWriter, error) {
			mu.Lock()
			base := []byte(nil)
			if isAppend {
				base = append(base, files[filePath]...)
			}
			mu.Unlock()

			buf := bytes.NewBuffer(base)

			return &mocks.FileWriterMock{
				WriteFn: func(p []byte) (int, error) {
					return buf.Write(p)
				},
				CommitFn: func() error {
					mu.Lock()
					defer mu.Unlock()

					ensureParents(filePath)
					files[filePath] = append([]byte(nil), buf.Bytes()...)

					return nil
				},
			}, nil
		},
		PutContentFn: func(_ context.Context, filePath string, content []byte) error {
			mu.Lock()
			defer mu.Unlock()

			ensureParents(filePath)
			files[filePath] = append([]byte(nil), content...)

			return nil
		},
		MoveFn: func(_ context.Context, sourcePath, destPath string) error {
			mu.Lock()
			defer mu.Unlock()

			content, ok := files[sourcePath]
			if !ok {
				return driver.PathNotFoundError{Path: sourcePath}
			}

			ensureParents(destPath)
			files[destPath] = append([]byte(nil), content...)
			delete(files, sourcePath)

			return nil
		},
		DeleteFn: func(_ context.Context, filePath string) error {
			mu.Lock()
			defer mu.Unlock()

			if _, ok := files[filePath]; !ok {
				if _, dirExists := dirs[filePath]; !dirExists {
					return driver.PathNotFoundError{Path: filePath}
				}
			}

			delete(files, filePath)
			delete(dirs, filePath)

			return nil
		},
	}
}

func TestNewImageStoreUpgradeStreamsRemoteBlob(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	rootDir := "/oci-repo-test/migration-stream"
	repo := "repo"
	content := []byte("blob-content-stream")
	digest := godigest.FromBytes(content)
	blobsAlgoDir := path.Join(rootDir, repo, ispec.ImageBlobsDir, digest.Algorithm().String())
	blobPath := path.Join(blobsAlgoDir, digest.Encoded())
	markerPath := path.Join(rootDir, constants.BlobstoreMigratedMarker)
	globalBlobPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())

	var (
		readFileCalled bool
		readerCalled   bool
		writtenBlob    bytes.Buffer
	)

	storeMock := &mocks.StorageDriverMock{
		GetContentFn: func(_ context.Context, _ string) ([]byte, error) {
			readFileCalled = true

			return content, nil
		},
		ReaderFn: func(_ context.Context, filePath string, _ int64) (io.ReadCloser, error) {
			if filePath == blobPath {
				readerCalled = true
			}

			return io.NopCloser(bytes.NewReader(content)), nil
		},
		WriterFn: func(_ context.Context, filePath string, _ bool) (driver.FileWriter, error) {
			writer := &mocks.FileWriterMock{
				WriteFn: func(p []byte) (int, error) {
					if filePath == globalBlobPath {
						_, _ = writtenBlob.Write(p)
					}

					return len(p), nil
				},
			}

			return writer, nil
		},
		StatFn: func(_ context.Context, filePath string) (driver.FileInfo, error) {
			if filePath == markerPath {
				return nil, driver.PathNotFoundError{Path: filePath}
			}

			if filePath == blobPath {
				return &mocks.FileInfoMock{SizeFn: func() int64 { return int64(len(content)) }}, nil
			}

			return &mocks.FileInfoMock{}, nil
		},
		ListFn: func(_ context.Context, filePath string) ([]string, error) {
			switch filePath {
			case rootDir, path.Join(rootDir, repo):
				return []string{
					path.Join(rootDir, repo, ispec.ImageLayoutFile),
					path.Join(rootDir, repo, ispec.ImageIndexFile),
					path.Join(rootDir, repo, ispec.ImageBlobsDir),
				}, nil
			case path.Join(rootDir, repo, ispec.ImageBlobsDir):
				return []string{blobsAlgoDir}, nil
			case blobsAlgoDir:
				return []string{blobPath}, nil
			}

			return []string{}, nil
		},
		WalkFn: func(_ context.Context, filePath string, walkFn driver.WalkFn,
			_ ...func(*driver.WalkOptions),
		) error {
			if filePath != rootDir {
				return nil
			}

			return walkFn(&mocks.FileInfoMock{
				IsDirFn: func() bool { return true },
				PathFn:  func() string { return path.Join(rootDir, repo) },
			})
		},
	}

	store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		gcs.New(storeMock), nil, nil, nil)
	if store == nil {
		t.Fatal("expected image store initialization to succeed")
	}

	if !readerCalled {
		t.Fatal("expected migration to use streaming reader for remote blob copy")
	}

	if readFileCalled {
		t.Fatal("did not expect migration to read full blob content into memory")
	}

	if !bytes.Equal(writtenBlob.Bytes(), content) {
		t.Fatal("expected migrated global blob to match streamed content")
	}
}

func TestNewImageStoreUpgradeFailsOnPromotedBlobDigestMismatch(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	rootDir := "/oci-repo-test/migration-verify-fail"
	repo := "repo"
	content := []byte("blob-content-to-verify")
	digest := godigest.FromBytes(content)
	repoBlobPath := path.Join(rootDir, repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
	globalBlobPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())
	migrationMarkerPath := path.Join(rootDir, constants.BlobstoreMigratedMarker)

	storeMock := makeStatefulMigrationStoreMock(rootDir, repo, repoBlobPath, content)
	originalReader := storeMock.ReaderFn

	storeMock.ReaderFn = func(ctx context.Context, filePath string, offset int64) (io.ReadCloser, error) {
		// Simulate corrupted remote read for the promoted global blob only.
		if filePath == globalBlobPath {
			return io.NopCloser(bytes.NewReader([]byte("corrupted-global-content"))), nil
		}

		return originalReader(ctx, filePath, offset)
	}

	store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		gcs.New(storeMock), newMapBackedCache(), nil, nil)
	if store != nil {
		t.Fatal("expected initialization to fail on promoted blob digest mismatch")
	}

	repoBlobAfterFailure, err := storeMock.GetContent(context.Background(), repoBlobPath)
	if err != nil {
		t.Fatal("expected repo blob content path to remain present after verify failure")
	}

	if !bytes.Equal(repoBlobAfterFailure, content) {
		t.Fatal("expected repo blob content to remain unchanged when verify fails")
	}

	if _, err := storeMock.GetContent(context.Background(), migrationMarkerPath); err == nil {
		t.Fatal("expected migration marker to be absent after verify failure")
	}
}

func TestNewImageStoreUpgradeResumesAfterPartialFailureWithPopulatedCache(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	rootDir := "/oci-repo-test/migration-resume"
	repo := "repo"
	content := []byte("blob-content-to-preserve")
	digest := godigest.FromBytes(content)
	repoBlobPath := path.Join(rootDir, repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
	globalBlobPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())
	migrationMarkerPath := path.Join(rootDir, constants.BlobstoreMigratedMarker)

	storeMock := makeStatefulMigrationStoreMock(rootDir, repo, repoBlobPath, content)
	cache := newMapBackedCache()
	cache.failOnCall = 2

	store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		gcs.New(storeMock), cache, nil, nil)
	if store != nil {
		t.Fatal("expected initialization to fail on injected cache write error")
	}

	globalBlobAfterFailure, err := storeMock.GetContent(context.Background(), globalBlobPath)
	if err != nil {
		t.Fatal("expected promoted global blob to exist after partial failure")
	}

	if !bytes.Equal(globalBlobAfterFailure, content) {
		t.Fatal("expected partial migration to keep full global blob content")
	}

	repoBlobAfterFailure, err := storeMock.GetContent(context.Background(), repoBlobPath)
	if err != nil {
		t.Fatal("expected repo blob path to still exist after partial failure")
	}

	if len(repoBlobAfterFailure) != 0 {
		t.Fatal("expected repo blob to be converted to marker before failure")
	}

	if _, err := storeMock.GetContent(context.Background(), migrationMarkerPath); err == nil {
		t.Fatal("expected migration marker to be absent after partial failure")
	}

	cache.failOnCall = 0

	store = imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		gcs.New(storeMock), cache, nil, nil)
	if store == nil {
		t.Fatal("expected initialization to succeed on resumed migration")
	}

	globalBlobAfterResume, err := storeMock.GetContent(context.Background(), globalBlobPath)
	if err != nil {
		t.Fatal("expected global blob to exist after resumed migration")
	}

	if !bytes.Equal(globalBlobAfterResume, content) {
		t.Fatal("expected resumed migration to preserve existing global blob content")
	}

	if _, err := storeMock.GetContent(context.Background(), migrationMarkerPath); err != nil {
		t.Fatal("expected migration marker to be written after resumed migration")
	}

	if !cache.HasBlob(digest, globalBlobPath) {
		t.Fatal("expected cache to contain global blob path after resumed migration")
	}

	if !cache.HasBlob(digest, repoBlobPath) {
		t.Fatal("expected cache to contain repo marker path after resumed migration")
	}
}

func TestDedupeBlobRecoversWhenStaleOriginalIsKeptByCache(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	rootDir := "/oci-repo-test/dedupe-self-heal"
	repoWithMarker := "repo"
	repoUploading := "repo-upload"

	content := []byte("blob-content-for-self-heal")
	digest := godigest.FromBytes(content)

	staleGlobalPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())

	markerPath := path.Join(rootDir, repoWithMarker, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())

	srcUploadPath := path.Join(rootDir, repoUploading, constants.BlobUploadDir, "upload-id")
	dstPath := path.Join(rootDir, repoUploading, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())

	storeMock := makeStatefulMigrationStoreMock(rootDir, repoWithMarker, markerPath, []byte{})
	if err := storeMock.PutContent(context.Background(), srcUploadPath, content); err != nil {
		t.Fatal(err)
	}

	cache := newStickyOriginalCache()
	if err := cache.PutBlob(digest, staleGlobalPath); err != nil {
		t.Fatal(err)
	}

	if err := cache.PutBlob(digest, markerPath); err != nil {
		t.Fatal(err)
	}

	store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
		gcs.New(storeMock), cache, nil, nil)
	if store == nil {
		t.Fatal("expected image store initialization to succeed")
	}

	if err := store.DedupeBlob(srcUploadPath, digest, repoUploading, dstPath); err != nil {
		t.Fatal(err)
	}

	globalContent, err := storeMock.GetContent(context.Background(), staleGlobalPath)
	if err != nil {
		t.Fatal("expected stale global path to be re-created from upload content")
	}

	if !bytes.Equal(globalContent, content) {
		t.Fatal("expected re-created global blob to preserve upload content")
	}

	dstContent, err := storeMock.GetContent(context.Background(), dstPath)
	if err != nil {
		t.Fatal("expected destination marker path to be created")
	}

	if len(dstContent) != 0 {
		t.Fatal("expected destination deduped marker blob to be zero-size")
	}

	if _, err := storeMock.GetContent(context.Background(), srcUploadPath); err == nil {
		t.Fatal("expected upload source to be moved away after dedupe")
	}
}

// TestRestoreDedupedBlobFallsBackToGlobalBlobstore covers the dedupe=true->false restore path
// when the cache has no record for a digest (e.g. lost/rebuilt) and every per-repo copy is a
// zero-byte dedupe marker - the normal steady state under the global blobstore scheme. Before
// routing getOriginalBlob through the blobLifecycle seam, this left restoreDedupedBlobs unable
// to find the content (it only scanned the given per-repo paths, never GlobalBlobsRepo) even
// though the real bytes were sitting right there, and the digest was wrongly reported as lost.
func TestRestoreDedupedBlobFallsBackToGlobalBlobstore(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	rootDir := "/oci-repo-test/restore-global-fallback"
	repo := "repo1"

	content := []byte("blob-content-for-restore-fallback")
	digest := godigest.FromBytes(content)

	repoBlobPath := path.Join(rootDir, repo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())
	globalBlobPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())
	migratedMarkerPath := path.Join(rootDir, constants.BlobstoreMigratedMarker)

	// repo1's own copy is a zero-byte dedupe marker; the real content lives only in the
	// global blobstore. The migration marker is pre-seeded so NewImageStore starts in the
	// already-migrated steady state instead of running the migration walk.
	storeMock := makeStatefulMigrationStoreMock(rootDir, repo, repoBlobPath, []byte{})
	if err := storeMock.PutContent(context.Background(), globalBlobPath, content); err != nil {
		t.Fatal(err)
	}

	if err := storeMock.PutContent(context.Background(), migratedMarkerPath, []byte("1")); err != nil {
		t.Fatal(err)
	}

	// An empty cache simulates one that was lost/rebuilt and has no record of this digest.
	store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		gcs.New(storeMock), newMapBackedCache(), nil, nil)
	if store == nil {
		t.Fatal("expected image store initialization to succeed")
	}

	if err := store.RunDedupeForDigest(context.Background(), digest, false, []string{repoBlobPath}); err != nil {
		t.Fatal(err)
	}

	restoredContent, err := storeMock.GetContent(context.Background(), repoBlobPath)
	if err != nil {
		t.Fatal("expected repo blob to be restored with content")
	}

	if !bytes.Equal(restoredContent, content) {
		t.Fatal("expected restored repo blob content to match the global blobstore copy")
	}
}
