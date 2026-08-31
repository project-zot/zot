package imagestore_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	. "github.com/smartystreets/goconvey/convey"

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

func (cache *mapBackedCache) GetAllBlobRefs() (map[godigest.Digest][]string, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	allRefs := make(map[godigest.Digest][]string, len(cache.entries))
	for digestString, pathsMap := range cache.entries {
		paths := make([]string, 0, len(pathsMap))
		for blobPath := range pathsMap {
			paths = append(paths, blobPath)
		}

		sort.Strings(paths)
		allRefs[godigest.Digest(digestString)] = paths
	}

	return allRefs, nil
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
	Convey("Migration streams a remote blob into the global blobstore instead of buffering it", t, func() {
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
			gcs.New(storeMock), newMapBackedCache(), nil, nil)
		So(store, ShouldNotBeNil)

		So(readerCalled, ShouldBeTrue)
		So(readFileCalled, ShouldBeFalse)
		So(writtenBlob.Bytes(), ShouldResemble, content)
	})
}

// TestNewImageStoreSkipsMigrationScanWhenMarkerExists proves the migration-marker
// check actually short-circuits the repo scan, rather than the scan just happening
// to be a no-op on an empty root: with the marker present, Walk must never be called.
func TestNewImageStoreSkipsMigrationScanWhenMarkerExists(t *testing.T) {
	Convey("The migration scan is skipped when the marker already exists", t, func() {
		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		rootDir := "/oci-repo-test/migration-marker-skip"
		markerPath := path.Join(rootDir, constants.BlobstoreMigratedMarker)

		var walkCalled bool

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, filePath string) (driver.FileInfo, error) {
				if filePath == markerPath {
					return &mocks.FileInfoMock{}, nil
				}

				return nil, driver.PathNotFoundError{Path: filePath}
			},
			WalkFn: func(_ context.Context, _ string, _ driver.WalkFn,
				_ ...func(*driver.WalkOptions),
			) error {
				walkCalled = true

				return nil
			},
		}

		store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
			gcs.New(storeMock), newMapBackedCache(), nil, nil)
		So(store, ShouldNotBeNil)

		So(walkCalled, ShouldBeFalse)
	})
}

func TestNewImageStoreUpgradeFailsOnPromotedBlobDigestMismatch(t *testing.T) {
	Convey("Migration fails initialization when a promoted blob's digest doesn't verify", t, func() {
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
			if filePath == globalBlobPath {
				return io.NopCloser(bytes.NewReader([]byte("corrupted-global-content"))), nil
			}

			return originalReader(ctx, filePath, offset)
		}

		store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
			gcs.New(storeMock), newMapBackedCache(), nil, nil)
		So(store, ShouldBeNil)

		repoBlobAfterFailure, err := storeMock.GetContent(context.Background(), repoBlobPath)
		So(err, ShouldBeNil)
		So(repoBlobAfterFailure, ShouldResemble, content)

		_, err = storeMock.GetContent(context.Background(), migrationMarkerPath)
		So(err, ShouldNotBeNil)
	})
}

func TestNewImageStoreUpgradeResumesAfterPartialFailureWithPopulatedCache(t *testing.T) {
	Convey("Migration resumes from where it left off after a partial cache-write failure", t, func() {
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
		So(store, ShouldBeNil)

		globalBlobAfterFailure, err := storeMock.GetContent(context.Background(), globalBlobPath)
		So(err, ShouldBeNil)
		So(globalBlobAfterFailure, ShouldResemble, content)

		repoBlobAfterFailure, err := storeMock.GetContent(context.Background(), repoBlobPath)
		So(err, ShouldBeNil)
		So(repoBlobAfterFailure, ShouldResemble, content)

		_, err = storeMock.GetContent(context.Background(), migrationMarkerPath)
		So(err, ShouldNotBeNil)

		cache.failOnCall = 0

		store = imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
			gcs.New(storeMock), cache, nil, nil)
		So(store, ShouldNotBeNil)

		globalBlobAfterResume, err := storeMock.GetContent(context.Background(), globalBlobPath)
		So(err, ShouldBeNil)
		So(globalBlobAfterResume, ShouldResemble, content)

		_, err = storeMock.GetContent(context.Background(), migrationMarkerPath)
		So(err, ShouldBeNil)

		So(cache.HasBlob(digest, globalBlobPath), ShouldBeTrue)
		So(cache.HasBlob(digest, repoBlobPath), ShouldBeTrue)

		_, err = storeMock.GetContent(context.Background(), repoBlobPath)
		So(err, ShouldNotBeNil)
	})
}

func TestDedupeBlobRecoversWhenStaleOriginalIsKeptByCache(t *testing.T) {
	Convey("DedupeBlob self-heals when the cache's original path is stale", t, func() {
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
		err := storeMock.PutContent(context.Background(), srcUploadPath, content)
		So(err, ShouldBeNil)

		cache := newStickyOriginalCache()
		err = cache.PutBlob(digest, staleGlobalPath)
		So(err, ShouldBeNil)

		err = cache.PutBlob(digest, markerPath)
		So(err, ShouldBeNil)

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), cache, nil, nil)
		So(store, ShouldNotBeNil)

		err = store.DedupeBlob(srcUploadPath, digest, repoUploading, dstPath)
		So(err, ShouldBeNil)

		globalContent, err := storeMock.GetContent(context.Background(), staleGlobalPath)
		So(err, ShouldBeNil)
		So(globalContent, ShouldResemble, content)

		_, err = storeMock.GetContent(context.Background(), dstPath)
		So(err, ShouldNotBeNil)

		_, err = storeMock.GetContent(context.Background(), srcUploadPath)
		So(err, ShouldNotBeNil)
	})
}

// TestRestoreDedupedBlobFallsBackToGlobalBlobstore covers the remote dedupe=true->false
// transition from durable logical ownership to a full per-repository payload.
func TestRestoreDedupedBlobFallsBackToGlobalBlobstore(t *testing.T) {
	Convey("Restoring a deduped blob falls back to the global blobstore copy", t, func() {
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

		storeMock := makeStatefulMigrationStoreMock(rootDir, repo, repoBlobPath, []byte{})
		err := storeMock.Delete(context.Background(), repoBlobPath)
		So(err, ShouldBeNil)

		err = storeMock.PutContent(context.Background(), globalBlobPath, content)
		So(err, ShouldBeNil)

		err = storeMock.PutContent(context.Background(), migratedMarkerPath, []byte("1"))
		So(err, ShouldBeNil)

		cache := newMapBackedCache()
		err = cache.PutBlob(digest, globalBlobPath)
		So(err, ShouldBeNil)

		err = cache.PutBlob(digest, repoBlobPath)
		So(err, ShouldBeNil)

		store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
			gcs.New(storeMock), cache, nil, nil)
		So(store, ShouldNotBeNil)

		err = store.RunDedupeForDigest(context.Background(), digest, false, []string{repoBlobPath})
		So(err, ShouldBeNil)

		restoredContent, err := storeMock.GetContent(context.Background(), repoBlobPath)
		So(err, ShouldBeNil)
		So(restoredContent, ShouldResemble, content)
	})
}

func TestRemoteRestoreMaterializesLogicalBlobRefs(t *testing.T) {
	testCases := []struct {
		name    string
		content []byte
	}{
		{name: "non-empty blob", content: []byte("remote-restore-content")},
		{name: "genuine empty blob", content: nil},
	}

	Convey("Restoring materializes logical blob refs into real repository content", t, func() {
		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				rootDir := path.Join("/oci-repo-test/restore-logical", strings.ReplaceAll(testCase.name, " ", "-"))
				repo := "repo"
				digest := godigest.FromBytes(testCase.content)
				repoBlobPath := path.Join(rootDir, repo, ispec.ImageBlobsDir,
					digest.Algorithm().String(), digest.Encoded())
				globalBlobPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
					digest.Algorithm().String(), digest.Encoded())

				storeMock := makeStatefulMigrationStoreMock(rootDir, repo, repoBlobPath, testCase.content)
				err := storeMock.Delete(context.Background(), repoBlobPath)
				So(err, ShouldBeNil)

				err = storeMock.PutContent(context.Background(), globalBlobPath, testCase.content)
				So(err, ShouldBeNil)

				cache := newMapBackedCache()
				err = cache.PutBlob(digest, globalBlobPath)
				So(err, ShouldBeNil)

				err = cache.PutBlob(digest, repoBlobPath)
				So(err, ShouldBeNil)

				store := imagestore.NewImageStore(rootDir, "", false, false, log.NewTestLogger(),
					monitoring.NewMetricsServer(false, log.NewTestLogger()), nil, gcs.New(storeMock), cache, nil, nil)
				So(store, ShouldNotBeNil)

				nextDigest, refs, err := store.GetNextDigestWithBlobPaths([]string{repo}, nil)
				So(err, ShouldBeNil)
				So(nextDigest, ShouldEqual, digest)

				err = store.RunDedupeForDigest(context.Background(), digest, false, refs)
				So(err, ShouldBeNil)

				restored, err := storeMock.GetContent(context.Background(), repoBlobPath)
				So(err, ShouldBeNil)
				So(restored, ShouldResemble, testCase.content)

				_, err = storeMock.GetContent(context.Background(), globalBlobPath)
				So(err, ShouldNotBeNil)
			})
		}
	})
}

func TestRemoteLogicalRefsReadDirectRepoBlob(t *testing.T) {
	Convey("A blob written directly to a repository (no logical ref) remains readable and protected", t, func() {
		rootDir := "/oci-repo-test/direct-repo-blob"
		repo := "repo"
		content := []byte("directly-stored-manifest")
		digest := godigest.FromBytes(content)
		repoBlobPath := path.Join(rootDir, repo, ispec.ImageBlobsDir,
			digest.Algorithm().String(), digest.Encoded())

		storeMock := makeStatefulMigrationStoreMock(rootDir, repo, repoBlobPath, content)
		cache := newMapBackedCache()
		testLog := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, testLog)
		t.Cleanup(metrics.Stop)

		store := imagestore.NewImageStore(rootDir, "", true, false, testLog, metrics, nil,
			gcs.New(storeMock), cache, nil, nil)
		So(store, ShouldNotBeNil)

		// Manifests are written directly to the repository and therefore have no logical blob ref.
		actual, err := store.GetBlobContent(repo, digest)
		So(err, ShouldBeNil)
		So(actual, ShouldResemble, content)

		index := ispec.Index{
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    digest,
				Size:      int64(len(content)),
			}},
		}
		index.SchemaVersion = 2
		indexContent, err := json.Marshal(index)
		So(err, ShouldBeNil)

		err = storeMock.PutContent(context.Background(), path.Join(rootDir, repo, ispec.ImageIndexFile), indexContent)
		So(err, ShouldBeNil)

		err = store.DeleteBlob(repo, digest)
		So(errors.Is(err, zerr.ErrBlobReferenced), ShouldBeTrue)
	})
}

func TestRemoteGetAllBlobsMergesDirectAndLogicalBlobs(t *testing.T) {
	Convey("GetAllBlobs merges directly-stored and logically-referenced blobs", t, func() {
		rootDir := "/oci-repo-test/mixed-repo-blobs"
		repo := "repo"
		manifestContent := []byte("directly-stored-manifest")
		manifestDigest := godigest.FromBytes(manifestContent)
		manifestPath := path.Join(rootDir, repo, ispec.ImageBlobsDir,
			manifestDigest.Algorithm().String(), manifestDigest.Encoded())
		layerDigest := godigest.FromBytes([]byte("logical-layer"))
		layerPath := path.Join(rootDir, repo, ispec.ImageBlobsDir,
			layerDigest.Algorithm().String(), layerDigest.Encoded())

		storeMock := makeStatefulMigrationStoreMock(rootDir, repo, manifestPath, manifestContent)
		err := storeMock.PutContent(context.Background(), path.Join(rootDir, constants.BlobstoreMigratedMarker), []byte("1"))
		So(err, ShouldBeNil)

		cache := newMapBackedCache()
		err = cache.PutBlob(layerDigest, layerPath)
		So(err, ShouldBeNil)

		testLog := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, testLog)
		t.Cleanup(metrics.Stop)

		store := imagestore.NewImageStore(rootDir, "", true, false, testLog, metrics, nil,
			gcs.New(storeMock), cache, nil, nil)
		So(store, ShouldNotBeNil)

		digests, err := store.GetAllBlobs(repo)
		So(err, ShouldBeNil)
		So(digests, ShouldContain, manifestDigest)
		So(digests, ShouldContain, layerDigest)

		logicalOnlyDriver := &mocks.StorageDriverMock{
			ListFn: func(_ context.Context, fullPath string) ([]string, error) {
				return nil, driver.PathNotFoundError{Path: fullPath}
			},
		}
		logicalOnlyStore := imagestore.NewImageStore(rootDir, "", true, false, testLog, metrics, nil,
			gcs.New(logicalOnlyDriver), cache, nil, nil)
		So(logicalOnlyStore, ShouldNotBeNil)

		digests, err = logicalOnlyStore.GetAllBlobs(repo)
		So(err, ShouldBeNil)
		So(digests, ShouldContain, layerDigest)
	})
}

// TestRemoteLogicalRefsReadableWithDedupeDisabled guards against gating the
// global-blobstore lookup on the current store's is.dedupe flag instead of the
// backend's structural UsesLogicalRepoRefs() capability. Remote backends route
// every write through the global blobstore regardless of dedupe, so a repo blob
// can have no local file - only a logical ref in the cache pointing at _blobstore.
// Reopening with dedupe disabled must still resolve such blobs via the logical
// ref, not fail as if the blob never existed.
func TestRemoteLogicalRefsReadableWithDedupeDisabled(t *testing.T) {
	Convey("A logically-referenced blob remains readable and deletable with dedupe disabled", t, func() {
		rootDir := "/oci-repo-test/dedupe-switch"
		repo := "repo"
		content := []byte("previously-deduped-content")
		digest := godigest.FromBytes(content)
		globalBlobPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
			digest.Algorithm().String(), digest.Encoded())
		repoBlobPath := path.Join(rootDir, repo, ispec.ImageBlobsDir,
			digest.Algorithm().String(), digest.Encoded())

		// Only the global blobstore copy has real content, matching what an earlier
		// dedupe=true instance leaves behind; replicate DedupeBlob's cache refs for
		// both the global path and the repo's logical path.
		storeMock := makeStatefulMigrationStoreMock(rootDir, repo, globalBlobPath, content)
		cache := newMapBackedCache()
		err := cache.PutBlob(digest, globalBlobPath)
		So(err, ShouldBeNil)

		err = cache.PutBlob(digest, repoBlobPath)
		So(err, ShouldBeNil)

		testLog := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, testLog)
		t.Cleanup(metrics.Stop)

		store := imagestore.NewImageStore(rootDir, "", false, false, testLog, metrics, nil,
			gcs.New(storeMock), cache, nil, nil)
		So(store, ShouldNotBeNil)

		actual, err := store.GetBlobContent(repo, digest)
		So(err, ShouldBeNil)
		So(actual, ShouldResemble, content)

		err = store.DeleteBlob(repo, digest)
		So(err, ShouldBeNil)
	})
}

// TestGlobalBlobstoreFallbackAfterBlobRefLoss covers the state a repository is left in when a
// migrated bucket is opened with a local root that has no blob refs: the migration deleted the
// repo's blob objects after promoting them into the global blobstore and recorded ownership only
// in the cache, so nothing but index.json is left under the repo. Reads must recover from the
// blobstore, but only for digests this repo's own manifest graph reaches - the blobstore is
// shared, so an ungated fallback would let any repo serve any other repo's blobs.
func TestGlobalBlobstoreFallbackAfterBlobRefLoss(t *testing.T) {
	Convey("A migrated repo with no blob refs resolves reads through the global blobstore", t, func() {
		rootDir := "/oci-repo-test/blobstore-fallback"
		repo := "repo"
		ctx := context.Background()

		layerContent := []byte("referenced-layer-content")
		layerDigest := godigest.FromBytes(layerContent)
		configContent := []byte(`{"architecture":"amd64","os":"linux"}`)
		configDigest := godigest.FromBytes(configContent)

		manifest := ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    configDigest,
				Size:      int64(len(configContent)),
			},
			Layers: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
				Size:      int64(len(layerContent)),
			}},
		}
		manifest.SchemaVersion = 2

		manifestContent, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		manifestDigest := godigest.FromBytes(manifestContent)

		index := ispec.Index{
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(manifestContent)),
			}},
		}
		index.SchemaVersion = 2

		indexContent, err := json.Marshal(index)
		So(err, ShouldBeNil)

		globalPath := func(digest godigest.Digest) string {
			return path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
				digest.Algorithm().String(), digest.Encoded())
		}
		repoPath := func(digest godigest.Digest) string {
			return path.Join(rootDir, repo, ispec.ImageBlobsDir,
				digest.Algorithm().String(), digest.Encoded())
		}

		// Post-migration bucket: every payload lives in the global blobstore, the repo keeps
		// only index.json, and the migration marker stops the upgrade from running again.
		storeMock := makeStatefulMigrationStoreMock(rootDir, repo, globalPath(manifestDigest), manifestContent)
		So(storeMock.PutContent(ctx, path.Join(rootDir, constants.BlobstoreMigratedMarker), []byte("1")), ShouldBeNil)
		So(storeMock.PutContent(ctx, path.Join(rootDir, repo, ispec.ImageIndexFile), indexContent), ShouldBeNil)
		So(storeMock.PutContent(ctx, globalPath(configDigest), configContent), ShouldBeNil)
		So(storeMock.PutContent(ctx, globalPath(layerDigest), layerContent), ShouldBeNil)

		// A digest another repository pushed: present in the shared blobstore, unreachable
		// from this repo's index.json.
		foreignContent := []byte("blob-owned-by-another-repository")
		foreignDigest := godigest.FromBytes(foreignContent)
		So(storeMock.PutContent(ctx, globalPath(foreignDigest), foreignContent), ShouldBeNil)

		// Empty cache: this is a fresh local root pointed at an already migrated bucket.
		cache := newMapBackedCache()

		testLog := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, testLog)
		t.Cleanup(metrics.Stop)

		store := imagestore.NewImageStore(rootDir, "", true, false, testLog, metrics, nil,
			gcs.New(storeMock), cache, nil, nil)
		So(store, ShouldNotBeNil)

		Convey("blobs referenced by the repo's index are served from the global blobstore", func() {
			actual, err := store.GetBlobContent(repo, manifestDigest)
			So(err, ShouldBeNil)
			So(actual, ShouldResemble, manifestContent)

			actual, err = store.GetBlobContent(repo, configDigest)
			So(err, ShouldBeNil)
			So(actual, ShouldResemble, configContent)

			actual, err = store.GetBlobContent(repo, layerDigest)
			So(err, ShouldBeNil)
			So(actual, ShouldResemble, layerContent)

			found, size, err := store.CheckBlob(ctx, repo, layerDigest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
			So(size, ShouldEqual, int64(len(layerContent)))
		})

		Convey("a blobstore blob this repo does not reference stays unreadable", func() {
			_, err := store.GetBlobContent(repo, foreignDigest)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)

			found, _, err := store.CheckBlob(ctx, repo, foreignDigest)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
			So(found, ShouldBeFalse)

			_, err = cache.GetAllBlobs(foreignDigest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		})

		Convey("a successful fallback restores the blob ref so the next read is a fast path", func() {
			_, err := cache.GetAllBlobs(layerDigest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)

			_, err = store.GetBlobContent(repo, layerDigest)
			So(err, ShouldBeNil)

			refs, err := cache.GetAllBlobs(layerDigest)
			So(err, ShouldBeNil)
			So(refs, ShouldContain, repoPath(layerDigest))

			// The restored ref alone resolves the read now: the index walk is not needed
			// again, and the payload still comes from the global blobstore.
			actual, err := store.GetBlobContent(repo, layerDigest)
			So(err, ShouldBeNil)
			So(actual, ShouldResemble, layerContent)
		})
	})
}
