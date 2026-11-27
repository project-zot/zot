package imagestore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// Package-level so tests can hand the driver a static error. err113 rejects
// errors.New at the call site.
var ( //nolint: gochecknoglobals
	errDeleteFailed       = errors.New("delete failed")
	errDriverFailed       = errors.New("driver failed")
	errLayoutStatBlip     = errors.New("layout stat blip")
	errIndexBlip          = errors.New("index blip")
	errAlgListBlip        = errors.New("alg list blip")
	errAlgListDenied      = errors.New("alg list denied")
	errStatBlip           = errors.New("stat blip")
	errCacheBlip          = errors.New("cache blip")
	errCachePutDenied     = errors.New("cache put denied")
	errListBlip           = errors.New("list blip")
	errRawListFailure     = errors.New("raw list failure")
	errBlobsStatBlip      = errors.New("blobs stat blip")
	errBlobsDenied        = errors.New("blobs denied")
	errRawBlobsStat       = errors.New("raw blobs stat")
	errLastStatBlip       = errors.New("last stat blip")
	errLastValidateBlip   = errors.New("last validate blip")
	errLastValidateDenied = errors.New("last validate denied")
	errRootListFailed     = errors.New("root list failed")
	errFlushEdquot        = errors.New("flush edquot")
	errWriteEdquot        = errors.New("write edquot")
	errDiskFull           = errors.New("disk full")
)

// rawListDriver returns List errors without driver formatErr classification so
// ImageStore.ValidateRepo's unclassified MarkTransient fallback stays reachable.
type rawListDriver struct {
	storageTypes.Driver

	listErr error
}

func (d *rawListDriver) List(string) ([]string, error) {
	return nil, d.listErr
}

// blobsStatDriver overrides Stat for the repo blobs/ directory so local
// ValidateRepo can be exercised with classed errors without chmod/root races.
type blobsStatDriver struct {
	storageTypes.Driver

	blobsStatErr error
}

func (d *blobsStatDriver) Stat(statPath string) (driver.FileInfo, error) {
	if path.Base(statPath) == ispec.ImageBlobsDir && d.blobsStatErr != nil {
		return nil, d.blobsStatErr
	}

	return d.Driver.Stat(statPath)
}

func writeMinimalLocalOCILayout(t *testing.T, rootDir, repo string) {
	t.Helper()

	repoDir := path.Join(rootDir, repo)
	So(os.MkdirAll(path.Join(repoDir, ispec.ImageBlobsDir), 0o755), ShouldBeNil)
	So(os.WriteFile(path.Join(repoDir, ispec.ImageIndexFile),
		[]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`),
		0o600), ShouldBeNil)
	So(os.WriteFile(path.Join(repoDir, ispec.ImageLayoutFile),
		[]byte(`{"imageLayoutVersion": "1.0.0"}`), 0o600), ShouldBeNil)
}

func TestGetAllDedupeReposCandidatesSkipsMalformedPaths(t *testing.T) {
	rootDir := t.TempDir()
	outsideDir := t.TempDir()
	digest := godigest.FromString("dedupe-cache-path")
	blobSuffix := path.Join(ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())

	tests := []struct {
		name              string
		usesRelativePaths bool
		cachedPaths       []string
		wantRepositories  []string
	}{
		{
			name:              "relative paths",
			usesRelativePaths: true,
			cachedPaths: []string{
				"bad-path",
				"",
				path.Join("relative-repo", blobSuffix),
			},
			wantRepositories: []string{"relative-repo"},
		},
		{
			name:              "absolute paths",
			usesRelativePaths: false,
			cachedPaths: []string{
				path.Join(outsideDir, "not-a-blob"),
				path.Join(rootDir, "absolute-repo", blobSuffix),
			},
			wantRepositories: []string{"absolute-repo"},
		},
		{
			name:              "all paths malformed",
			usesRelativePaths: false,
			cachedPaths:       []string{"bad-path", ""},
			wantRepositories:  []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cache := mocks.CacheMock{
				GetAllBlobsFn: func(_ godigest.Digest) ([]string, error) {
					return test.cachedPaths, nil
				},
				UsesRelativePathsFn: func() bool { return test.usesRelativePaths },
			}

			store := imagestore.NewImageStore(rootDir, rootDir, true, true, zlog.NewTestLogger(),
				monitoring.NewNopMetricServer(), nil, local.New(true), cache, nil, nil)
			repos, err := store.GetAllDedupeReposCandidates(digest)

			require.NoError(t, err)
			require.Equal(t, test.wantRepositories, repos)
		})
	}
}

func TestGetBlobRedirectURL(t *testing.T) {
	Convey("GetBlobRedirectURL", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		Convey("returns bad digest for invalid digest", func() {
			store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
				local.New(true), nil, nil, nil)

			url, err := store.GetBlobRedirectURL(nil, "repo", godigest.Digest("not-a-digest"))
			So(url, ShouldEqual, "")
			So(errors.Is(err, zerr.ErrBadBlobDigest), ShouldBeTrue)
		})

		Convey("returns empty URL for local storage", func() {
			store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
				local.New(true), nil, nil, nil)

			digest := godigest.FromString("blob-content")
			// Local driver has no external signed URL endpoint, so redirect is intentionally empty.
			url, err := store.GetBlobRedirectURL(nil, "repo", digest)
			So(err, ShouldBeNil)
			So(url, ShouldEqual, "")
		})

		Convey("returns redirect URL for remote storage", func() {
			rootDir := t.TempDir()
			storeMock := &mocks.StorageDriverMock{}
			remoteDriver := gcs.New(storeMock)
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				remoteDriver, nil, nil, nil)

			repo := "repo"
			digest := godigest.FromString("blob-content")
			expectedBlobPath := store.BlobPath(repo, digest)
			expectedURL := "https://example.com/signed/blob"

			storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
				So(path, ShouldEqual, expectedBlobPath)

				return &mocks.FileInfoMock{
					PathFn: func() string { return path },
					SizeFn: func() int64 { return 42 },
				}, nil
			}

			storeMock.RedirectURLFn = func(_ *http.Request, path string) (string, error) {
				So(path, ShouldEqual, expectedBlobPath)

				return expectedURL, nil
			}

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"http://localhost/v2/repo/blobs/sha256:deadbeef", nil)

			url, err := store.GetBlobRedirectURL(req, repo, digest)
			So(err, ShouldBeNil)
			So(url, ShouldEqual, expectedURL)
		})

		Convey("returns blob not found when blob path does not exist", func() {
			rootDir := t.TempDir()
			storeMock := &mocks.StorageDriverMock{}
			remoteDriver := gcs.New(storeMock)
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				remoteDriver, nil, nil, nil)

			storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
				return nil, driver.PathNotFoundError{Path: path}
			}

			digest := godigest.FromString("blob-content")
			url, err := store.GetBlobRedirectURL(nil, "repo", digest)
			So(url, ShouldEqual, "")
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
		})
	})
}

func TestCleanupRepoToleratesDeletePathNotFound(t *testing.T) {
	Convey("CleanupRepo tolerates PathNotFound on delete", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		rootDir := t.TempDir()
		storeMock := &mocks.StorageDriverMock{}
		remoteDriver := gcs.New(storeMock)
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			remoteDriver, nil, nil, nil)

		repo := "repo"
		ctx := context.Background()
		So(store.InitRepo(ctx, repo), ShouldBeNil)

		digest := godigest.FromString("blob-content")
		blobPath := store.BlobPath(repo, digest)

		storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
			if path == blobPath {
				return mocks.FileInfoFile(10), nil
			}

			return mocks.FileInfoDir(), nil
		}
		storeMock.DeleteFn = func(_ context.Context, path string) error {
			if path == blobPath {
				return driver.PathNotFoundError{Path: path}
			}

			return nil
		}
		storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
			return nil, nil
		}

		count, err := store.CleanupRepo(repo, []godigest.Digest{digest})
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 1)
	})
}

func TestCleanupRepoFailsOnUnexpectedDeleteBlobError(t *testing.T) {
	Convey("CleanupRepo returns error when deleteBlob fails unexpectedly", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		rootDir := t.TempDir()
		storeMock := &mocks.StorageDriverMock{}
		remoteDriver := gcs.New(storeMock)
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			remoteDriver, nil, nil, nil)

		repo := "repo"
		ctx := context.Background()
		So(store.InitRepo(ctx, repo), ShouldBeNil)

		digest := godigest.FromString("blob-content")
		blobPath := store.BlobPath(repo, digest)

		storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
			if path == blobPath {
				return mocks.FileInfoFile(10), nil
			}

			return mocks.FileInfoDir(), nil
		}
		storeMock.DeleteFn = func(_ context.Context, path string) error {
			if path == blobPath {
				return errDeleteFailed
			}

			return nil
		}
		storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
			return nil, nil
		}

		count, err := store.CleanupRepo(repo, []godigest.Digest{digest})
		So(err, ShouldNotBeNil)
		So(count, ShouldEqual, 0)
	})
}

func TestRemoveIdleRepository(t *testing.T) {
	newStore := func(rootDir string) storageTypes.ImageStore {
		return imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
	}

	removeIdle := func(store storageTypes.ImageStore, repo string, maxBlobAge time.Duration) (bool, error) {
		var removed bool

		err := store.WithRepoLock(repo, func() error {
			var err error

			removed, err = store.RemoveIdleRepository(repo, maxBlobAge)

			return err
		})

		return removed, err
	}

	Convey("An emptied repo loses its layout, orphan blobs included", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		// an orphan blob, as left behind by a manifest delete
		content := []byte("orphan blob")
		digest := godigest.FromBytes(content)
		_, _, err := store.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		removed, err := removeIdle(store, "repo", 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeFalse)
	})

	Convey("A repo still holding a manifest is kept", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		index := ispec.Index{
			SchemaVersion: 2,
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromString("manifest"),
				Size:      1,
			}},
		}
		So(store.PutIndexContent("repo", index), ShouldBeNil)

		removed, err := removeIdle(store, "repo", 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeTrue)
	})

	Convey("A repo with a blob upload in progress is kept", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		_, err := store.NewBlobUpload(ctx, "repo")
		So(err, ShouldBeNil)

		removed, err := removeIdle(store, "repo", 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeTrue)
	})

	Convey("Blobs younger than maxBlobAge keep the repo", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		content := []byte("young blob")
		digest := godigest.FromBytes(content)
		_, _, err := store.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		removed, err := removeIdle(store, "repo", time.Hour)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeTrue)

		ok, _, _, err := store.StatBlob("repo", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
	})

	Convey("A bare empty layout is removed", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		removed, err := removeIdle(store, "repo", 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeFalse)
	})

	Convey("A nested repository survives idle removal of its parent", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "demo/app"), ShouldBeNil)
		So(store.InitRepo(ctx, "demo/app/cache"), ShouldBeNil)

		cacheContent := []byte("cache layer")
		cacheDigest := godigest.FromBytes(cacheContent)
		_, _, err := store.FullBlobUpload(ctx, "demo/app/cache", bytes.NewReader(cacheContent), cacheDigest)
		So(err, ShouldBeNil)

		removed, err := removeIdle(store, "demo/app", 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)

		ok, err := store.ValidateRepo("demo/app/cache")
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)

		present, _, _, err := store.StatBlob("demo/app/cache", cacheDigest)
		So(err, ShouldBeNil)
		So(present, ShouldBeTrue)

		repos, err := store.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldContain, "demo/app/cache")
		So(repos, ShouldNotContain, "demo/app")
	})

	Convey("A mid-flight layout cleanup failure keeps layout markers for retry", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, ispec.ImageIndexFile)
		layoutPath := path.Join(repoDir, ispec.ImageLayoutFile)
		uploadsDir := path.Join(repoDir, storageConstants.BlobUploadDir)
		blobsDir := path.Join(repoDir, ispec.ImageBlobsDir)
		emptyIndex := []byte(`{"schemaVersion":2,"manifests":[]}`)

		// Fail during pruneEmptyBlobDirs (before oci-layout / index.json) so both
		// markers remain and ValidateRepo / GetIndex can still find the repo.
		failBlobsList := true

		var deleted []string

		fileInfo := func(size int64) driver.FileInfo {
			return mocks.FileInfoFile(size)
		}
		dirInfo := func() driver.FileInfo {
			return mocks.FileInfoDir()
		}
		notFound := func(objectPath string) error {
			return driver.PathNotFoundError{Path: objectPath}
		}

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
				if objectPath == indexPath || objectPath == layoutPath {
					return fileInfo(10), nil
				}

				return dirInfo(), nil
			},
			GetContentFn: func(_ context.Context, _ string) ([]byte, error) {
				return emptyIndex, nil
			},
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch listPath {
				case uploadsDir:
					return nil, notFound(listPath)
				case blobsDir:
					if failBlobsList {
						return nil, errDriverFailed
					}

					return nil, notFound(listPath)
				case repoDir:
					return []string{}, nil
				default:
					return nil, notFound(listPath)
				}
			},
			DeleteFn: func(_ context.Context, objectPath string) error {
				deleted = append(deleted, objectPath)

				return nil
			},
		}
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)

		removed, err := removeIdle(store, repo, 0)
		So(err, ShouldNotBeNil)
		So(removed, ShouldBeFalse)
		So(deleted, ShouldNotContain, layoutPath)
		So(deleted, ShouldNotContain, indexPath)

		failBlobsList = false
		deleted = nil

		removed, err = removeIdle(store, repo, 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)
		So(deleted, ShouldContain, layoutPath)
		So(deleted, ShouldContain, indexPath)
	})

	Convey("Missing index with oci-layout already gone resumes layout prune", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, ispec.ImageIndexFile)
		layoutPath := path.Join(repoDir, ispec.ImageLayoutFile)
		uploadsDir := path.Join(repoDir, storageConstants.BlobUploadDir)
		blobsDir := path.Join(repoDir, ispec.ImageBlobsDir)

		var deleted []string

		notFound := func(objectPath string) error {
			return driver.PathNotFoundError{Path: objectPath}
		}

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
				switch objectPath {
				case indexPath, layoutPath:
					return nil, notFound(objectPath)
				case repoDir, uploadsDir, blobsDir:
					return mocks.FileInfoDir(), nil
				default:
					return nil, notFound(objectPath)
				}
			},
			GetContentFn: func(_ context.Context, objectPath string) ([]byte, error) {
				return nil, notFound(objectPath)
			},
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch listPath {
				case uploadsDir, blobsDir:
					return nil, notFound(listPath)
				case repoDir:
					// Leftover uploads dir from the interrupted prune.
					return []string{uploadsDir}, nil
				default:
					return nil, notFound(listPath)
				}
			},
			DeleteFn: func(_ context.Context, objectPath string) error {
				deleted = append(deleted, objectPath)

				return nil
			},
		}
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)

		removed, err := removeIdle(store, repo, 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)
		So(deleted, ShouldContain, uploadsDir)
	})

	Convey("Missing markers with a listed upload leave the staging tree alone", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, ispec.ImageIndexFile)
		layoutPath := path.Join(repoDir, ispec.ImageLayoutFile)
		uploadsDir := path.Join(repoDir, storageConstants.BlobUploadDir)
		uploadPath := path.Join(uploadsDir, "active-uuid")

		var deleted []string

		notFound := func(objectPath string) error {
			return driver.PathNotFoundError{Path: objectPath}
		}

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
				switch objectPath {
				case indexPath, layoutPath:
					return nil, notFound(objectPath)
				case repoDir, uploadsDir:
					return mocks.FileInfoDir(), nil
				default:
					return nil, notFound(objectPath)
				}
			},
			GetContentFn: func(_ context.Context, objectPath string) ([]byte, error) {
				return nil, notFound(objectPath)
			},
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				if listPath == uploadsDir {
					return []string{uploadPath}, nil
				}

				return nil, notFound(listPath)
			},
			DeleteFn: func(_ context.Context, objectPath string) error {
				deleted = append(deleted, objectPath)

				return nil
			},
		}
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)

		removed, err := removeIdle(store, repo, 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
		So(deleted, ShouldBeEmpty)
	})

	Convey("A repo already gone from storage is a no-op", t, func() {
		store := newStore(t.TempDir())

		removed, err := removeIdle(store, "ghost", 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
	})

	Convey("GetIndex Transient fails closed (not a silent skip)", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		indexPath := path.Join(rootDir, repo, ispec.ImageIndexFile)
		transient := errclass.MarkTransient(errIndexBlip)
		storeMock := &mocks.StorageDriverMock{
			GetContentFn: func(_ context.Context, getPath string) ([]byte, error) {
				So(getPath, ShouldEqual, indexPath)

				return nil, transient
			},
		}
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)

		removed, err := removeIdle(store, repo, 0)
		So(removed, ShouldBeFalse)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
	})
}

func TestRemoveIdleRepositoryInterruptedPruneErrors(t *testing.T) {
	removeIdle := func(store storageTypes.ImageStore, repo string, maxBlobAge time.Duration) (bool, error) {
		var removed bool

		err := store.WithRepoLock(repo, func() error {
			var err error

			removed, err = store.RemoveIdleRepository(repo, maxBlobAge)

			return err
		})

		return removed, err
	}

	Convey("Interrupted prune fails closed on driver errors", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, ispec.ImageIndexFile)
		layoutPath := path.Join(repoDir, ispec.ImageLayoutFile)
		uploadsDir := path.Join(repoDir, storageConstants.BlobUploadDir)

		notFound := func(objectPath string) error {
			return driver.PathNotFoundError{Path: objectPath}
		}

		newInterruptedStore := func(storeMock *mocks.StorageDriverMock) storageTypes.ImageStore {
			return imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)
		}

		Convey("repo dir Stat failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
					if objectPath == indexPath {
						return nil, notFound(objectPath)
					}
					if objectPath == repoDir {
						return nil, errDriverFailed
					}

					return nil, notFound(objectPath)
				},
				GetContentFn: func(_ context.Context, objectPath string) ([]byte, error) {
					return nil, notFound(objectPath)
				},
			}

			removed, err := removeIdle(newInterruptedStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("oci-layout Stat failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
					switch objectPath {
					case indexPath:
						return nil, notFound(objectPath)
					case repoDir:
						return mocks.FileInfoDir(), nil
					case layoutPath:
						return nil, errDriverFailed
					default:
						return nil, notFound(objectPath)
					}
				},
				GetContentFn: func(_ context.Context, objectPath string) ([]byte, error) {
					return nil, notFound(objectPath)
				},
			}

			removed, err := removeIdle(newInterruptedStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("uploads list failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
					switch objectPath {
					case indexPath, layoutPath:
						return nil, notFound(objectPath)
					case repoDir:
						return mocks.FileInfoDir(), nil
					default:
						return nil, notFound(objectPath)
					}
				},
				GetContentFn: func(_ context.Context, objectPath string) ([]byte, error) {
					return nil, notFound(objectPath)
				},
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					if listPath == uploadsDir {
						return nil, errDriverFailed
					}

					return nil, notFound(listPath)
				},
			}

			removed, err := removeIdle(newInterruptedStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("prune failure after idle gates", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
					switch objectPath {
					case indexPath, layoutPath:
						return nil, notFound(objectPath)
					case repoDir:
						return mocks.FileInfoDir(), nil
					default:
						return nil, notFound(objectPath)
					}
				},
				GetContentFn: func(_ context.Context, objectPath string) ([]byte, error) {
					return nil, notFound(objectPath)
				},
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					if listPath == uploadsDir {
						return nil, notFound(listPath)
					}
					// Fail the first pruneEmptyBlobDirs list.
					return nil, errDriverFailed
				},
			}

			removed, err := removeIdle(newInterruptedStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})
	})
}

func TestRemoveIdleRepositoryDriverFailures(t *testing.T) {
	removeIdle := func(store storageTypes.ImageStore, repo string, maxBlobAge time.Duration) (bool, error) {
		var removed bool

		err := store.WithRepoLock(repo, func() error {
			var err error

			removed, err = store.RemoveIdleRepository(repo, maxBlobAge)

			return err
		})

		return removed, err
	}

	Convey("Driver failures fail closed", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		repo := "repo"
		rootDir := t.TempDir()
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, "index.json")
		uploadsDir := path.Join(repoDir, ".uploads")
		blobsDir := path.Join(repoDir, "blobs")

		emptyIndex := []byte(`{"schemaVersion":2,"manifests":[]}`)

		blobContent := []byte("orphan blob")
		blobDigest := godigest.FromBytes(blobContent)
		sha256Dir := path.Join(blobsDir, "sha256")
		blobPath := path.Join(sha256Dir, blobDigest.Encoded())

		newMockStore := func(storeMock *mocks.StorageDriverMock) storageTypes.ImageStore {
			return imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)
		}

		dirInfo := func() driver.FileInfo {
			return mocks.FileInfoDir()
		}
		notFound := func(path string) error {
			return driver.PathNotFoundError{Path: path}
		}

		Convey("an index read failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, path string) ([]byte, error) {
					So(path, ShouldEqual, indexPath)

					return nil, errDriverFailed
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a blob uploads listing failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, path string) ([]string, error) {
					So(path, ShouldEqual, uploadsDir)

					return nil, errDriverFailed
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a blob listing failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, path string) ([]string, error) {
					if path == uploadsDir {
						return nil, notFound(path)
					}

					return nil, errDriverFailed
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		fileInfo := func(size int64) driver.FileInfo {
			return mocks.FileInfoFile(size)
		}

		Convey("a blob stat failure under a grace period", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, path string) (driver.FileInfo, error) {
					if path == blobPath {
						return nil, errDriverFailed
					}

					return dirInfo(), nil
				},
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, path string) ([]string, error) {
					switch path {
					case uploadsDir:
						return nil, notFound(path)
					case blobsDir:
						return []string{sha256Dir}, nil
					case sha256Dir:
						return []string{blobPath}, nil
					}

					return nil, notFound(path)
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, time.Hour)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a blob delete failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, path string) (driver.FileInfo, error) {
					if path == blobPath {
						return fileInfo(10), nil
					}

					return dirInfo(), nil
				},
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, path string) ([]string, error) {
					switch path {
					case uploadsDir:
						return nil, notFound(path)
					case blobsDir:
						return []string{sha256Dir}, nil
					case sha256Dir:
						return []string{blobPath}, nil
					}

					return nil, notFound(path)
				},
				DeleteFn: func(_ context.Context, path string) error {
					So(path, ShouldEqual, blobPath)

					return errDriverFailed
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a relisting failure after the sweep", func() {
			blobsListCalls := 0
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, path string) (driver.FileInfo, error) {
					if path == blobPath {
						return fileInfo(10), nil
					}

					return dirInfo(), nil
				},
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, path string) ([]string, error) {
					switch path {
					case uploadsDir:
						return nil, notFound(path)
					case blobsDir:
						blobsListCalls++
						if blobsListCalls > 1 {
							return nil, errDriverFailed
						}

						return []string{sha256Dir}, nil
					case sha256Dir:
						return []string{blobPath}, nil
					}

					return nil, notFound(path)
				},
				DeleteFn: func(_ context.Context, _ string) error { return nil },
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})
	})
}

func TestRemoveIdleRepositoryPruneFailures(t *testing.T) {
	removeIdle := func(store storageTypes.ImageStore, repo string, maxBlobAge time.Duration) (bool, error) {
		var removed bool

		err := store.WithRepoLock(repo, func() error {
			var err error

			removed, err = store.RemoveIdleRepository(repo, maxBlobAge)

			return err
		})

		return removed, err
	}

	Convey("Prune driver failures fail closed", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		repo := "repo"
		rootDir := t.TempDir()
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, "index.json")
		uploadsDir := path.Join(repoDir, ".uploads")
		blobsDir := path.Join(repoDir, "blobs")

		emptyIndex := []byte(`{"schemaVersion":2,"manifests":[]}`)

		blobContent := []byte("orphan blob")
		blobDigest := godigest.FromBytes(blobContent)
		sha256Dir := path.Join(blobsDir, "sha256")
		blobPath := path.Join(sha256Dir, blobDigest.Encoded())

		newMockStore := func(storeMock *mocks.StorageDriverMock) storageTypes.ImageStore {
			return imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)
		}

		dirInfo := func() driver.FileInfo {
			return mocks.FileInfoDir()
		}
		notFound := func(path string) error {
			return driver.PathNotFoundError{Path: path}
		}
		fileInfo := func(size int64) driver.FileInfo {
			return mocks.FileInfoFile(size)
		}

		Convey("a layout delete failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					if listPath == repoDir {
						return []string{}, nil
					}

					return nil, notFound(listPath)
				},
				DeleteFn: func(_ context.Context, deletePath string) error {
					if deletePath == repoDir {
						return errDriverFailed
					}

					return nil
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a countBlobFiles Stat failure after the sweep", func() {
			blobStatCalls := 0
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
					if objectPath == blobPath {
						blobStatCalls++
						if blobStatCalls > 1 {
							return nil, errDriverFailed
						}

						return fileInfo(10), nil
					}

					return dirInfo(), nil
				},
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					switch listPath {
					case uploadsDir:
						return nil, notFound(listPath)
					case blobsDir:
						return []string{sha256Dir}, nil
					case sha256Dir:
						return []string{blobPath}, nil
					}

					return nil, notFound(listPath)
				},
				DeleteFn: func(_ context.Context, _ string) error { return nil },
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a blobsDir list failure during prune", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					switch listPath {
					case uploadsDir:
						return nil, notFound(listPath)
					case blobsDir:
						return nil, errDriverFailed
					}

					return nil, notFound(listPath)
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("an algorithm dir list failure during prune", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					switch listPath {
					case uploadsDir:
						return nil, notFound(listPath)
					case blobsDir:
						return []string{sha256Dir}, nil
					case sha256Dir:
						return nil, errDriverFailed
					}

					return nil, notFound(listPath)
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("an empty algorithm dir delete failure during prune", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					switch listPath {
					case uploadsDir:
						return nil, notFound(listPath)
					case blobsDir:
						return []string{sha256Dir}, nil
					case sha256Dir:
						return []string{}, nil
					}

					return nil, notFound(listPath)
				},
				DeleteFn: func(_ context.Context, deletePath string) error {
					if deletePath == sha256Dir {
						return errDriverFailed
					}

					return nil
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a second blobsDir list failure during prune", func() {
			blobsListCalls := 0
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					switch listPath {
					case uploadsDir:
						return nil, notFound(listPath)
					case blobsDir:
						blobsListCalls++
						if blobsListCalls > 1 {
							return nil, errDriverFailed
						}

						return []string{sha256Dir}, nil
					case sha256Dir:
						return []string{}, nil
					}

					return nil, notFound(listPath)
				},
				DeleteFn: func(_ context.Context, _ string) error { return nil },
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("an uploads dir delete failure during prune", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					return nil, notFound(listPath)
				},
				DeleteFn: func(_ context.Context, deletePath string) error {
					if deletePath == uploadsDir {
						return errDriverFailed
					}

					return nil
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("an index.json delete failure during prune", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
					if objectPath == indexPath {
						return fileInfo(10), nil
					}

					return dirInfo(), nil
				},
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					return nil, notFound(listPath)
				},
				DeleteFn: func(_ context.Context, deletePath string) error {
					if deletePath == indexPath {
						return errDriverFailed
					}

					return nil
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})

		Convey("a final repo list failure during prune", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					if listPath == repoDir {
						return nil, errDriverFailed
					}

					return nil, notFound(listPath)
				},
				DeleteFn: func(_ context.Context, _ string) error { return nil },
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})
	})
}

func TestRemoveIdleRepositoryLayoutEdges(t *testing.T) {
	newStore := func(rootDir string) storageTypes.ImageStore {
		return imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
	}

	removeIdle := func(store storageTypes.ImageStore, repo string, maxBlobAge time.Duration) (bool, error) {
		var removed bool

		err := store.WithRepoLock(repo, func() error {
			var err error

			removed, err = store.RemoveIdleRepository(repo, maxBlobAge)

			return err
		})

		return removed, err
	}

	Convey("Index missing while oci-layout remains is a no-op", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, ispec.ImageIndexFile)
		layoutPath := path.Join(repoDir, ispec.ImageLayoutFile)

		var deleted []string

		notFound := func(objectPath string) error {
			return driver.PathNotFoundError{Path: objectPath}
		}

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
				switch objectPath {
				case indexPath:
					return nil, notFound(objectPath)
				case layoutPath:
					return mocks.FileInfoFile(10), nil
				case repoDir:
					return mocks.FileInfoDir(), nil
				default:
					return nil, notFound(objectPath)
				}
			},
			GetContentFn: func(_ context.Context, objectPath string) ([]byte, error) {
				return nil, notFound(objectPath)
			},
			DeleteFn: func(_ context.Context, objectPath string) error {
				deleted = append(deleted, objectPath)

				return nil
			},
		}
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)

		removed, err := removeIdle(store, repo, 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
		So(deleted, ShouldBeEmpty)
	})

	Convey("Non-algorithm names under blobs/ are skipped when pruning empty blob dirs", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()
		repo := "repo"

		So(store.InitRepo(ctx, repo), ShouldBeNil)

		strayDir := path.Join(rootDir, repo, ispec.ImageBlobsDir, "notanalgorithm")
		So(os.MkdirAll(strayDir, 0o755), ShouldBeNil)

		removed, err := removeIdle(store, repo, 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)

		_, err = os.Stat(strayDir)
		So(err, ShouldBeNil)
	})

	Convey("deleteFileIfPresent surfaces non-missing Stat failures", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		repoDir := path.Join(rootDir, repo)
		indexPath := path.Join(repoDir, ispec.ImageIndexFile)
		layoutPath := path.Join(repoDir, ispec.ImageLayoutFile)
		uploadsDir := path.Join(repoDir, storageConstants.BlobUploadDir)
		blobsDir := path.Join(repoDir, ispec.ImageBlobsDir)
		emptyIndex := []byte(`{"schemaVersion":2,"manifests":[]}`)

		notFound := func(objectPath string) error {
			return driver.PathNotFoundError{Path: objectPath}
		}
		statBlip := errclass.MarkTransient(errLayoutStatBlip)

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, objectPath string) (driver.FileInfo, error) {
				switch objectPath {
				case indexPath:
					return mocks.FileInfoFile(10), nil
				case layoutPath:
					return nil, statBlip
				case repoDir, uploadsDir, blobsDir:
					return mocks.FileInfoDir(), nil
				default:
					return nil, notFound(objectPath)
				}
			},
			GetContentFn: func(_ context.Context, _ string) ([]byte, error) {
				return emptyIndex, nil
			},
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch listPath {
				case uploadsDir, blobsDir:
					return nil, notFound(listPath)
				case repoDir:
					return []string{}, nil
				default:
					return nil, notFound(listPath)
				}
			},
		}
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)

		removed, err := removeIdle(store, repo, 0)
		So(removed, ShouldBeFalse)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
	})
}

func TestStatBlobEntry(t *testing.T) {
	Convey("StatBlobEntry rejects an invalid digest", t, func() {
		store := imagestore.NewImageStore(t.TempDir(), "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)

		ok, size, modtime, err := store.StatBlobEntry("repo", "inexistent")
		So(ok, ShouldBeFalse)
		So(size, ShouldEqual, int64(-1))
		So(modtime.IsZero(), ShouldBeTrue)
		So(err, ShouldNotBeNil)
	})

	Convey("StatBlobEntry returns the local object without following dedupe", t, func() {
		store := imagestore.NewImageStore(t.TempDir(), "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
		ctx := context.Background()

		content := []byte("entry blob")
		digest := godigest.FromBytes(content)
		_, _, err := store.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		ok, size, _, err := store.StatBlobEntry("repo", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, int64(len(content)))
	})
}

func TestInitRepoRejectsReservedLayoutLeaves(t *testing.T) {
	Convey("InitRepo rejects reserved layout path components and allows nested repos", t, func() {
		store := imagestore.NewImageStore(t.TempDir(), "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
		ctx := context.Background()

		for _, name := range []string{
			"blobs",
			"index.json",
			"oci-layout",
			"demo/blobs",
			"demo/netlify/blobs",
			"demo/index.json",
			"demo/oci-layout",
			"demo/blobs/cache",
			"demo/index.json/cache",
			"blobs/foo",
			"parent/blobs/child",
		} {
			err := store.InitRepo(ctx, name)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)
		}

		So(store.InitRepo(ctx, "image"), ShouldBeNil)
		So(store.InitRepo(ctx, "image/cache"), ShouldBeNil)
		So(store.InitRepo(ctx, "myblobs"), ShouldBeNil)
		So(store.InitRepo(ctx, "demo/myblobs"), ShouldBeNil)
	})
}

func TestDigestShapedDirectoryUnderBlobsIsNotDeleted(t *testing.T) {
	Convey("StatBlobEntry and delete refuse a directory at a blob path", t, func() {
		rootDir := t.TempDir()
		store := imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
		ctx := context.Background()
		repo := "demo/x"

		So(store.InitRepo(ctx, repo), ShouldBeNil)

		content := []byte("real blob")
		digest := godigest.FromBytes(content)
		_, _, err := store.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		nestedHex := "233562de1a0288b139c4fa40b7d189f806e906eeb048517aeb67f34ac0e2faf1"
		nestedDir := path.Join(rootDir, repo, ispec.ImageBlobsDir, "sha256", nestedHex)
		So(os.MkdirAll(nestedDir, 0o755), ShouldBeNil)
		So(os.WriteFile(path.Join(nestedDir, ispec.ImageLayoutFile), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600),
			ShouldBeNil)

		nestedDigest := godigest.NewDigestFromEncoded(godigest.SHA256, nestedHex)

		// GetAllBlobs is List+Validate only, so the digest-shaped directory is named.
		digests, err := store.GetAllBlobs(repo)
		So(err, ShouldBeNil)
		So(digests, ShouldContain, digest)
		So(digests, ShouldContain, nestedDigest)

		ok, _, _, err := store.StatBlobEntry(repo, nestedDigest)
		So(ok, ShouldBeFalse)
		So(errors.Is(err, zerr.ErrBadBlob), ShouldBeTrue)

		var removed bool
		err = store.WithRepoLock(repo, func() error {
			var lockErr error
			removed, lockErr = store.RemoveIdleRepository(repo, 0)

			return lockErr
		})
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)

		_, err = os.Stat(nestedDir)
		So(err, ShouldBeNil)
	})

	Convey("Age checks skip digest-shaped directories via ErrBadBlob", t, func() {
		rootDir := t.TempDir()
		store := imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
		ctx := context.Background()
		repo := "demo/aged"

		So(store.InitRepo(ctx, repo), ShouldBeNil)

		// Empty the index so RemoveIdleRepository will age-check listed digests.
		So(store.PutIndexContent(repo, ispec.Index{SchemaVersion: 2}), ShouldBeNil)

		nestedHex := "433562de1a0288b139c4fa40b7d189f806e906eeb048517aeb67f34ac0e2faf1"
		nestedDir := path.Join(rootDir, repo, ispec.ImageBlobsDir, "sha256", nestedHex)
		So(os.MkdirAll(nestedDir, 0o755), ShouldBeNil)

		nestedDigest := godigest.NewDigestFromEncoded(godigest.SHA256, nestedHex)
		digests, err := store.GetAllBlobs(repo)
		So(err, ShouldBeNil)
		So(digests, ShouldContain, nestedDigest)

		var removed bool
		err = store.WithRepoLock(repo, func() error {
			var lockErr error
			// Non-zero maxBlobAge forces StatBlobEntry; ErrBadBlob must be skipped.
			removed, lockErr = store.RemoveIdleRepository(repo, time.Hour)

			return lockErr
		})
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)

		_, err = os.Stat(nestedDir)
		So(err, ShouldBeNil)
	})
}

// TestGetAllBlobsNestedListMissing locks the inventory contract: a Missing
// List under blobs/<alg>/ after a successful parent List must not surface as
// ErrStorageMissing (GC soft-empties on that and can prune live index rows).
func TestGetAllBlobsNestedListMissing(t *testing.T) {
	Convey("GetAllBlobs reclassifies nested alg List Missing as Transient", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		blobsDir := path.Join(rootDir, repo, ispec.ImageBlobsDir)
		sha256Dir := path.Join(blobsDir, "sha256")
		sha512Dir := path.Join(blobsDir, "sha512")

		keptDigest := godigest.FromString("still-under-sha512")

		storeMock := &mocks.StorageDriverMock{
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch listPath {
				case blobsDir:
					// List a content-bearing alg first so a soft-empty bug would
					// discard a non-empty partial inventory.
					return []string{sha512Dir, sha256Dir}, nil
				case sha512Dir:
					return []string{path.Join(sha512Dir, keptDigest.Encoded())}, nil
				case sha256Dir:
					return nil, errclass.MarkMissing(driver.PathNotFoundError{Path: listPath})
				default:
					return nil, driver.PathNotFoundError{Path: listPath}
				}
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		digests, err := store.GetAllBlobs(repo)
		So(digests, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		// Must not keep Missing in the chain — GC soft-empties on that predicate.
		So(errclass.IsStorageObjectMissing(err), ShouldBeFalse)
	})

	Convey("GetAllBlobs propagates nested alg List Transient", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		blobsDir := path.Join(rootDir, repo, ispec.ImageBlobsDir)
		sha256Dir := path.Join(blobsDir, "sha256")

		storeMock := &mocks.StorageDriverMock{
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch listPath {
				case blobsDir:
					return []string{sha256Dir}, nil
				case sha256Dir:
					return nil, errclass.MarkTransient(errAlgListBlip)
				default:
					return nil, driver.PathNotFoundError{Path: listPath}
				}
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		digests, err := store.GetAllBlobs(repo)
		So(digests, ShouldBeEmpty)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
	})

	Convey("GetAllBlobs propagates nested alg List Permanent", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		blobsDir := path.Join(rootDir, repo, ispec.ImageBlobsDir)
		sha256Dir := path.Join(blobsDir, "sha256")

		storeMock := &mocks.StorageDriverMock{
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch listPath {
				case blobsDir:
					return []string{sha256Dir}, nil
				case sha256Dir:
					return nil, errclass.MarkPermanent(errAlgListDenied)
				default:
					return nil, driver.PathNotFoundError{Path: listPath}
				}
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		digests, err := store.GetAllBlobs(repo)
		So(digests, ShouldBeEmpty)
		So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
	})
}

// TestGetImageManifestRepoStatClasses locks the repo-dir Stat contract: Missing
// wraps ErrRepoNotFound (Missing kept); Transient/non-dir Permanent must not
// collapse to ErrRepoNotFound.
func TestGetImageManifestRepoStatClasses(t *testing.T) {
	Convey("GetImageManifest propagates Transient repo-dir Stat", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, _ string) (driver.FileInfo, error) {
				return nil, errclass.MarkTransient(errStatBlip)
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		_, _, _, err := store.GetImageManifest(repo, "tag")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeFalse)
	})

	Convey("GetImageManifest wraps Missing repo-dir Stat with ErrRepoNotFound", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "missing-repo"

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
				return nil, errclass.MarkMissing(driver.PathNotFoundError{Path: statPath})
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		_, _, _, err := store.GetImageManifest(repo, "tag")
		So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeTrue)
		So(errclass.IsStorageObjectMissing(err), ShouldBeTrue)
	})

	Convey("GetImageManifest maps non-directory repo path to Permanent", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "not-a-dir"

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, _ string) (driver.FileInfo, error) {
				return &mocks.FileInfoMock{IsDirFn: func() bool { return false }}, nil
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		_, _, _, err := store.GetImageManifest(repo, "tag")
		So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrRepoBadLayout), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeFalse)
	})
}

// TestCheckBlobTransientSkipsCacheFallback locks the Missing-only cache/`Link`
// gate: a Transient Stat must not consult the cache or write a remote stub.
func TestCheckBlobTransientSkipsCacheFallback(t *testing.T) {
	Convey("CheckBlob does not cache-fallback or Link after Transient Stat", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()

		digest := godigest.FromString("checkblob-transient")
		cacheHitPath := path.Join(rootDir, "origin/blobs/sha256", digest.Encoded())

		cacheLookups := 0
		putContentCalls := 0

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
				// an upgraded store, so that it opens without upgrading
				if path.Base(statPath) == storageConstants.BlobstoreMigratedMarker {
					return &mocks.FileInfoMock{}, nil
				}

				return nil, errclass.MarkTransient(errStatBlip)
			},
			PutContentFn: func(_ context.Context, _ string, _ []byte) error {
				putContentCalls++

				return nil
			},
		}

		cacheMock := mocks.CacheMock{
			GetBlobFn: func(d godigest.Digest) (string, error) {
				So(d, ShouldEqual, digest)

				cacheLookups++

				return cacheHitPath, nil
			},
			HasBlobFn: func(godigest.Digest, string) bool { return true },
		}

		store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
			gcs.New(storeMock), cacheMock, nil, nil)
		So(store, ShouldNotBeNil)

		ok, size, err := store.CheckBlob(context.Background(), "repo", digest)
		So(ok, ShouldBeFalse)
		So(size, ShouldEqual, -1)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)
		So(cacheLookups, ShouldEqual, 0)
		So(putContentCalls, ShouldEqual, 0)
	})
}

// TestCheckBlobWithSize checks that a known size replaces the descriptor lookup, which reads
// index.json and then the manifests of the repo, while CheckBlob keeps doing that lookup.
func TestCheckBlobWithSize(t *testing.T) {
	Convey("CheckBlobWithSize compares against the given size without reading the repo", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()

		digest := godigest.FromString("checkblob-with-size")
		blobPath := path.Join(rootDir, "repo", ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())

		var contentReads []string

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
				So(statPath, ShouldEqual, blobPath)

				return mocks.FileInfoFile(5), nil
			},
			GetContentFn: func(_ context.Context, contentPath string) ([]byte, error) {
				contentReads = append(contentReads, contentPath)

				return nil, driver.PathNotFoundError{Path: contentPath}
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		ctx := context.Background()

		Convey("blob with the expected size is found", func() {
			ok, size, err := store.CheckBlobWithSize(ctx, "repo", digest, 5)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
			So(size, ShouldEqual, 5)
			So(contentReads, ShouldBeEmpty)
		})

		Convey("blob with a different size is reported as not found", func() {
			for _, expectedSize := range []int64{0, 4, 6} {
				ok, size, err := store.CheckBlobWithSize(ctx, "repo", digest, expectedSize)
				So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
				So(ok, ShouldBeFalse)
				So(size, ShouldEqual, -1)
			}

			So(contentReads, ShouldBeEmpty)
		})

		Convey("unknown size falls back to the descriptor lookup", func() {
			ok, size, err := store.CheckBlobWithSize(ctx, "repo", digest, -1)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
			So(size, ShouldEqual, 5)
			So(contentReads, ShouldResemble, []string{path.Join(rootDir, "repo", ispec.ImageIndexFile)})
		})

		Convey("CheckBlob keeps the descriptor lookup", func() {
			ok, size, err := store.CheckBlob(ctx, "repo", digest)
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
			So(size, ShouldEqual, 5)
			So(contentReads, ShouldResemble, []string{path.Join(rootDir, "repo", ispec.ImageIndexFile)})
		})
	})
}

// TestCheckBlobWithSizeCacheOrigin checks that a known size is also compared against content found
// through the dedupe cache, both when the blob is missing from the repo and when it is a placeholder.
func TestCheckBlobWithSizeCacheOrigin(t *testing.T) {
	Convey("CheckBlobWithSize compares content found through the dedupe cache", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()

		digest := godigest.FromString("checkblob-with-size-cache-origin")
		blobPath := path.Join(rootDir, "repo", ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
		cacheHitPath := path.Join(rootDir, "origin", ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())

		for _, testCase := range []struct {
			name     string
			blobInfo func(statPath string) (driver.FileInfo, error)
		}{
			{
				name: "blob missing from the repo",
				blobInfo: func(statPath string) (driver.FileInfo, error) {
					return nil, driver.PathNotFoundError{Path: statPath}
				},
			},
			{
				name: "blob is a placeholder",
				blobInfo: func(string) (driver.FileInfo, error) {
					return mocks.FileInfoFile(0), nil
				},
			},
		} {
			Convey(testCase.name, func() {
				var putBlobs []string

				storeMock := &mocks.StorageDriverMock{
					StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
						switch statPath {
						case blobPath:
							return testCase.blobInfo(statPath)
						case cacheHitPath:
							return mocks.FileInfoFile(42), nil
						default:
							// initRepo layout/index: absent so WriteFile creates them.
							return nil, driver.PathNotFoundError{Path: statPath}
						}
					},
				}

				store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
					gcs.New(storeMock), mocks.CacheMock{
						GetBlobFn: func(godigest.Digest) (string, error) {
							return cacheHitPath, nil
						},
						PutBlobFn: func(_ godigest.Digest, putPath string) error {
							putBlobs = append(putBlobs, putPath)

							return nil
						},
						HasBlobFn: func(godigest.Digest, string) bool { return true },
					}, nil, nil)

				ctx := context.Background()

				Convey("origin with the expected size is found", func() {
					ok, size, err := store.CheckBlobWithSize(ctx, "repo", digest, 42)
					So(err, ShouldBeNil)
					So(ok, ShouldBeTrue)
					So(size, ShouldEqual, 42)
					So(putBlobs, ShouldResemble, []string{blobPath})
				})

				Convey("origin with a different size is reported as not found", func() {
					ok, size, err := store.CheckBlobWithSize(ctx, "repo", digest, 41)
					So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
					So(ok, ShouldBeFalse)
					So(size, ShouldEqual, -1)
					So(putBlobs, ShouldBeEmpty)
				})

				Convey("unknown size accepts the origin", func() {
					ok, size, err := store.CheckBlobWithSize(ctx, "repo", digest, -1)
					So(err, ShouldBeNil)
					So(ok, ShouldBeTrue)
					So(size, ShouldEqual, 42)
					So(putBlobs, ShouldResemble, []string{blobPath})
				})
			})
		}
	})
}

// TestCheckBlobMissingCacheLookupErrors covers Missing Stat + non-unavailable
// cache lookup, and PutBlob failure after a successful cache heal/`Link`.
func TestCheckBlobMissingCacheLookupErrors(t *testing.T) {
	Convey("CheckBlob Missing Stat cache-fallback error paths", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()

		Convey("preserves Transient from cache GetBlob after Missing Stat", func() {
			rootDir := t.TempDir()
			digest := godigest.FromString("checkblob-cache-transient")
			blobPath := path.Join(rootDir, "repo", ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())

			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
					if statPath == blobPath {
						return nil, driver.PathNotFoundError{Path: statPath}
					}

					return mocks.FileInfoFile(1), nil
				},
			}

			cacheMock := mocks.CacheMock{
				GetBlobFn: func(godigest.Digest) (string, error) {
					return "", errclass.MarkTransient(errCacheBlip)
				},
			}

			store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
				gcs.New(storeMock), cacheMock, nil, nil)

			ok, size, err := store.CheckBlob(context.Background(), "repo", digest)
			So(ok, ShouldBeFalse)
			So(size, ShouldEqual, -1)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)
		})

		Convey("preserves PutBlob failure after successful Missing heal", func() {
			rootDir := t.TempDir()
			digest := godigest.FromString("checkblob-putblob-fail")
			blobPath := path.Join(rootDir, "repo", ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
			cacheHitPath := path.Join(rootDir, "origin/blobs/sha256", digest.Encoded())
			putBlobErr := errclass.MarkPermanent(errCachePutDenied)
			storeMock := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
					if statPath == blobPath {
						return nil, driver.PathNotFoundError{Path: statPath}
					}

					if statPath == cacheHitPath {
						return &mocks.FileInfoMock{
							PathFn: func() string { return cacheHitPath },
							SizeFn: func() int64 { return 42 },
						}, nil
					}

					// initRepo layout/index: absent so WriteFile creates them.
					return nil, driver.PathNotFoundError{Path: statPath}
				},
				PutContentFn: func(_ context.Context, _ string, _ []byte) error {
					return nil
				},
			}

			store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
				gcs.New(storeMock), mocks.CacheMock{
					GetBlobFn: func(d godigest.Digest) (string, error) {
						So(d, ShouldEqual, digest)

						return cacheHitPath, nil
					},
					PutBlobFn: func(godigest.Digest, string) error {
						return putBlobErr
					},
					HasBlobFn: func(godigest.Digest, string) bool { return true },
				}, nil, nil)

			ok, size, err := store.CheckBlob(context.Background(), "repo", digest)
			So(ok, ShouldBeFalse)
			So(size, ShouldEqual, -1)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)
		})
	})
}

func TestValidateRepoListStorageClasses(t *testing.T) {
	Convey("ValidateRepo Map List failures by storage class", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"

		Convey("Missing → ErrRepoNotFound", func() {
			storeMock := &mocks.StorageDriverMock{
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					return nil, driver.PathNotFoundError{Path: listPath}
				},
			}
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)

			ok, err := store.ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeTrue)
			So(errclass.IsStorageObjectMissing(err), ShouldBeTrue)
		})

		Convey("Transient propagates without ErrRepoNotFound", func() {
			storeMock := &mocks.StorageDriverMock{
				ListFn: func(_ context.Context, _ string) ([]string, error) {
					return nil, errclass.MarkTransient(errListBlip)
				},
			}
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)

			ok, err := store.ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeFalse)
		})

		Convey("unclassified List error is marked Transient", func() {
			// Bypass gcs/local formatErr (they already MarkTransient) so ValidateRepo
			// itself applies the unclassified → Transient fallback.
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				&rawListDriver{
					Driver:  gcs.New(&mocks.StorageDriverMock{}),
					listErr: errRawListFailure,
				}, nil, nil, nil)

			ok, err := store.ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeFalse)
		})
	})
}

func TestValidateRepoLocalBlobsStatStorageClasses(t *testing.T) {
	Convey("ValidateRepo maps local blobs/ Stat failures by storage class", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"
		writeMinimalLocalOCILayout(t, rootDir, repo)

		newStore := func(statErr error) storageTypes.ImageStore {
			return imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				&blobsStatDriver{Driver: local.New(false), blobsStatErr: statErr}, nil, nil, nil)
		}

		Convey("Missing blobs/ is invalid layout, not RepoNotFound", func() {
			ok, err := newStore(errclass.MarkMissing(driver.PathNotFoundError{
				Path: path.Join(rootDir, repo, ispec.ImageBlobsDir),
			})).ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(err, ShouldBeNil)
		})

		Convey("Transient blobs/ Stat propagates (inventory fail-closed)", func() {
			transient := errclass.MarkTransient(errBlobsStatBlip)
			ok, err := newStore(transient).ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("Permanent blobs/ Stat propagates", func() {
			permanent := errclass.MarkPermanent(errBlobsDenied)
			ok, err := newStore(permanent).ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("unclassified blobs/ Stat is marked Transient", func() {
			ok, err := newStore(errRawBlobsStat).ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("GetRepositories aborts on Transient blobs/ Stat", func() {
			transient := errclass.MarkTransient(errBlobsStatBlip)
			store := newStore(transient)
			repos, err := store.GetRepositories()
			So(repos, ShouldBeEmpty)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})
	})
}

func TestGetNextRepositoriesValidateRepoSoftSkip(t *testing.T) {
	Convey("GetNextRepositories soft-skips per-path ValidateRepo Transient", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		flakyRepo := "flaky"
		goodRepo := "good"

		storeMock := &mocks.StorageDriverMock{
			WalkFn: func(_ context.Context, _ string, walkFn driver.WalkFn,
				_ ...func(*driver.WalkOptions),
			) error {
				for _, name := range []string{flakyRepo, goodRepo} {
					repoPath := path.Join(rootDir, name)
					fi := &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
						PathFn:  func() string { return repoPath },
					}
					if err := walkFn(fi); err != nil {
						return err
					}
				}

				return nil
			},
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch path.Base(listPath) {
				case flakyRepo:
					return nil, errclass.MarkTransient(errListBlip)
				case goodRepo:
					return []string{
						path.Join(listPath, ispec.ImageIndexFile),
						path.Join(listPath, ispec.ImageLayoutFile),
					}, nil
				default:
					return nil, driver.PathNotFoundError{Path: listPath}
				}
			},
			StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
				return nil, driver.PathNotFoundError{Path: statPath}
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		repos, more, err := store.GetNextRepositories("", 10,
			func(_ string) (bool, error) { return true, nil })
		So(err, ShouldBeNil)
		So(more, ShouldBeFalse)
		So(repos, ShouldResemble, []string{goodRepo})
	})
}

func TestGetNextRepositoriesLastRepoProbe(t *testing.T) {
	Convey("GetNextRepositories probes catalog last with Stat, not DirExists", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		lastRepo := "aaa"
		keepRepo := "bbb"

		newStore := func(statLast error) storageTypes.ImageStore {
			storeMock := &mocks.StorageDriverMock{
				WalkFn: func(_ context.Context, _ string, walkFn driver.WalkFn,
					_ ...func(*driver.WalkOptions),
				) error {
					// last is gone from the walk (deleted cursor); only keepRepo remains.
					repoPath := path.Join(rootDir, keepRepo)
					fi := &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
						PathFn:  func() string { return repoPath },
					}

					return walkFn(fi)
				},
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					if path.Base(listPath) == keepRepo {
						return []string{
							path.Join(listPath, ispec.ImageIndexFile),
							path.Join(listPath, ispec.ImageLayoutFile),
						}, nil
					}

					return nil, driver.PathNotFoundError{Path: listPath}
				},
				StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
					if path.Base(statPath) == lastRepo {
						return nil, statLast
					}

					return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}, nil
				},
			}

			return imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)
		}

		acceptAll := func(_ string) (bool, error) { return true, nil }

		Convey("A last that is not a repository name is not looked up in storage", func() {
			statted := []string{}
			storeMock := &mocks.StorageDriverMock{
				WalkFn: func(_ context.Context, _ string, _ driver.WalkFn, _ ...func(*driver.WalkOptions)) error {
					return nil
				},
				StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
					statted = append(statted, statPath)

					return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}, nil
				},
			}
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)

			_, _, err := store.GetNextRepositories("../outside", 10, acceptAll)
			So(err, ShouldBeNil)
			So(statted, ShouldBeEmpty)
		})

		Convey("Missing last stays quiet and uses lexical after-last", func() {
			repos, more, err := newStore(driver.PathNotFoundError{Path: lastRepo}).
				GetNextRepositories(lastRepo, 10, acceptAll)
			So(err, ShouldBeNil)
			So(more, ShouldBeFalse)
			So(repos, ShouldResemble, []string{keepRepo})
		})

		Convey("Transient Stat on last treats as missing without failing the page", func() {
			transient := errclass.MarkTransient(errLastStatBlip)
			repos, more, err := newStore(transient).GetNextRepositories(lastRepo, 10, acceptAll)
			So(err, ShouldBeNil)
			So(more, ShouldBeFalse)
			So(repos, ShouldResemble, []string{keepRepo})
		})

		Convey("ValidateRepo Transient on last after Stat treats as missing", func() {
			// Stat succeeds (dir exists) but ValidateRepo List blips: catalogLastExists
			// must warn and return false so lexical after-last still yields keepRepo.
			storeMock := &mocks.StorageDriverMock{
				WalkFn: func(_ context.Context, _ string, walkFn driver.WalkFn,
					_ ...func(*driver.WalkOptions),
				) error {
					repoPath := path.Join(rootDir, keepRepo)
					fi := &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
						PathFn:  func() string { return repoPath },
					}

					return walkFn(fi)
				},
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					switch path.Base(listPath) {
					case lastRepo:
						return nil, errclass.MarkTransient(errLastValidateBlip)
					case keepRepo:
						return []string{
							path.Join(listPath, ispec.ImageIndexFile),
							path.Join(listPath, ispec.ImageLayoutFile),
						}, nil
					default:
						return nil, driver.PathNotFoundError{Path: listPath}
					}
				},
				StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
					if path.Base(statPath) == lastRepo {
						return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}, nil
					}

					return nil, driver.PathNotFoundError{Path: statPath}
				},
			}

			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)
			repos, more, err := store.GetNextRepositories(lastRepo, 10, acceptAll)
			So(err, ShouldBeNil)
			So(more, ShouldBeFalse)
			So(repos, ShouldResemble, []string{keepRepo})
		})

		Convey("ValidateRepo Permanent on last after Stat treats as missing", func() {
			storeMock := &mocks.StorageDriverMock{
				WalkFn: func(_ context.Context, _ string, walkFn driver.WalkFn,
					_ ...func(*driver.WalkOptions),
				) error {
					repoPath := path.Join(rootDir, keepRepo)
					fi := &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
						PathFn:  func() string { return repoPath },
					}

					return walkFn(fi)
				},
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					switch path.Base(listPath) {
					case lastRepo:
						return nil, errclass.MarkPermanent(errLastValidateDenied)
					case keepRepo:
						return []string{
							path.Join(listPath, ispec.ImageIndexFile),
							path.Join(listPath, ispec.ImageLayoutFile),
						}, nil
					default:
						return nil, driver.PathNotFoundError{Path: listPath}
					}
				},
				StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
					if path.Base(statPath) == lastRepo {
						return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}, nil
					}

					return nil, driver.PathNotFoundError{Path: statPath}
				},
			}

			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)
			repos, more, err := store.GetNextRepositories(lastRepo, 10, acceptAll)
			So(err, ShouldBeNil)
			So(more, ShouldBeFalse)
			So(repos, ShouldResemble, []string{keepRepo})
		})
	})
}

func TestGetNextRepositoryValidateRepoFailClosed(t *testing.T) {
	Convey("GetNextRepository fails closed on per-path ValidateRepo Transient", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		flakyRepo := "flaky"
		goodRepo := "good"

		storeMock := &mocks.StorageDriverMock{
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				if listPath == rootDir {
					return []string{path.Join(rootDir, flakyRepo), path.Join(rootDir, goodRepo)}, nil
				}

				switch path.Base(listPath) {
				case flakyRepo:
					return nil, errclass.MarkTransient(errListBlip)
				case goodRepo:
					return []string{
						path.Join(listPath, ispec.ImageIndexFile),
						path.Join(listPath, ispec.ImageLayoutFile),
					}, nil
				default:
					return nil, driver.PathNotFoundError{Path: listPath}
				}
			},
			WalkFn: func(_ context.Context, _ string, walkFn driver.WalkFn,
				_ ...func(*driver.WalkOptions),
			) error {
				for _, name := range []string{flakyRepo, goodRepo} {
					repoPath := path.Join(rootDir, name)
					fi := &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
						PathFn:  func() string { return repoPath },
					}
					if err := walkFn(fi); err != nil {
						return err
					}
				}

				return nil
			},
			StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
				return nil, driver.PathNotFoundError{Path: statPath}
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		repo, err := store.GetNextRepository(map[string]struct{}{})
		So(repo, ShouldEqual, "")
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
	})
}

func TestGetRepositoriesValidateRepoFailClosed(t *testing.T) {
	Convey("GetRepositories fails closed on per-path ValidateRepo Transient", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		flakyRepo := "flaky"
		goodRepo := "good"

		storeMock := &mocks.StorageDriverMock{
			WalkFn: func(_ context.Context, _ string, walkFn driver.WalkFn,
				_ ...func(*driver.WalkOptions),
			) error {
				// Visit a healthy repo before the flaky one so a buggy return of
				// (partialRepos, err) would leave a non-empty slice.
				for _, name := range []string{goodRepo, flakyRepo} {
					repoPath := path.Join(rootDir, name)
					fi := &mocks.FileInfoMock{
						IsDirFn: func() bool { return true },
						PathFn:  func() string { return repoPath },
					}
					if err := walkFn(fi); err != nil {
						return err
					}
				}

				return nil
			},
			ListFn: func(_ context.Context, listPath string) ([]string, error) {
				switch path.Base(listPath) {
				case flakyRepo:
					return nil, errclass.MarkTransient(errListBlip)
				case goodRepo:
					return []string{
						path.Join(listPath, ispec.ImageIndexFile),
						path.Join(listPath, ispec.ImageLayoutFile),
					}, nil
				default:
					return nil, driver.PathNotFoundError{Path: listPath}
				}
			},
			StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
				return nil, driver.PathNotFoundError{Path: statPath}
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(storeMock), nil, nil, nil)
		So(store, ShouldNotBeNil)

		repos, err := store.GetRepositories()
		So(repos, ShouldBeEmpty)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
	})
}

// TestConfirmEmptyStoreWalkMissing locks the walk-level Missing contract used by
// GetRepositories / GetNextRepository / GetNextRepositories: empty or absent root
// is an empty store; a Missing Walk with a non-empty root is Transient.
func TestConfirmEmptyStoreWalkMissing(t *testing.T) {
	acceptAll := func(string) (bool, error) { return true, nil }
	listErr := errRootListFailed

	Convey("Walk PathNotFound with an empty root is an empty store", t, func() {
		rootDir := t.TempDir()
		store := imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, gcs.New(&mocks.StorageDriverMock{
				ListFn: func(_ context.Context, _ string) ([]string, error) {
					return []string{}, nil
				},
				WalkFn: func(_ context.Context, _ string, _ driver.WalkFn,
					_ ...func(*driver.WalkOptions),
				) error {
					return driver.PathNotFoundError{}
				},
			}), nil, nil, nil)

		repo, err := store.GetNextRepository(map[string]struct{}{"testRepo": {}})
		So(err, ShouldBeNil)
		So(repo, ShouldEqual, "")

		repos, err := store.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldBeEmpty)

		repos, more, err := store.GetNextRepositories("", 10, acceptAll)
		So(err, ShouldBeNil)
		So(repos, ShouldBeEmpty)
		So(more, ShouldBeFalse)
	})

	Convey("Walk PathNotFound with a non-empty root is an incomplete listing", t, func() {
		rootDir := t.TempDir()
		store := imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, gcs.New(&mocks.StorageDriverMock{
				ListFn: func(_ context.Context, listPath string) ([]string, error) {
					return []string{listPath + "/repo"}, nil
				},
				WalkFn: func(_ context.Context, walkPath string, _ driver.WalkFn,
					_ ...func(*driver.WalkOptions),
				) error {
					return driver.PathNotFoundError{Path: walkPath + "/repo/nested"}
				},
			}), nil, nil, nil)

		repo, err := store.GetNextRepository(map[string]struct{}{})
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
		So(repo, ShouldEqual, "")

		repos, err := store.GetRepositories()
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		So(repos, ShouldBeEmpty)

		repos, more, err := store.GetNextRepositories("", 10, acceptAll)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		So(repos, ShouldBeEmpty)
		So(more, ShouldBeFalse)
	})

	Convey("Walk PathNotFound with a failing root List returns the List error", t, func() {
		rootDir := t.TempDir()
		listCalls := 0
		store := imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, gcs.New(&mocks.StorageDriverMock{
				ListFn: func(_ context.Context, _ string) ([]string, error) {
					listCalls++

					return nil, listErr
				},
				WalkFn: func(_ context.Context, walkPath string, _ driver.WalkFn,
					_ ...func(*driver.WalkOptions),
				) error {
					return driver.PathNotFoundError{Path: walkPath + "/repo/nested"}
				},
			}), nil, nil, nil)

		repos, err := store.GetRepositories()
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
		So(repos, ShouldBeEmpty)
		So(listCalls, ShouldEqual, 1)
	})
}

// walkFallbackFS emulates List/Stat where an empty prefix is PathNotFound, the
// same surface GCS/Azure expose to distribution WalkFallback. Assertions below
// are ImageStore policy, not a specific cloud driver.
type walkFallbackFS struct {
	objects  []string
	poisoned map[string]bool
}

func (m *walkFallbackFS) list(dir string) ([]string, error) {
	if m.poisoned[dir] {
		return nil, driver.PathNotFoundError{Path: dir, DriverName: "walkfallback"}
	}

	prefix := strings.TrimSuffix(dir, "/") + "/"
	seen := map[string]bool{}
	out := []string{}

	for _, obj := range m.objects {
		if !strings.HasPrefix(obj, prefix) {
			continue
		}

		rest := obj[len(prefix):]
		if before, _, found := strings.Cut(rest, "/"); found {
			child := prefix + before
			if !seen[child] {
				seen[child] = true

				out = append(out, child)
			}
		} else {
			out = append(out, obj)
		}
	}

	if len(out) == 0 {
		return nil, driver.PathNotFoundError{Path: dir, DriverName: "walkfallback"}
	}

	sort.Strings(out)

	return out, nil
}

func (m *walkFallbackFS) stat(path string) (driver.FileInfo, error) {
	dirPrefix := strings.TrimSuffix(path, "/") + "/"
	for _, obj := range m.objects {
		if obj == path {
			return &walkFallbackFileInfo{isDir: false, path: path}, nil
		}

		if strings.HasPrefix(obj, dirPrefix) {
			return &walkFallbackFileInfo{isDir: true, path: path}, nil
		}
	}

	return nil, driver.PathNotFoundError{Path: path, DriverName: "walkfallback"}
}

type walkFallbackFileInfo struct {
	isDir bool
	path  string
}

func (f *walkFallbackFileInfo) Path() string       { return f.path }
func (f *walkFallbackFileInfo) Size() int64        { return 0 }
func (f *walkFallbackFileInfo) ModTime() time.Time { return time.Time{} }
func (f *walkFallbackFileInfo) IsDir() bool        { return f.isDir }

func newWalkFallbackStore(memfs *walkFallbackFS) *mocks.StorageDriverMock {
	storeMock := &mocks.StorageDriverMock{}
	storeMock.NameFn = func() string { return "walkfallback" }
	storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
		return memfs.list(path)
	}
	storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
		return memfs.stat(path)
	}
	storeMock.WalkFn = func(ctx context.Context, path string, f driver.WalkFn,
		options ...func(*driver.WalkOptions),
	) error {
		return driver.WalkFallback(ctx, storeMock, path, f, options...)
	}

	return storeMock
}

func TestWalkFallbackNestedMissingFailsClosed(t *testing.T) {
	rootDir := "/zot"
	objects := []string{
		"/zot/repo-a/repo-a/blobs/sha256/aaa",
		"/zot/repo-a/repo-a/index.json",
		"/zot/repo-a/repo-a/oci-layout",
		"/zot/repo-b/repo-b/blobs/sha256/bbb",
		"/zot/repo-b/repo-b/index.json",
		"/zot/repo-b/repo-b/oci-layout",
	}

	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()

	newStore := func(memfs *walkFallbackFS) storageTypes.ImageStore {
		return imagestore.NewImageStore(rootDir, t.TempDir(), false, false, log, metrics,
			nil, gcs.New(newWalkFallbackStore(memfs)), nil, nil, nil)
	}

	acceptAll := func(string) (bool, error) { return true, nil }

	Convey("A non-reserved nested prefix that lists empty aborts the walk", t, func() {
		// The namespace prefix is still listed under the root, but listing it
		// returns PathNotFound (emptied concurrently). WalkFallback aborts with
		// Missing; that must not read as "no more repositories".
		memfs := &walkFallbackFS{
			objects:  objects,
			poisoned: map[string]bool{"/zot/repo-b": true},
		}
		imgStore := newStore(memfs)

		Convey("GetNextRepository returns Transient instead of ending the sweep", func() {
			repo, err := imgStore.GetNextRepository(map[string]struct{}{})
			So(err, ShouldBeNil)
			So(repo, ShouldEqual, "repo-a/repo-a")

			repo, err = imgStore.GetNextRepository(map[string]struct{}{"repo-a/repo-a": {}})
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
			So(repo, ShouldEqual, "")
		})

		Convey("GetRepositories returns Transient instead of a partial list", func() {
			repos, err := imgStore.GetRepositories()
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
			So(repos, ShouldBeEmpty)
		})

		Convey("GetNextRepositories returns Transient instead of a truncated catalog", func() {
			repos, more, err := imgStore.GetNextRepositories("", 100, acceptAll)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
			So(repos, ShouldBeEmpty)
			So(more, ShouldBeFalse)
		})
	})

	Convey("An empty root is still an empty store", t, func() {
		imgStore := newStore(&walkFallbackFS{})

		repo, err := imgStore.GetNextRepository(map[string]struct{}{})
		So(err, ShouldBeNil)
		So(repo, ShouldEqual, "")

		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(repos, ShouldBeEmpty)

		repos, more, err := imgStore.GetNextRepositories("", 100, acceptAll)
		So(err, ShouldBeNil)
		So(repos, ShouldBeEmpty)
		So(more, ShouldBeFalse)
	})
}

func TestBlobUploadWriterMissing(t *testing.T) {
	Convey("Writer Missing on blob upload open maps to not-found sentinels", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		repo := "repo"

		missingWriter := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, statPath string) (driver.FileInfo, error) {
				return nil, driver.PathNotFoundError{Path: statPath}
			},
			WriterFn: func(_ context.Context, writerPath string, _ bool) (driver.FileWriter, error) {
				if strings.Contains(writerPath, ".uploads") {
					return nil, driver.PathNotFoundError{Path: writerPath}
				}

				return &mocks.FileWriterMock{}, nil
			},
		}

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(missingWriter), nil, nil, nil)
		So(store, ShouldNotBeNil)

		Convey("NewBlobUpload → ErrRepoNotFound", func() {
			uid, err := store.NewBlobUpload(context.Background(), repo)
			So(uid, ShouldEqual, "")
			So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeTrue)
			So(errclass.IsStorageObjectMissing(err), ShouldBeFalse)
		})

		Convey("FullBlobUpload → ErrUploadNotFound", func() {
			digest := godigest.FromString("full-upload-missing-writer")
			uid, n, err := store.FullBlobUpload(context.Background(), repo, bytes.NewReader([]byte("x")), digest)
			So(uid, ShouldEqual, "")
			So(n, ShouldEqual, -1)
			So(errors.Is(err, zerr.ErrUploadNotFound), ShouldBeTrue)
		})
	})
}

func TestPutBlobChunkCloseError(t *testing.T) {
	Convey("PutBlobChunk propagates Close Permanent after a successful Write", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		flushPermanent := errclass.MarkPermanent(errFlushEdquot)
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(&mocks.StorageDriverMock{
				WriterFn: func(_ context.Context, _ string, _ bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(p []byte) (int, error) {
							return len(p), nil
						},
						CloseFn: func() error {
							return flushPermanent
						},
					}, nil
				},
			}), nil, nil, nil)

		// FileWriterMock.Size is 12; from must match existing upload size.
		n, err := store.PutBlobChunk(context.Background(), "repo", "upload-uuid", 12, 20,
			bytes.NewReader([]byte("chunk-data")))
		So(n, ShouldEqual, int64(12+len("chunk-data")))
		So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
	})

	Convey("PutBlobChunkStreamed prefers Copy Permanent over Close", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		writePermanent := errclass.MarkPermanent(errWriteEdquot)
		closed := false

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(&mocks.StorageDriverMock{
				WriterFn: func(_ context.Context, _ string, _ bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(_ []byte) (int, error) {
							return 0, writePermanent
						},
						CloseFn: func() error {
							closed = true

							return nil
						},
					}, nil
				},
			}), nil, nil, nil)

		_, err := store.PutBlobChunkStreamed(context.Background(), "repo", "upload-uuid",
			bytes.NewReader([]byte("streamed")))
		So(closed, ShouldBeTrue)
		So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
	})
}

func TestFullBlobUploadStagingCleanup(t *testing.T) {
	Convey("FullBlobUpload removes staging UUID on digest mismatch", t, func() {
		rootDir := t.TempDir()
		store := imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
		ctx := context.Background()

		content := []byte("monolithic-blob")
		wrongDigest := godigest.FromString("wrong-digest")
		_, _, err := store.FullBlobUpload(ctx, "repo", bytes.NewReader(content), wrongDigest)
		So(errors.Is(err, zerr.ErrBadBlobDigest), ShouldBeTrue)

		uploadsDir := path.Join(rootDir, "repo", ".uploads")
		entries, err := os.ReadDir(uploadsDir)
		So(err, ShouldBeNil)
		So(entries, ShouldBeEmpty)
	})

	Convey("FullBlobUpload deletes staging when Write returns Permanent", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		rootDir := t.TempDir()
		writePermanent := errclass.MarkPermanent(errDiskFull)

		var deleted []string

		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			gcs.New(&mocks.StorageDriverMock{
				WriterFn: func(_ context.Context, _ string, _ bool) (driver.FileWriter, error) {
					return &mocks.FileWriterMock{
						WriteFn: func(_ []byte) (int, error) {
							return 0, writePermanent
						},
					}, nil
				},
				DeleteFn: func(_ context.Context, deletePath string) error {
					deleted = append(deleted, deletePath)

					return nil
				},
			}), nil, nil, nil)

		_, _, err := store.FullBlobUpload(context.Background(), "repo",
			bytes.NewReader([]byte("x")), godigest.FromString("x"))
		So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		So(len(deleted), ShouldEqual, 1)
		So(strings.Contains(deleted[0], ".uploads"), ShouldBeTrue)
	})
}

func TestRetagManifest(t *testing.T) {
	Convey("RetagManifest", t, func() {
		newStore := func(rootDir string) storageTypes.ImageStore {
			return imagestore.NewImageStore(rootDir, "", false, false, zlog.NewTestLogger(),
				monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)
		}

		Convey("rejects empty reference or digest", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()
			So(store.InitRepo(ctx, "repo"), ShouldBeNil)

			digest := godigest.FromString("manifest")
			So(errors.Is(store.RetagManifest(ctx, "repo", "", digest), zerr.ErrBadManifest), ShouldBeTrue)
			So(errors.Is(store.RetagManifest(ctx, "repo", "latest", ""), zerr.ErrBadManifest), ShouldBeTrue)
		})

		Convey("returns repo error when the repository layout is missing", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()

			err := store.RetagManifest(ctx, "missing", "latest", godigest.FromString("manifest"))
			So(err, ShouldNotBeNil)
		})

		Convey("returns an error when index.json cannot be read", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()
			So(store.InitRepo(ctx, "repo"), ShouldBeNil)
			So(os.WriteFile(path.Join(rootDir, "repo", ispec.ImageIndexFile), []byte("{"), 0o600), ShouldBeNil)

			err := store.RetagManifest(ctx, "repo", "latest", godigest.FromString("manifest"))
			So(err, ShouldNotBeNil)
		})

		Convey("returns ErrManifestNotFound when the digest is absent", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()
			So(store.InitRepo(ctx, "repo"), ShouldBeNil)

			err := store.RetagManifest(ctx, "repo", "latest", godigest.FromString("missing"))
			So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
		})

		indexByTag := func(store storageTypes.ImageStore, repo, tag string) (ispec.Descriptor, bool) {
			buf, err := store.GetIndexContent(repo)
			So(err, ShouldBeNil)

			var index ispec.Index
			So(json.Unmarshal(buf, &index), ShouldBeNil)

			for _, desc := range index.Manifests {
				if name, ok := desc.Annotations[ispec.AnnotationRefName]; ok && name == tag {
					return desc, true
				}
			}

			return ispec.Descriptor{}, false
		}

		Convey("reattaches a tag to an untagged digest left by overwrite", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()
			So(store.InitRepo(ctx, "repo"), ShouldBeNil)

			prior := godigest.FromString("prior")
			newer := godigest.FromString("newer")
			index := ispec.Index{
				SchemaVersion: 2,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    prior,
						Size:      1,
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    newer,
						Size:      1,
						Annotations: map[string]string{
							ispec.AnnotationRefName: "latest",
						},
					},
				},
			}
			So(store.PutIndexContent("repo", index), ShouldBeNil)

			So(store.DeleteImageManifest(ctx, "repo", "latest", false), ShouldBeNil)
			So(store.RetagManifest(ctx, "repo", "latest", prior), ShouldBeNil)

			desc, ok := indexByTag(store, "repo", "latest")
			So(ok, ShouldBeTrue)
			So(desc.Digest, ShouldEqual, prior)
		})

		Convey("prefers an untagged row when the digest is also tagged elsewhere", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()
			So(store.InitRepo(ctx, "repo"), ShouldBeNil)

			shared := godigest.FromString("shared")
			index := ispec.Index{
				SchemaVersion: 2,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    shared,
						Size:      1,
						Annotations: map[string]string{
							ispec.AnnotationRefName: "v1",
							"extra":                 "from-tagged",
						},
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    shared,
						Size:      1,
						Annotations: map[string]string{
							"extra": "from-untagged",
						},
					},
				},
			}
			So(store.PutIndexContent("repo", index), ShouldBeNil)

			So(store.RetagManifest(ctx, "repo", "latest", shared), ShouldBeNil)

			latest, ok := indexByTag(store, "repo", "latest")
			So(ok, ShouldBeTrue)
			So(latest.Digest, ShouldEqual, shared)
			So(latest.Annotations["extra"], ShouldEqual, "from-untagged")

			v1, ok := indexByTag(store, "repo", "v1")
			So(ok, ShouldBeTrue)
			So(v1.Digest, ShouldEqual, shared)
		})

		Convey("drops an existing tag owner and clones a nil-annotation descriptor", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()
			So(store.InitRepo(ctx, "repo"), ShouldBeNil)

			prior := godigest.FromString("prior")
			newer := godigest.FromString("newer")
			index := ispec.Index{
				SchemaVersion: 2,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    prior,
						Size:      1,
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    newer,
						Size:      1,
						Annotations: map[string]string{
							ispec.AnnotationRefName: "latest",
						},
					},
				},
			}
			So(store.PutIndexContent("repo", index), ShouldBeNil)

			// Retag without deleting first: drop the current latest owner, then attach prior.
			So(store.RetagManifest(ctx, "repo", "latest", prior), ShouldBeNil)

			latest, ok := indexByTag(store, "repo", "latest")
			So(ok, ShouldBeTrue)
			So(latest.Digest, ShouldEqual, prior)
			So(latest.Annotations[ispec.AnnotationRefName], ShouldEqual, "latest")
		})

		Convey("clones a tagged-only digest when no untagged row exists", func() {
			rootDir := t.TempDir()
			store := newStore(rootDir)
			ctx := context.Background()
			So(store.InitRepo(ctx, "repo"), ShouldBeNil)

			shared := godigest.FromString("shared-tagged-only")
			index := ispec.Index{
				SchemaVersion: 2,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    shared,
						Size:      1,
						Annotations: map[string]string{
							ispec.AnnotationRefName: "v1",
						},
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromString("other"),
						Size:      1,
					},
				},
			}
			So(store.PutIndexContent("repo", index), ShouldBeNil)

			So(store.RetagManifest(ctx, "repo", "latest", shared), ShouldBeNil)

			latest, ok := indexByTag(store, "repo", "latest")
			So(ok, ShouldBeTrue)
			So(latest.Digest, ShouldEqual, shared)

			v1, ok := indexByTag(store, "repo", "v1")
			So(ok, ShouldBeTrue)
			So(v1.Digest, ShouldEqual, shared)
		})
	})
}

func TestRepositoryWalkReservedDirNames(t *testing.T) {
	Convey("Repositories whose names end in blobs, .uploads or .sync are found by every walk", t, func() {
		rootDir := t.TempDir()
		imgStore := local.NewImageStore(rootDir, false, false, zlog.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		storeController := storage.StoreController{DefaultStore: imgStore}

		// Exact layout path components (blobs, index.json, oci-layout) are rejected
		// at create time. Names that merely end with those strings remain valid.
		repos := []string{
			"demo/my.sync",
			"demo/my.uploads",
			"demo/myblobs",
			"demo/plain",
			"demo/plain/team",
		}

		image := CreateRandomImage()

		for _, repo := range repos {
			So(WriteImageToFileSystem(image, repo, "v1", storeController), ShouldBeNil)
		}

		So(errors.Is(imgStore.InitRepo(context.Background(), "blobs"), zerr.ErrInvalidRepositoryName), ShouldBeTrue)
		So(errors.Is(imgStore.InitRepo(context.Background(), "demo/netlify/blobs"), zerr.ErrInvalidRepositoryName),
			ShouldBeTrue)

		// the content of a repository is still not taken for repositories: an interrupted
		// upload, and sync staging, which holds an OCI layout of its own
		So(os.MkdirAll(path.Join(rootDir, "demo/plain", storageConstants.BlobUploadDir, "uuid"), 0o755), ShouldBeNil)
		writeMinimalLocalOCILayout(t, rootDir, path.Join("demo/plain", syncConstants.SyncBlobUploadDir, "uuid"))

		Convey("GetRepositories", func() {
			found, err := imgStore.GetRepositories()
			So(err, ShouldBeNil)
			So(found, ShouldResemble, repos)
		})

		Convey("GetNextRepositories", func() {
			found, more, err := imgStore.GetNextRepositories("", 100, func(string) (bool, error) { return true, nil })
			So(err, ShouldBeNil)
			So(more, ShouldBeFalse)
			So(found, ShouldResemble, repos)
		})

		Convey("GetNextRepository", func() {
			processedRepos := map[string]struct{}{}
			found := []string{}

			for {
				repo, err := imgStore.GetNextRepository(processedRepos)
				So(err, ShouldBeNil)

				if repo == "" {
					break
				}

				processedRepos[repo] = struct{}{}
				found = append(found, repo)
			}

			So(found, ShouldResemble, repos)
		})

		Convey("GetNextDigestWithBlobPaths", func() {
			digest, blobPaths, err := imgStore.GetNextDigestWithBlobPaths(repos, []godigest.Digest{})
			So(err, ShouldBeNil)
			So(digest, ShouldNotBeEmpty)

			expected := make([]string, 0, len(repos))
			for _, repo := range repos {
				expected = append(expected, imgStore.BlobPath(repo, digest))
			}

			sort.Strings(blobPaths)
			sort.Strings(expected)
			So(blobPaths, ShouldResemble, expected)
		})
	})
}
