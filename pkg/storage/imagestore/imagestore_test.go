package imagestore_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var (
	errDeleteFailed = errors.New("delete failed")
	errWalkFailed   = errors.New("walk failed")
) //nolint: gochecknoglobals

func TestRepoExists(t *testing.T) {
	Convey("RepoExists resolves repository names under the image store root", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
			local.New(true), nil, nil, nil)

		So(store.RepoExists("repo"), ShouldBeFalse)
		So(store.InitRepo(context.Background(), "repo"), ShouldBeNil)
		So(store.RepoExists("repo"), ShouldBeTrue)
	})
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
			expectedRepoDir := path.Join(rootDir, repo)
			expectedBlobPath := store.BlobPath(repo, digest)
			expectedGlobalBlobPath := store.BlobPath(storageConstants.GlobalBlobsRepo, digest)
			expectedURL := "https://example.com/signed/blob"

			storeMock.StatFn = func(_ context.Context, statPath string) (driver.FileInfo, error) {
				if statPath == expectedRepoDir {
					return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}, nil
				}

				So(statPath == expectedBlobPath || statPath == expectedGlobalBlobPath, ShouldBeTrue)

				return &mocks.FileInfoMock{
					PathFn: func() string { return statPath },
					SizeFn: func() int64 { return 42 },
				}, nil
			}

			storeMock.RedirectURLFn = func(_ *http.Request, path string) (string, error) {
				So(path, ShouldEqual, expectedGlobalBlobPath)

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

			repo := "repo"
			expectedRepoDir := path.Join(rootDir, repo)

			storeMock.StatFn = func(_ context.Context, statPath string) (driver.FileInfo, error) {
				if statPath == expectedRepoDir {
					return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}, nil
				}

				return nil, driver.PathNotFoundError{Path: statPath}
			}

			digest := godigest.FromString("blob-content")
			url, err := store.GetBlobRedirectURL(nil, repo, digest)
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
				return &mocks.FileInfoMock{
					SizeFn: func() int64 { return 10 },
				}, nil
			}

			return &mocks.FileInfoMock{}, nil
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

		count, err := store.CleanupRepo(repo, []godigest.Digest{digest}, false)
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
				return &mocks.FileInfoMock{
					SizeFn: func() int64 { return 10 },
				}, nil
			}

			return &mocks.FileInfoMock{}, nil
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

		count, err := store.CleanupRepo(repo, []godigest.Digest{digest}, false)
		So(err, ShouldNotBeNil)
		So(count, ShouldEqual, 0)
	})
}

func TestNewImageStoreFailsWhenMigrationFails(t *testing.T) {
	Convey("NewImageStore returns nil when global blobstore migration fails", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		storeMock := &mocks.StorageDriverMock{}
		remoteDriver := gcs.New(storeMock)

		storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
			return nil, driver.PathNotFoundError{Path: path}
		}

		storeMock.WalkFn = func(_ context.Context, _ string, _ driver.WalkFn,
			_ ...func(*driver.WalkOptions),
		) error {
			return errWalkFailed
		}

		store := imagestore.NewImageStore("", "", true, false, log, metrics, nil,
			remoteDriver, nil, nil, nil)
		So(store, ShouldBeNil)
	})
}
