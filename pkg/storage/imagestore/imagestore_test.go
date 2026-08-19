package imagestore_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errDeleteFailed = errors.New("delete failed") //nolint: gochecknoglobals

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

func TestInitRepoErrors(t *testing.T) {
	Convey("InitRepo error paths", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewNopMetricServer()
		ctx := context.Background()

		Convey("rejects an invalid UTF-8 repo name", func() {
			store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
				local.New(true), nil, nil, nil)

			So(errors.Is(store.InitRepo(ctx, "\xff"), zerr.ErrInvalidRepositoryName), ShouldBeTrue)
		})

		Convey("rejects a repo name outside the distribution grammar", func() {
			store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
				local.New(true), nil, nil, nil)

			So(errors.Is(store.InitRepo(ctx, "INVALID??"), zerr.ErrInvalidRepositoryName), ShouldBeTrue)
		})

		Convey("fails when the repo directory cannot be created", func() {
			rootDir := t.TempDir()

			// a regular file where the repo's parent directory must be created
			So(os.WriteFile(path.Join(rootDir, "repo"), []byte("file"), 0o600), ShouldBeNil)

			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				local.New(true), nil, nil, nil)

			So(store.InitRepo(ctx, "repo"), ShouldNotBeNil)
		})

		Convey("fails when the oci-layout marker cannot be written", func() {
			rootDir := t.TempDir()
			repoDir := path.Join(rootDir, "repo")

			// directories in place, but the repo dir is read-only, so the marker write fails
			So(os.MkdirAll(path.Join(repoDir, "blobs", "sha256"), 0o755), ShouldBeNil)
			So(os.MkdirAll(path.Join(repoDir, ".uploads"), 0o755), ShouldBeNil)
			So(os.Chmod(repoDir, 0o555), ShouldBeNil)

			t.Cleanup(func() { _ = os.Chmod(repoDir, 0o755) })

			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				local.New(true), nil, nil, nil)

			So(store.InitRepo(ctx, "repo"), ShouldNotBeNil)
		})

		Convey("fails when the index cannot be written", func() {
			rootDir := t.TempDir()
			repoDir := path.Join(rootDir, "repo")

			// marker present, directories in place, read-only repo dir: the index write fails
			So(os.MkdirAll(path.Join(repoDir, "blobs", "sha256"), 0o755), ShouldBeNil)
			So(os.MkdirAll(path.Join(repoDir, ".uploads"), 0o755), ShouldBeNil)
			So(os.WriteFile(path.Join(repoDir, "oci-layout"),
				[]byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600), ShouldBeNil)
			So(os.Chmod(repoDir, 0o555), ShouldBeNil)

			t.Cleanup(func() { _ = os.Chmod(repoDir, 0o755) })

			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				local.New(true), nil, nil, nil)

			So(store.InitRepo(ctx, "repo"), ShouldNotBeNil)
		})
	})
}
