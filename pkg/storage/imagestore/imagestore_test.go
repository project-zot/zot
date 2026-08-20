package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
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

	removeIdle := func(store storageTypes.ImageStore, repo string, maxBlobAge time.Duration,
		metaDB mTypes.MetaDB,
	) (bool, error) {
		var lockLatency time.Time

		store.Lock(&lockLatency)
		defer store.Unlock(&lockLatency)

		return store.RemoveIdleRepository(repo, maxBlobAge, metaDB)
	}

	Convey("An emptied repo loses its layout and its meta record together", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		// an orphan blob, as left behind by a manifest delete
		content := []byte("orphan blob")
		digest := godigest.FromBytes(content)
		_, _, err := store.FullBlobUpload(ctx, "repo", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		var metaDeleted string
		metaDB := mocks.MetaDBMock{
			DeleteRepoMetaFn: func(repo string) error {
				metaDeleted = repo

				return nil
			},
		}

		removed, err := removeIdle(store, "repo", 0, metaDB)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)
		So(metaDeleted, ShouldEqual, "repo")
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeFalse)
	})

	Convey("A repo still holding a manifest is kept", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		index := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromString("manifest"),
				Size:      1,
			}},
		}
		So(store.PutIndexContent("repo", index), ShouldBeNil)

		called := false
		metaDB := mocks.MetaDBMock{
			DeleteRepoMetaFn: func(repo string) error {
				called = true

				return nil
			},
		}

		removed, err := removeIdle(store, "repo", 0, metaDB)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
		So(called, ShouldBeFalse)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeTrue)
	})

	Convey("A repo with a blob upload in progress is kept", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		_, err := store.NewBlobUpload(ctx, "repo")
		So(err, ShouldBeNil)

		removed, err := removeIdle(store, "repo", 0, mocks.MetaDBMock{})
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

		removed, err := removeIdle(store, "repo", time.Hour, mocks.MetaDBMock{})
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeTrue)

		ok, _, _, err := store.StatBlob("repo", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
	})

	Convey("A nil metadb still removes the idle layout", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		removed, err := removeIdle(store, "repo", 0, nil)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeFalse)
	})

	Convey("A failed meta delete does not undo the removal", t, func() {
		rootDir := t.TempDir()
		store := newStore(rootDir)
		ctx := context.Background()

		So(store.InitRepo(ctx, "repo"), ShouldBeNil)

		metaDB := mocks.MetaDBMock{
			DeleteRepoMetaFn: func(repo string) error { return errDeleteFailed },
		}

		removed, err := removeIdle(store, "repo", 0, metaDB)
		So(err, ShouldBeNil)
		So(removed, ShouldBeTrue)
		So(store.DirExists(path.Join(rootDir, "repo")), ShouldBeFalse)
	})

	Convey("A repo already gone from storage is a no-op", t, func() {
		store := newStore(t.TempDir())

		removed, err := removeIdle(store, "ghost", 0, mocks.MetaDBMock{})
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
	})
}
