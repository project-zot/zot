package imagestore_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var (
	errDeleteFailed = errors.New("delete failed") //nolint: gochecknoglobals
	errDriverFailed = errors.New("driver failed") //nolint: gochecknoglobals
)

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

	removeIdle := func(store storageTypes.ImageStore, repo string, maxBlobAge time.Duration) (bool, error) {
		var lockLatency time.Time

		store.Lock(&lockLatency)
		defer store.Unlock(&lockLatency)

		return store.RemoveIdleRepository(repo, maxBlobAge)
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
			Versioned: specs.Versioned{SchemaVersion: 2},
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

	Convey("A repo already gone from storage is a no-op", t, func() {
		store := newStore(t.TempDir())

		removed, err := removeIdle(store, "ghost", 0)
		So(err, ShouldBeNil)
		So(removed, ShouldBeFalse)
	})

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
			return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}
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
						return &mocks.FileInfoMock{SizeFn: func() int64 { return 10 }}, nil
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
						return &mocks.FileInfoMock{SizeFn: func() int64 { return 10 }}, nil
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

		Convey("a layout delete failure", func() {
			storeMock := &mocks.StorageDriverMock{
				StatFn:       func(_ context.Context, _ string) (driver.FileInfo, error) { return dirInfo(), nil },
				GetContentFn: func(_ context.Context, _ string) ([]byte, error) { return emptyIndex, nil },
				ListFn:       func(_ context.Context, path string) ([]string, error) { return nil, notFound(path) },
				DeleteFn: func(_ context.Context, path string) error {
					So(path, ShouldEqual, repoDir)

					return errDriverFailed
				},
			}

			removed, err := removeIdle(newMockStore(storeMock), repo, 0)
			So(err, ShouldNotBeNil)
			So(removed, ShouldBeFalse)
		})
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
