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
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
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
				return nil, errclass.MarkTransient(errors.New("stat blip")) //nolint:err113 // test
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
			StatFn: func(_ context.Context, _ string) (driver.FileInfo, error) {
				return nil, errclass.MarkTransient(errors.New("stat blip")) //nolint:err113 // test
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

					return &mocks.FileInfoMock{SizeFn: func() int64 { return 1 }}, nil
				},
			}

			cacheMock := mocks.CacheMock{
				GetBlobFn: func(godigest.Digest) (string, error) {
					return "", errclass.MarkTransient(errors.New("cache blip")) //nolint:err113 // test
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
			putBlobErr := errclass.MarkPermanent(errors.New("cache put denied")) //nolint:err113 // test

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
					return nil, errclass.MarkTransient(errors.New("list blip")) //nolint:err113 // test
				},
			}
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				gcs.New(storeMock), nil, nil, nil)

			ok, err := store.ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeFalse)
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
					return nil, errclass.MarkTransient(errors.New("list blip")) //nolint:err113 // test
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
