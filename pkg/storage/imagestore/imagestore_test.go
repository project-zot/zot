package imagestore_test

import (
	"bytes"
	"context"
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

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var (
	errDeleteFailed = errors.New("delete failed")
	errDriverFailed = errors.New("driver failed")
	errWalkFailed   = errors.New("walk failed")
) //nolint: gochecknoglobals

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
		var removed bool

		err := store.WithBlobstoreAndRepoLock(repo, func() error {
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
		transient := errclass.MarkTransient(errors.New("index blip")) //nolint:err113 // test

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
					return nil, errclass.MarkTransient(errors.New("alg list blip")) //nolint:err113 // test
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
					return nil, errclass.MarkPermanent(errors.New("alg list denied")) //nolint:err113 // test
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

		// Stat only starts failing once the store is constructed: with dedupe on,
		// NewImageStore runs the global blobstore upgrade, which fails closed (nil
		// store) on a Transient Stat.
		statBlip := false

		storeMock := &mocks.StorageDriverMock{
			StatFn: func(_ context.Context, _ string) (driver.FileInfo, error) {
				if !statBlip {
					return &mocks.FileInfoMock{}, nil
				}

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

		// construction may itself touch the cache/driver; only count CheckBlob's calls
		statBlip = true
		cacheLookups = 0
		putContentCalls = 0

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

		Convey("unclassified List error is marked Transient", func() {
			// Bypass gcs/local formatErr (they already MarkTransient) so ValidateRepo
			// itself applies the unclassified → Transient fallback.
			store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
				&rawListDriver{
					Driver:  gcs.New(&mocks.StorageDriverMock{}),
					listErr: errors.New("raw list failure"), //nolint:err113 // test
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
			transient := errclass.MarkTransient(errors.New("blobs stat blip")) //nolint:err113 // test
			ok, err := newStore(transient).ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("Permanent blobs/ Stat propagates", func() {
			permanent := errclass.MarkPermanent(errors.New("blobs denied")) //nolint:err113 // test
			ok, err := newStore(permanent).ValidateRepo(repo)
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("unclassified blobs/ Stat is marked Transient", func() {
			ok, err := newStore(errors.New("raw blobs stat")).ValidateRepo(repo) //nolint:err113 // test
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("GetRepositories aborts on Transient blobs/ Stat", func() {
			transient := errclass.MarkTransient(errors.New("blobs stat blip")) //nolint:err113 // test
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

		Convey("Missing last stays quiet and uses lexical after-last", func() {
			repos, more, err := newStore(driver.PathNotFoundError{Path: lastRepo}).
				GetNextRepositories(lastRepo, 10, acceptAll)
			So(err, ShouldBeNil)
			So(more, ShouldBeFalse)
			So(repos, ShouldResemble, []string{keepRepo})
		})

		Convey("Transient Stat on last treats as missing without failing the page", func() {
			transient := errclass.MarkTransient(errors.New("last stat blip")) //nolint:err113 // test
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
						return nil, errclass.MarkTransient(errors.New("last validate blip")) //nolint:err113 // test
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
						return nil, errclass.MarkPermanent(errors.New("last validate denied")) //nolint:err113 // test
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
	listErr := errors.New("root list failed") //nolint:err113 // test

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
		flushPermanent := errclass.MarkPermanent(errors.New("flush edquot")) //nolint:err113 // test

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
		writePermanent := errclass.MarkPermanent(errors.New("write edquot")) //nolint:err113 // test
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
		writePermanent := errclass.MarkPermanent(errors.New("disk full")) //nolint:err113 // test

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
