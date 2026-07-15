package imagestore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errDeleteFailed = errors.New("delete failed") //nolint: gochecknoglobals

func TestGetBlobRedirectURL(t *testing.T) {
	Convey("GetBlobRedirectURL", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

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
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

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
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

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

func TestCleanupRepoFailsOnDeleteImageManifest(t *testing.T) {
	Convey("CleanupRepo returns error when deleteImageManifest fails", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		store := local.NewImageStore(dir, true, true, log, metrics, nil, nil, nil, nil)
		repo := "repo"
		ctx := context.Background()

		content := []byte("layer content")
		digest := godigest.FromBytes(content)
		_, _, err := store.FullBlobUpload(ctx, repo, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()
		_, _, err = store.FullBlobUpload(ctx, repo, bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    digest,
					Size:      int64(len(content)),
				},
			},
		}
		manifest.SchemaVersion = 2

		body, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(body)
		_, _, err = store.PutImageManifest(ctx, repo, "1.0", ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		indexPath := path.Join(dir, repo, ispec.ImageIndexFile)
		err = os.Chmod(indexPath, 0o444)
		So(err, ShouldBeNil)

		defer func() {
			err := os.Chmod(indexPath, 0o644)
			So(err, ShouldBeNil)
		}()

		count, err := store.CleanupRepo(repo, []godigest.Digest{manifestDigest}, false)
		So(err, ShouldNotBeNil)
		So(count, ShouldEqual, 0)
	})
}

func TestCleanupRepoReadsEachManifestOnlyOnce(t *testing.T) {
	Convey("CleanupRepo reads each manifest once instead of once per deleted blob", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		rootDir := t.TempDir()
		storeMock := &mocks.StorageDriverMock{}
		remoteDriver := gcs.New(storeMock)
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			remoteDriver, nil, nil, nil)

		repo := "repo"

		// three tagged manifests, each referencing its own config and layer
		manifestBodies := map[string][]byte{}

		var index ispec.Index

		for i := range 3 {
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    godigest.FromString(fmt.Sprintf("config-%d", i)),
					Size:      10,
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    godigest.FromString(fmt.Sprintf("layer-%d", i)),
						Size:      10,
					},
				},
			}
			manifest.SchemaVersion = 2

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(body)
			manifestBodies[store.BlobPath(repo, manifestDigest)] = body
			index.Manifests = append(index.Manifests, ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(body)),
			})
		}

		indexBody, err := json.Marshal(index)
		So(err, ShouldBeNil)

		indexPath := path.Join(rootDir, repo, ispec.ImageIndexFile)
		manifestReads := map[string]int{}

		storeMock.GetContentFn = func(_ context.Context, path string) ([]byte, error) {
			if path == indexPath {
				return indexBody, nil
			}

			if body, ok := manifestBodies[path]; ok {
				manifestReads[path]++

				return body, nil
			}

			return nil, driver.PathNotFoundError{Path: path}
		}
		storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
			return &mocks.FileInfoMock{
				PathFn: func() string { return path },
				SizeFn: func() int64 { return 10 },
			}, nil
		}
		storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
			return nil, nil
		}

		// four orphan blobs, none referenced by any manifest
		var toDelete []godigest.Digest
		for i := range 4 {
			toDelete = append(toDelete, godigest.FromString(fmt.Sprintf("orphan-%d", i)))
		}

		count, err := store.CleanupRepo(repo, toDelete, false)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, len(toDelete))

		totalReads := 0
		for _, reads := range manifestReads {
			totalReads += reads
		}

		So(totalReads, ShouldEqual, len(manifestBodies))
	})
}

func TestCleanupRepoReadsSharedManifestDigestOnlyOnce(t *testing.T) {
	Convey("CleanupRepo reads a manifest digest shared by two descriptors only once", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		rootDir := t.TempDir()
		storeMock := &mocks.StorageDriverMock{}
		remoteDriver := gcs.New(storeMock)
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			remoteDriver, nil, nil, nil)

		repo := "repo"

		// three distinct tagged manifests, each referencing its own config and layer
		manifestBodies := map[string][]byte{}

		var index ispec.Index

		for i := range 3 {
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    godigest.FromString(fmt.Sprintf("shared-config-%d", i)),
					Size:      10,
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    godigest.FromString(fmt.Sprintf("shared-layer-%d", i)),
						Size:      10,
					},
				},
			}
			manifest.SchemaVersion = 2

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(body)
			manifestBodies[store.BlobPath(repo, manifestDigest)] = body
			index.Manifests = append(index.Manifests, ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(body)),
			})

			// the first manifest is additionally tagged under a second descriptor
			// pointing at the SAME digest (e.g. multiple tags for one image)
			if i == 0 {
				index.Manifests = append(index.Manifests, ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    manifestDigest,
					Size:      int64(len(body)),
				})
			}
		}

		indexBody, err := json.Marshal(index)
		So(err, ShouldBeNil)

		indexPath := path.Join(rootDir, repo, ispec.ImageIndexFile)
		manifestReads := map[string]int{}

		storeMock.GetContentFn = func(_ context.Context, path string) ([]byte, error) {
			if path == indexPath {
				return indexBody, nil
			}

			if body, ok := manifestBodies[path]; ok {
				manifestReads[path]++

				return body, nil
			}

			return nil, driver.PathNotFoundError{Path: path}
		}
		storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
			return &mocks.FileInfoMock{
				PathFn: func() string { return path },
				SizeFn: func() int64 { return 10 },
			}, nil
		}
		storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
			return nil, nil
		}

		// two orphan blobs, none referenced by any manifest
		var toDelete []godigest.Digest
		for i := range 2 {
			toDelete = append(toDelete, godigest.FromString(fmt.Sprintf("shared-orphan-%d", i)))
		}

		count, err := store.CleanupRepo(repo, toDelete, false)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, len(toDelete))

		totalReads := 0
		for _, reads := range manifestReads {
			totalReads += reads
		}

		// the shared manifest digest must be read exactly once, not once per descriptor
		So(totalReads, ShouldEqual, len(manifestBodies))
	})
}

func TestCleanupRepoFallsBackWhenReferencedSetUnavailable(t *testing.T) {
	Convey("CleanupRepo falls back to per-blob check when the referenced set cannot be built", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		rootDir := t.TempDir()
		storeMock := &mocks.StorageDriverMock{}
		remoteDriver := gcs.New(storeMock)
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			remoteDriver, nil, nil, nil)

		repo := "repo"

		// a healthy manifest whose config blob must survive GC
		healthyConfigDigest := godigest.FromString("healthy-config")
		healthyLayerDigest := godigest.FromString("healthy-layer")
		healthyManifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    healthyConfigDigest,
				Size:      10,
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    healthyLayerDigest,
					Size:      10,
				},
			},
		}
		healthyManifest.SchemaVersion = 2

		healthyBody, err := json.Marshal(healthyManifest)
		So(err, ShouldBeNil)
		healthyDigest := godigest.FromBytes(healthyBody)

		// a corrupt manifest whose blob content is invalid JSON, so building the
		// referenced set fails with a non-not-found error
		corruptDigest := godigest.FromString("corrupt-manifest")
		corruptBody := []byte("{not valid json")

		var index ispec.Index
		index.Manifests = append(index.Manifests,
			ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    healthyDigest,
				Size:      int64(len(healthyBody)),
			},
			ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    corruptDigest,
				Size:      int64(len(corruptBody)),
			},
		)

		indexBody, err := json.Marshal(index)
		So(err, ShouldBeNil)

		indexPath := path.Join(rootDir, repo, ispec.ImageIndexFile)
		healthyPath := store.BlobPath(repo, healthyDigest)
		corruptPath := store.BlobPath(repo, corruptDigest)

		storeMock.GetContentFn = func(_ context.Context, path string) ([]byte, error) {
			switch path {
			case indexPath:
				return indexBody, nil
			case healthyPath:
				return healthyBody, nil
			case corruptPath:
				return corruptBody, nil
			}

			return nil, driver.PathNotFoundError{Path: path}
		}
		storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
			return &mocks.FileInfoMock{
				PathFn: func() string { return path },
				SizeFn: func() int64 { return 10 },
			}, nil
		}
		storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
			return nil, nil
		}

		deletedPaths := map[string]bool{}
		storeMock.DeleteFn = func(_ context.Context, path string) error {
			deletedPaths[path] = true

			return nil
		}

		trueOrphan := godigest.FromString("true-orphan")

		// the true orphan is processed first and must be cleaned up via the
		// fallback; the healthy manifest's config blob is referenced and its
		// content must never be deleted, even though the referenced-set build
		// failed (corrupt manifest). Since a config digest is not itself a
		// manifest reference, the subsequent "referenced -> try untag" branch
		// fails with ErrManifestNotFound, which surfaces as a non-nil error -
		// what matters for this fix is that the referenced blob's content is
		// never removed and the orphan still is.
		count, err := store.CleanupRepo(repo, []godigest.Digest{trueOrphan, healthyConfigDigest}, false)
		So(err, ShouldNotBeNil)
		So(count, ShouldEqual, 1)

		So(deletedPaths[store.BlobPath(repo, healthyConfigDigest)], ShouldBeFalse)
		So(deletedPaths[store.BlobPath(repo, trueOrphan)], ShouldBeTrue)
	})
}

func TestCleanupRepoFallsBackWhenRefreshFails(t *testing.T) {
	Convey("CleanupRepo falls back to per-blob check when the post-untag refresh fails", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		rootDir := t.TempDir()
		storeMock := &mocks.StorageDriverMock{}
		remoteDriver := gcs.New(storeMock)
		store := imagestore.NewImageStore(rootDir, "", false, false, log, metrics, nil,
			remoteDriver, nil, nil, nil)

		repo := "repo"

		// manifestA is tagged and will be untagged/deleted by this CleanupRepo
		// call (its own blobs are irrelevant to the assertions below)
		manifestA := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    godigest.FromString("manifestA-config"),
				Size:      10,
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    godigest.FromString("manifestA-layer"),
					Size:      10,
				},
			},
		}
		manifestA.SchemaVersion = 2

		manifestABody, err := json.Marshal(manifestA)
		So(err, ShouldBeNil)
		manifestADigest := godigest.FromBytes(manifestABody)

		// manifestB stays tagged and healthy; its config blob must survive GC
		healthyConfigDigest := godigest.FromString("healthy-config")
		healthyLayerDigest := godigest.FromString("healthy-layer")
		manifestB := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    healthyConfigDigest,
				Size:      10,
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    healthyLayerDigest,
					Size:      10,
				},
			},
		}
		manifestB.SchemaVersion = 2

		manifestBBody, err := json.Marshal(manifestB)
		So(err, ShouldBeNil)
		manifestBDigest := godigest.FromBytes(manifestBBody)

		// full index: both manifests present - used for the initial
		// GetReferencedBlobs build and for deleteImageManifest's own read
		// while looking up manifestA to untag it
		fullIndex := ispec.Index{Manifests: []ispec.Descriptor{
			{MediaType: ispec.MediaTypeImageManifest, Digest: manifestADigest, Size: int64(len(manifestABody))},
			{MediaType: ispec.MediaTypeImageManifest, Digest: manifestBDigest, Size: int64(len(manifestBBody))},
		}}

		fullIndexBody, err := json.Marshal(fullIndex)
		So(err, ShouldBeNil)

		// post-delete index: only manifestB remains - this is the "real"
		// state of index.json after the untag; used once the refresh's own
		// read has already failed and the fallback re-reads the index
		postDeleteIndex := ispec.Index{Manifests: []ispec.Descriptor{
			{MediaType: ispec.MediaTypeImageManifest, Digest: manifestBDigest, Size: int64(len(manifestBBody))},
		}}

		postDeleteIndexBody, err := json.Marshal(postDeleteIndex)
		So(err, ShouldBeNil)

		indexPath := path.Join(rootDir, repo, ispec.ImageIndexFile)
		manifestAPath := store.BlobPath(repo, manifestADigest)
		manifestBPath := store.BlobPath(repo, manifestBDigest)

		// index.json is read multiple times across one CleanupRepo call:
		//   1: the initial GetReferencedBlobs build (must succeed)
		//   2: deleteImageManifest's own lookup of manifestA to untag it (must succeed)
		//   3: the post-untag refresh's GetReferencedBlobs call (forced to fail
		//      here with corrupt JSON, so `referenced = nil` at the refresh site,
		//      distinct from the initial-build nil-assignment)
		//   4+: subsequent per-blob common.IsBlobReferenced fallback calls, which
		//      re-read the (now real) post-delete index and must succeed
		indexReads := 0

		storeMock.GetContentFn = func(_ context.Context, path string) ([]byte, error) {
			switch path {
			case indexPath:
				indexReads++

				switch {
				case indexReads <= 2:
					return fullIndexBody, nil
				case indexReads == 3:
					return []byte("{not valid json"), nil
				default:
					return postDeleteIndexBody, nil
				}
			case manifestAPath:
				return manifestABody, nil
			case manifestBPath:
				return manifestBBody, nil
			}

			return nil, driver.PathNotFoundError{Path: path}
		}
		storeMock.StatFn = func(_ context.Context, path string) (driver.FileInfo, error) {
			return &mocks.FileInfoMock{
				PathFn: func() string { return path },
				SizeFn: func() int64 { return 10 },
			}, nil
		}
		storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
			return nil, nil
		}

		deletedPaths := map[string]bool{}
		storeMock.DeleteFn = func(_ context.Context, path string) error {
			deletedPaths[path] = true

			return nil
		}

		trueOrphan := godigest.FromString("true-orphan")

		// manifestA is untagged first (rewrites index.json and triggers the
		// refresh, which fails); then a true orphan (still cleaned via the
		// fallback); then the healthy config blob, which must survive even
		// though the refresh could not rebuild the referenced set
		count, err := store.CleanupRepo(repo,
			[]godigest.Digest{manifestADigest, trueOrphan, healthyConfigDigest}, false)
		So(err, ShouldNotBeNil)
		So(count, ShouldEqual, 2)

		So(deletedPaths[store.BlobPath(repo, healthyConfigDigest)], ShouldBeFalse)
		So(deletedPaths[store.BlobPath(repo, trueOrphan)], ShouldBeTrue)
	})
}

func TestCleanupRepoDeletesBlobsOrphanedByManifestDelete(t *testing.T) {
	Convey("blobs referenced only by a manifest deleted in the same run are cleaned up", t, func() {
		dir := t.TempDir()
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop()

		store := local.NewImageStore(dir, true, true, log, metrics, nil, nil, nil, nil)
		repo := "repo"
		ctx := context.Background()

		content := []byte("layer content")
		layerDigest := godigest.FromBytes(content)
		_, _, err := store.FullBlobUpload(ctx, repo, bytes.NewReader(content), layerDigest)
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()
		_, _, err = store.FullBlobUpload(ctx, repo, bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    layerDigest,
					Size:      int64(len(content)),
				},
			},
		}
		manifest.SchemaVersion = 2

		body, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(body)
		_, _, err = store.PutImageManifest(ctx, repo, "1.0", ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		// the manifest is still tagged, so its blobs are referenced until it is
		// deleted as part of the same cleanup run
		count, err := store.CleanupRepo(repo,
			[]godigest.Digest{manifestDigest, cdigest, layerDigest}, false)
		So(err, ShouldBeNil)
		So(count, ShouldEqual, 3)

		ok, _, err := store.CheckBlob(ctx, repo, layerDigest)
		So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
		So(ok, ShouldBeFalse)
	})
}
