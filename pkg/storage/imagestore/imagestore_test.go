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
