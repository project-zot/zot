package api

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type manifestDeleteFaultDriver struct {
	storageTypes.Driver

	manifestPath      string
	indexPath         string
	deleteErr         error
	deleteBeforeError bool
	writeErr          error
}

func (d *manifestDeleteFaultDriver) Delete(deletePath string) error {
	if deletePath == d.manifestPath && d.deleteErr != nil {
		if d.deleteBeforeError {
			if err := d.Driver.Delete(deletePath); err != nil {
				return err
			}
		}

		return d.deleteErr
	}

	return d.Driver.Delete(deletePath)
}

func (d *manifestDeleteFaultDriver) WriteFile(writePath string, content []byte) (int, error) {
	if writePath == d.indexPath && d.writeErr != nil {
		return 0, d.writeErr
	}

	return d.Driver.WriteFile(writePath, content)
}

func newManifestDeleteFixture(t *testing.T, faultDriver *manifestDeleteFaultDriver) (
	*RouteHandler, storageTypes.ImageStore, *boltdb.BoltDB, image.Image, image.Image, *mocks.EventRecorderMock,
) {
	t.Helper()

	rootDir := t.TempDir()
	logger := log.NewTestLogger()
	faultDriver.Driver = local.New(true)
	eventCapture := &mocks.EventRecorderMock{}
	store := imagestore.NewImageStore(rootDir, rootDir, false, true, logger,
		monitoring.NewNopMetricServer(), nil, faultDriver, nil, nil, eventCapture)
	controller := storage.StoreController{DefaultStore: store}

	metaRoot := t.TempDir()
	boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: metaRoot})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, boltDriver.Close()) })
	metaDB, err := boltdb.New(boltDriver, logger)
	require.NoError(t, err)

	firstImage := image.CreateRandomImage()
	secondImage := image.CreateRandomImage()
	for _, item := range []struct {
		img image.Image
		ref string
	}{
		{img: firstImage, ref: "first"},
		{img: secondImage, ref: "keep"},
	} {
		require.NoError(t, image.WriteImageToFileSystem(item.img, "repo", item.ref, controller))

		body, marshalErr := json.Marshal(item.img.Manifest)
		require.NoError(t, marshalErr)
		mediaType := item.img.ManifestDescriptor.MediaType
		if mediaType == "" {
			mediaType = ispec.MediaTypeImageManifest
		}
		require.NoError(t, meta.OnUpdateManifest(t.Context(), "repo", item.ref, mediaType,
			item.img.Digest(), body, controller, metaDB, logger))
	}

	faultDriver.manifestPath = store.BlobPath("repo", firstImage.Digest())
	faultDriver.indexPath = path.Join(rootDir, "repo", ispec.ImageIndexFile)

	controllerAPI := &Controller{
		Config:          config.New(),
		Log:             logger,
		MetaDB:          metaDB,
		StoreController: controller,
	}

	return &RouteHandler{c: controllerAPI}, store, metaDB, firstImage, secondImage, eventCapture
}

func invokeDeleteManifest(t *testing.T, handler *RouteHandler, digest godigest.Digest) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
		"/v2/repo/manifests/"+digest.String(), http.NoBody)
	request = mux.SetURLVars(request, map[string]string{
		"name":      "repo",
		"reference": digest.String(),
	})
	response := httptest.NewRecorder()
	handler.DeleteManifest(response, request)

	return response
}

func TestDeleteManifestCompletesMetaDBCleanupAfterBlobDeleteError(t *testing.T) {
	for _, testCase := range []struct {
		name              string
		err               error
		deleteBeforeError bool
		blobDeleted       bool
	}{
		{
			name:              "transient after remote commit",
			err:               errclass.MarkTransient(errors.New("manifest delete acknowledgement lost")), //nolint:err113 // test
			deleteBeforeError: true,
			blobDeleted:       true,
		},
		{
			name:        "permanent before remote commit",
			err:         errclass.MarkPermanent(errors.New("manifest delete permission denied")), //nolint:err113 // test
			blobDeleted: false,
		},
		{
			name:              "permanent after remote commit",
			err:               errclass.MarkPermanent(errors.New("manifest delete acknowledgement lost")), //nolint:err113 // test
			deleteBeforeError: true,
			blobDeleted:       true,
		},
		{
			name:              "already missing blob",
			err:               errclass.MarkMissing(errors.New("manifest blob already removed")), //nolint:err113 // test
			deleteBeforeError: true,
			blobDeleted:       true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			faultDriver := &manifestDeleteFaultDriver{
				deleteErr:         testCase.err,
				deleteBeforeError: testCase.deleteBeforeError,
			}
			handler, store, metaDB, firstImage, secondImage, eventCapture := newManifestDeleteFixture(t, faultDriver)

			response := invokeDeleteManifest(t, handler, firstImage.Digest())
			require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())

			_, _, _, err := store.GetImageManifest("repo", firstImage.Digest().String())
			require.ErrorIs(t, err, zerr.ErrManifestNotFound)
			_, storedDigest, _, err := store.GetImageManifest("repo", secondImage.Digest().String())
			require.NoError(t, err)
			require.Equal(t, secondImage.Digest(), storedDigest)

			_, err = os.Stat(faultDriver.manifestPath)
			if testCase.blobDeleted {
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.NoError(t, err)
			}

			indexContent, err := store.GetIndexContent("repo")
			require.NoError(t, err)
			var index ispec.Index
			require.NoError(t, json.Unmarshal(indexContent, &index))
			require.Len(t, index.Manifests, 1)
			require.Equal(t, secondImage.Digest(), index.Manifests[0].Digest)

			repoMeta, err := metaDB.GetRepoMeta(t.Context(), "repo")
			require.NoError(t, err)
			require.NotContains(t, repoMeta.Tags, "first")
			require.Equal(t, secondImage.Digest().String(), repoMeta.Tags["keep"].Digest)

			searchResults, err := metaDB.SearchTags(t.Context(), "repo:first")
			require.NoError(t, err)
			require.Empty(t, searchResults)

			eventCapture.Lock()
			require.Len(t, eventCapture.ImageDeletedCalls, 1)
			require.Equal(t, firstImage.Digest().String(), eventCapture.ImageDeletedCalls[0].Digest)
			eventCapture.Unlock()
		})
	}
}

func TestDeleteManifestKeepsStateWhenIndexCommitFails(t *testing.T) {
	faultDriver := &manifestDeleteFaultDriver{
		writeErr: errclass.MarkTransient(errors.New("index write failed")), //nolint:err113 // test
	}
	handler, store, metaDB, firstImage, secondImage, _ := newManifestDeleteFixture(t, faultDriver)

	response := invokeDeleteManifest(t, handler, firstImage.Digest())
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())

	_, storedDigest, _, err := store.GetImageManifest("repo", firstImage.Digest().String())
	require.NoError(t, err)
	require.Equal(t, firstImage.Digest(), storedDigest)
	_, _, _, err = store.GetImageManifest("repo", secondImage.Digest().String())
	require.NoError(t, err)

	_, err = os.Stat(faultDriver.manifestPath)
	require.NoError(t, err)

	repoMeta, err := metaDB.GetRepoMeta(t.Context(), "repo")
	require.NoError(t, err)
	require.Equal(t, firstImage.Digest().String(), repoMeta.Tags["first"].Digest)
	require.Equal(t, secondImage.Digest().String(), repoMeta.Tags["keep"].Digest)
}

func TestWritePutImageManifestErrorMissingBlob(t *testing.T) {
	t.Parallel()

	routeHandler := &RouteHandler{c: &Controller{Log: log.NewTestLogger()}}

	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("%w: %w", zerr.ErrBadManifest, zerr.ErrBlobNotFound), http.StatusBadRequest, "MANIFEST_BLOB_UNKNOWN"},
		{fmt.Errorf("%w: %w", zerr.ErrManifestCacheLookup, zerr.ErrBlobNotFound), http.StatusInternalServerError, ""},
	} {
		response := httptest.NewRecorder()
		routeHandler.writePutImageManifestError(response, "repo", "tag", tc.err)

		if response.Code != tc.status {
			t.Errorf("writePutImageManifestError(%v) status = %d, want %d", tc.err, response.Code, tc.status)
		}

		if !strings.Contains(response.Body.String(), tc.code) {
			t.Errorf("writePutImageManifestError(%v) body = %q, want %s", tc.err, response.Body.String(), tc.code)
		}
	}
}

type delayedManifestMetaDB struct {
	mTypes.MetaDB

	method  string
	digest  godigest.Digest
	entered chan struct{}
	release chan struct{}
}

func (db *delayedManifestMetaDB) SetRepoReference(ctx context.Context, repo, reference string,
	imageMeta mTypes.ImageMeta, opts ...mTypes.SetRepoReferenceOption,
) error {
	if db.method == http.MethodPut && repo == "repo" && reference == "latest" && imageMeta.Digest == db.digest {
		close(db.entered)
		<-db.release
	}

	return db.MetaDB.SetRepoReference(ctx, repo, reference, imageMeta, opts...)
}

func (db *delayedManifestMetaDB) RemoveRepoReference(repo, reference string, digest godigest.Digest) error {
	if db.method == http.MethodDelete && repo == "repo" {
		close(db.entered)
		<-db.release
	}

	return db.MetaDB.RemoveRepoReference(repo, reference, digest)
}

func TestManifestMutationsKeepMetaDBConsistent(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		method    string
		byDigest  bool
		extraTags bool
	}{
		{name: "push-push", method: http.MethodPut},
		{name: "delete-push", method: http.MethodDelete},
		{name: "multi-tag-push-push", method: http.MethodPut, byDigest: true, extraTags: true},
		{name: "digest-delete-push", method: http.MethodDelete, byDigest: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rootDir := t.TempDir()
			logger := log.NewTestLogger()
			store := local.NewImageStore(rootDir, false, false, logger,
				monitoring.NewNopMetricServer(), nil, nil, nil, nil)
			driver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: t.TempDir()})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, driver.Close()) })
			metaDB, err := boltdb.New(driver, logger)
			require.NoError(t, err)

			ctlr := &Controller{
				Config:          config.New(),
				Log:             logger,
				MetaDB:          metaDB,
				StoreController: storage.StoreController{DefaultStore: store},
			}
			require.Zero(t, ctlr.Config.Storage.MaxRepoBytes)
			handler := &RouteHandler{c: ctlr}
			firstImage := image.CreateRandomImage()
			secondImage := image.CreateRandomImage()
			require.NoError(t, image.WriteImageToFileSystem(firstImage, "repo", "seed-a", ctlr.StoreController))
			require.NoError(t, image.WriteImageToFileSystem(secondImage, "repo", "seed-b", ctlr.StoreController))
			require.NoError(t, image.WriteImageToFileSystem(secondImage, "other", "seed", ctlr.StoreController))
			firstBody, err := json.Marshal(firstImage.Manifest)
			require.NoError(t, err)
			secondBody, err := json.Marshal(secondImage.Manifest)
			require.NoError(t, err)

			run := func(method, repo, reference string, body []byte, extraTags bool) *httptest.ResponseRecorder {
				url := "/v2/" + repo + "/manifests/" + reference
				if extraTags {
					url += "?tag=latest&tag=alias"
				}

				request := httptest.NewRequestWithContext(t.Context(), method, url, bytes.NewReader(body))
				request = mux.SetURLVars(request, map[string]string{"name": repo, "reference": reference})
				request.Header.Set("Content-Type", ispec.MediaTypeImageManifest)
				response := httptest.NewRecorder()
				if method == http.MethodPut {
					handler.UpdateManifest(response, request)
				} else {
					handler.DeleteManifest(response, request)
				}

				return response
			}
			if testCase.method == http.MethodDelete {
				require.Equal(t, http.StatusCreated, run(http.MethodPut, "repo", "latest", firstBody, false).Code)
			}

			delayedDB := &delayedManifestMetaDB{
				MetaDB: metaDB, method: testCase.method, digest: firstImage.Digest(),
				entered: make(chan struct{}), release: make(chan struct{}),
			}
			ctlr.MetaDB = delayedDB

			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(delayedDB.release) }) }
			defer release()

			firstDone := make(chan *httptest.ResponseRecorder, 1)
			reference := "latest"

			if testCase.byDigest {
				reference = firstImage.DigestStr()
			}
			go func() { firstDone <- run(testCase.method, "repo", reference, firstBody, testCase.extraTags) }()
			select {
			case <-delayedDB.entered:
			case <-time.After(10 * time.Second):
				t.Fatal("first mutation did not reach the MetaDB hook")
			}

			// A paused repository must not block mutations in another repository.
			otherDone := make(chan *httptest.ResponseRecorder, 1)
			go func() { otherDone <- run(http.MethodPut, "other", "latest", secondBody, false) }()
			select {
			case response := <-otherDone:
				require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			case <-time.After(10 * time.Second):
				t.Fatal("unrelated repository mutation was blocked")
			}

			secondDone := make(chan *httptest.ResponseRecorder, 1)
			go func() { secondDone <- run(http.MethodPut, "repo", "latest", secondBody, false) }()

			// Wait for the second request to queue on the lock, not for an arbitrary
			// sleep. Without serialization it completes while the first hook is paused.
			deadline := time.After(10 * time.Second)
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()

			for {
				ctlr.repoMutationLocks.mu.Lock()
				lock := ctlr.repoMutationLocks.locks["repo"]
				queued := lock != nil && lock.references == 2
				ctlr.repoMutationLocks.mu.Unlock()
				if queued {
					break
				}

				completedEarly := false
				select {
				case response := <-secondDone:
					secondDone <- response
					t.Error("second mutation completed before the first MetaDB hook")
					completedEarly = true
				case <-deadline:
					t.Fatal("second mutation neither queued nor completed")
				case <-ticker.C:
				}
				if completedEarly {
					break
				}
			}

			release()

			for i, done := range []chan *httptest.ResponseRecorder{firstDone, secondDone} {
				select {
				case response := <-done:
					status := http.StatusCreated
					if i == 0 && testCase.method == http.MethodDelete {
						status = http.StatusAccepted
					}
					require.Equal(t, status, response.Code, response.Body.String())
				case <-time.After(10 * time.Second):
					t.Fatalf("mutation %d did not finish", i)
				}
			}

			_, storedDigest, _, err := store.GetImageManifest("repo", "latest")
			require.NoError(t, err)
			require.Equal(t, secondImage.Digest(), storedDigest)
			repoMeta, err := metaDB.GetRepoMeta(t.Context(), "repo")
			require.NoError(t, err)
			require.Equal(t, storedDigest.String(), repoMeta.Tags["latest"].Digest)
			if testCase.extraTags {
				require.Equal(t, firstImage.DigestStr(), repoMeta.Tags["alias"].Digest)
			}
		})
	}
}
