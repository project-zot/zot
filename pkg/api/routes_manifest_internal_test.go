package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

type failingManifestMetaDB struct {
	mTypes.MetaDB

	failDigest       godigest.Digest
	failRef          string
	failErr          error
	commitBeforeFail bool
}

func (db *failingManifestMetaDB) SetRepoReference(ctx context.Context, repo, reference string,
	imageMeta mTypes.ImageMeta, opts ...mTypes.SetRepoReferenceOption,
) error {
	if repo == "repo" && reference == db.failRef && imageMeta.Digest == db.failDigest {
		if db.commitBeforeFail {
			if err := db.MetaDB.SetRepoReference(ctx, repo, reference, imageMeta, opts...); err != nil {
				return err
			}
		}

		return db.failErr
	}

	return db.MetaDB.SetRepoReference(ctx, repo, reference, imageMeta, opts...)
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

func TestManifestMetaFailureRestoresPreviousTag(t *testing.T) {
	rootDir := t.TempDir()
	logger := log.NewTestLogger()
	store := local.NewImageStore(rootDir, false, false, logger,
		monitoring.NewNopMetricServer(), nil, nil, nil, nil)
	driver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, driver.Close()) })
	metaDB, err := boltdb.New(driver, logger)
	require.NoError(t, err)

	controller := &Controller{
		Config:          config.New(),
		Log:             logger,
		MetaDB:          metaDB,
		StoreController: storage.StoreController{DefaultStore: store},
	}
	handler := &RouteHandler{c: controller}

	firstImage := image.CreateRandomImage()
	secondImage := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(firstImage, "repo", firstImage.DigestStr(), controller.StoreController))
	require.NoError(t, image.WriteImageToFileSystem(secondImage, "repo", secondImage.DigestStr(), controller.StoreController))

	put := func(body []byte) *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPut,
			"/v2/repo/manifests/latest", bytes.NewReader(body))
		request = mux.SetURLVars(request, map[string]string{"name": "repo", "reference": "latest"})
		request.Header.Set("Content-Type", ispec.MediaTypeImageManifest)

		response := httptest.NewRecorder()
		handler.UpdateManifest(response, request)

		return response
	}

	firstBody, err := json.Marshal(firstImage.Manifest)
	require.NoError(t, err)
	secondBody, err := json.Marshal(secondImage.Manifest)
	require.NoError(t, err)

	require.Equal(t, http.StatusCreated, put(firstBody).Code)

	controller.MetaDB = &failingManifestMetaDB{
		MetaDB:           metaDB,
		failDigest:       secondImage.Digest(),
		failRef:          "latest",
		failErr:          errors.New("injected manifest MetaDB update failure"), //nolint:err113 // test sentinel
		commitBeforeFail: true,
	}

	response := put(secondBody)
	require.Equal(t, http.StatusInternalServerError, response.Code)

	_, storedDigest, _, err := store.GetImageManifest("repo", "latest")
	require.NoError(t, err)
	require.Equal(t, firstImage.Digest(), storedDigest)

	repoMeta, err := metaDB.GetRepoMeta(t.Context(), "repo")
	require.NoError(t, err)
	require.Equal(t, firstImage.DigestStr(), repoMeta.Tags["latest"].Digest)
}

func TestManifestMetaSnapshotFailureSkipsStorageWrite(t *testing.T) {
	snapshotErr := errors.New("failed to read previous manifest") //nolint:err113 // test sentinel
	putCalled := false

	controller := &Controller{
		Config: config.New(),
		Log:    log.NewTestLogger(),
		MetaDB: mocks.MetaDBMock{},
		StoreController: storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetImageManifestFn: func(string, string) ([]byte, godigest.Digest, string, error) {
				return nil, "", "", snapshotErr
			},
			PutImageManifestFn: func(context.Context, string, string, string, []byte, []string) (
				godigest.Digest, godigest.Digest, error,
			) {
				putCalled = true

				return "", "", nil
			},
		}},
	}
	handler := &RouteHandler{c: controller}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPut,
		"/v2/repo/manifests/latest", bytes.NewReader([]byte(`{"schemaVersion":2}`)))
	request = mux.SetURLVars(request, map[string]string{"name": "repo", "reference": "latest"})
	request.Header.Set("Content-Type", ispec.MediaTypeImageManifest)
	response := httptest.NewRecorder()

	handler.UpdateManifest(response, request)

	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.False(t, putCalled)
}
