package gc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	image "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// scanHookStore runs onScan synchronously right after GetAllBlobs has listed the repository, so
// the hook's writes land after the scan's snapshot and before the locked commit. onLock runs
// before the cleanup lock is taken, i.e. after the whole unlocked scan; hooks that write through
// the store must not run once GC runs the locked fallback.
type scanHookStore struct {
	storageTypes.ImageStore
	calls         atomic.Int32
	locks         atomic.Int32
	beforeScan    func(call int32)
	onScan        func(call int32)
	onLock        func(call int32)
	beforeRead    func(digest godigest.Digest)
	beforeStatOld func(digest godigest.Digest)
}

func (s *scanHookStore) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	if s.beforeRead != nil {
		s.beforeRead(digest)
	}

	return s.ImageStore.GetBlobContent(repo, digest)
}

func (s *scanHookStore) StatBlobEntry(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	if s.beforeStatOld != nil {
		s.beforeStatOld(digest)
	}

	return s.ImageStore.StatBlobEntry(repo, digest)
}

func (s *scanHookStore) WithRepoCleanupLock(repo string, wrappedFunc func() error) error {
	call := s.locks.Add(1)
	if s.onLock != nil {
		s.onLock(call)
	}

	return s.ImageStore.WithRepoCleanupLock(repo, wrappedFunc)
}

func (s *scanHookStore) GetAllBlobs(repo string) ([]godigest.Digest, error) {
	call := s.calls.Add(1)
	if s.beforeScan != nil {
		s.beforeScan(call)
	}

	blobs, err := s.ImageStore.GetAllBlobs(repo)

	if s.onScan != nil {
		s.onScan(call)
	}

	return blobs, err
}

type scanBarrierStore struct {
	storageTypes.ImageStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *scanBarrierStore) GetAllBlobs(repo string) ([]godigest.Digest, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release

	return s.ImageStore.GetAllBlobs(repo)
}

func newScanTestStore(t *testing.T) storageTypes.ImageStore {
	t.Helper()

	return local.NewImageStore(t.TempDir(), false, false, zlog.NewTestLogger(), monitoring.NewNopMetricServer(),
		nil, nil, nil, nil)
}

func uploadRandomBlob(t *testing.T, store storageTypes.ImageStore, repo string) (godigest.Digest, []byte) {
	t.Helper()

	content := make([]byte, 64)
	_, err := rand.Read(content)
	require.NoError(t, err)

	digest := godigest.FromBytes(content)
	_, _, err = store.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
	require.NoError(t, err)

	return digest, content
}

// publishManifestReferencing publishes a manifest under tag whose only layer is the already
// uploaded blob layer.
func publishManifestReferencing(t *testing.T, store storageTypes.ImageStore, repo, tag string,
	layer godigest.Digest, layerSize int64,
) {
	t.Helper()

	img := image.CreateDefaultImage()
	cfg, err := json.Marshal(img.Config)
	require.NoError(t, err)

	configDigest := godigest.FromBytes(cfg)
	_, _, err = store.FullBlobUpload(context.Background(), repo, bytes.NewReader(cfg), configDigest)
	require.NoError(t, err)

	manifest := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(cfg)),
		},
		Layers: []ispec.Descriptor{{
			MediaType: ispec.MediaTypeImageLayer,
			Digest:    layer,
			Size:      layerSize,
		}},
	}
	manifest.SchemaVersion = 2

	body, err := json.Marshal(manifest)
	require.NoError(t, err)

	_, _, err = store.PutImageManifest(context.Background(), repo, tag, ispec.MediaTypeImageManifest, body, nil)
	require.NoError(t, err)
}

func auditRecords(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()

	var records []map[string]any

	for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}

		var record map[string]any
		require.NoError(t, json.Unmarshal(line, &record))
		records = append(records, record)
	}

	return records
}

func countDeleteRecords(t *testing.T, output *bytes.Buffer, reference string) int {
	t.Helper()

	deletes := 0

	for _, record := range auditRecords(t, output) {
		if record["decision"] == "delete" && record["reference"] == reference {
			deletes++
		}
	}

	return deletes
}

func TestGCScanDoesNotBlockUnrelatedRead(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "scanned", "latest", controller))
	require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "unrelated", "latest", controller))

	expected, _, _, err := store.GetImageManifest("unrelated", "latest")
	require.NoError(t, err)

	wrapped := &scanBarrierStore{ImageStore: store, entered: make(chan struct{}), release: make(chan struct{})}

	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(wrapped.release) }) })

	collector := NewGarbageCollect(wrapped, nil, Options{}, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	done := make(chan error, 1)

	go func() { done <- collector.CleanRepo(context.Background(), "scanned") }()

	select {
	case <-wrapped.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("GC did not reach blob enumeration")
	}

	read := make(chan []byte, 1)

	go func() {
		body, _, _, readErr := store.GetImageManifest("unrelated", "latest")
		if readErr != nil {
			body = nil
		}

		read <- body
	}()

	select {
	case body := <-read:
		require.Equal(t, expected, body)
	case <-time.After(5 * time.Second):
		t.Fatal("read blocked behind the GC scan")
	}

	release.Do(func() { close(wrapped.release) })
	require.NoError(t, <-done)
}

func TestGCRescansWhenIndexChangesDuringScan(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "repo", "v1", controller))

	layer, layerContent := uploadRandomBlob(t, store, "repo")
	orphan, _ := uploadRandomBlob(t, store, "repo")

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onScan = func(call int32) {
		if call == 1 {
			publishManifestReferencing(t, store, "repo", "v2", layer, int64(len(layerContent)))
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: 0}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	_, _, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)
	_, _, _, err = store.GetImageManifest("repo", "v2")
	require.NoError(t, err)

	content, err := store.GetBlobContent("repo", layer)
	require.NoError(t, err)
	require.Equal(t, layerContent, content)

	_, err = store.GetBlobContent("repo", orphan)
	require.ErrorIs(t, err, zerr.ErrBlobNotFound)

	require.EqualValues(t, 2, wrapped.calls.Load())
	require.EqualValues(t, 2, wrapped.locks.Load())
}

func TestGCFallsBackToLockedScanAfterRepeatedConflicts(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "repo", "v0", controller))
	orphan, _ := uploadRandomBlob(t, store, "repo")

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onScan = func(call int32) {
		if call <= maxOptimisticGCAttempts {
			tag := "conflict-" + string(rune('a'+call))
			require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "repo", tag, controller))
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: 0}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	for _, tag := range []string{"v0", "conflict-b", "conflict-c", "conflict-d"} {
		_, _, _, err := store.GetImageManifest("repo", tag)
		require.NoError(t, err, tag)
	}

	_, err := store.GetBlobContent("repo", orphan)
	require.ErrorIs(t, err, zerr.ErrBlobNotFound)

	// Three optimistic scans, then the locked pass lists blobs twice (stale prune, blob cleanup).
	require.EqualValues(t, maxOptimisticGCAttempts+2, wrapped.calls.Load())
	require.EqualValues(t, maxOptimisticGCAttempts+1, wrapped.locks.Load())
}

// A manifest blob that is missing during the scan and restored before the commit leaves index.json
// byte-identical. Committing that plan would drop the tag and delete its config and layers.
func TestGCRescansWhenPrunedManifestIsRestoredBeforeCommit(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	img := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(img, "repo", "v1", controller))

	manifestBytes, manifestDigest, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	manifestPath := store.BlobPath("repo", manifestDigest)

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.beforeScan = func(call int32) {
		if call == 1 {
			require.NoError(t, os.Remove(manifestPath))
		}
	}
	wrapped.onLock = func(call int32) {
		if call == 1 {
			require.NoError(t, os.WriteFile(manifestPath, manifestBytes, 0o600))
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: 0}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	body, _, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)
	require.Equal(t, manifestBytes, body)

	_, err = store.GetBlobContent("repo", img.Manifest.Config.Digest)
	require.NoError(t, err)

	require.EqualValues(t, 2, wrapped.calls.Load())
}

// A same-digest upload after the scan refreshes the orphan's modification time without changing
// index.json or the blob set, so the scan's age check no longer holds at commit time.
func TestGCKeepsOrphanReuploadedBeforeCommit(t *testing.T) {
	store := newScanTestStore(t)

	require.NoError(t, store.InitRepo(context.Background(), "repo"))
	orphan, content := uploadRandomBlob(t, store, "repo")
	stale, _ := uploadRandomBlob(t, store, "repo")

	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(store.BlobPath("repo", orphan), old, old))
	require.NoError(t, os.Chtimes(store.BlobPath("repo", stale), old, old))

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onLock = func(call int32) {
		if call == 1 {
			_, _, err := store.FullBlobUpload(context.Background(), "repo", bytes.NewReader(content), orphan)
			require.NoError(t, err)
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: time.Hour}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	got, err := store.GetBlobContent("repo", orphan)
	require.NoError(t, err)
	require.Equal(t, content, got)

	_, err = store.GetBlobContent("repo", stale)
	require.ErrorIs(t, err, zerr.ErrBlobNotFound)

	require.EqualValues(t, 1, wrapped.calls.Load())
}

// An untagged manifest past the retention delay is removed by the scan; a same-digest upload of
// the manifest after the scan makes it young again without touching index.json.
func TestGCRescansWhenAgedManifestIsReuploadedBeforeCommit(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	img := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(img, "repo", img.DigestStr(), controller))

	manifestBytes, manifestDigest, _, err := store.GetImageManifest("repo", img.DigestStr())
	require.NoError(t, err)

	old := time.Now().Add(-2 * time.Hour)
	for _, digest := range []godigest.Digest{manifestDigest, img.Manifest.Config.Digest} {
		require.NoError(t, os.Chtimes(store.BlobPath("repo", digest), old, old))
	}

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onLock = func(call int32) {
		if call == 1 {
			_, _, err := store.FullBlobUpload(context.Background(), "repo", bytes.NewReader(manifestBytes), manifestDigest)
			require.NoError(t, err)
		}
	}

	deleteUntagged := true
	opts := Options{Delay: time.Hour, ImageRetention: config.ImageRetention{
		Delay: time.Hour,
		Policies: []config.RetentionPolicy{{
			Repositories:   []string{"**"},
			DeleteUntagged: &deleteUntagged,
		}},
	}}

	collector := NewGarbageCollect(wrapped, nil, opts, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	body, _, _, err := store.GetImageManifest("repo", img.DigestStr())
	require.NoError(t, err)
	require.Equal(t, manifestBytes, body)

	_, err = store.GetBlobContent("repo", img.Manifest.Config.Digest)
	require.NoError(t, err)

	require.EqualValues(t, 2, wrapped.calls.Load())
}

// A manifest removed after the blob listing but before the reference walk is skipped by the
// walk, so its config and layers look unreferenced.
func TestGCRescansWhenManifestVanishesBeforeReferenceWalk(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	img := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(img, "repo", "v1", controller))

	manifestBytes, manifestDigest, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	manifestPath := store.BlobPath("repo", manifestDigest)

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onScan = func(call int32) {
		switch call {
		case 1:
			require.NoError(t, os.Remove(manifestPath))
		case 2:
			require.NoError(t, os.WriteFile(manifestPath, manifestBytes, 0o600))
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: 0}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	body, _, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)
	require.Equal(t, manifestBytes, body)

	_, err = store.GetBlobContent("repo", img.Manifest.Config.Digest)
	require.NoError(t, err)

	for _, layer := range img.Manifest.Layers {
		_, err = store.GetBlobContent("repo", layer.Digest)
		require.NoError(t, err)
	}

	require.EqualValues(t, 2, wrapped.calls.Load())
}

// A sparse index keeps a child whose manifest blob is missing, so that child is neither
// stale-pruned nor a scan conflict. Restoring it before the commit leaves index.json unchanged
// while its config and layers are planned for deletion.
func TestGCRescansWhenMissingNestedManifestIsRestoredBeforeCommit(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	surviving := image.CreateRandomImage()
	restored := image.CreateRandomImage()
	multi := image.CreateMultiarchWith().Images([]image.Image{surviving, restored}).Build()

	require.NoError(t, image.WriteImageToFileSystem(surviving, "repo", surviving.DigestStr(), controller))

	for _, layer := range restored.Layers {
		_, _, err := store.FullBlobUpload(context.Background(), "repo", bytes.NewReader(layer), godigest.FromBytes(layer))
		require.NoError(t, err)
	}

	restoredConfig, err := json.Marshal(restored.Config)
	require.NoError(t, err)
	_, _, err = store.FullBlobUpload(context.Background(), "repo", bytes.NewReader(restoredConfig),
		godigest.FromBytes(restoredConfig))
	require.NoError(t, err)

	restoredManifest, err := json.Marshal(restored.Manifest)
	require.NoError(t, err)
	restoredPath := store.BlobPath("repo", godigest.FromBytes(restoredManifest))
	require.NoError(t, os.WriteFile(restoredPath, restoredManifest, 0o600))

	indexBytes, err := json.Marshal(multi.Index)
	require.NoError(t, err)
	_, _, err = store.PutImageManifest(context.Background(), "repo", "multi", multi.Index.MediaType, indexBytes, nil)
	require.NoError(t, err)

	require.NoError(t, os.Remove(restoredPath))

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onLock = func(call int32) {
		if call == 1 {
			require.NoError(t, os.WriteFile(restoredPath, restoredManifest, 0o600))
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: 0}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	_, _, _, err = store.GetImageManifest("repo", "multi")
	require.NoError(t, err)

	_, err = store.GetBlobContent("repo", godigest.FromBytes(restoredConfig))
	require.NoError(t, err)

	for _, layer := range restored.Layers {
		_, err = store.GetBlobContent("repo", godigest.FromBytes(layer))
		require.NoError(t, err)
	}

	require.EqualValues(t, 2, wrapped.calls.Load())
}

type lockTrackingStore struct {
	mocks.MockedImageStore
	locked bool
	locks  int
}

func (s *lockTrackingStore) WithRepoCleanupLock(_ string, wrappedFunc func() error) error {
	s.locked = true
	s.locks++

	defer func() { s.locked = false }()

	return wrappedFunc()
}

func staleIndexJSON(digest godigest.Digest) []byte {
	return []byte(`{"schemaVersion":2,"manifests":[{"mediaType":"` + ispec.MediaTypeImageManifest +
		`","digest":"` + digest.String() + `","size":1}]}`)
}

func manifestJSON() []byte {
	return []byte(`{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageManifest +
		`","config":{"mediaType":"` + ispec.MediaTypeImageConfig + `","digest":"` +
		godigest.FromString("config").String() + `","size":1},"layers":[]}`)
}

// keepUntaggedOpts disables the default untagged deletion so the only index edit in the mock
// tests below is the stale prune of a manifest absent from the blob listing.
func keepUntaggedOpts() Options {
	deleteUntagged := false

	return Options{ImageRetention: config.ImageRetention{
		Policies: []config.RetentionPolicy{{Repositories: []string{"**"}, DeleteUntagged: &deleteUntagged}},
	}}
}

// The commit re-checks that a stale-pruned manifest is still absent. A stat failure under the
// lock must fail the run rather than confirm the removal.
func TestGCCommitFailsClosedWhenRevalidationStatFails(t *testing.T) {
	store := &lockTrackingStore{}
	stale := godigest.FromString("stale-manifest")
	transient := errors.New("transient stat failure")
	store.GetIndexContentFn = func(string) ([]byte, error) { return staleIndexJSON(stale), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{}, nil }
	store.StatBlobFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		if store.locked {
			return false, 0, time.Time{}, transient
		}

		return false, 0, time.Time{}, zerr.ErrBlobNotFound
	}
	store.PutIndexContentFn = func(string, ispec.Index) error {
		t.Fatal("index.json written after revalidation failed")

		return nil
	}

	collector := NewGarbageCollect(store, nil, keepUntaggedOpts(), nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), transient)
	require.False(t, store.locked)
}

// Cancellation observed while revalidating under the lock must stop before any recorded metaDB
// write is replayed.
func TestGCCommitSkipsMetaDBReplayWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &lockTrackingStore{}
	stale := godigest.FromString("stale-manifest")
	store.GetIndexContentFn = func(string) ([]byte, error) { return staleIndexJSON(stale), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{}, nil }
	store.StatBlobFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		if store.locked {
			cancel()
		}

		return false, 0, time.Time{}, zerr.ErrBlobNotFound
	}
	store.PutIndexContentFn = func(string, ispec.Index) error {
		t.Fatal("index.json written after cancellation")

		return nil
	}

	metaDB := mocks.MetaDBMock{
		RemoveRepoReferenceFn: func(string, string, godigest.Digest) error {
			t.Fatal("metaDB write replayed after cancellation")

			return nil
		},
	}

	collector := NewGarbageCollect(store, metaDB, keepUntaggedOpts(), nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.ErrorIs(t, collector.CleanRepo(ctx, "repo"), context.Canceled)
	require.False(t, store.locked)
}

// An age-based removal whose commit-time stat fails is a conflict, not a confirmation. The scan
// reruns, and the locked pass skips the row for the same stat failure instead of removing it.
func TestGCAgeRevalidationFailsClosedOnStatError(t *testing.T) {
	store := &lockTrackingStore{}
	untagged := godigest.FromString("untagged-manifest")
	puts := 0
	store.GetIndexContentFn = func(string) ([]byte, error) { return staleIndexJSON(untagged), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{untagged}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return manifestJSON(), nil }
	store.StatBlobFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		return true, 0, time.Now().Add(-2 * time.Hour), nil
	}
	store.StatBlobEntryFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		if store.locked {
			return false, 0, time.Time{}, zerr.ErrBlobNotFound
		}

		return true, 0, time.Now().Add(-2 * time.Hour), nil
	}
	store.PutIndexContentFn = func(_ string, index ispec.Index) error {
		puts++

		require.Len(t, index.Manifests, 1)

		return nil
	}

	deleteUntagged := true
	opts := Options{ImageRetention: config.ImageRetention{
		Delay:    time.Hour,
		Policies: []config.RetentionPolicy{{Repositories: []string{"**"}, DeleteUntagged: &deleteUntagged}},
	}}

	collector := NewGarbageCollect(store, nil, opts, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	require.Equal(t, 1, puts)
	require.Equal(t, maxOptimisticGCAttempts+1, store.locks)
	require.False(t, store.locked)
}

func TestGCCommitStopsCleanupWhenCancelledDuringStat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &lockTrackingStore{}
	orphan := godigest.FromString("orphan")
	store.GetIndexContentFn = func(string) ([]byte, error) {
		return []byte(`{"schemaVersion":2,"manifests":[]}`), nil
	}
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{orphan}, nil }
	store.StatBlobEntryFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		if store.locked {
			cancel()
		}

		return true, 0, time.Now().Add(-time.Hour), nil
	}
	store.CleanupRepoFn = func(string, []godigest.Digest) (int, error) {
		t.Fatal("cleanup ran after the context was cancelled")

		return 0, nil
	}

	collector := NewGarbageCollect(store, nil, Options{}, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.ErrorIs(t, collector.CleanRepo(ctx, "repo"), context.Canceled)
	require.False(t, store.locked)
}

// An untagged referrer whose blob is missing when the policy walk reads it is not marked as
// protected by its subject. Restored before its age stat, it would be removed with Delay=0
// although the subject is still present and index.json is unchanged.
func TestGCRescansWhenReferrerIsRestoredBetweenPolicyWalkAndStat(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	subject := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(subject, "repo", "v1", controller))

	subjectBytes, subjectDigest, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	referrer := image.CreateRandomImageWith().Subject(&ispec.Descriptor{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    subjectDigest,
		Size:      int64(len(subjectBytes)),
	}).Build()
	require.NoError(t, image.WriteImageToFileSystem(referrer, "repo", referrer.DigestStr(), controller))

	referrerBytes, referrerDigest, _, err := store.GetImageManifest("repo", referrer.DigestStr())
	require.NoError(t, err)

	referrerPath := store.BlobPath("repo", referrerDigest)

	var removed, restored atomic.Bool

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.beforeRead = func(digest godigest.Digest) {
		if digest == referrerDigest && removed.CompareAndSwap(false, true) {
			require.NoError(t, os.Remove(referrerPath))
		}
	}
	wrapped.beforeStatOld = func(digest godigest.Digest) {
		if digest == referrerDigest && removed.Load() && restored.CompareAndSwap(false, true) {
			require.NoError(t, os.WriteFile(referrerPath, referrerBytes, 0o600))
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: 0}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	require.True(t, removed.Load())
	require.True(t, restored.Load())

	body, _, _, err := store.GetImageManifest("repo", referrer.DigestStr())
	require.NoError(t, err)
	require.Equal(t, referrerBytes, body)

	require.EqualValues(t, 2, wrapped.calls.Load())
}

func pulledRepoMeta(digest godigest.Digest, tags map[mTypes.Tag]mTypes.Descriptor, pulled *atomic.Bool,
) func(context.Context, string) (mTypes.RepoMeta, error) {
	return func(context.Context, string) (mTypes.RepoMeta, error) {
		lastPull := time.Now().Add(-2 * time.Hour)
		if pulled.Load() {
			lastPull = time.Now()
		}

		return mTypes.RepoMeta{
			Name: "repo",
			Tags: tags,
			Statistics: map[mTypes.ImageDigest]mTypes.DescriptorStatistics{digest.String(): {
				PushTimestamp:     time.Now().Add(-3 * time.Hour),
				LastPullTimestamp: lastPull,
			}},
		}, nil
	}
}

// A pull completed during the scan updates LastPullTimestamp in metaDB without touching
// index.json or any blob, so a pulledWithin keep policy that excluded the tag at scan time
// includes it at commit time.
func TestGCRescansWhenTagIsPulledDuringScan(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "repo", "v1", controller))

	_, digest, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	var pulled atomic.Bool

	metaDB := mocks.MetaDBMock{
		GetRepoMetaFn: pulledRepoMeta(digest,
			map[mTypes.Tag]mTypes.Descriptor{"v1": {Digest: digest.String(), MediaType: ispec.MediaTypeImageManifest}},
			&pulled),
		RemoveRepoReferenceFn: func(string, string, godigest.Digest) error {
			t.Fatal("tag removed from metaDB although it was pulled during the scan")

			return nil
		},
	}

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onLock = func(call int32) {
		if call == 1 {
			pulled.Store(true)
		}
	}

	pulledWithin := time.Hour
	opts := Options{ImageRetention: config.ImageRetention{
		Policies: []config.RetentionPolicy{{
			Repositories: []string{"**"},
			KeepTags:     []config.KeepTagsPolicy{{Patterns: []string{"v.*"}, PulledWithin: &pulledWithin}},
		}},
	}}

	var auditOut bytes.Buffer

	audit := zlog.Logger{Logger: slog.New(slog.NewJSONHandler(&auditOut, nil))}

	collector := NewGarbageCollect(wrapped, metaDB, opts, &audit, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	_, _, _, err = store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	require.EqualValues(t, 2, wrapped.calls.Load())

	for _, record := range auditRecords(t, &auditOut) {
		require.NotEqual(t, "delete", record["decision"], "audit record for a rejected plan: %v", record)
	}
}

// The untagged retention pass runs until nothing changes, so only its first pass still contains
// the manifest it removed. A digest pull completed before commit must be checked against that
// pass, not the last one.
func TestGCRescansWhenUntaggedDigestIsPulledDuringScan(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	img := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(img, "repo", img.DigestStr(), controller))

	_, digest, _, err := store.GetImageManifest("repo", img.DigestStr())
	require.NoError(t, err)

	var pulled atomic.Bool

	metaDB := mocks.MetaDBMock{
		GetRepoMetaFn: pulledRepoMeta(digest, map[mTypes.Tag]mTypes.Descriptor{}, &pulled),
		RemoveRepoReferenceFn: func(string, string, godigest.Digest) error {
			t.Fatal("untagged manifest removed from metaDB although it was pulled during the scan")

			return nil
		},
	}

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onLock = func(call int32) {
		if call == 1 {
			pulled.Store(true)
		}
	}

	pulledWithin := time.Hour
	deleteUntagged := true
	opts := Options{ImageRetention: config.ImageRetention{
		Policies: []config.RetentionPolicy{{
			Repositories:   []string{"**"},
			DeleteUntagged: &deleteUntagged,
			KeepUntagged:   &config.KeepUntaggedPolicy{PulledWithin: &pulledWithin},
		}},
	}}

	collector := NewGarbageCollect(wrapped, metaDB, opts, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	_, _, _, err = store.GetImageManifest("repo", img.DigestStr())
	require.NoError(t, err)

	require.EqualValues(t, 2, wrapped.calls.Load())
}

// A retention snapshot must not change when a later pass removes a last tag, which rewrites the
// descriptor's annotations in place.
func TestRetentionSnapshotSurvivesLaterTagRemoval(t *testing.T) {
	digest := godigest.FromString("manifest")
	index := ispec.Index{Manifests: []ispec.Descriptor{{
		MediaType:   ispec.MediaTypeImageManifest,
		Digest:      digest,
		Annotations: map[string]string{ispec.AnnotationRefName: "v1"},
	}}}

	snapshot := cloneIndex(index)

	_, err := common.RemoveManifestDescByReference(&index, "v1", true)
	require.NoError(t, err)

	require.Len(t, index.Manifests, 1)
	_, stillTagged := index.Manifests[0].Annotations[ispec.AnnotationRefName]
	require.False(t, stillTagged)

	require.Len(t, snapshot.Manifests, 1)
	require.Equal(t, "v1", snapshot.Manifests[0].Annotations[ispec.AnnotationRefName])
}

// A committed plan's proposed deletions are published to the audit log once, after commit.
func TestGCAuditEventsPublishedForCommittedPlan(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	img := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(img, "repo", img.DigestStr(), controller))

	var auditOut bytes.Buffer

	audit := zlog.Logger{Logger: slog.New(slog.NewJSONHandler(&auditOut, nil))}

	collector := NewGarbageCollect(store, nil, Options{Delay: 0}, &audit, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	_, _, _, err := store.GetImageManifest("repo", img.DigestStr())
	require.Error(t, err)

	require.Equal(t, 1, countDeleteRecords(t, &auditOut, img.DigestStr()))
}

// A listed orphan deleted by a client before the scan stats it is skipped, not a failed run.
func TestGCSkipsOrphanDeletedBeforeAgeCheck(t *testing.T) {
	store := newScanTestStore(t)

	require.NoError(t, store.InitRepo(context.Background(), "repo"))
	orphan, _ := uploadRandomBlob(t, store, "repo")
	other, _ := uploadRandomBlob(t, store, "repo")

	var removed atomic.Bool

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.beforeStatOld = func(digest godigest.Digest) {
		if digest == orphan && removed.CompareAndSwap(false, true) {
			require.NoError(t, os.Remove(store.BlobPath("repo", orphan)))
		}
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: 0}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	require.True(t, removed.Load())

	_, err := store.GetBlobContent("repo", other)
	require.ErrorIs(t, err, zerr.ErrBlobNotFound)
}

// Once index.json is written the manifest removals are durable, so their audit records must be
// published even when the blob cleanup that follows fails.
func TestGCAuditEventsSurviveCleanupFailureAfterIndexWrite(t *testing.T) {
	store := &lockTrackingStore{}
	untagged := godigest.FromString("untagged-manifest")
	cleanupErr := errors.New("cleanup failed")
	writes := 0
	store.GetIndexContentFn = func(string) ([]byte, error) { return staleIndexJSON(untagged), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{untagged}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return manifestJSON(), nil }
	store.StatBlobFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		return true, 0, time.Now().Add(-2 * time.Hour), nil
	}
	store.PutIndexContentFn = func(_ string, index ispec.Index) error {
		writes++
		require.Empty(t, index.Manifests)

		return nil
	}
	store.CleanupRepoFn = func(string, []godigest.Digest) (int, error) { return 0, cleanupErr }

	var auditOut bytes.Buffer

	audit := zlog.Logger{Logger: slog.New(slog.NewJSONHandler(&auditOut, nil))}

	collector := NewGarbageCollect(store, nil, Options{}, &audit, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), cleanupErr)
	require.Equal(t, 1, writes)
	require.Equal(t, 1, countDeleteRecords(t, &auditOut, untagged.String()))
}

// PutImageManifest rewrites a manifest blob in place under the write lock. A scan read that
// overlapped it would see a partial document and fail the run; the read must wait for the lock.
func TestGCScanReadWaitsForInPlaceManifestRewrite(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	img := image.CreateRandomImage()
	require.NoError(t, image.WriteImageToFileSystem(img, "repo", "v1", controller))

	manifestBytes, manifestDigest, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	manifestPath := store.BlobPath("repo", manifestDigest)

	var started sync.Once

	writerDone := make(chan struct{})

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onScan = func(int32) {
		started.Do(func() {
			partialWritten := make(chan struct{})

			go func() {
				defer close(writerDone)

				assert := require.New(t)

				assert.NoError(store.WithRepoLock("repo", func() error {
					assert.NoError(os.WriteFile(manifestPath, manifestBytes[:len(manifestBytes)/2], 0o600))
					close(partialWritten)
					time.Sleep(200 * time.Millisecond)

					return os.WriteFile(manifestPath, manifestBytes, 0o600)
				}))
			}()

			<-partialWritten
		})
	}

	collector := NewGarbageCollect(wrapped, nil, Options{Delay: time.Hour}, nil, zlog.NewTestLogger(),
		monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	<-writerDone

	body, _, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)
	require.Equal(t, manifestBytes, body)

	_, err = store.GetBlobContent("repo", img.Manifest.Config.Digest)
	require.NoError(t, err)
}

// Day-based keep rules evaluate against the current clock, so a tag can age out of pulledWithin
// between scan and commit with unchanged metadata. That shrinks the keep set; the plan, which
// kept the tag, is the conservative outcome and must commit without a rescan.
func TestGCAcceptsKeepSetShrinkageFromClockDrift(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "repo", "v1", controller))

	_, digest, _, err := store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	pulledWithin := time.Hour
	lastPull := time.Now().Add(-pulledWithin + 300*time.Millisecond)

	metaDB := mocks.MetaDBMock{
		GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
			return mTypes.RepoMeta{
				Name: "repo",
				Tags: map[mTypes.Tag]mTypes.Descriptor{"v1": {Digest: digest.String(), MediaType: ispec.MediaTypeImageManifest}},
				Statistics: map[mTypes.ImageDigest]mTypes.DescriptorStatistics{digest.String(): {
					PushTimestamp:     time.Now().Add(-3 * time.Hour),
					LastPullTimestamp: lastPull,
				}},
			}, nil
		},
		RemoveRepoReferenceFn: func(string, string, godigest.Digest) error {
			t.Fatal("tag removed although the scan decided to keep it")

			return nil
		},
	}

	wrapped := &scanHookStore{ImageStore: store}
	wrapped.onLock = func(int32) { time.Sleep(600 * time.Millisecond) }

	opts := Options{ImageRetention: config.ImageRetention{
		Policies: []config.RetentionPolicy{{
			Repositories: []string{"**"},
			KeepTags:     []config.KeepTagsPolicy{{Patterns: []string{"v.*"}, PulledWithin: &pulledWithin}},
		}},
	}}

	collector := NewGarbageCollect(wrapped, metaDB, opts, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	_, _, _, err = store.GetImageManifest("repo", "v1")
	require.NoError(t, err)

	require.EqualValues(t, 1, wrapped.calls.Load())
	require.EqualValues(t, 1, wrapped.locks.Load())
}

func TestGCDryRunTakesNoLock(t *testing.T) {
	store := newScanTestStore(t)
	controller := storage.StoreController{DefaultStore: store}

	require.NoError(t, image.WriteImageToFileSystem(image.CreateRandomImage(), "repo", "v1", controller))
	orphan, _ := uploadRandomBlob(t, store, "repo")

	opts := Options{Delay: 0}
	opts.ImageRetention.DryRun = true

	wrapped := &scanHookStore{ImageStore: store}

	collector := NewGarbageCollect(wrapped, nil, opts, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))

	_, err := store.GetBlobContent("repo", orphan)
	require.NoError(t, err)

	require.Zero(t, wrapped.locks.Load())
}
