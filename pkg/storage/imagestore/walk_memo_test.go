package imagestore_test

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	testImage "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

const testRepo = "ci-repo"

// countingDriver counts and optionally delays storage reads. On remote storage
// every read is a network round-trip, so the count and the serialisation of
// those reads, not local wall-clock, are what predict latency.
type countingDriver struct {
	storageTypes.Driver

	reads     atomic.Int64
	readDelay time.Duration
}

func (d *countingDriver) ReadFile(path string) ([]byte, error) {
	d.reads.Add(1)

	if d.readDelay > 0 {
		time.Sleep(d.readDelay)
	}

	return d.Driver.ReadFile(path)
}

func newCountingStore(t *testing.T, readDelay time.Duration) (storageTypes.ImageStore, *countingDriver,
	storage.StoreController,
) {
	t.Helper()

	counter := &countingDriver{Driver: local.New(true), readDelay: readDelay}
	store := imagestore.NewImageStore(t.TempDir(), "", false, false,
		zlog.NewTestLogger(), monitoring.NewNopMetricServer(), nil, counter, nil, nil, nil)

	return store, counter, storage.StoreController{DefaultStore: store}
}

func sortedTags(t *testing.T, store storageTypes.ImageStore) []string {
	t.Helper()

	tags, err := store.GetImageTags(testRepo)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}

	sort.Strings(tags)

	return tags
}

func sameTags(before, after []string) bool {
	if len(before) != len(after) {
		return false
	}

	for i := range before {
		if before[i] != after[i] {
			return false
		}
	}

	return true
}

// seedMultiarchBuilds writes count multi-arch builds and returns how many
// distinct manifests and indexes that put in the repository.
func seedMultiarchBuilds(t *testing.T, ctrl storage.StoreController, count int) int {
	t.Helper()

	distinct := 0

	for i := range count {
		mi := testImage.CreateRandomMultiarch()
		if err := testImage.WriteMultiArchImageToFileSystem(mi, testRepo, fmt.Sprintf("build-%d", i), ctrl); err != nil {
			t.Fatalf("seeding build %d: %v", i, err)
		}

		distinct += 1 + len(mi.Images)
	}

	return distinct
}

// Overwriting a multi-arch tag reads every other image index in the repository
// to decide what the old index's constituents are still referenced by. Those
// reads are independent, so they must not run one round-trip at a time: on a
// repository with thousands of tagged builds a serial walk is minutes per push.
func TestOverwritingMultiarchTagReadsOtherIndexesConcurrently(t *testing.T) {
	const (
		existingIndexes = 64
		readDelay       = 20 * time.Millisecond
	)

	store, counter, ctrl := newCountingStore(t, 0)

	_ = seedMultiarchBuilds(t, ctrl, existingIndexes)

	latest := testImage.CreateRandomMultiarch()
	if err := testImage.WriteMultiArchImageToFileSystem(latest, testRepo, "latest", ctrl); err != nil {
		t.Fatalf("seeding latest: %v", err)
	}

	tagsBefore := sortedTags(t, store)

	next := testImage.CreateRandomMultiarch()
	for _, img := range next.Images {
		if err := testImage.WriteImageToFileSystem(img, testRepo, img.DigestStr(), ctrl); err != nil {
			t.Fatalf("writing constituent: %v", err)
		}
	}

	// From here every read costs readDelay, as it would against remote storage.
	counter.readDelay = readDelay
	counter.reads.Store(0)

	start := time.Now()

	if _, _, err := store.PutImageManifest(context.Background(), testRepo, "latest",
		next.IndexDescriptor.MediaType, next.IndexDescriptor.Data, nil); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	elapsed := time.Since(start)
	reads := counter.reads.Load()
	serial := time.Duration(reads) * readDelay

	t.Logf("indexes=%d reads=%d elapsed=%v (serial would be %v)", existingIndexes, reads, elapsed, serial)

	if reads < existingIndexes {
		t.Fatalf("expected at least one read per other index, got %d", reads)
	}

	if elapsed > serial/3 {
		t.Fatalf("overwrite took %v for %d reads; they are still serialised (serial=%v)", elapsed, reads, serial)
	}

	if !sameTags(tagsBefore, sortedTags(t, store)) {
		t.Fatal("tag set changed across an overwrite of an unrelated tag")
	}
}

// A GC pass reads every manifest and index in the repository in more than one
// place: to find what is referenced, to compute the live blob set, and per
// retention checks. Within a pass each blob must be read once, not once per
// walk, and the pass must still collect exactly what it did before.
func TestGCPassReadsEachManifestOnce(t *testing.T) {
	const builds = 40

	store, counter, ctrl := newCountingStore(t, 0)
	log := zlog.NewTestLogger()
	metrics := monitoring.NewNopMetricServer()

	distinct := int64(seedMultiarchBuilds(t, ctrl, builds)) + 1 // + the orphan

	orphan := testImage.CreateRandomImage()
	if err := testImage.WriteImageToFileSystem(orphan, testRepo, orphan.DigestStr(), ctrl); err != nil {
		t.Fatalf("seeding orphan: %v", err)
	}

	collector := gc.NewGarbageCollect(store, mocks.MetaDBMock{}, gc.Options{
		Delay:          0,
		ImageRetention: config.ImageRetention{Delay: 0},
	}, nil, log, metrics)

	tagsBefore := sortedTags(t, store)

	counter.reads.Store(0)

	if err := collector.CleanRepo(context.Background(), testRepo); err != nil {
		t.Fatalf("gc: %v", err)
	}

	reads := counter.reads.Load()

	// Allow index.json and a small constant on top of one read per blob.
	t.Logf("builds=%d distinct manifests+indexes=%d gc reads=%d", builds, distinct, reads)

	if reads > distinct+8 {
		t.Fatalf("gc read %d blobs for %d distinct manifests and indexes; the pass is re-reading", reads, distinct)
	}

	if !sameTags(tagsBefore, sortedTags(t, store)) {
		t.Fatal("gc changed the tag set")
	}
}
