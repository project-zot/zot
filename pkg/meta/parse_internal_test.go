package meta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	testimage "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errParseInternal = errors.New("parse internal test error")

// ParseChunkSize lets the external benchmark chunk its writes the way parseRepo does.
const ParseChunkSize = parseChunkSize

func indexBlobFor(digest godigest.Digest, tag string) []byte {
	blob, err := json.Marshal(ispec.Index{
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{{
			MediaType:   ispec.MediaTypeImageManifest,
			Digest:      digest,
			Annotations: map[string]string{ispec.AnnotationRefName: tag},
		}},
	})
	if err != nil {
		panic("image index should always be marshable")
	}

	return blob
}

func TestParseStatsComplete(t *testing.T) {
	Convey("parseStats.complete is true only with no failed or partial repos", t, func() {
		So(parseStats{}.complete(), ShouldBeTrue)
		So(parseStats{failedRepos: 1}.complete(), ShouldBeFalse)
		So(parseStats{partialRepos: 1}.complete(), ShouldBeFalse)
		So(parseStats{failedRepos: 2, partialRepos: 3}.complete(), ShouldBeFalse)
	})
}

func TestFastRestartStamp(t *testing.T) {
	Convey("FastRestartStamp joins the binary version and storage fingerprint", t, func() {
		So(FastRestartStamp("v2.3.4+abc123", "deadbeef"), ShouldEqual, "v2.3.4+abc123|deadbeef")
	})

	Convey("FastRestartStamp returns empty when the binary version is empty", t, func() {
		So(FastRestartStamp("", "deadbeef"), ShouldEqual, "")
	})

	Convey("FastRestartStamp returns empty when the storage fingerprint is empty", t, func() {
		So(FastRestartStamp("v2.3.4+abc123", ""), ShouldEqual, "")
	})
}

func TestIsSignatureCosignTag(t *testing.T) {
	Convey("isSignature handles cosign-style tags safely", t, func() {
		manifest := ispec.Manifest{}

		Convey("a short tag matching the cosign regex does not panic and is not a signature", func() {
			ok, sigType, digest := isSignature("sha256-abc.sig", manifest)
			So(ok, ShouldBeFalse)
			So(sigType, ShouldBeEmpty)
			So(digest, ShouldBeEmpty)
		})

		Convey("a tag with a non-hex digest of the right length is not a signature", func() {
			nonHex := ""
			for range 64 {
				nonHex += "z"
			}
			ok, _, _ := isSignature("sha256-"+nonHex+".sig", manifest)
			So(ok, ShouldBeFalse)
		})

		Convey("a well-formed cosign tag is recognized as a signature", func() {
			signed := godigest.FromString("signed-image")
			tag := "sha256-" + signed.Encoded() + ".sig"
			ok, sigType, digest := isSignature(tag, manifest)
			So(ok, ShouldBeTrue)
			So(sigType, ShouldEqual, CosignType)
			So(digest, ShouldEqual, signed)
		})
	})
}

func TestParseStorageStats(t *testing.T) {
	logger := log.NewTestLogger()

	// A valid image whose manifest + config blobs parse cleanly through ParseRepo.
	validImage := testimage.CreateRandomImage()

	manifestBlob, err := json.Marshal(validImage.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	configBlob, err := json.Marshal(validImage.Config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	goodDigest := godigest.FromString("good-manifest")
	missingDigest := godigest.FromString("missing-manifest")

	// blobFor maps the descriptor digests our mocked index references back to the
	// valid image blobs, anything else is reported as a missing blob.
	blobFor := func(_ string, digest godigest.Digest) ([]byte, error) {
		switch digest {
		case goodDigest:
			return manifestBlob, nil
		case validImage.ConfigDescriptor.Digest:
			return configBlob, nil
		default:
			return nil, zerr.ErrBlobNotFound
		}
	}

	metaDB := mocks.MetaDBMock{
		SetRepoReferenceFn: func(context.Context, string, string, mTypes.ImageMeta) error { return nil },
	}

	Convey("a fully-parsed repo yields a complete parseStats", t, func() {
		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) { return []string{"goodrepo"}, nil },
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobFor(goodDigest, "gtag"), nil },
			GetBlobContentFn:  blobFor,
		}}

		stats, err := parseStorage(metaDB, store, logger)
		So(err, ShouldBeNil)
		So(stats.failedRepos, ShouldEqual, 0)
		So(stats.partialRepos, ShouldEqual, 0)
		So(stats.complete(), ShouldBeTrue)
	})

	Convey("failed and partial repos are counted independently", t, func() {
		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{"failrepo", "partialrepo", "goodrepo"}, nil
			},
			StatIndexFn: func(repo string) (bool, int64, time.Time, error) {
				if repo == "failrepo" {
					return false, 0, time.Time{}, errParseInternal
				}

				return true, 0, time.Time{}, nil
			},
			GetIndexContentFn: func(repo string) ([]byte, error) {
				if repo == "partialrepo" {
					return indexBlobFor(missingDigest, "ptag"), nil
				}

				return indexBlobFor(goodDigest, "gtag"), nil
			},
			GetBlobContentFn: blobFor,
		}}

		stats, err := parseStorage(metaDB, store, logger)
		So(err, ShouldBeNil)
		So(stats.failedRepos, ShouldEqual, 1)
		So(stats.partialRepos, ShouldEqual, 1)
		So(stats.complete(), ShouldBeFalse)
	})
}

func TestParseStorageParallel(t *testing.T) {
	logger := log.NewTestLogger()

	validImage := testimage.CreateRandomImage()

	manifestBlob, err := json.Marshal(validImage.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	configBlob, err := json.Marshal(validImage.Config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	manifestDigest := godigest.FromString("manifest")

	blobFor := func(_ string, digest godigest.Digest) ([]byte, error) {
		switch digest {
		case manifestDigest:
			return manifestBlob, nil
		case validImage.ConfigDescriptor.Digest:
			return configBlob, nil
		default:
			return nil, zerr.ErrBlobNotFound
		}
	}

	reposNamed := func(count int) []string {
		repos := make([]string, 0, count)
		for i := range count {
			repos = append(repos, fmt.Sprintf("repo%d", i))
		}

		return repos
	}

	// recordingMetaDB stores the name of every repo it gets an image for in parsedRepos.
	recordingMetaDB := func(parsedRepos *sync.Map) mocks.MetaDBMock {
		return mocks.MetaDBMock{
			SetRepoReferenceFn: func(_ context.Context, repo string, _ string, _ mTypes.ImageMeta) error {
				parsedRepos.Store(repo, struct{}{})

				return nil
			},
		}
	}

	Convey("repos are parsed concurrently", t, func() {
		repos := reposNamed(parseStorageWorkers)

		var parsedRepos sync.Map

		metaDB := recordingMetaDB(&parsedRepos)

		// Every StatIndex call waits until all repos have reached StatIndex, which only
		// happens when they are parsed concurrently. A serial walk times out on each repo.
		var arrived sync.WaitGroup

		arrived.Add(len(repos))

		allArrived := make(chan struct{})

		go func() {
			arrived.Wait()
			close(allArrived)
		}()

		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) { return repos, nil },
			StatIndexFn: func(string) (bool, int64, time.Time, error) {
				arrived.Done()

				select {
				case <-allArrived:
					return true, 0, time.Time{}, nil
				case <-time.After(5 * time.Second):
					return false, 0, time.Time{}, errParseInternal
				}
			},
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobFor(manifestDigest, "tag"), nil },
			GetBlobContentFn:  blobFor,
		}}

		stats, err := parseStorage(metaDB, store, logger)
		So(err, ShouldBeNil)
		So(stats.complete(), ShouldBeTrue)

		for _, repo := range repos {
			_, ok := parsedRepos.Load(repo)
			So(ok, ShouldBeTrue)
		}
	})

	Convey("no more than parseStorageWorkers repos are parsed at once", t, func() {
		repos := reposNamed(3 * parseStorageWorkers)

		var parsedRepos sync.Map

		metaDB := recordingMetaDB(&parsedRepos)

		var inFlight, maxInFlight atomic.Int32

		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) { return repos, nil },
			StatIndexFn: func(string) (bool, int64, time.Time, error) {
				current := inFlight.Add(1)
				defer inFlight.Add(-1)

				for {
					seen := maxInFlight.Load()
					if current <= seen || maxInFlight.CompareAndSwap(seen, current) {
						break
					}
				}

				time.Sleep(10 * time.Millisecond)

				return true, 0, time.Time{}, nil
			},
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobFor(manifestDigest, "tag"), nil },
			GetBlobContentFn:  blobFor,
		}}

		stats, err := parseStorage(metaDB, store, logger)
		So(err, ShouldBeNil)
		So(stats.complete(), ShouldBeTrue)
		So(maxInFlight.Load(), ShouldBeGreaterThan, 1)
		So(maxInFlight.Load(), ShouldBeLessThanOrEqualTo, parseStorageWorkers)

		for _, repo := range repos {
			_, ok := parsedRepos.Load(repo)
			So(ok, ShouldBeTrue)
		}
	})
}

const (
	fixtureArchitecture = "riscv64"
	fixtureOS           = "plan9"

	probeThreshold = 33
	probeSettle    = 200 * time.Millisecond
)

// concurrentStore is a mock image store that declares its reads safe to issue concurrently.
type concurrentStore struct {
	mocks.MockedImageStore
}

func (concurrentStore) ConcurrentReadSafe() bool { return true }

// readProbe holds each caller until threshold callers arrived or the settle delay passed,
// and records how many callers were inside at once.
type readProbe struct {
	threshold int32
	settle    time.Duration

	arrived     atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	release     chan struct{}
	releaseOnce sync.Once
}

func newReadProbe(threshold int32, settle time.Duration) *readProbe {
	return &readProbe{threshold: threshold, settle: settle, release: make(chan struct{})}
}

func (p *readProbe) hold() {
	current := p.inFlight.Add(1)
	defer p.inFlight.Add(-1)

	for {
		seen := p.maxInFlight.Load()
		if current <= seen || p.maxInFlight.CompareAndSwap(seen, current) {
			break
		}
	}

	if p.arrived.Add(1) >= p.threshold {
		p.releaseOnce.Do(func() { close(p.release) })
	}

	select {
	case <-p.release:
	case <-time.After(p.settle):
	}
}

// parseFixture serves one valid image manifest and its config for every manifest digest it hands out.
type parseFixture struct {
	manifestBlob []byte
	configBlob   []byte
	configDigest godigest.Digest
}

func newParseFixture(t *testing.T) parseFixture {
	t.Helper()

	image := testimage.CreateRandomImage()

	manifestBlob, err := json.Marshal(image.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	config := image.Config
	config.Architecture, config.OS = fixtureArchitecture, fixtureOS

	configBlob, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	return parseFixture{manifestBlob: manifestBlob, configBlob: configBlob, configDigest: image.ConfigDescriptor.Digest}
}

func (f parseFixture) manifestDigest(prefix string, i int) godigest.Digest {
	return godigest.FromString(fmt.Sprintf("%s-%d", prefix, i))
}

func (f parseFixture) blob(digest godigest.Digest) ([]byte, error) {
	if digest == f.configDigest {
		return f.configBlob, nil
	}

	return f.manifestBlob, nil
}

type indexEntry struct {
	digest godigest.Digest
	tag    string
}

func indexBlobOf(entries []indexEntry) []byte {
	return indexBlobOfSized(entries, nil)
}

// indexBlobOfSized is indexBlobOf with the descriptor sizes of the entries, zero where sizes is short.
func indexBlobOfSized(entries []indexEntry, sizes []int64) []byte {
	manifests := make([]ispec.Descriptor, 0, len(entries))

	for i, entry := range entries {
		descriptor := ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: entry.digest}
		if i < len(sizes) {
			descriptor.Size = sizes[i]
		}

		if entry.tag != "" {
			descriptor.Annotations = map[string]string{ispec.AnnotationRefName: entry.tag}
		}

		manifests = append(manifests, descriptor)
	}

	blob, err := json.Marshal(ispec.Index{MediaType: ispec.MediaTypeImageIndex, Manifests: manifests})
	if err != nil {
		panic("image index should always be marshable")
	}

	return blob
}

func numberedEntries(f parseFixture, prefix string, count int) []indexEntry {
	entries := make([]indexEntry, 0, count)

	for i := range count {
		entries = append(entries, indexEntry{digest: f.manifestDigest(prefix, i), tag: fmt.Sprintf("%s-tag-%d", prefix, i)})
	}

	return entries
}

// batchRecorder collects every SetRepoReferences batch in call order.
type batchRecorder struct {
	mu            sync.Mutex
	batches       [][]string
	references    []mTypes.RepoReference
	singleCalls   atomic.Int32
	singleRecords []string
}

func (r *batchRecorder) metaDB() mocks.MetaDBMock {
	return mocks.MetaDBMock{
		SetRepoReferencesFn: func(_ context.Context, _ string, refs []mTypes.RepoReference) error {
			names := make([]string, 0, len(refs))
			for _, ref := range refs {
				names = append(names, ref.Reference)
			}

			r.mu.Lock()
			defer r.mu.Unlock()

			r.batches = append(r.batches, names)
			r.references = append(r.references, refs...)

			return nil
		},
		SetRepoReferenceFn: func(_ context.Context, _ string, reference string, _ mTypes.ImageMeta) error {
			r.singleCalls.Add(1)

			r.mu.Lock()
			defer r.mu.Unlock()

			r.singleRecords = append(r.singleRecords, reference)

			return nil
		},
	}
}

func (r *batchRecorder) flat() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	flat := []string{}
	for _, batch := range r.batches {
		flat = append(flat, batch...)
	}

	return append(flat, r.singleRecords...)
}

// storeModes runs body once with a plain mock store and once with a concurrency-safe one.
func storeModes(body func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController)) {
	body("plain", func(store mocks.MockedImageStore) storage.StoreController {
		return storage.StoreController{DefaultStore: store}
	})
	body("concurrent", func(store mocks.MockedImageStore) storage.StoreController {
		return storage.StoreController{DefaultStore: concurrentStore{store}}
	})
}

func TestParseRepoMissingManifestIsPartial(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		Convey("a missing manifest blob is skipped and marks the parse partial, "+mode+" store", t, func() {
			missing := fixture.manifestDigest("missing", 0)
			valid := fixture.manifestDigest("valid", 0)

			recorder := &batchRecorder{}
			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) {
					return indexBlobOf([]indexEntry{{missing, "missing-tag"}, {valid, "valid-tag"}}), nil
				},
				GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
					if digest == missing {
						return nil, zerr.ErrBlobNotFound
					}

					return fixture.blob(digest)
				},
			})

			partial, err := parseRepo("repo", recorder.metaDB(), controller, logger)
			So(err, ShouldBeNil)
			So(partial, ShouldBeTrue)
			So(recorder.flat(), ShouldResemble, []string{"valid-tag"})
		})
	})
}

func TestParseRepoFlushesPrefixOnReadError(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	badImage := testimage.CreateRandomImage()

	badManifestBlob, err := json.Marshal(badImage.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	signed := fixture.manifestDigest("signed", 0)
	signatureDigest := fixture.manifestDigest("signature", 0)
	signatureTag := "sha256-" + signed.Encoded() + ".sig"

	failing := fixture.manifestDigest("failing", 0)

	entries := []indexEntry{
		{fixture.manifestDigest("first", 0), "first"},
		{signatureDigest, signatureTag},
		{failing, "failing"},
		{fixture.manifestDigest("after", 0), "after-1"},
		{fixture.manifestDigest("after", 1), "after-2"},
	}

	cases := []struct {
		name string
		blob func(digest godigest.Digest) ([]byte, error)
		want error
	}{
		{
			name: "manifest read fails",
			blob: func(digest godigest.Digest) ([]byte, error) {
				if digest == failing {
					return nil, errParseInternal
				}

				return fixture.blob(digest)
			},
			want: errParseInternal,
		},
		{
			name: "config blob is missing",
			blob: func(digest godigest.Digest) ([]byte, error) {
				switch digest {
				case failing:
					return badManifestBlob, nil
				case badImage.ConfigDescriptor.Digest:
					return nil, zerr.ErrBlobNotFound
				}

				return fixture.blob(digest)
			},
			want: zerr.ErrBlobNotFound,
		},
	}

	for _, testCase := range cases {
		storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
			Convey("the references before a read error are flushed and the signatures applied, "+
				testCase.name+", "+mode+" store", t, func() {
				recorder := &batchRecorder{}
				metaDB := recorder.metaDB()

				var (
					mu         sync.Mutex
					signatures []godigest.Digest
				)

				metaDB.AddManifestSignatureFn = func(_ string, signedDigest godigest.Digest, _ mTypes.SignatureMetadata) error {
					mu.Lock()
					defer mu.Unlock()

					signatures = append(signatures, signedDigest)

					return nil
				}

				controller := wrap(mocks.MockedImageStore{
					GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
					GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
						if digest == failing {
							time.Sleep(100 * time.Millisecond)
						}

						return testCase.blob(digest)
					},
				})

				partial, err := parseRepo("repo", metaDB, controller, logger)
				So(errors.Is(err, testCase.want), ShouldBeTrue)
				So(partial, ShouldBeFalse)
				So(recorder.batches, ShouldResemble, [][]string{{"first"}})
				So(recorder.singleCalls.Load(), ShouldEqual, 0)
				So(signatures, ShouldResemble, []godigest.Digest{signed})
			})
		})
	}
}

func TestParseRepoKeepsIndexOrder(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	Convey("the references reach the metaDB in index.json order whatever order the reads finish in", t, func() {
		const count = 6

		entries := numberedEntries(fixture, "order", count)
		delays := map[godigest.Digest]time.Duration{}

		for i, entry := range entries {
			delays[entry.digest] = time.Duration(count-i) * 20 * time.Millisecond
		}

		recorder := &batchRecorder{}
		controller := storage.StoreController{DefaultStore: concurrentStore{mocks.MockedImageStore{
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
			GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
				time.Sleep(delays[digest])

				return fixture.blob(digest)
			},
		}}}

		_, err := parseRepo("repo", recorder.metaDB(), controller, logger)
		So(err, ShouldBeNil)

		want := make([]string, 0, count)
		for _, entry := range entries {
			want = append(want, entry.tag)
		}

		So(recorder.flat(), ShouldResemble, want)
	})
}

func TestParseRepoBoundedConcurrentReads(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	manifestHold := func(probe *readProbe, entries []indexEntry) func(string, godigest.Digest) ([]byte, error) {
		manifests := map[godigest.Digest]struct{}{}
		for _, entry := range entries {
			manifests[entry.digest] = struct{}{}
		}

		return func(_ string, digest godigest.Digest) ([]byte, error) {
			if _, ok := manifests[digest]; ok {
				probe.hold()
			}

			return fixture.blob(digest)
		}
	}

	Convey("the manifest reads of a ConcurrentReadSafe store overlap, at most 32 at a time", t, func() {
		entries := numberedEntries(fixture, "bound", 100)
		probe := newReadProbe(probeThreshold, probeSettle)
		recorder := &batchRecorder{}
		controller := storage.StoreController{DefaultStore: concurrentStore{mocks.MockedImageStore{
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
			GetBlobContentFn:  manifestHold(probe, entries),
		}}}

		_, err := parseRepo("repo", recorder.metaDB(), controller, logger)
		So(err, ShouldBeNil)
		So(probe.maxInFlight.Load(), ShouldBeGreaterThan, 1)
		So(probe.maxInFlight.Load(), ShouldBeLessThanOrEqualTo, 32)
		So(len(recorder.flat()), ShouldEqual, 100)
	})

	Convey("a store that is not ConcurrentReadSafe is read one blob at a time", t, func() {
		entries := numberedEntries(fixture, "plain", 4)
		probe := newReadProbe(probeThreshold, 20*time.Millisecond)
		recorder := &batchRecorder{}
		controller := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
			GetBlobContentFn:  manifestHold(probe, entries),
		}}

		_, err := parseRepo("repo", recorder.metaDB(), controller, logger)
		So(err, ShouldBeNil)
		So(probe.maxInFlight.Load(), ShouldEqual, 1)
	})
}

func TestParseRepoReadBoundSharedAcrossRepos(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	Convey("the read bound holds across repos parsed at the same time", t, func() {
		entriesA := numberedEntries(fixture, "repoA", 100)
		entriesB := numberedEntries(fixture, "repoB", 100)
		manifests := map[godigest.Digest]struct{}{}

		for _, entry := range append(append([]indexEntry{}, entriesA...), entriesB...) {
			manifests[entry.digest] = struct{}{}
		}

		probe := newReadProbe(probeThreshold, probeSettle)
		controller := storage.StoreController{DefaultStore: concurrentStore{mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				if repo == "repoA" {
					return indexBlobOf(entriesA), nil
				}

				return indexBlobOf(entriesB), nil
			},
			GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
				if _, ok := manifests[digest]; ok {
					probe.hold()
				}

				return fixture.blob(digest)
			},
		}}}

		var wg sync.WaitGroup

		errs := make([]error, 2)

		for i, repo := range []string{"repoA", "repoB"} {
			wg.Go(func() {
				recorder := &batchRecorder{}
				_, errs[i] = parseRepo(repo, recorder.metaDB(), controller, logger)
			})
		}

		wg.Wait()

		So(errs[0], ShouldBeNil)
		So(errs[1], ShouldBeNil)
		So(probe.maxInFlight.Load(), ShouldBeGreaterThan, 1)
		So(probe.maxInFlight.Load(), ShouldBeLessThanOrEqualTo, 32)
	})
}

func TestParseRepoWritesInChunks(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	Convey("1201 entries are written with three SetRepoReferences calls", t, func() {
		entries := numberedEntries(fixture, "chunk", 1201)
		recorder := &batchRecorder{}
		controller := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
			GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
				return fixture.blob(digest)
			},
		}}

		_, err := parseRepo("repo", recorder.metaDB(), controller, logger)
		So(err, ShouldBeNil)

		sizes := []int{}
		for _, batch := range recorder.batches {
			sizes = append(sizes, len(batch))
		}

		So(sizes, ShouldResemble, []int{500, 500, 201})
		So(recorder.singleCalls.Load(), ShouldEqual, 0)
	})
}

func TestParseRepoReadsDigestOnce(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		Convey("two tags on one digest read and stat the manifest once, "+mode+" store", t, func() {
			shared := fixture.manifestDigest("shared", 0)

			var manifestReads, manifestStats atomic.Int32

			recorder := &batchRecorder{}
			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) {
					return indexBlobOf([]indexEntry{{shared, "tag-a"}, {shared, "tag-b"}}), nil
				},
				GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
					if digest == shared {
						manifestReads.Add(1)
					}

					return fixture.blob(digest)
				},
				StatBlobFn: func(_ string, digest godigest.Digest) (bool, int64, time.Time, error) {
					if digest == shared {
						manifestStats.Add(1)
					}

					return true, 0, time.Time{}, nil
				},
			})

			_, err := parseRepo("repo", recorder.metaDB(), controller, logger)
			So(err, ShouldBeNil)
			So(manifestReads.Load(), ShouldEqual, 1)
			So(manifestStats.Load(), ShouldEqual, 1)
			So(recorder.flat(), ShouldResemble, []string{"tag-a", "tag-b"})
		})
	})
}

func TestParseRepoAppliesSignaturesAfterReferencesInOrder(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	Convey("signatures are applied only after the last reference batch", t, func() {
		signed := fixture.manifestDigest("signed", 0)
		entries := append([]indexEntry{
			{fixture.manifestDigest("signature", 0), "sha256-" + signed.Encoded() + ".sig"},
		}, numberedEntries(fixture, "sigorder", 600)...)

		var (
			mu     sync.Mutex
			events []string
		)

		record := func(event string) {
			mu.Lock()
			defer mu.Unlock()

			events = append(events, event)
		}

		metaDB := mocks.MetaDBMock{
			SetRepoReferenceFn: func(context.Context, string, string, mTypes.ImageMeta) error {
				record("refs")

				return nil
			},
			SetRepoReferencesFn: func(context.Context, string, []mTypes.RepoReference) error {
				record("refs")

				return nil
			},
			AddManifestSignatureFn: func(string, godigest.Digest, mTypes.SignatureMetadata) error {
				record("signature")

				return nil
			},
			UpdateSignaturesValidityFn: func(context.Context, string, godigest.Digest) error {
				record("validity")

				return nil
			},
		}

		controller := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
			GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
				return fixture.blob(digest)
			},
		}}

		_, err := parseRepo("repo", metaDB, controller, logger)
		So(err, ShouldBeNil)

		lastRefs, firstSignature := -1, len(events)

		for i, event := range events {
			if event == "refs" {
				lastRefs = i
			}

			if event != "refs" && i < firstSignature {
				firstSignature = i
			}
		}

		So(lastRefs, ShouldBeGreaterThanOrEqualTo, 0)
		So(firstSignature, ShouldBeGreaterThan, lastRefs)
		So(events[len(events)-2:], ShouldResemble, []string{"signature", "validity"})
	})
}

func TestParseRepoReadsSharedConfigOnce(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		Convey("manifests sharing a config read it once and keep its fields, "+mode+" store", t, func() {
			entries := numberedEntries(fixture, "shared-config", 500)

			var configReads atomic.Int32

			recorder := &batchRecorder{}
			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
				GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
					if digest == fixture.configDigest {
						configReads.Add(1)
					}

					return fixture.blob(digest)
				},
			})

			_, err := parseRepo("repo", recorder.metaDB(), controller, logger)
			So(err, ShouldBeNil)
			So(configReads.Load(), ShouldEqual, 1)
			So(recorder.references, ShouldHaveLength, 500)

			for _, reference := range recorder.references {
				So(reference.ImageMeta.Manifests[0].Config.Architecture, ShouldEqual, fixtureArchitecture)
				So(reference.ImageMeta.Manifests[0].Config.OS, ShouldEqual, fixtureOS)
			}
		})
	})
}

func TestParseRepoRereadsSignatureBlobWhenApplying(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	Convey("a signature manifest blob is read again when the signature is applied", t, func() {
		signed := fixture.manifestDigest("signed", 0)
		signatureDigest := fixture.manifestDigest("signature", 0)
		entries := []indexEntry{
			{fixture.manifestDigest("before", 0), "before"},
			{signatureDigest, "sha256-" + signed.Encoded() + ".sig"},
			{fixture.manifestDigest("after", 0), "after"},
		}

		var (
			mu     sync.Mutex
			events []string
		)

		record := func(event string) {
			mu.Lock()
			defer mu.Unlock()

			events = append(events, event)
		}

		metaDB := mocks.MetaDBMock{
			SetRepoReferencesFn: func(context.Context, string, []mTypes.RepoReference) error {
				record("refs")

				return nil
			},
			AddManifestSignatureFn: func(string, godigest.Digest, mTypes.SignatureMetadata) error {
				record("signature")

				return nil
			},
		}

		controller := storage.StoreController{DefaultStore: concurrentStore{mocks.MockedImageStore{
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
			GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
				if digest == signatureDigest {
					record("read signature")
				}

				return fixture.blob(digest)
			},
		}}}

		_, err := parseRepo("repo", metaDB, controller, logger)
		So(err, ShouldBeNil)
		So(events, ShouldResemble, []string{"read signature", "refs", "read signature", "signature"})
	})
}

func TestParseRepoSignatureReadsTakeReadSlot(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	var signatureManifest ispec.Manifest
	if err := json.Unmarshal(fixture.manifestBlob, &signatureManifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	layerDigests := map[godigest.Digest]struct{}{}
	for _, layer := range signatureManifest.Layers {
		layerDigests[layer.Digest] = struct{}{}
	}

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		Convey("the signature reads wait for a shared read slot and hold one each, "+mode+" store", t, func() {
			signed := fixture.manifestDigest("signed", 0)
			signatureDigest := fixture.manifestDigest("signature", 0)
			entries := []indexEntry{
				{fixture.manifestDigest("image", 0), "image"},
				{signatureDigest, "sha256-" + signed.Encoded() + ".sig"},
			}

			var (
				signatureReads  atomic.Int32
				slotsHeldByTest atomic.Int32
				allHeld         = make(chan struct{})
				reReadStarted   = make(chan struct{})
				done            = make(chan error, 1)
				mu              sync.Mutex
				slotsAtRead     []int
				holdOnce        sync.Once
			)

			// the slots a read sees taken: the test holds 31, so a read holding its own slot sees 32
			recordSlots := func() {
				mu.Lock()
				defer mu.Unlock()

				slotsAtRead = append(slotsAtRead, len(parseReadSlots))
			}

			metaDB := mocks.MetaDBMock{
				SetRepoReferencesFn: func(context.Context, string, []mTypes.RepoReference) error {
					holdOnce.Do(func() {
						for range parseReadParallelism {
							parseReadSlots <- struct{}{}
							slotsHeldByTest.Add(1)
						}

						close(allHeld)
					})

					return nil
				},
			}

			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
				GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
					if digest == signatureDigest && signatureReads.Add(1) == 2 {
						recordSlots()
						close(reReadStarted)
					}

					return fixture.blob(digest)
				},
				StatBlobFn: func(_ string, digest godigest.Digest) (bool, int64, time.Time, error) {
					if _, isLayer := layerDigests[digest]; isLayer {
						recordSlots()
					}

					return true, 0, time.Time{}, nil
				},
			})

			defer func() {
				for slotsHeldByTest.Load() > 0 {
					<-parseReadSlots
					slotsHeldByTest.Add(-1)
				}

				<-done
			}()

			go func() {
				_, err := parseRepo("repo", metaDB, controller, logger)
				done <- err
			}()

			select {
			case <-allHeld:
			case <-time.After(5 * time.Second):
				t.Fatal("the references were never written")
			}

			select {
			case <-reReadStarted:
				t.Fatal("the signature blob was read while every read slot was held")
			case <-time.After(probeSettle):
			}

			<-parseReadSlots
			slotsHeldByTest.Add(-1)

			var err error

			select {
			case err = <-done:
				done <- err
			case <-time.After(5 * time.Second):
				t.Fatal("the signature phase did not finish with one free read slot")
			}

			So(err, ShouldBeNil)
			So(slotsAtRead, ShouldHaveLength, 1+len(layerDigests))

			for _, slots := range slotsAtRead {
				So(slots, ShouldEqual, parseReadParallelism)
			}
		})
	})
}

// verificationTrustStore stands for an image trust store: it reads a signature layer when asked to verify.
type verificationTrustStore struct {
	onVerify func()
}

func (v verificationTrustStore) VerifySignatureLayer(string, godigest.Digest, string, godigest.Digest,
	mTypes.ImageMeta, string,
) (mTypes.Author, mTypes.ExpiryDate, mTypes.Validity, error) {
	v.onVerify()

	return "", time.Time{}, true, nil
}

func TestParseRepoSignatureVerificationTakesReadSlot(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	var signatureManifest ispec.Manifest
	if err := json.Unmarshal(fixture.manifestBlob, &signatureManifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	layerDigest := signatureManifest.Layers[0].Digest

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		Convey("signature verification waits for a shared read slot during parse, "+mode+" store", t, func() {
			signed := fixture.manifestDigest("signed", 0)
			signatureDigest := fixture.manifestDigest("signature", 0)
			entries := []indexEntry{
				{fixture.manifestDigest("image", 0), "image"},
				{signatureDigest, "sha256-" + signed.Encoded() + ".sig"},
			}

			var (
				slotsHeldByTest atomic.Int32
				allHeld         = make(chan struct{})
				heldAgain       = make(chan struct{})
				verifyStarted   = make(chan struct{})
				done            = make(chan error, 1)
				mu              sync.Mutex
				slotsAtVerify   []int
				holdOnce        sync.Once
			)

			holdSlot := func() {
				parseReadSlots <- struct{}{}
				slotsHeldByTest.Add(1)
			}

			releaseSlot := func() {
				<-parseReadSlots
				slotsHeldByTest.Add(-1)
			}

			trustStore := verificationTrustStore{onVerify: func() {
				mu.Lock()
				defer mu.Unlock()

				slotsAtVerify = append(slotsAtVerify, len(parseReadSlots))
			}}

			var metaDB mocks.MetaDBMock

			metaDB = mocks.MetaDBMock{
				ImageTrustStoreFn: func() mTypes.ImageTrustStore { return trustStore },
				SetRepoReferencesFn: func(context.Context, string, []mTypes.RepoReference) error {
					holdOnce.Do(func() {
						for range parseReadParallelism {
							holdSlot()
						}

						close(allHeld)
					})

					return nil
				},
				AddManifestSignatureFn: func(string, godigest.Digest, mTypes.SignatureMetadata) error {
					// the layer stats are done: take back the slot the test released
					holdSlot()
					close(heldAgain)

					return nil
				},
				UpdateSignaturesValidityFn: func(_ context.Context, repo string, manifestDigest godigest.Digest) error {
					close(verifyStarted)

					_, _, _, err := metaDB.ImageTrustStore().VerifySignatureLayer(CosignType, layerDigest, "", manifestDigest,
						mTypes.ImageMeta{}, repo)

					return err
				},
			}

			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
				GetBlobContentFn:  func(_ string, digest godigest.Digest) ([]byte, error) { return fixture.blob(digest) },
			})

			defer func() {
				for slotsHeldByTest.Load() > 0 {
					releaseSlot()
				}

				<-done
			}()

			go func() {
				_, err := parseRepo("repo", metaDB, controller, logger)
				done <- err
			}()

			select {
			case <-allHeld:
			case <-time.After(5 * time.Second):
				t.Fatal("the references were never written")
			}

			releaseSlot()

			select {
			case <-heldAgain:
			case <-time.After(5 * time.Second):
				t.Fatal("the signature was never added")
			}

			select {
			case <-verifyStarted:
				t.Fatal("signature verification started while every read slot was held")
			case <-time.After(probeSettle):
			}

			releaseSlot()

			var err error

			select {
			case err = <-done:
				done <- err
			case <-time.After(5 * time.Second):
				t.Fatal("the signature phase did not finish with one free read slot")
			}

			So(err, ShouldBeNil)
			So(slotsAtVerify, ShouldResemble, []int{parseReadParallelism})
		})
	})
}

func TestSetImageMetaFromInputTakesNoReadSlot(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	Convey("a pushed signature is verified without a parse read slot", t, func() {
		signed := fixture.manifestDigest("signed", 0)
		signatureDigest := fixture.manifestDigest("signature", 0)

		var verified atomic.Bool

		metaDB := mocks.MetaDBMock{
			UpdateSignaturesValidityFn: func(context.Context, string, godigest.Digest) error {
				verified.Store(true)

				return nil
			},
		}
		store := mocks.MockedImageStore{
			GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) { return fixture.blob(digest) },
		}

		for range parseReadParallelism {
			parseReadSlots <- struct{}{}
		}

		defer func() {
			for range parseReadParallelism {
				<-parseReadSlots
			}
		}()

		done := make(chan error, 1)

		go func() {
			done <- SetImageMetaFromInput(context.Background(), "repo", "sha256-"+signed.Encoded()+".sig",
				ispec.MediaTypeImageManifest, signatureDigest, fixture.manifestBlob, store, metaDB, logger)
		}()

		select {
		case err := <-done:
			So(err, ShouldBeNil)
			So(verified.Load(), ShouldBeTrue)
		case <-time.After(5 * time.Second):
			t.Fatal("the push path waited for a parse read slot")
		}
	})
}

func TestParseRepoReturnsSignatureError(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	cases := []struct {
		name              string
		failSignatureRead bool
		setup             func(metaDB *mocks.MetaDBMock)
	}{
		{"adding the signature fails", false, func(metaDB *mocks.MetaDBMock) {
			metaDB.AddManifestSignatureFn = func(string, godigest.Digest, mTypes.SignatureMetadata) error {
				return errParseInternal
			}
		}},
		{"validating the signature fails", false, func(metaDB *mocks.MetaDBMock) {
			metaDB.UpdateSignaturesValidityFn = func(context.Context, string, godigest.Digest) error {
				return errParseInternal
			}
		}},
		{"reading the signature blob again fails", true, func(*mocks.MetaDBMock) {}},
	}

	for _, testCase := range cases {
		Convey("the error is returned and every reference is written, "+testCase.name, t, func() {
			signed := fixture.manifestDigest("signed", 0)
			signatureDigest := fixture.manifestDigest("signature", 0)
			entries := []indexEntry{
				{fixture.manifestDigest("before", 0), "before"},
				{signatureDigest, "sha256-" + signed.Encoded() + ".sig"},
				{fixture.manifestDigest("after", 0), "after"},
			}

			recorder := &batchRecorder{}
			metaDB := recorder.metaDB()
			testCase.setup(&metaDB)

			var signatureReads atomic.Int32

			controller := storage.StoreController{DefaultStore: mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
				GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
					if digest == signatureDigest && signatureReads.Add(1) == 2 && testCase.failSignatureRead {
						return nil, errParseInternal
					}

					return fixture.blob(digest)
				},
			}}

			_, err := parseRepo("repo", metaDB, controller, logger)
			So(errors.Is(err, errParseInternal), ShouldBeTrue)
			So(recorder.flat(), ShouldResemble, []string{"before", "after"})
		})
	}
}

func TestParseRepoAppliesSignatureOfEarlierChunkOnReadError(t *testing.T) {
	logger := log.NewTestLogger()
	fixture := newParseFixture(t)

	Convey("a signature of the first chunk is applied when a read in the second chunk fails", t, func() {
		signed := fixture.manifestDigest("signed", 0)
		entries := append([]indexEntry{
			{fixture.manifestDigest("signature", 0), "sha256-" + signed.Encoded() + ".sig"},
		}, numberedEntries(fixture, "chunks", 600)...)
		failing := entries[550].digest

		var signatures atomic.Int32

		recorder := &batchRecorder{}
		metaDB := recorder.metaDB()
		metaDB.AddManifestSignatureFn = func(string, godigest.Digest, mTypes.SignatureMetadata) error {
			signatures.Add(1)

			return nil
		}

		controller := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
			GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
				if digest == failing {
					return nil, errParseInternal
				}

				return fixture.blob(digest)
			},
		}}

		_, err := parseRepo("repo", metaDB, controller, logger)
		So(errors.Is(err, errParseInternal), ShouldBeTrue)
		So(signatures.Load(), ShouldEqual, 1)
		So(recorder.batches, ShouldHaveLength, 2)
		So(recorder.batches[0], ShouldHaveLength, 499)
		So(recorder.batches[1], ShouldHaveLength, 50)
	})
}

const mebibyte = 1 << 20

// budgetScenario describes entries whose declared and real sizes differ, to drive the chunk byte budget.
type budgetScenario struct {
	descriptorSizes    []int64 // index.json descriptor size per entry, 0 where short
	manifestConfigSize int64   // Config.Size every manifest declares
	configSizes        []int64 // size StatBlob reports for the config of each entry
	failManifest       int     // entry whose manifest read fails, -1 for none
	statFailure        *configStatFailure
	sharedConfig       bool // every manifest points to the config of entry 0
}

// configStatFailure makes the StatBlob of one entry's config fail with an error, or report it as not found.
type configStatFailure struct {
	entry    int
	notFound bool
}

// budgetRun is what parseRepo did with a budgetScenario, as entry numbers.
type budgetRun struct {
	err                   error
	batches               [][]int
	configReadsPerBatch   [][]int
	manifestReadsBeforeWr int
}

func runBudgetScenario(t *testing.T, fixture parseFixture, controller func(mocks.MockedImageStore) storage.StoreController,
	scenario budgetScenario,
) budgetRun {
	t.Helper()

	var manifest ispec.Manifest
	So(json.Unmarshal(fixture.manifestBlob, &manifest), ShouldBeNil)

	entries := make([]indexEntry, 0, len(scenario.configSizes))
	manifestBlobs := map[godigest.Digest][]byte{}
	manifestIndex := map[godigest.Digest]int{}
	configIndex := map[godigest.Digest]int{}

	for i := range scenario.configSizes {
		entry := indexEntry{digest: fixture.manifestDigest("budget", i), tag: fmt.Sprintf("budget-%d", i)}
		entries = append(entries, entry)

		entryManifest := manifest
		entryManifest.Config.Digest = godigest.FromString(fmt.Sprintf("budget-config-%d", i))
		if scenario.sharedConfig {
			entryManifest.Config.Digest = godigest.FromString("budget-config-0")
		}

		entryManifest.Config.Size = scenario.manifestConfigSize

		if _, shared := configIndex[entryManifest.Config.Digest]; !shared {
			configIndex[entryManifest.Config.Digest] = i
		}

		manifestIndex[entry.digest] = i

		blob, err := json.Marshal(entryManifest)
		So(err, ShouldBeNil)

		manifestBlobs[entry.digest] = blob
	}

	var (
		mu                sync.Mutex
		run               = budgetRun{}
		manifestReads     int
		configReads       []int
		firstWriteHappend bool
	)

	metaDB := mocks.MetaDBMock{
		SetRepoReferencesFn: func(_ context.Context, _ string, refs []mTypes.RepoReference) error {
			mu.Lock()
			defer mu.Unlock()

			if !firstWriteHappend {
				firstWriteHappend = true
				run.manifestReadsBeforeWr = manifestReads
			}

			batch := make([]int, 0, len(refs))

			for _, ref := range refs {
				var number int

				_, err := fmt.Sscanf(ref.Reference, "budget-%d", &number)
				So(err, ShouldBeNil)

				batch = append(batch, number)
			}

			sort.Ints(configReads)

			run.batches = append(run.batches, batch)
			run.configReadsPerBatch = append(run.configReadsPerBatch, configReads)
			configReads = nil

			return nil
		},
	}

	store := controller(mocks.MockedImageStore{
		GetIndexContentFn: func(string) ([]byte, error) {
			return indexBlobOfSized(entries, scenario.descriptorSizes), nil
		},
		GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()

			if number, ok := manifestIndex[digest]; ok {
				manifestReads++

				if number == scenario.failManifest {
					return nil, errParseInternal
				}

				return manifestBlobs[digest], nil
			}

			configReads = append(configReads, configIndex[digest])

			return fixture.configBlob, nil
		},
		StatBlobFn: func(_ string, digest godigest.Digest) (bool, int64, time.Time, error) {
			if number, ok := configIndex[digest]; ok {
				if failure := scenario.statFailure; failure != nil && failure.entry == number {
					if failure.notFound {
						return false, 0, time.Time{}, nil
					}

					return false, 0, time.Time{}, errParseInternal
				}

				return true, scenario.configSizes[number], time.Time{}, nil
			}

			return true, 0, time.Time{}, nil
		},
	})

	_, run.err = parseRepo("repo", metaDB, store, log.NewTestLogger())

	return run
}

func batchSizes(batches [][]int) []int {
	sizes := make([]int, 0, len(batches))
	for _, batch := range batches {
		sizes = append(sizes, len(batch))
	}

	return sizes
}

func repeatSize(size int64, count int) []int64 {
	sizes := make([]int64, 0, count)
	for range count {
		sizes = append(sizes, size)
	}

	return sizes
}

func TestParseRepoChunkByteBudget(t *testing.T) {
	fixture := newParseFixture(t)

	cases := []struct {
		name        string
		configSizes []int64
		want        []int
	}{
		{"ten entries of 10 MiB configs", repeatSize(10*mebibyte, 10), []int{3, 3, 3, 1}},
		{"a config of 100 MiB forms a chunk on its own", []int64{100 * mebibyte, 1, 1}, []int{1, 2}},
		{"a config of 100 MiB in the middle", []int64{1, 100 * mebibyte, 1}, []int{1, 1, 1}},
	}

	for _, testCase := range cases {
		storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
			Convey("chunks are cut at the config byte budget, "+testCase.name+", "+mode+" store", t, func() {
				run := runBudgetScenario(t, fixture, wrap, budgetScenario{configSizes: testCase.configSizes, failManifest: -1})

				So(run.err, ShouldBeNil)
				So(batchSizes(run.batches), ShouldResemble, testCase.want)

				// the configs of a chunk are read before its write and never earlier
				for i, batch := range run.batches {
					So(run.configReadsPerBatch[i], ShouldResemble, batch)
				}
			})
		})
	}
}

func TestParseRepoChunkBudgetUsesRealConfigSize(t *testing.T) {
	fixture := newParseFixture(t)

	for name, declared := range map[string]int64{"zero": 0, "negative": -1 << 40} {
		storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
			Convey("the budget charges the blob size, not the declared "+name+" config size, "+mode+" store", t, func() {
				run := runBudgetScenario(t, fixture, wrap, budgetScenario{
					manifestConfigSize: declared,
					configSizes:        repeatSize(10*mebibyte, 10),
					failManifest:       -1,
				})

				So(run.err, ShouldBeNil)
				So(batchSizes(run.batches), ShouldResemble, []int{3, 3, 3, 1})
			})
		})
	}
}

func TestParseRepoChunkBudgetCountsManifests(t *testing.T) {
	fixture := newParseFixture(t)

	negativeFirst := repeatSize(10*mebibyte, 10)
	negativeFirst[0] = -100 * mebibyte

	cases := []struct {
		name            string
		descriptorSizes []int64
		configSize      int64
		want            []int
		maxReadsAtWrite int
	}{
		{"manifests of 10 MiB with empty configs", repeatSize(10*mebibyte, 10), 0, []int{3, 3, 3, 1}, 3},
		{"manifests and configs of 10 MiB", repeatSize(10*mebibyte, 10), 10 * mebibyte, []int{3, 3, 3, 1}, 3},
		{"a negative descriptor size counts as zero", negativeFirst, 0, []int{4, 3, 3}, 4},
	}

	for _, testCase := range cases {
		storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
			Convey("the manifests read ahead count against the budget, "+testCase.name+", "+mode+" store", t, func() {
				run := runBudgetScenario(t, fixture, wrap, budgetScenario{
					descriptorSizes: testCase.descriptorSizes,
					configSizes:     repeatSize(testCase.configSize, 10),
					failManifest:    -1,
				})

				So(run.err, ShouldBeNil)
				So(batchSizes(run.batches), ShouldResemble, testCase.want)
				So(run.manifestReadsBeforeWr, ShouldBeLessThanOrEqualTo, testCase.maxReadsAtWrite)
			})
		})
	}
}

func TestParseRepoChargesSharedConfigPerEntry(t *testing.T) {
	fixture := newParseFixture(t)

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		Convey("every entry is charged the size of the config it shares, "+mode+" store", t, func() {
			run := runBudgetScenario(t, fixture, wrap, budgetScenario{
				configSizes:  repeatSize(10*mebibyte, 10),
				failManifest: -1,
				sharedConfig: true,
			})

			So(run.err, ShouldBeNil)
			So(batchSizes(run.batches), ShouldResemble, []int{3, 3, 3, 1})

			for _, reads := range run.configReadsPerBatch {
				So(len(reads), ShouldBeLessThanOrEqualTo, 1)
			}
		})
	})
}

func TestParseRepoReadErrorBeyondChunkCut(t *testing.T) {
	fixture := newParseFixture(t)

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		Convey("a failed manifest read past the cut does not stop the earlier chunk, "+mode+" store", t, func() {
			run := runBudgetScenario(t, fixture, wrap, budgetScenario{
				descriptorSizes: repeatSize(2*mebibyte, 6),
				configSizes:     repeatSize(10*mebibyte, 6),
				failManifest:    4,
			})

			So(errors.Is(run.err, errParseInternal), ShouldBeTrue)
			So(run.batches, ShouldResemble, [][]int{{0, 1, 2}, {3}})
		})
	})
}

func TestParseRepoConfigStatErrorStopsParse(t *testing.T) {
	fixture := newParseFixture(t)

	cases := []struct {
		name    string
		failure configStatFailure
		want    error
	}{
		{"StatBlob fails", configStatFailure{entry: 1}, errParseInternal},
		{"StatBlob reports the config as missing", configStatFailure{entry: 1, notFound: true}, zerr.ErrBlobNotFound},
	}

	for _, testCase := range cases {
		storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
			Convey("a config that cannot be statted ends the parse at its entry, "+testCase.name+", "+mode+" store", t, func() {
				run := runBudgetScenario(t, fixture, wrap, budgetScenario{
					configSizes:  repeatSize(1, 3),
					failManifest: -1,
					statFailure:  &testCase.failure,
				})

				So(errors.Is(run.err, testCase.want), ShouldBeTrue)
				So(run.batches, ShouldResemble, [][]int{{0}})
			})
		})
	}
}
