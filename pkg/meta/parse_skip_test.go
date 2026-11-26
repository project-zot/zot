package meta_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	"zotregistry.dev/zot/v2/pkg/test/signature"
)

const skipTestTagCount = 3

// skipTestStore wraps an image store to count blob reads and stats and to inject errors.
type skipTestStore struct {
	storageTypes.ImageStore

	mu             sync.Mutex
	blobReads      int
	blobStats      int
	statErrors     map[godigest.Digest]error
	statNotFound   map[godigest.Digest]bool
	failIndexReads int
	indexReads     int
}

func (s *skipTestStore) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	s.mu.Lock()
	s.blobReads++
	s.mu.Unlock()

	return s.ImageStore.GetBlobContent(repo, digest)
}

func (s *skipTestStore) StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	s.mu.Lock()
	s.blobStats++
	injected := s.statErrors[digest]
	statNotFound := s.statNotFound[digest]
	s.mu.Unlock()

	if injected != nil {
		return false, -1, time.Time{}, injected
	}

	if statNotFound {
		return false, -1, time.Time{}, nil
	}

	return s.ImageStore.StatBlob(repo, digest)
}

func (s *skipTestStore) GetIndexContent(repo string) ([]byte, error) {
	s.mu.Lock()
	s.indexReads++
	fail := s.failIndexReads > 0

	if fail {
		s.failIndexReads--
	}
	s.mu.Unlock()

	if fail {
		return nil, errMetaTestInjected
	}

	return s.ImageStore.GetIndexContent(repo)
}

func (s *skipTestStore) resetCounts() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blobReads = 0
	s.blobStats = 0
	s.indexReads = 0
}

func (s *skipTestStore) reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.blobReads
}

func (s *skipTestStore) indexReadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.indexReads
}

func (s *skipTestStore) stats() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.blobStats
}

type skipFixture struct {
	rootDir string
	logger  log.Logger
	metaDB  mTypes.MetaDB
	store   *skipTestStore
	sc      storage.StoreController

	images map[string]Image
}

func tagName(i int) string {
	return fmt.Sprintf("tag%d", i)
}

// newSkipFixture returns a local store holding tag0..tag2 that is not parsed yet.
func newSkipFixture(t *testing.T) *skipFixture {
	t.Helper()

	logger := log.NewTestLogger()

	boltDriver, err := boltdb.GetBoltDriver(boltdb.DBParameters{RootDir: t.TempDir()})
	So(err, ShouldBeNil)

	metaDB, err := boltdb.New(boltDriver, logger)
	So(err, ShouldBeNil)

	rootDir := t.TempDir()
	store := &skipTestStore{
		ImageStore: local.NewImageStore(rootDir, false, false, logger, monitoring.NewNopMetricServer(),
			nil, nil, nil, nil),
		statErrors:   map[godigest.Digest]error{},
		statNotFound: map[godigest.Digest]bool{},
	}

	fixture := &skipFixture{
		rootDir: rootDir,
		logger:  logger,
		metaDB:  metaDB,
		store:   store,
		sc:      storage.StoreController{DefaultStore: store},
		images:  map[string]Image{},
	}

	for i := range skipTestTagCount {
		fixture.push(tagName(i))
	}

	return fixture
}

func (fixture *skipFixture) push(ref string) Image {
	image := CreateRandomImage()

	So(WriteImageToFileSystem(image, repo, ref, fixture.sc), ShouldBeNil)

	fixture.images[ref] = image

	return image
}

func (fixture *skipFixture) digestOf(ref string) string {
	image := fixture.images[ref]

	return image.DigestStr()
}

func (fixture *skipFixture) parse() {
	So(meta.ParseStorage(fixture.metaDB, fixture.sc, fixture.logger), ShouldBeNil) //nolint: contextcheck
}

func (fixture *skipFixture) repoMeta() mTypes.RepoMeta {
	repoMeta, err := fixture.metaDB.GetRepoMeta(context.Background(), repo)
	So(err, ShouldBeNil)

	return repoMeta
}

func (fixture *skipFixture) indexPath() string {
	return path.Join(fixture.rootDir, repo, "index.json")
}

func (fixture *skipFixture) readIndex() ispec.Index {
	buf, err := os.ReadFile(fixture.indexPath())
	So(err, ShouldBeNil)

	var index ispec.Index

	So(json.Unmarshal(buf, &index), ShouldBeNil)

	return index
}

func (fixture *skipFixture) writeIndex(index ispec.Index) {
	buf, err := json.Marshal(index)
	So(err, ShouldBeNil)

	So(os.WriteFile(fixture.indexPath(), buf, 0o600), ShouldBeNil)
}

func (fixture *skipFixture) descriptorFor(ref string) ispec.Descriptor {
	for _, desc := range fixture.readIndex().Manifests {
		if desc.Annotations[ispec.AnnotationRefName] == ref || desc.Digest.String() == ref {
			return desc
		}
	}

	So(fmt.Sprintf("no descriptor for %s in index.json", ref), ShouldBeEmpty)

	return ispec.Descriptor{}
}

// refreshRepoMeta stamps RepoLastUpdated with a correct tag, as SetRepoMeta zeroes it.
func (fixture *skipFixture) refreshRepoMeta() {
	image := fixture.images[tagName(0)]

	err := fixture.metaDB.SetRepoReference(context.Background(), repo, tagName(0), image.AsImageMeta())
	So(err, ShouldBeNil)
}

func (fixture *skipFixture) editRepoMeta(edit func(repoMeta *mTypes.RepoMeta)) {
	repoMeta := fixture.repoMeta()

	edit(&repoMeta)

	So(fixture.metaDB.SetRepoMeta(repo, repoMeta), ShouldBeNil)

	fixture.refreshRepoMeta()
}

// backdateIndex makes the mtime check alone skip the repo.
func (fixture *skipFixture) backdateIndex() {
	past := time.Now().Add(-time.Hour)

	So(os.Chtimes(fixture.indexPath(), past, past), ShouldBeNil)

	_, _, storageLastUpdated, err := fixture.store.StatIndex(repo)
	So(err, ShouldBeNil)

	metaLastUpdated := fixture.metaDB.GetRepoLastUpdated(repo)

	So(metaLastUpdated.IsZero(), ShouldBeFalse)
	So(storageLastUpdated, ShouldHappenBefore, metaLastUpdated)
}

func (fixture *skipFixture) uploadBlob(content []byte) godigest.Digest {
	digest := godigest.FromBytes(content)

	_, _, err := fixture.store.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
	So(err, ShouldBeNil)

	return digest
}

// pushCosignSignature stores a signature under the legacy cosign tag of the signed image.
func (fixture *skipFixture) pushCosignSignature(signedRef string) string {
	signed := fixture.images[signedRef]

	signatureTag, err := signature.GetCosignSignatureTagForManifest(signed.Manifest)
	So(err, ShouldBeNil)

	signatureImage := fixture.push(signatureTag)

	return signatureImage.DigestStr()
}

// pushNotationSignature stores an untagged notation signature of the signed image.
func (fixture *skipFixture) pushNotationSignature(signedRef string) string {
	signed := fixture.images[signedRef]
	notation := CreateMockNotationSignature(signed.DescriptorRef())

	fixture.uploadBlob(ispec.DescriptorEmptyJSON.Data)

	So(WriteImageToFileSystem(notation, repo, notation.DigestStr(), fixture.sc), ShouldBeNil)

	fixture.images[notation.DigestStr()] = notation

	return notation.DigestStr()
}

// applyDescriptor writes one index.json descriptor to the metaDB the way parseRepo does.
func (fixture *skipFixture) applyDescriptor(desc ispec.Descriptor) {
	ref := desc.Annotations[ispec.AnnotationRefName]
	if ref == "" {
		ref = desc.Digest.String()
	}

	blob, err := fixture.store.GetBlobContent(repo, desc.Digest)
	So(err, ShouldBeNil)

	err = meta.SetImageMetaFromInput(context.Background(), repo, ref, desc.MediaType, desc.Digest, blob,
		fixture.store, fixture.metaDB, fixture.logger)
	So(err, ShouldBeNil)
}

func (fixture *skipFixture) tagsToKeep() map[string]bool {
	keep := map[string]bool{}

	for _, desc := range fixture.readIndex().Manifests {
		tag := desc.Annotations[ispec.AnnotationRefName]
		if tag != "" && !zcommon.IsReferrersTag(tag) {
			keep[tag] = true
		}
	}

	return keep
}

func (fixture *skipFixture) signatureDigests(signedDigest, signatureType string) []string {
	digests := []string{}

	for _, info := range fixture.repoMeta().Signatures[signedDigest][signatureType] {
		digests = append(digests, info.SignatureManifestDigest)
	}

	return digests
}

// expectComplete asserts that every pushed tag is in the metaDB with its own digest and statistics.
func (fixture *skipFixture) expectComplete(refs ...string) {
	repoMeta := fixture.repoMeta()

	for _, ref := range refs {
		digest := fixture.digestOf(ref)

		So(repoMeta.Tags[ref].Digest, ShouldEqual, digest)
		So(repoMeta.Statistics, ShouldContainKey, digest)
	}
}

func skipTestTags() []string {
	refs := []string{}

	for i := range skipTestTagCount {
		refs = append(refs, tagName(i))
	}

	return refs
}

func TestParseStorageSkipsOnlyCompleteRepo(t *testing.T) {
	Convey("a complete metaDB is skipped without reading a blob", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()
		fixture.expectComplete(skipTestTags()...)

		fixture.backdateIndex()
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.reads(), ShouldEqual, 0)
		So(fixture.store.stats(), ShouldEqual, 0)
		fixture.expectComplete(skipTestTags()...)
	})

	Convey("a metaDB missing a tag whose digest has statistics is reparsed", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		// tagA names the digest of tag0, so its statistics exist already
		sameDigest := fixture.images["tag0"]
		So(WriteImageToFileSystem(sameDigest, repo, "tagA", fixture.sc), ShouldBeNil)

		fixture.images["tagA"] = sameDigest

		fixture.backdateIndex()

		repoMeta := fixture.repoMeta()
		So(repoMeta.Tags, ShouldNotContainKey, "tagA")
		So(repoMeta.Statistics, ShouldContainKey, fixture.digestOf("tag0"))

		fixture.parse()

		repoMeta = fixture.repoMeta()
		So(repoMeta.Tags["tagA"].Digest, ShouldEqual, fixture.digestOf("tag0"))
	})

	Convey("a metaDB missing only a tagged image index is reparsed", t, func() {
		fixture := newSkipFixture(t)

		indexImage := CreateRandomMultiarch()
		So(WriteMultiArchImageToFileSystem(indexImage, repo, "tagIdx", fixture.sc), ShouldBeNil)

		fixture.parse()

		indexDigest := indexImage.DigestStr()

		fixture.editRepoMeta(func(repoMeta *mTypes.RepoMeta) {
			delete(repoMeta.Tags, "tagIdx")
			delete(repoMeta.Statistics, indexDigest)
		})
		fixture.backdateIndex()

		So(fixture.repoMeta().Tags, ShouldNotContainKey, "tagIdx")

		fixture.parse()

		So(fixture.repoMeta().Tags, ShouldContainKey, "tagIdx")
		So(fixture.repoMeta().Statistics, ShouldContainKey, indexDigest)
	})

	Convey("a tag whose digest has no statistics is reparsed", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		digest := fixture.digestOf("tag1")

		fixture.editRepoMeta(func(repoMeta *mTypes.RepoMeta) { delete(repoMeta.Statistics, digest) })
		fixture.backdateIndex()

		So(fixture.repoMeta().Statistics, ShouldNotContainKey, digest)

		fixture.parse()

		fixture.expectComplete(skipTestTags()...)
	})

	Convey("a tag pointing at another digest than index.json is reparsed", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		other := fixture.repoMeta().Tags["tag2"]

		fixture.editRepoMeta(func(repoMeta *mTypes.RepoMeta) { repoMeta.Tags["tag1"] = other })
		fixture.backdateIndex()

		So(fixture.repoMeta().Tags["tag1"].Digest, ShouldEqual, fixture.digestOf("tag2"))

		fixture.parse()

		So(fixture.repoMeta().Tags["tag1"].Digest, ShouldEqual, fixture.digestOf("tag1"))
	})

	Convey("an untagged image without statistics is reparsed", t, func() {
		fixture := newSkipFixture(t)

		untagged := CreateRandomImage()
		untaggedDigest := untagged.DigestStr()
		So(WriteImageToFileSystem(untagged, repo, untaggedDigest, fixture.sc), ShouldBeNil)

		fixture.parse()

		So(fixture.repoMeta().Statistics, ShouldContainKey, untaggedDigest)

		fixture.editRepoMeta(func(repoMeta *mTypes.RepoMeta) { delete(repoMeta.Statistics, untaggedDigest) })
		fixture.backdateIndex()

		So(fixture.repoMeta().Statistics, ShouldNotContainKey, untaggedDigest)

		fixture.parse()

		So(fixture.repoMeta().Statistics, ShouldContainKey, untaggedDigest)
	})
}

func TestParseStorageSkipSignatures(t *testing.T) {
	Convey("signatures count as covered when RepoMeta.Signatures records their digest, "+
		"so a signed repo is skipped", t, func() {
		fixture := newSkipFixture(t)
		cosignDigest := fixture.pushCosignSignature("tag0")
		notationDigest := fixture.pushNotationSignature("tag0")

		fixture.parse()

		signedDigest := fixture.digestOf("tag0")
		So(fixture.signatureDigests(signedDigest, zcommon.CosignSignature), ShouldContain, cosignDigest)
		So(fixture.signatureDigests(signedDigest, zcommon.NotationSignature), ShouldContain, notationDigest)

		fixture.backdateIndex()
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.reads(), ShouldEqual, 0)
		So(fixture.signatureDigests(signedDigest, zcommon.CosignSignature), ShouldContain, cosignDigest)
		So(fixture.signatureDigests(signedDigest, zcommon.NotationSignature), ShouldContain, notationDigest)
	})

	Convey("an interrupted parse on an empty metaDB, which leaves tags missing, is reparsed", t, func() {
		fixture := newSkipFixture(t)
		cosignDigest := fixture.pushCosignSignature("tag0")
		notationDigest := fixture.pushNotationSignature("tag0")

		// parseRepo resets, sets tag0 and adds both signatures before it is interrupted
		So(fixture.metaDB.ResetRepoReferences(repo, fixture.tagsToKeep()), ShouldBeNil)
		fixture.applyDescriptor(fixture.descriptorFor("tag0"))
		fixture.applyDescriptor(fixture.descriptorFor(cosignDigest))
		fixture.applyDescriptor(fixture.descriptorFor(notationDigest))
		fixture.backdateIndex()

		repoMeta := fixture.repoMeta()
		for _, ref := range []string{"tag1", "tag2"} {
			So(repoMeta.Tags, ShouldNotContainKey, ref)
			So(repoMeta.Statistics, ShouldNotContainKey, fixture.digestOf(ref))
		}

		fixture.parse()

		fixture.expectComplete(skipTestTags()...)
	})

	Convey("an interrupted parse that wiped a legacy cosign signature is reparsed", t, func() {
		fixture := newSkipFixture(t)
		cosignDigest := fixture.pushCosignSignature("tag0")

		fixture.parse()

		signedDigest := fixture.digestOf("tag0")
		So(fixture.signatureDigests(signedDigest, zcommon.CosignSignature), ShouldContain, cosignDigest)

		So(fixture.metaDB.ResetRepoReferences(repo, fixture.tagsToKeep()), ShouldBeNil)
		fixture.backdateIndex()

		So(fixture.signatureDigests(signedDigest, zcommon.CosignSignature), ShouldBeEmpty)

		fixture.parse()

		So(fixture.signatureDigests(signedDigest, zcommon.CosignSignature), ShouldContain, cosignDigest)
	})

	Convey("an interrupted parse that wiped a notation signature is reparsed", t, func() {
		fixture := newSkipFixture(t)
		notationDigest := fixture.pushNotationSignature("tag0")

		fixture.parse()

		signedDigest := fixture.digestOf("tag0")
		So(fixture.signatureDigests(signedDigest, zcommon.NotationSignature), ShouldContain, notationDigest)

		So(fixture.metaDB.ResetRepoReferences(repo, fixture.tagsToKeep()), ShouldBeNil)
		fixture.backdateIndex()

		So(fixture.signatureDigests(signedDigest, zcommon.NotationSignature), ShouldBeEmpty)

		fixture.parse()

		So(fixture.signatureDigests(signedDigest, zcommon.NotationSignature), ShouldContain, notationDigest)
	})
}

func TestParseStorageSkipMissingAndIgnoredDescriptors(t *testing.T) {
	Convey("a descriptor whose manifest blob is missing counts as covered, "+
		"so the repo is not reparsed on every start", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		digest := fixture.digestOf("tag1")

		So(os.Remove(fixture.store.BlobPath(repo, godigest.Digest(digest))), ShouldBeNil)

		fixture.editRepoMeta(func(repoMeta *mTypes.RepoMeta) {
			delete(repoMeta.Tags, "tag1")
			delete(repoMeta.Statistics, digest)
		})
		fixture.backdateIndex()
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.reads(), ShouldEqual, 0)
		So(fixture.store.stats(), ShouldEqual, 1)
	})

	Convey("referrers tags and non-image media types are ignored by the coverage check", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		manifestImage := CreateRandomImage()
		manifestBlob, err := json.Marshal(manifestImage.Manifest)
		So(err, ShouldBeNil)

		manifestDigest := fixture.uploadBlob(manifestBlob)
		layerBlob := []byte("a layer that is not an image manifest")
		layerDigest := fixture.uploadBlob(layerBlob)

		index := fixture.readIndex()
		index.Manifests = append(index.Manifests,
			ispec.Descriptor{
				MediaType:   ispec.MediaTypeImageManifest,
				Digest:      manifestDigest,
				Size:        int64(len(manifestBlob)),
				Annotations: map[string]string{ispec.AnnotationRefName: "sha256-" + manifestDigest.Encoded()},
			},
			ispec.Descriptor{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    layerDigest,
				Size:      int64(len(layerBlob)),
			},
		)
		fixture.writeIndex(index)

		fixture.backdateIndex()
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.reads(), ShouldEqual, 0)
		So(fixture.store.stats(), ShouldEqual, 0)
	})
}

func TestParseStorageSkipErrors(t *testing.T) {
	Convey("a repo meta read error parses the repo", t, func() {
		var (
			resetMu    sync.Mutex
			resetRepos []string
		)

		metaDB := mocks.MetaDBMock{
			GetRepoLastUpdatedFn: func(repo string) time.Time { return time.Now() },
			GetRepoMetaFn: func(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
				return mTypes.RepoMeta{}, errMetaTestInjected
			},
			ResetRepoReferencesFn: func(repo string, tagsToKeep map[string]bool) error {
				resetMu.Lock()
				defer resetMu.Unlock()

				resetRepos = append(resetRepos, repo)

				return nil
			},
		}
		imageStore := mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) { return []string{"repo1"}, nil },
			StatIndexFn: func(repo string) (bool, int64, time.Time, error) {
				return true, 0, time.Now().Add(-time.Hour), nil
			},
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return []byte(`{"schemaVersion":2,"manifests":[]}`), nil
			},
		}

		err := meta.ParseStorage(metaDB, storage.StoreController{DefaultStore: imageStore}, //nolint: contextcheck
			log.NewTestLogger())
		So(err, ShouldBeNil)

		resetMu.Lock()
		defer resetMu.Unlock()

		So(resetRepos, ShouldResemble, []string{"repo1"})
	})

	Convey("a stat error other than not found parses the repo", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		digest := fixture.digestOf("tag1")

		fixture.editRepoMeta(func(repoMeta *mTypes.RepoMeta) { delete(repoMeta.Statistics, digest) })
		fixture.backdateIndex()

		fixture.store.statErrors[godigest.Digest(digest)] = errMetaTestInjected
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.reads(), ShouldBeGreaterThan, 0)
		So(fixture.repoMeta().Statistics, ShouldContainKey, digest)
	})

	Convey("a stat of a missing blob without an error is not a missing blob, so the repo is parsed", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		digest := fixture.digestOf("tag1")

		fixture.editRepoMeta(func(repoMeta *mTypes.RepoMeta) { delete(repoMeta.Statistics, digest) })
		fixture.backdateIndex()

		fixture.store.statNotFound[godigest.Digest(digest)] = true
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.reads(), ShouldBeGreaterThan, 0)
		So(fixture.repoMeta().Statistics, ShouldContainKey, digest)
	})

	Convey("an unparsable index.json with a newer metaDB falls through to parseRepo", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()

		So(os.WriteFile(fixture.indexPath(), []byte("not json"), 0o600), ShouldBeNil)

		fixture.backdateIndex()
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.indexReadCount(), ShouldEqual, 2)
	})

	Convey("an index.json read error in the coverage check parses the repo", t, func() {
		fixture := newSkipFixture(t)
		fixture.parse()
		fixture.backdateIndex()

		fixture.store.failIndexReads = 1
		fixture.store.resetCounts()

		fixture.parse()

		So(fixture.store.reads(), ShouldBeGreaterThan, 0)
	})
}
