package meta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

const (
	unknownMediaType = "application/vnd.example.unknown.v1+json"
	setRepoFailedMsg = "failed to set repo meta"
)

// lockedBuffer is a log sink that is safe for the concurrent writers of a parse.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buffer.String()
}

func TestParseRepoReturnsSetRepoReferencesError(t *testing.T) {
	fixture := newParseFixture(t)

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		t.Run("the write error ends the parse after one batch and is logged once, "+mode+" store", func(t *testing.T) {
			signed := fixture.manifestDigest("signed", 0)
			entries := append(numberedEntries(fixture, "failing", ParseChunkSize+100), indexEntry{
				fixture.manifestDigest("signature", 0), "sha256-" + signed.Encoded() + ".sig",
			})

			var (
				batches    atomic.Int32
				signatures atomic.Int32
			)

			metaDB := mocks.MetaDBMock{
				SetRepoReferencesFn: func(context.Context, string, []mTypes.RepoReference) error {
					batches.Add(1)

					return errParseInternal
				},
				AddManifestSignatureFn: func(string, godigest.Digest, mTypes.SignatureMetadata) error {
					signatures.Add(1)

					return nil
				},
			}

			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
				GetBlobContentFn:  func(_ string, digest godigest.Digest) ([]byte, error) { return fixture.blob(digest) },
			})

			logs := &lockedBuffer{}

			_, err := parseRepo("repo", metaDB, controller, log.NewLoggerWithWriter("debug", logs))
			if !errors.Is(err, errParseInternal) {
				t.Fatalf("expected the write error, got: %v", err)
			}

			if got := batches.Load(); got != 1 {
				t.Errorf("SetRepoReferences calls = %d, want 1", got)
			}

			if got := signatures.Load(); got != 0 {
				t.Errorf("signatures applied = %d, want 0", got)
			}

			if got := strings.Count(logs.String(), setRepoFailedMsg); got != 1 {
				t.Errorf("%q logged %d times, want 1", setRepoFailedMsg, got)
			}
		})
	})
}

func TestParseRepoReportsReadErrorWhenFlushFails(t *testing.T) {
	fixture := newParseFixture(t)
	errFlush := errors.New("flush failure")

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		t.Run("the read error is returned and no signature is applied, "+mode+" store", func(t *testing.T) {
			signed := fixture.manifestDigest("signed", 0)
			failing := fixture.manifestDigest("failing", 0)
			entries := []indexEntry{
				{fixture.manifestDigest("first", 0), "first"},
				{fixture.manifestDigest("signature", 0), "sha256-" + signed.Encoded() + ".sig"},
				{failing, "failing"},
			}

			var (
				batches    atomic.Int32
				signatures atomic.Int32
			)

			metaDB := mocks.MetaDBMock{
				SetRepoReferencesFn: func(context.Context, string, []mTypes.RepoReference) error {
					batches.Add(1)

					return errFlush
				},
				AddManifestSignatureFn: func(string, godigest.Digest, mTypes.SignatureMetadata) error {
					signatures.Add(1)

					return nil
				},
			}

			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
				GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
					if digest == failing {
						return nil, errParseInternal
					}

					return fixture.blob(digest)
				},
			})

			_, err := parseRepo("repo", metaDB, controller, log.NewTestLogger())
			if !errors.Is(err, errParseInternal) || errors.Is(err, errFlush) {
				t.Fatalf("expected the read error only, got: %v", err)
			}

			if got := batches.Load(); got != 1 {
				t.Errorf("SetRepoReferences calls = %d, want 1", got)
			}

			if got := signatures.Load(); got != 0 {
				t.Errorf("signatures applied = %d, want 0", got)
			}
		})
	})
}

func TestParseRepoReleasesReadSlotWhenSchedulingStops(t *testing.T) {
	fixture := newParseFixture(t)

	// The slot channel is global: all slots but one are taken, so that the scheduler has to wait for the
	// failing read to hand its slot back, and sees the failure when it gets it.
	held := cap(parseReadSlots) - 1
	for range held {
		parseReadSlots <- struct{}{}
	}

	t.Cleanup(func() {
		for len(parseReadSlots) > 0 {
			<-parseReadSlots
		}
	})

	entries := numberedEntries(fixture, "stopping", 4)
	failing := entries[0].digest

	var laterReads atomic.Int32

	controller := storage.StoreController{DefaultStore: concurrentStore{mocks.MockedImageStore{
		GetIndexContentFn: func(string) ([]byte, error) { return indexBlobOf(entries), nil },
		GetBlobContentFn: func(_ string, digest godigest.Digest) ([]byte, error) {
			if digest == failing {
				return nil, errParseInternal
			}

			if digest != fixture.configDigest {
				laterReads.Add(1)
			}

			return fixture.blob(digest)
		},
	}}}

	recorder := &batchRecorder{}

	_, err := parseRepo("repo", recorder.metaDB(), controller, log.NewTestLogger())
	if !errors.Is(err, errParseInternal) {
		t.Fatalf("expected the read error, got: %v", err)
	}

	if got := laterReads.Load(); got != 0 {
		t.Errorf("%d manifests were read after the failure, want 0", got)
	}

	if got := len(parseReadSlots); got != held {
		t.Errorf("read slots in use after the parse = %d, want %d", got, held)
	}
}

func TestParseRepoSkipsEntriesOfUnknownMediaType(t *testing.T) {
	fixture := newParseFixture(t)

	storeModes(func(mode string, wrap func(mocks.MockedImageStore) storage.StoreController) {
		t.Run("an entry that is neither manifest nor index is not written, "+mode+" store", func(t *testing.T) {
			unknown := fixture.manifestDigest("unknown", 0)

			index, err := json.Marshal(ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType:   ispec.MediaTypeImageManifest,
						Digest:      fixture.manifestDigest("before", 0),
						Annotations: map[string]string{ispec.AnnotationRefName: "before"},
					},
					{
						MediaType:   unknownMediaType,
						Digest:      unknown,
						Annotations: map[string]string{ispec.AnnotationRefName: "unknown"},
					},
					{
						MediaType:   ispec.MediaTypeImageManifest,
						Digest:      fixture.manifestDigest("after", 0),
						Annotations: map[string]string{ispec.AnnotationRefName: "after"},
					},
				},
			})
			if err != nil {
				t.Fatalf("marshal index: %v", err)
			}

			recorder := &batchRecorder{}
			controller := wrap(mocks.MockedImageStore{
				GetIndexContentFn: func(string) ([]byte, error) { return index, nil },
				GetBlobContentFn:  func(_ string, digest godigest.Digest) ([]byte, error) { return fixture.blob(digest) },
			})

			partial, err := parseRepo("repo", recorder.metaDB(), controller, log.NewTestLogger())
			if err != nil || partial {
				t.Fatalf("parseRepo = partial %t, error %v, want a complete parse", partial, err)
			}

			if got := recorder.flat(); !slices.Equal(got, []string{"before", "after"}) {
				t.Errorf("written references = %v, want [before after]", got)
			}
		})
	})
}

func TestParseChunkRejectsEntriesWithoutBuiltRead(t *testing.T) {
	digest := godigest.FromString("chunk-entry")
	chunk := []ispec.Descriptor{{
		MediaType:   ispec.MediaTypeImageManifest,
		Digest:      digest,
		Annotations: map[string]string{ispec.AnnotationRefName: "tag"},
	}}

	cases := []struct {
		name  string
		reads map[blobKey]*blobRead
	}{
		{"the read was never scheduled", map[blobKey]*blobRead{}},
		{
			"the read finished without building an image meta",
			map[blobKey]*blobRead{{digest: digest, mediaType: ispec.MediaTypeImageManifest}: {}},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := parseChunk("repo", chunk, testCase.reads, log.NewTestLogger())
			if !errors.Is(err, errBlobNotRead) {
				t.Fatalf("expected errBlobNotRead, got: %v", err)
			}

			if len(parsed.references) != 0 || len(parsed.signatures) != 0 {
				t.Errorf("parsed = %+v, want nothing", parsed)
			}
		})
	}
}
