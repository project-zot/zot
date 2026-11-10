package gc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func indexJSON(t *testing.T, manifests ...ispec.Descriptor) []byte {
	t.Helper()

	body, err := json.Marshal(ispec.Index{Manifests: manifests})
	require.NoError(t, err)

	return body
}

func manifestDescriptor(digest godigest.Digest, tag string) ispec.Descriptor {
	desc := ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: digest, Size: 1}
	if tag != "" {
		desc.Annotations = map[string]string{ispec.AnnotationRefName: tag}
	}

	return desc
}

// keepTagsOpts removes every tag that does not match release-.* and leaves untagged rows alone.
func keepTagsOpts() Options {
	deleteUntagged := false

	return Options{ImageRetention: config.ImageRetention{
		Policies: []config.RetentionPolicy{{
			Repositories:   []string{"**"},
			DeleteUntagged: &deleteUntagged,
			KeepTags:       []config.KeepTagsPolicy{{Patterns: []string{"release-.*"}}},
		}},
	}}
}

func taggedRepoMeta(tag string, digest godigest.Digest) mTypes.RepoMeta {
	return mTypes.RepoMeta{
		Name: "repo",
		Tags: map[mTypes.Tag]mTypes.Descriptor{tag: {Digest: digest.String(), MediaType: ispec.MediaTypeImageManifest}},
		Statistics: map[mTypes.ImageDigest]mTypes.DescriptorStatistics{
			digest.String(): {PushTimestamp: time.Now().Add(-time.Hour)},
		},
	}
}

func newMockCollector(store *lockTrackingStore, metaDB mTypes.MetaDB, opts Options) GarbageCollect {
	return NewGarbageCollect(store, metaDB, opts, nil, zlog.NewTestLogger(), monitoring.NewNopMetricServer())
}

func TestDeferredWritesWithoutRecorder(t *testing.T) {
	require.Zero(t, GarbageCollect{}.deferredWrites())
}

func TestAuditBufferViewCarriesAttrsIntoPublishedRecords(t *testing.T) {
	buffer := &auditBuffer{}
	logger := slog.New(buffer).With("repository", "repo").WithGroup("gc").With("decision", "delete")

	require.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
	logger.Info("removed")

	var out bytes.Buffer

	target := zlog.Logger{Logger: slog.New(slog.NewJSONHandler(&out, nil))}
	buffer.publish(context.Background(), &target)
	buffer.publish(context.Background(), &target)

	records := auditRecords(t, &out)
	require.Len(t, records, 1)
	require.Equal(t, "repo", records[0]["repository"])
	require.Equal(t, "delete", records[0]["decision"])
	require.Equal(t, "removed", records[0]["msg"])

	require.Same(t, buffer, buffer.WithGroup("ignored"))

	view, ok := buffer.WithAttrs(nil).WithGroup("ignored").(*auditBufferView)
	require.True(t, ok)
	require.Same(t, buffer, view.parent)
}

func TestAuditBufferPublishWithoutTargetDrainsRecords(t *testing.T) {
	buffer := &auditBuffer{}
	slog.New(buffer).Info("removed")
	require.Len(t, buffer.records, 1)

	buffer.publish(context.Background(), nil)
	require.Empty(t, buffer.records)
}

func TestReadLockedStoreRejectsInvalidDigest(t *testing.T) {
	store := readLockedStore{ImageStore: mocks.MockedImageStore{}}

	_, err := store.GetBlobContent("repo", "not-a-digest")
	require.Error(t, err)
}

func TestGCScanFailsWhenRepoMetaReadFails(t *testing.T) {
	store := &lockTrackingStore{}
	digest := godigest.FromBytes(manifestJSON())
	metaErr := errors.New("metadb unavailable") //nolint:err113
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t, manifestDescriptor(digest, "v1")), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{digest}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return manifestJSON(), nil }

	metaDB := mocks.MetaDBMock{
		GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) { return mTypes.RepoMeta{}, metaErr },
	}

	collector := newMockCollector(store, metaDB, keepTagsOpts())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), metaErr)
	require.Zero(t, store.locks)
}

func TestGCScanFailsClosedWhenStalePruneStatFails(t *testing.T) {
	store := &lockTrackingStore{}
	stale := godigest.FromString("stale-manifest")
	transient := errclass.MarkTransient(errors.New("stat blip")) //nolint:err113
	store.GetIndexContentFn = func(string) ([]byte, error) { return staleIndexJSON(stale), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{}, nil }
	store.StatBlobFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		return false, 0, time.Time{}, transient
	}

	collector := newMockCollector(store, nil, keepUntaggedOpts())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), zerr.ErrStorageTransient)
	require.Zero(t, store.locks)
}

func TestGCScanFailsWhenReferencedBlobWalkFails(t *testing.T) {
	store := &lockTrackingStore{}
	digest := godigest.FromBytes(manifestJSON())
	transient := errclass.MarkTransient(errors.New("read blip")) //nolint:err113
	store.GetIndexContentFn = func(string) ([]byte, error) { return staleIndexJSON(digest), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{digest}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return nil, transient }

	collector := newMockCollector(store, nil, keepUntaggedOpts())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), zerr.ErrStorageTransient)
	require.Zero(t, store.locks)
}

func TestGCScanStopsWhenCancelledDuringOrphanStat(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &lockTrackingStore{}
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) {
		return []godigest.Digest{godigest.FromString("first"), godigest.FromString("second")}, nil
	}
	store.StatBlobEntryFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		cancel()

		return true, 0, time.Now().Add(-time.Hour), nil
	}

	collector := newMockCollector(store, nil, Options{})
	require.ErrorIs(t, collector.CleanRepo(ctx, "repo"), context.Canceled)
	require.Zero(t, store.locks)
}

func TestGCScanRejectsInvalidDigestInBlobListing(t *testing.T) {
	store := &lockTrackingStore{}
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{"sha256:not-hex"}, nil }

	collector := newMockCollector(store, nil, Options{})
	require.Error(t, collector.CleanRepo(context.Background(), "repo"))
	require.Zero(t, store.locks)
}

func TestGCCommitStopsWhenCancelledBeforeLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &lockTrackingStore{onLock: cancel}
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t), nil }
	store.PutIndexContentFn = func(string, ispec.Index) error {
		t.Fatal("index.json written after cancellation")

		return nil
	}

	collector := newMockCollector(store, nil, Options{})
	require.ErrorIs(t, collector.CleanRepo(ctx, "repo"), context.Canceled)
	require.Equal(t, 1, store.locks)
}

func TestGCCommitMapsMissingIndexToRepoNotFound(t *testing.T) {
	store := &lockTrackingStore{}
	store.GetIndexContentFn = func(string) ([]byte, error) {
		if store.locked {
			return nil, errclass.MarkMissing(errors.New("index gone")) //nolint:err113
		}

		return indexJSON(t), nil
	}

	collector := newMockCollector(store, nil, Options{})
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), zerr.ErrRepoNotFound)
}

// A metaDB write that fails after index.json was committed restores the index the plan was computed
// from, as cleanRepoLocked does, so storage and metaDB stay aligned for a later pass.
func TestGCCommitRestoresIndexWhenMetaDBReplayFails(t *testing.T) {
	store := &lockTrackingStore{}
	digest := godigest.FromBytes(manifestJSON())
	replayErr := errors.New("replay failed") //nolint:err113
	puts := 0
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t, manifestDescriptor(digest, "v1")), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{digest}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return manifestJSON(), nil }
	store.PutIndexContentFn = func(_ string, index ispec.Index) error {
		puts++

		if puts == 2 {
			require.Len(t, index.Manifests, 1)
			require.Equal(t, digest, index.Manifests[0].Digest)
		}

		return nil
	}

	metaDB := mocks.MetaDBMock{
		GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
			return taggedRepoMeta("v1", digest), nil
		},
		RemoveRepoReferenceFn: func(string, string, godigest.Digest) error { return replayErr },
	}

	collector := newMockCollector(store, metaDB, keepTagsOpts())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), replayErr)
	require.Equal(t, 2, puts)
	require.Equal(t, 1, store.locks)
}

func TestGCCommitTreatsMissingSignatureMetaAsRemoved(t *testing.T) {
	store := &lockTrackingStore{}
	subject := godigest.FromString("subject")
	referrer := ispec.Manifest{
		MediaType:    ispec.MediaTypeImageManifest,
		ArtifactType: zcommon.ArtifactTypeNotation,
		Config:       ispec.DescriptorEmptyJSON,
		Subject:      &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: subject, Size: 1},
	}
	referrer.SchemaVersion = 2

	referrerBody, err := json.Marshal(referrer)
	require.NoError(t, err)

	referrerDigest := godigest.FromBytes(referrerBody)
	puts := 0
	store.GetIndexContentFn = func(string) ([]byte, error) {
		return indexJSON(t, manifestDescriptor(referrerDigest, "")), nil
	}
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{referrerDigest}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return referrerBody, nil }
	store.StatBlobFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		return true, 0, time.Now().Add(-time.Hour), nil
	}
	store.PutIndexContentFn = func(_ string, index ispec.Index) error {
		puts++

		require.Empty(t, index.Manifests)

		return nil
	}

	metaDB := mocks.MetaDBMock{
		DeleteSignatureFn: func(string, godigest.Digest, mTypes.SignatureMetadata) error {
			return zerr.ErrImageMetaNotFound
		},
	}

	deleteUntagged := false
	opts := Options{ImageRetention: config.ImageRetention{
		Policies: []config.RetentionPolicy{{
			Repositories: []string{"**"}, DeleteReferrers: true, DeleteUntagged: &deleteUntagged,
		}},
	}}

	collector := newMockCollector(store, metaDB, opts)
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	require.Equal(t, 1, puts)
}

func TestGCCommitFailsWhenUploadListingFails(t *testing.T) {
	store := &lockTrackingStore{}
	listErr := errors.New("uploads unavailable") //nolint:err113
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t), nil }
	store.ListBlobUploadsFn = func(string) ([]string, error) { return nil, listErr }
	store.PutIndexContentFn = func(string, ispec.Index) error {
		t.Fatal("index.json written after upload listing failed")

		return nil
	}

	collector := newMockCollector(store, nil, Options{})
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), listErr)
}

// A sparse index keeps a child whose manifest is missing from the listing. The reference walk
// records it, and the commit must fail closed when it cannot confirm the child is still absent.
func TestGCCommitFailsClosedWhenMissingReferenceStatFails(t *testing.T) {
	store := &lockTrackingStore{}
	present := godigest.FromBytes(manifestJSON())
	missing := godigest.FromString("missing-child")
	transient := errclass.MarkTransient(errors.New("stat blip")) //nolint:err113

	indexBody := indexJSON(t, manifestDescriptor(present, ""), manifestDescriptor(missing, ""))
	indexDigest := godigest.FromBytes(indexBody)

	store.GetIndexContentFn = func(string) ([]byte, error) {
		return indexJSON(t, ispec.Descriptor{MediaType: ispec.MediaTypeImageIndex, Digest: indexDigest, Size: 1}), nil
	}
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{indexDigest, present}, nil }
	store.GetBlobContentFn = func(_ string, digest godigest.Digest) ([]byte, error) {
		switch digest {
		case indexDigest:
			return indexBody, nil
		case present:
			return manifestJSON(), nil
		default:
			return nil, zerr.ErrBlobNotFound
		}
	}
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

	collector := newMockCollector(store, nil, keepUntaggedOpts())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), zerr.ErrStorageTransient)
	require.Equal(t, 1, store.locks)
}

func TestStaleDecisionHolds(t *testing.T) {
	nested := godigest.FromBytes(manifestJSON())
	indexBody := indexJSON(t, manifestDescriptor(nested, ""))
	emptyIndexBody := indexJSON(t)
	transient := errclass.MarkTransient(errors.New("stat blip")) //nolint:err113

	manifestDesc := manifestDescriptor(godigest.FromString("manifest"), "")
	indexDesc := ispec.Descriptor{MediaType: ispec.MediaTypeImageIndex, Digest: godigest.FromBytes(indexBody)}
	emptyIndexDesc := ispec.Descriptor{MediaType: ispec.MediaTypeImageIndex, Digest: godigest.FromBytes(emptyIndexBody)}

	type statFn = func(string, godigest.Digest) (bool, int64, time.Time, error)

	present := func(string, godigest.Digest) (bool, int64, time.Time, error) { return true, 1, time.Now(), nil }
	nestedStat := func(err error) statFn {
		return func(_ string, digest godigest.Digest) (bool, int64, time.Time, error) {
			if digest == nested {
				return false, 0, time.Time{}, err
			}

			return present("", digest)
		}
	}
	blob := func(body []byte, err error) func(string, godigest.Digest) ([]byte, error) {
		return func(string, godigest.Digest) ([]byte, error) { return body, err }
	}

	cases := []struct {
		name  string
		desc  ispec.Descriptor
		stat  statFn
		read  func(string, godigest.Digest) ([]byte, error)
		holds bool
		err   error
	}{
		{name: "restored manifest", desc: manifestDesc, stat: present},
		{name: "restored index that cannot be read", desc: indexDesc, stat: present, read: blob(nil, transient)},
		{name: "restored empty index", desc: emptyIndexDesc, stat: present, read: blob(emptyIndexBody, nil)},
		{name: "restored index with a present child", desc: indexDesc, stat: present, read: blob(indexBody, nil)},
		{
			name: "restored index whose child stat fails", desc: indexDesc, read: blob(indexBody, nil),
			stat: nestedStat(transient), err: transient,
		},
		{
			name: "restored index whose children are still absent", desc: indexDesc, read: blob(indexBody, nil),
			stat: nestedStat(zerr.ErrBlobNotFound), holds: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collector := GarbageCollect{
				imgStore: mocks.MockedImageStore{StatBlobFn: tc.stat, GetBlobContentFn: tc.read},
				log:      zlog.NewTestLogger(),
			}

			holds, err := collector.staleDecisionHolds("repo", tc.desc)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.holds, holds)
		})
	}
}

func TestGCRetentionRecheckWithoutRepoMetaFallsBackToLockedPass(t *testing.T) {
	store := &lockTrackingStore{}
	digest := godigest.FromBytes(manifestJSON())
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t, manifestDescriptor(digest, "v1")), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{digest}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return manifestJSON(), nil }

	metaDB := mocks.MetaDBMock{
		GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
			if store.locked {
				return mTypes.RepoMeta{}, zerr.ErrRepoMetaNotFound
			}

			return taggedRepoMeta("v1", digest), nil
		},
		RemoveRepoReferenceFn: func(string, string, godigest.Digest) error {
			t.Fatal("tag removed although its metadata vanished before commit")

			return nil
		},
	}

	collector := newMockCollector(store, metaDB, keepTagsOpts())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	require.Equal(t, maxOptimisticGCAttempts+1, store.locks)
}

func TestGCRetentionRecheckSurfacesRepoMetaError(t *testing.T) {
	store := &lockTrackingStore{}
	digest := godigest.FromBytes(manifestJSON())
	metaErr := errors.New("metadb unavailable") //nolint:err113
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t, manifestDescriptor(digest, "v1")), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{digest}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return manifestJSON(), nil }

	metaDB := mocks.MetaDBMock{
		GetRepoMetaFn: func(context.Context, string) (mTypes.RepoMeta, error) {
			if store.locked {
				return mTypes.RepoMeta{}, metaErr
			}

			return taggedRepoMeta("v1", digest), nil
		},
	}

	collector := newMockCollector(store, metaDB, keepTagsOpts())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), metaErr)
	require.Equal(t, 1, store.locks)
}

func TestGCCommitStopsWhenCancelledBeforeBlobDeletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &lockTrackingStore{}
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) {
		return []godigest.Digest{godigest.FromString("orphan")}, nil
	}
	store.StatBlobEntryFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		return true, 0, time.Now().Add(-time.Hour), nil
	}
	store.PutIndexContentFn = func(string, ispec.Index) error {
		cancel()

		return nil
	}
	store.CleanupRepoFn = func(string, []godigest.Digest) (int, error) {
		t.Fatal("cleanup ran after the context was cancelled")

		return 0, nil
	}

	collector := newMockCollector(store, nil, Options{})
	require.ErrorIs(t, collector.CleanRepo(ctx, "repo"), context.Canceled)
}

func TestGCCommitSkipsOrphanWhoseStatFailsUnderLock(t *testing.T) {
	store := &lockTrackingStore{}
	cleanups := 0
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) {
		return []godigest.Digest{godigest.FromString("orphan")}, nil
	}
	store.StatBlobEntryFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		if store.locked {
			return false, 0, time.Time{}, errclass.MarkTransient(errors.New("stat blip")) //nolint:err113
		}

		return true, 0, time.Now().Add(-time.Hour), nil
	}
	store.CleanupRepoFn = func(_ string, blobs []godigest.Digest) (int, error) {
		cleanups++

		require.Empty(t, blobs)

		return 0, nil
	}

	collector := newMockCollector(store, nil, Options{})
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	require.Equal(t, 1, cleanups)
}

func TestGCLockedPassSurfacesIdleRepositoryRemovalError(t *testing.T) {
	store := &lockTrackingStore{}
	digest := godigest.FromString("manifest")
	removeErr := errors.New("remove failed") //nolint:err113
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t, manifestDescriptor(digest, "v1")), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{digest}, nil }
	store.GetBlobContentFn = func(string, godigest.Digest) ([]byte, error) { return manifestJSON(), nil }
	store.RemoveIdleRepositoryFn = func(string, time.Duration) (bool, error) { return false, removeErr }

	collector := newMockCollector(store, nil, keepUntaggedOpts())
	require.ErrorIs(t, collector.CleanRepo(context.Background(), "repo"), removeErr)
	require.Equal(t, 1, store.locks)
}

func TestGCCommitContinuesWhenBestEffortMetaDBReplayFails(t *testing.T) {
	store := &lockTrackingStore{}
	stale := godigest.FromString("stale-manifest")
	puts := 0
	store.GetIndexContentFn = func(string) ([]byte, error) { return staleIndexJSON(stale), nil }
	store.GetAllBlobsFn = func(string) ([]godigest.Digest, error) { return []godigest.Digest{}, nil }
	store.StatBlobFn = func(string, godigest.Digest) (bool, int64, time.Time, error) {
		return false, 0, time.Time{}, zerr.ErrBlobNotFound
	}
	store.PutIndexContentFn = func(_ string, index ispec.Index) error {
		puts++

		require.Empty(t, index.Manifests)

		return nil
	}

	metaDB := mocks.MetaDBMock{
		RemoveRepoReferenceFn: func(string, string, godigest.Digest) error {
			return errors.New("metadb unavailable") //nolint:err113
		},
	}

	collector := newMockCollector(store, metaDB, keepUntaggedOpts())
	require.NoError(t, collector.CleanRepo(context.Background(), "repo"))
	require.Equal(t, 1, puts)
}

func TestGCCommitStopsWhenCancelledAfterUploadCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := &lockTrackingStore{}
	store.GetIndexContentFn = func(string) ([]byte, error) { return indexJSON(t), nil }
	store.ListBlobUploadsFn = func(string) ([]string, error) {
		cancel()

		return nil, nil
	}
	store.PutIndexContentFn = func(string, ispec.Index) error {
		t.Fatal("index.json written after cancellation")

		return nil
	}

	collector := newMockCollector(store, nil, Options{})
	require.ErrorIs(t, collector.CleanRepo(ctx, "repo"), context.Canceled)
}
