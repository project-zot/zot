//go:build sync

package sync

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/descriptor"
	manifestpkg "github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// streamDrainTimeout bounds how long teardown waits for stalled clients before closing them. It is
// one deadline for all blobs torn down together, since teardown holds the reference's flight.
const streamDrainTimeout = 30 * time.Second

type ChunkingStreamManager struct {
	tempStore       StreamTempStore
	storeController storage.StoreController
	// activeStreams maps streamKey(source, digest) to that blob's stream. Clients pulling a blob
	// through the same registry share it. The source is in the key because bytes reach clients
	// before the digest is verified: never feed a client another registry's bytes.
	activeStreams map[string]*ChunkedBlobReader
	// streamingRefs maps "repo:reference" to its staged image manifest (never an index).
	streamingRefs map[string]*StreamableManifest
	// blobInfoMap holds each stream key's blob descriptor.
	blobInfoMap map[string]descriptor.Descriptor
	// refCounts counts the staged repo:references using each stream key; the last one tears it down.
	refCounts map[string]int
	// draining counts streams torn down (out of activeStreams) whose temp files are not deleted
	// yet: their clients may take up to drainTimeout to finish. They still count against
	// maxConcurrentStreams, which bounds the temp files on staging disk.
	draining             int
	maxConcurrentStreams int
	// drainTimeout is streamDrainTimeout; a field so tests can shorten it.
	drainTimeout time.Duration
	logger       log.Logger
	streamLock   sync.Mutex
}

// streamKey namespaces a blob digest by the source registry streaming it (see activeStreams).
func streamKey(source, blobDigest string) string {
	return source + "@" + blobDigest
}

// NewChunkingStreamManager stages blobs under each repo's sync staging directory.
// maxConcurrentStreams <= 0 means syncConstants.DefaultMaxConcurrentStreams.
func NewChunkingStreamManager(storeController storage.StoreController, maxConcurrentStreams int,
	logger log.Logger,
) *ChunkingStreamManager {
	return &ChunkingStreamManager{
		tempStore:            NewLocalTempStore(storeController, logger),
		storeController:      storeController,
		activeStreams:        map[string]*ChunkedBlobReader{},
		streamingRefs:        map[string]*StreamableManifest{},
		blobInfoMap:          map[string]descriptor.Descriptor{},
		refCounts:            map[string]int{},
		maxConcurrentStreams: normalizeMaxConcurrentStreams(maxConcurrentStreams),
		drainTimeout:         streamDrainTimeout,
		logger:               logger,
	}
}

// normalizeMaxConcurrentStreams maps n <= 0 to syncConstants.DefaultMaxConcurrentStreams.
func normalizeMaxConcurrentStreams(n int) int {
	if n <= 0 {
		return syncConstants.DefaultMaxConcurrentStreams
	}

	return n
}

// SetMaxConcurrentStreams changes the cap on a config reload. If lowered, active streams keep
// running and new ones are refused until enough finish.
func (sm *ChunkingStreamManager) SetMaxConcurrentStreams(maxConcurrentStreams int) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	sm.maxConcurrentStreams = normalizeMaxConcurrentStreams(maxConcurrentStreams)
}

// MaxConcurrentStreams returns the current cap on distinct streams.
func (sm *ChunkingStreamManager) MaxConcurrentStreams() int {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	return sm.maxConcurrentStreams
}

// ConnectClient attaches a client to blobDigest's active stream for repo.
func (sm *ChunkingStreamManager) ConnectClient(repo, blobDigest string, writer io.Writer) (BlobCopier, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	// Validate the client's digest before using it as a map key or log field.
	if _, err := godigest.Parse(blobDigest); err != nil {
		return nil, err
	}

	// Only serve blobs of a manifest staged under this repo, or a client of repo B could read a
	// blob streaming for private repo A by its digest.
	source, ok := sm.sourceForRepoDigest(repo, blobDigest)
	if !ok {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	stream, ok := sm.activeStreams[streamKey(source, blobDigest)]
	if !ok {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	// A failed producer never finishes the blob; refuse so the caller rechecks storage first.
	if stream.Err() != nil {
		return nil, zerr.ErrBlobNotFoundInActiveStreams
	}

	// Subscribe under streamLock: the caller writes a 200 next, so teardown must already see this
	// client and keep the temp file.
	announceChan, subscriptionID := stream.Subscribe()

	copier := NewInFlightBlobCopier(stream, stream.OnDiskPath(), writer, announceChan, subscriptionID, sm.logger)
	sm.logger.Debug().Str("repo", repo).Str("blob", blobDigest).Msg("connected client for blob")

	return copier, nil
}

// sourceForRepoDigest returns the source of the manifests staged under repo that stream blobDigest.
// If they disagree it returns false: we can't tell which manifest the client followed, so we can't
// pick a source it trusts. Must be called with streamLock held.
func (sm *ChunkingStreamManager) sourceForRepoDigest(repo, blobDigest string) (string, bool) {
	prefix := repo + ":"

	var (
		found  string
		exists bool
	)

	for key, staged := range sm.streamingRefs {
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		// Blobs already local at staging have no stream; storage serves them.
		if _, ok := staged.streamKeys[streamKey(staged.source, blobDigest)]; !ok {
			continue
		}

		if exists && found != staged.source {
			sm.logger.Debug().Str("repo", repo).Str("blob", blobDigest).
				Msg("blob staged under repo from more than one source, not streaming it")

			return "", false
		}

		found, exists = staged.source, true
	}

	return found, exists
}

// HasStreamsForRepo reports whether any manifest staged under repo has blob streams.
func (sm *ChunkingStreamManager) HasStreamsForRepo(repo string) bool {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	prefix := repo + ":"

	for key, staged := range sm.streamingRefs {
		if strings.HasPrefix(key, prefix) && len(staged.streamKeys) > 0 {
			return true
		}
	}

	return false
}

// CachedBlobInfo returns a streaming blob's size and media type, known from the staged manifest
// before its download starts.
func (sm *ChunkingStreamManager) CachedBlobInfo(repo, blobDigest string) (int64, string, error) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	source, ok := sm.sourceForRepoDigest(repo, blobDigest)
	if !ok {
		return 0, "", zerr.ErrBlobNotFound
	}

	key := streamKey(source, blobDigest)

	// As in ConnectClient, don't advertise a failed stream: its GET would be refused.
	stream, ok := sm.activeStreams[key]
	if !ok || stream.Err() != nil {
		return 0, "", zerr.ErrBlobNotFound
	}

	desc, ok := sm.blobInfoMap[key]
	if !ok {
		return 0, "", zerr.ErrBlobNotFound
	}

	return desc.Size, desc.MediaType, nil
}

// streamedBlob is one stream of a staged image, as DownloadStreamedBlobs downloads it.
type streamedBlob struct {
	desc   descriptor.Descriptor
	stream *ChunkedBlobReader
}

// DownloadStreamedBlobs downloads repo:reference's streamed blobs for its background sync, each
// into its stream's temp file, which clients read as it fills. A stream another staged reference's
// sync is already downloading is waited for instead, so concurrent syncs share one download.
//
// It returns the temp file of each blob that completed, by digest. The sync links them into its
// layout, where ImageCopy finds them present and doesn't download them again, so a streamed blob
// is held on disk once. A failed blob is left out, and ImageCopy downloads it as usual.
//
// Downloads run concurrently; regclient's per-host throttle (reqConcurrent) bounds them.
func (sm *ChunkingStreamManager) DownloadStreamedBlobs(ctx context.Context, repo, reference string,
	fetch BlobFetcher,
) map[godigest.Digest]string {
	blobs := sm.streamedBlobs(repo, reference)

	var (
		completeMu sync.Mutex
		wg         sync.WaitGroup
	)

	complete := make(map[godigest.Digest]string, len(blobs))

	for _, streamed := range blobs {
		wg.Go(func() {
			var err error

			// A waiter holds no regclient throttle slot, and a download waits on nothing but
			// upstream, so two syncs waiting on each other's blobs can't deadlock.
			if streamed.stream.Claim() {
				err = sm.downloadStream(ctx, streamed, fetch)
			} else {
				err = streamed.stream.Wait(ctx)
			}

			if err != nil {
				sm.logger.Warn().Err(err).Str("repo", repo).Str("reference", reference).
					Str("blob", streamed.desc.Digest.String()).
					Msg("streamed blob did not complete, the sync will download it itself")

				return
			}

			completeMu.Lock()
			complete[streamed.desc.Digest] = streamed.stream.OnDiskPath()
			completeMu.Unlock()
		})
	}

	wg.Wait()

	return complete
}

// streamedBlobs returns the streams repo:reference's sync downloads: its config and layers not
// already local. They stay valid until RemoveStreamingImage, which runs after the sync.
func (sm *ChunkingStreamManager) streamedBlobs(repo, reference string) []streamedBlob {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	staged, ok := sm.streamingRefs[repo+":"+reference]
	if !ok {
		return nil
	}

	blobs := make([]streamedBlob, 0, len(staged.streamKeys))

	for key := range staged.streamKeys {
		stream, ok := sm.activeStreams[key]
		if !ok {
			continue
		}

		blobs = append(blobs, streamedBlob{desc: sm.blobInfoMap[key], stream: stream})
	}

	return blobs
}

// downloadStream fetches streamed's blob from upstream and fills its stream. The caller has
// claimed it.
func (sm *ChunkingStreamManager) downloadStream(ctx context.Context, streamed streamedBlob, fetch BlobFetcher) error {
	upstream, err := fetch(ctx, streamed.desc)
	if err != nil {
		streamed.stream.FailStart(err)

		return err
	}

	defer upstream.Close()

	// Only teardown can close a claimed stream first; nothing would read this one.
	if !streamed.stream.InitReader(upstream, streamed.desc) {
		return zerr.ErrStreamIncomplete
	}

	sm.logger.Debug().Str("blob", streamed.desc.Digest.String()).Msg("downloading streamed blob")

	return streamed.stream.Fill()
}

// prepareActiveStreamForBlob creates desc's stream from source, or adds a reference to an existing
// one. Must be called with streamLock held.
func (sm *ChunkingStreamManager) prepareActiveStreamForBlob(repo, source string, desc descriptor.Descriptor) error {
	digest := desc.Digest.String()
	key := streamKey(source, digest)

	if _, ok := sm.activeStreams[key]; ok {
		sm.refCounts[key]++
		sm.logger.Debug().Str("blob", digest).Str("source", source).Int("refCount", sm.refCounts[key]).
			Msg("active stream already exists for blob, adding reference")

		return nil
	}

	// The cap counts distinct streams, draining ones included; joining one (above) is always
	// allowed.
	if len(sm.activeStreams)+sm.draining >= sm.maxConcurrentStreams {
		return zerr.ErrTooManyConcurrentStreams
	}

	sm.logger.Debug().Str("blob", digest).Str("source", source).Msg("adding blob to active stream")

	// A unique file per stream: BlobPath is the same for every stream of a digest, and truncating
	// one still draining would corrupt it. CreateTemp (O_EXCL) also keeps it unique across
	// managers, e.g. after a reload turns streaming off and on while old streams drain.
	blobPath, err := sm.tempStore.BlobPath(repo, desc.Digest)
	if err != nil {
		return err
	}

	reserved, err := os.CreateTemp(filepath.Dir(blobPath), filepath.Base(blobPath)+".*")
	if err != nil {
		return err
	}

	onDiskPath := reserved.Name()
	_ = reserved.Close()

	reader, err := NewChunkedBlobReader(onDiskPath, sm.logger)
	if err != nil {
		_ = os.Remove(onDiskPath)

		return err
	}

	sm.activeStreams[key] = reader
	sm.blobInfoMap[key] = desc
	sm.refCounts[key] = 1

	return nil
}

// StoreImageForStreaming stages repo:reference's manifest and creates a stream per blob not
// already local. See StreamManager for why the returned manifest may differ from the one passed in.
func (sm *ChunkingStreamManager) StoreImageForStreaming(repo, reference string,
	manifest *StreamableManifest,
) (*StreamableManifest, error) {
	// Dedupe blobs and check storage before taking streamLock: a slow backend must not stall
	// every other repo's streams.
	descs := map[string]descriptor.Descriptor{}

	// Docker schema2 manifests stream alongside OCI.
	manifestMediaType := manifestpkg.GetMediaType(manifest.referenceManifest)
	switch manifestMediaType {
	case manifestpkg.MediaTypeOCI1Manifest, manifestpkg.MediaTypeDocker2Manifest:
		if err := sm.collectManifestDescriptorsForStream(repo, reference, manifest.referenceManifest, descs); err != nil {
			sm.logger.Error().Err(err).
				Str("repo", repo).
				Str("reference", reference).
				Str("manifest", manifest.referenceManifest.GetDescriptor().Digest.String()).
				Msg("failed to prepare manifest for stream")

			return nil, zerr.ErrSyncFailedToPrepareManifest
		}
	default:
		// Includes indexes: their sync is sparse, so they are never staged.
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Str("mediaType", manifestMediaType).Msg("invalid manifest mediatype")

		return nil, zerr.ErrSyncInvalidManifestMediaType
	}

	// Blobs the repo already stores get no stream: the sync seeds them (BaseService.shouldSeedRef),
	// so no producer would ever feed it, and storage serves them. This also keeps
	// maxConcurrentStreams a cap on real downloads.
	for digest, desc := range descs {
		if sm.isBlobLocal(repo, desc.Digest) {
			delete(descs, digest)
		}
	}

	sm.streamLock.Lock()

	key := repo + ":" + reference

	// Already staged: return that manifest, not ours. For a moved tag they differ, and only the
	// staged one has streams. Our callbacks ride on its sync.
	if existing, ok := sm.streamingRefs[key]; ok {
		existing.onSynced = append(existing.onSynced, manifest.onSynced...)

		sm.streamLock.Unlock()
		sm.logger.Warn().Str("repo", repo).Str("reference", reference).
			Msg("streaming manifest already exists for repo:reference")

		return existing, nil
	}

	// On failure (e.g. the cap), release only the references this call took.
	prepared := make(map[string]struct{}, len(descs))

	for digest, desc := range descs {
		if err := sm.prepareActiveStreamForBlob(repo, manifest.source, desc); err != nil {
			sm.logger.Error().Err(err).Str("repo", repo).Str("reference", reference).
				Str("blob", digest).Msg("failed to prepare active stream for blob")

			readers := sm.releaseStreams(prepared)
			sm.streamLock.Unlock()

			sm.drainAndDeleteStreams(readers)

			// Keep the cap error distinct: the caller falls back to a plain sync.
			if errors.Is(err, zerr.ErrTooManyConcurrentStreams) {
				return nil, err
			}

			return nil, zerr.ErrSyncFailedToPrepareManifest
		}

		prepared[streamKey(manifest.source, digest)] = struct{}{}
	}

	// Register last, so no one sees a partially staged entry.
	manifest.streamKeys = prepared
	sm.streamingRefs[key] = manifest

	sm.streamLock.Unlock()

	return manifest, nil
}

// isBlobLocal reports whether repo itself stores digest, using the same check as seeding
// (refSeeder.localBlobStat). An error counts as not local: an extra stream only costs a cap slot,
// a missing one would leave a client without the blob.
func (sm *ChunkingStreamManager) isBlobLocal(repo string, digest godigest.Digest) bool {
	imgStore := sm.storeController.GetImageStore(repo)
	if imgStore == nil {
		return false
	}

	var found bool

	err := imgStore.WithRepoReadLock(repo, func() error {
		var err error

		found, _, _, err = imgStore.StatBlob(repo, digest)

		return err
	})

	return err == nil && found
}

// collectManifestDescriptorsForStream adds manifest's config and layers to out, by digest: the blobs
// the background sync downloads. The manifest itself gets no stream: ImageCopy fetches it as a
// manifest, so nothing would feed one, and clients are served the staged manifest.
// Any failure is fatal: a manifest must not be partially staged.
func (sm *ChunkingStreamManager) collectManifestDescriptorsForStream(repo, reference string,
	manifest manifestpkg.Manifest, out map[string]descriptor.Descriptor,
) error {
	imager, ok := manifest.(manifestpkg.Imager)
	if !ok {
		sm.logger.Error().Str("repo", repo).Str("reference", reference).
			Msg("failed to cast manifest to imager")

		return zerr.ErrBadManifest
	}

	configDesc, err := imager.GetConfig()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get config descriptor from manifest")

		return err
	}

	layers, err := imager.GetLayers()
	if err != nil {
		sm.logger.Error().Err(err).Msg("failed to get layers from manifest")

		return err
	}

	for _, desc := range append([]descriptor.Descriptor{configDesc}, layers...) {
		// Upstream descriptors are untrusted, and a digest names the stream's temp file and its
		// link in the sync's layout: an invalid one (e.g. an algorithm with "/") could escape them.
		if err := desc.Digest.Validate(); err != nil {
			sm.logger.Error().Err(err).Str("repo", repo).Str("reference", reference).
				Str("digest", desc.Digest.String()).Msg("invalid blob digest in manifest")

			return err
		}

		out[desc.Digest.String()] = desc
	}

	return nil
}

// StreamingImageManifest returns the manifest staged for repo:reference, if any.
func (sm *ChunkingStreamManager) StreamingImageManifest(repo, reference string) (*StreamableManifest, bool) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	key := repo + ":" + reference
	manifest, ok := sm.streamingRefs[key]

	return manifest, ok
}

// JoinStreamingImage returns repo:reference's staged manifest, if any, and registers onSynced on
// it, both under streamLock so RemoveStreamingImage can't drop the callback.
func (sm *ChunkingStreamManager) JoinStreamingImage(repo, reference string,
	onSynced func(manifestpkg.Manifest),
) (*StreamableManifest, bool) {
	sm.streamLock.Lock()
	defer sm.streamLock.Unlock()

	manifest, ok := sm.streamingRefs[repo+":"+reference]
	if ok && onSynced != nil {
		manifest.onSynced = append(manifest.onSynced, onSynced)
	}

	return manifest, ok
}

// waitSynced waits until m is unstaged and reports whether its sync succeeded. Only for a manifest
// returned by StoreImageForStreaming, which built it with NewStreamableManifest.
func (m *StreamableManifest) waitSynced() bool {
	<-m.done

	return m.synced
}

// RemoveStreamingImage unstages repo:reference, releases its streams, and, if synced, runs its
// onSynced callbacks. Callbacks and draining run without streamLock, so a stalled client can't
// block other streams.
func (sm *ChunkingStreamManager) RemoveStreamingImage(repo, reference string, synced bool) {
	sm.streamLock.Lock()

	key := repo + ":" + reference

	manifest, ok := sm.streamingRefs[key]
	if !ok {
		sm.streamLock.Unlock()
		sm.logger.Debug().Str("repo", repo).Str("reference", reference).
			Msg("no streaming manifest found for repo:reference")

		return
	}

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("removing streaming image")

	delete(sm.streamingRefs, key)

	// Release exactly what staging took; the manifest's other blobs may be another repo's streams.
	readers := sm.releaseStreams(manifest.streamKeys)
	callbacks := manifest.onSynced
	manifest.onSynced = nil

	sm.streamLock.Unlock()

	// Before draining, so a slow client doesn't delay them.
	if synced {
		for _, onSynced := range callbacks {
			onSynced(manifest.referenceManifest)
		}
	}

	// After the callbacks, so a flight waiting on this one returns once they have run.
	if manifest.done != nil {
		manifest.synced = synced
		close(manifest.done)
	}

	sm.drainAndDeleteStreams(readers)

	sm.logger.Info().Str("repo", repo).Str("reference", reference).Msg("finished removing streaming image")
}

// releaseStreams drops one reference per key and returns the readers that reached zero, already
// unmapped so a new stage starts fresh instead of joining one being torn down. They count as
// draining until drainAndDeleteStreams deletes their files. Must be called with streamLock held;
// drain the readers after releasing it.
func (sm *ChunkingStreamManager) releaseStreams(keys map[string]struct{}) map[string]*ChunkedBlobReader {
	readers := make(map[string]*ChunkedBlobReader, len(keys))

	for key := range keys {
		count, ok := sm.refCounts[key]
		if !ok {
			continue
		}

		count--
		if count > 0 {
			sm.refCounts[key] = count

			continue
		}

		if reader, ok := sm.activeStreams[key]; ok {
			readers[key] = reader
			sm.draining++
		}

		delete(sm.activeStreams, key)
		delete(sm.blobInfoMap, key)
		delete(sm.refCounts, key)
	}

	return readers
}

// drainAndDeleteStreams waits for each reader's clients, then deletes its temp file. All readers
// share one deadline (see streamDrainTimeout). Must be called without streamLock held.
func (sm *ChunkingStreamManager) drainAndDeleteStreams(readers map[string]*ChunkedBlobReader) {
	deadline := time.Now().Add(sm.drainTimeout)

	var wg sync.WaitGroup

	for key, reader := range readers {
		// Nothing will feed this blob again: fail an unstarted or cut-short stream. A finished
		// one is left for its clients to drain.
		reader.Abort()

		wg.Go(func() {
			reader.WaitForClientEmpty(time.Until(deadline))
			sm.deleteStreamFile(key, reader.OnDiskPath())

			// Its cap slot frees only now that the file is gone (even if the delete failed: that
			// is logged, and a slot must not leak forever).
			sm.streamLock.Lock()
			sm.draining--
			sm.streamLock.Unlock()
		})
	}

	wg.Wait()
}

// deleteStreamFile removes a stream's temp file, if present. streamID is only used for logging.
// Called without streamLock held.
func (sm *ChunkingStreamManager) deleteStreamFile(streamID, blobPath string) {
	_, err := os.Stat(blobPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		sm.logger.Error().Err(err).Str("blob", streamID).Msg("failed to stat blob in temp store")

		return
	}

	if err := os.Remove(blobPath); err != nil {
		sm.logger.Error().Err(err).Str("blob", streamID).Msg("failed to remove blob from temp store")
	}
}
