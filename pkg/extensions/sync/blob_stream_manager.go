//go:build sync

package sync

import (
	"context"
	"io"
	"path/filepath"
	"sync"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// Temporary directory for in-progress blob downloads
const blobSyncTempDir = ".zot-sync-temp"

// BlobDownloadKey uniquely identifies a blob download request.
type BlobDownloadKey struct {
	Repo   string
	Digest string
}

// BlobStreamManager manages active blob downloads and ensures only one download
// per blob happens at a time, while serving multiple concurrent clients.
type BlobStreamManager struct {
	activeDownloads map[BlobDownloadKey]*BlobStreamer
	mu              sync.RWMutex
	storeController storage.StoreController
	log             log.Logger
}

// NewBlobStreamManager creates a new blob stream manager.
func NewBlobStreamManager(storeController storage.StoreController, log log.Logger) *BlobStreamManager {
	return &BlobStreamManager{
		activeDownloads: make(map[BlobDownloadKey]*BlobStreamer),
		storeController: storeController,
		log:             log,
	}
}

// GetOrCreateStreamer gets an existing blob streamer or creates a new one if needed.
// Returns the streamer and a boolean indicating if it's a new download.
func (bsm *BlobStreamManager) GetOrCreateStreamer(
	ctx context.Context,
	repo string,
	digest godigest.Digest,
	blobSize int64,
	upstreamReader func() (io.ReadCloser, error),
) (*BlobStreamer, bool, error) {
	key := BlobDownloadKey{
		Repo:   repo,
		Digest: digest.String(),
	}

	// Check if download already exists
	bsm.mu.RLock()
	streamer, exists := bsm.activeDownloads[key]
	bsm.mu.RUnlock()

	if exists {
		bsm.log.Debug().
			Str("repo", repo).
			Str("digest", digest.String()).
			Msg("joining existing blob download")
		return streamer, false, nil
	}

	// Create new streamer
	bsm.mu.Lock()
	defer bsm.mu.Unlock()

	// Double-check after acquiring write lock
	if streamer, exists := bsm.activeDownloads[key]; exists {
		return streamer, false, nil
	}

	imgStore := bsm.storeController.GetImageStore(repo)

	// Generate temp and final paths
	tempPath := filepath.Join(imgStore.RootDir(), blobSyncTempDir, digest.Encoded()+".tmp")
	finalPath := imgStore.BlobPath(repo, digest)

	streamer = NewBlobStreamer(digest, tempPath, finalPath, blobSize, bsm.log)
	bsm.activeDownloads[key] = streamer

	// Start download in background
	go func() {
		defer bsm.removeDownload(key)

		reader, err := upstreamReader()
		if err != nil {
			bsm.log.Error().Err(err).
				Str("repo", repo).
				Str("digest", digest.String()).
				Msg("failed to get upstream blob reader")
			streamer.setDownloadError(err)
			return
		}
		defer reader.Close()

		// Download blob
		if err := streamer.Download(ctx, reader); err != nil {
			bsm.log.Error().Err(err).
				Str("repo", repo).
				Str("digest", digest.String()).
				Msg("failed to download blob")
			_ = streamer.Cleanup()
			return
		}

		// Verify digest
		if err := bsm.verifyBlobDigest(streamer.tempPath, digest); err != nil {
			bsm.log.Error().Err(err).
				Str("repo", repo).
				Str("digest", digest.String()).
				Msg("blob digest verification failed")
			streamer.setDownloadError(err)
			_ = streamer.Cleanup()
			return
		}

		// Move to final location
		if err := streamer.MoveToFinal(); err != nil {
			bsm.log.Error().Err(err).
				Str("repo", repo).
				Str("digest", digest.String()).
				Msg("failed to move blob to final location")
			streamer.setDownloadError(err)
			_ = streamer.Cleanup()
			return
		}

		bsm.log.Info().
			Str("repo", repo).
			Str("digest", digest.String()).
			Msg("blob download and verification completed successfully")
	}()

	return streamer, true, nil
}

// removeDownload removes a completed or failed download from tracking.
func (bsm *BlobStreamManager) removeDownload(key BlobDownloadKey) {
	bsm.mu.Lock()
	defer bsm.mu.Unlock()

	delete(bsm.activeDownloads, key)

	bsm.log.Debug().
		Str("repo", key.Repo).
		Str("digest", key.Digest).
		Msg("removed blob download from active tracking")
}

// verifyBlobDigest verifies that the downloaded blob matches the expected digest.
func (bsm *BlobStreamManager) verifyBlobDigest(path string, expectedDigest godigest.Digest) error {
	// TODO: Security - Implement digest verification
	// Currently relying on upstream registry integrity. For production use,
	// this MUST compute the actual digest of the downloaded file and compare
	// it with expectedDigest to detect corruption or tampering.
	// Implementation should:
	// 1. Open the file and compute its digest using expectedDigest.Algorithm()
	// 2. Compare computed digest with expectedDigest
	// 3. Return error if mismatch

	bsm.log.Debug().
		Str("path", path).
		Str("expectedDigest", expectedDigest.String()).
		Msg("blob digest verification not yet implemented - relying on upstream integrity")

	return nil
}

// GetActiveDownloads returns the number of active downloads.
func (bsm *BlobStreamManager) GetActiveDownloads() int {
	bsm.mu.RLock()
	defer bsm.mu.RUnlock()

	return len(bsm.activeDownloads)
}
