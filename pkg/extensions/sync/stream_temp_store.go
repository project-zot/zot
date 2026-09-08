//go:build sync

package sync

import (
	"errors"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
)

// streamTempSubdir is the directory name, under a repo's own ImageStore root, where blobs being
// streamed to clients are staged while they're still arriving from upstream.
const streamTempSubdir = "_stream"

// StreamTempStore maps a (repo, blob digest) pair to the on-disk path a ChunkedBlobReader should
// write to while that blob is being downloaded from upstream and streamed to clients. Only ever
// called at active-stream creation time (see prepareActiveStreamForBlob in stream_manager.go);
// once a stream exists for a digest, its resolved path is fixed for the stream's lifetime and
// reused directly from the ChunkedBlobReader, never recomputed here.
type StreamTempStore interface {
	BlobPath(repo string, digest godigest.Digest) string
}

// LocalTempStore roots each blob's temp path under the repo's own sync staging directory, so
// staging files land on whatever local volume that repo is configured to use - the repo's own
// ImageStore root for a local-filesystem backend, or extensions.sync.downloadDir for a
// remote-backed one (S3/Azure/GCS), the same local staging directory non-streaming sync and GC
// already use via StoreController.SyncStagingRootForRepo.
type LocalTempStore struct {
	storeController storage.StoreController
	logger          log.Logger
}

func NewLocalTempStore(storeController storage.StoreController, logger log.Logger) *LocalTempStore {
	return &LocalTempStore{
		storeController: storeController,
		logger:          logger,
	}
}

// BlobPath returns the on-disk path a blob's content is written to, for example
// "<repo's sync staging root>/_stream/sha256/<encoded digest>". The digest parameter is always
// a validated godigest.Digest (never a raw string), so this never needs to independently guard
// against path traversal from caller input.
// Uses raw os.* calls against the staging root rather than going through the repo's
// StorageDriver (imageStore.storeDriver), unlike every other blob write in the codebase - this is
// always a real local filesystem path (SyncStagingRootForRepo maps remote-backed repos onto
// extensions.sync.downloadDir precisely so that holds), so this is staging-scratch-space use of
// the local disk, not a departure from how the backend's actual blob storage works.
func (lts *LocalTempStore) BlobPath(repo string, digest godigest.Digest) string {
	rootDir := lts.storeController.SyncStagingRootForRepo(repo)
	parentDir := path.Join(rootDir, streamTempSubdir, digest.Algorithm().String())

	if _, err := os.Stat(parentDir); err != nil && errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(parentDir, 0o755); err != nil {
			// Not fatal here: the caller will fail with a clear error the next time it tries to
			// use this path (open for write/read), so surface it there instead of exiting.
			lts.logger.Error().Str("parentDir", parentDir).Err(err).Msg("failed to create directory")
		}
	}

	return path.Join(parentDir, digest.Encoded())
}
