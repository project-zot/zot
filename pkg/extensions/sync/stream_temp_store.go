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

// streamTempSubdir is the directory, under a repo's sync staging root, holding blobs that are
// still downloading for streaming clients. It sits beside the repos, not in a <repo>/.sync session,
// so the staging reaper (which only reaps .sync/<session> dirs by mtime) never removes a live
// stream's file; the stream manager deletes each file itself. The leading "_" can't start a repo
// name, so it never collides with one.
const streamTempSubdir = "_stream"

// StreamTempStore picks the temp file path for a blob being streamed. It is only consulted when a
// stream is created.
type StreamTempStore interface {
	BlobPath(repo string, digest godigest.Digest) string
}

// LocalTempStore puts temp files under the repo's sync staging root: the repo's own root on a
// local filesystem, or extensions.sync.downloadDir for S3/Azure/GCS (the same place plain sync
// stages).
type LocalTempStore struct {
	storeController storage.StoreController
	logger          log.Logger
}

// NewLocalTempStore returns a LocalTempStore for storeController's repos.
func NewLocalTempStore(storeController storage.StoreController, logger log.Logger) *LocalTempStore {
	return &LocalTempStore{
		storeController: storeController,
		logger:          logger,
	}
}

// BlobPath returns "<sync staging root>/_stream/<algorithm>/<encoded digest>". digest is already
// validated, so it can't escape the directory. Uses os.* directly rather than the storage driver
// because the staging root is always on the local disk.
func (lts *LocalTempStore) BlobPath(repo string, digest godigest.Digest) string {
	rootDir := lts.storeController.SyncStagingRootForRepo(repo)
	parentDir := path.Join(rootDir, streamTempSubdir, digest.Algorithm().String())

	if _, err := os.Stat(parentDir); err != nil && errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(parentDir, 0o755); err != nil {
			// Not fatal here: opening the file fails next, with a clearer error.
			lts.logger.Error().Str("parentDir", parentDir).Err(err).Msg("failed to create directory")
		}
	}

	return path.Join(parentDir, digest.Encoded())
}
