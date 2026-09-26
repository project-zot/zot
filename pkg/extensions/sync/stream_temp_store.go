//go:build sync

package sync

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
)

// streamTempSubdir, under a sync staging root, holds streaming blobs' temp files. It sits outside
// any <repo>/.sync session, so the staging reaper never removes a live stream's file. The stream
// manager deletes each file; a crash's leftovers go at the next start (gc.RemoveStreamTempDirs).
const streamTempSubdir = syncConstants.StreamTempDir

// StreamTempStore picks the temp file path for a blob being streamed.
type StreamTempStore interface {
	BlobPath(repo string, digest godigest.Digest) (string, error)
}

// LocalTempStore puts temp files under the repo's sync staging root (the storage root on local
// disk, or extensions.sync.downloadDir for S3/Azure/GCS), where plain sync stages too.
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

// BlobPath returns "<sync staging root>/_stream/<algorithm>/<encoded digest>", the prefix of the
// stream's unique temp file (see prepareActiveStreamForBlob), creating its parent directory. An
// invalid digest is rejected, so the path can't escape _stream. The staging root is always local
// disk, hence os.* rather than the storage driver.
func (lts *LocalTempStore) BlobPath(repo string, digest godigest.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}

	rootDir := lts.storeController.SyncStagingRootForRepo(repo)
	if rootDir == "" {
		// A remote store without extensions.sync.downloadDir (config validation rejects this).
		// Fail rather than stage relative to the CWD, where startup cleanup would never look.
		return "", fmt.Errorf("%w: %s", zerr.ErrSyncNoStagingRoot, repo)
	}

	parentDir := path.Join(rootDir, streamTempSubdir, digest.Algorithm().String())

	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		lts.logger.Error().Str("parentDir", parentDir).Err(err).Msg("failed to create directory")

		return "", err
	}

	return path.Join(parentDir, digest.Encoded()), nil
}

// linkOrCopyFile places src at dst: a hard link when both are on one filesystem (the usual case:
// streams and the sync's temp layout share the repo's staging root), a copy otherwise, e.g. a
// stream shared with a repo in another substore. An existing dst is kept: blobs are named by
// digest, so it holds the same content.
func linkOrCopyFile(src, dst string) error {
	if err := os.MkdirAll(path.Dir(dst), storageConstants.DefaultDirPerms); err != nil {
		return err
	}

	err := os.Link(src, dst)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return nil
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Copy under a temp name and rename, so dst never exists partially written.
	out, err := os.CreateTemp(path.Dir(dst), path.Base(dst)+".*.tmp")
	if err != nil {
		return err
	}

	_, err = io.Copy(out, srcFile)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}

	if err == nil {
		err = os.Rename(out.Name(), dst)
	}

	if err != nil {
		_ = os.Remove(out.Name())
	}

	return err
}
