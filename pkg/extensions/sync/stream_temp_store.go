package sync

import (
	"errors"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
)

type StreamTempStore interface {
	BlobPath(digest godigest.Digest) string
}

type LocalTempStore struct {
	rootPath string
	logger   log.Logger
}

func NewLocalTempStore(rootDir string, logger log.Logger) *LocalTempStore {
	_, err := os.Stat(rootDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			err := os.MkdirAll(rootDir, 0o755)
			if err != nil {
				// If the root directory cannot be created, log a fatal error and exit.
				logger.Fatal().Str("rootDir", rootDir).Err(err).Msg("failed to create root dir for stream temp store")
			}
		} else {
			// If there is an error other than "not exists", log a fatal error and exit.
			logger.Fatal().Str("rootDir", rootDir).Err(err).Msg("failed to stat root dir for stream temp store")
		}
	}

	return &LocalTempStore{
		rootPath: rootDir,
		logger:   logger,
	}
}

func (lts *LocalTempStore) BlobPath(digest godigest.Digest) string {
	parentDir := path.Join(lts.rootPath, digest.Algorithm().String())
	_, err := os.Stat(parentDir)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(parentDir, 0o755)
		if err != nil {
			// It is safe to not use fatal here as the stream will hit an error while
			// trying to use the blob path, and the error will be handled there.
			lts.logger.Error().Str("parentDir", parentDir).Err(err).Msg("failed to create directory")
		}
	}

	return path.Join(parentDir, digest.Encoded())
}
