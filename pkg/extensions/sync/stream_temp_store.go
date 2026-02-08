package sync

import (
	"errors"
	"fmt"
	"os"
	"path"

	godigest "github.com/opencontainers/go-digest"
)

type StreamTempStore interface {
	BlobPath(digest godigest.Digest) string
}

type LocalTempStore struct {
	rootPath string
}

func NewLocalTempStore(rootDir string) *LocalTempStore {
	_, err := os.Stat(rootDir)
	if err != nil {
		os.MkdirAll(rootDir, 0o755)
	}

	return &LocalTempStore{
		rootPath: rootDir,
	}
}

func (lts *LocalTempStore) BlobPath(digest godigest.Digest) string {
	parentDir := path.Join(lts.rootPath, digest.Algorithm().String())
	_, err := os.Stat(parentDir)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(parentDir, 0o755)
		if err != nil {
			fmt.Println("failed to create directory " + err.Error())
		}
	}

	return path.Join(parentDir, digest.Encoded())
}
