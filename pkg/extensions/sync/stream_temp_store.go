package sync

import (
	"encoding/json"
	"os"
	"path"
	"sync"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type StreamTempStore interface {
	Manifest(name, ref string) (ispec.Manifest, error)
	WriteManifest(name string, ref string, manifest ispec.Manifest) error
	BlobPath(digest string) string
}

type LocalTempStore struct {
	rootPath string

	// TODO: figure out this locking behaviour
	manifestLocks map[string]sync.RWMutex
	manifestMu    sync.RWMutex
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

func (lts *LocalTempStore) Manifest(name, ref string) (ispec.Manifest, error) {
	lts.manifestMu.RLock()
	defer lts.manifestMu.RUnlock()

	manifestFilePath := path.Join(lts.rootPath, name+ref+".json")

	_, err := os.Stat(manifestFilePath)
	if err != nil {
		return ispec.Manifest{}, err
	}

	manifestContent, err := os.ReadFile(manifestFilePath)
	if err != nil {
		return ispec.Manifest{}, err
	}

	var manifest ispec.Manifest
	err = json.Unmarshal(manifestContent, &manifest)
	if err != nil {
		return ispec.Manifest{}, err
	}

	return manifest, nil
}

func (lts *LocalTempStore) WriteManifest(name string, ref string, manifest ispec.Manifest) error {
	lts.manifestMu.Lock()
	defer lts.manifestMu.Unlock()

	manifestFilePath := path.Join(lts.rootPath, name+ref+".json")
	content, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	err = os.WriteFile(manifestFilePath, content, 0o644)
	if err != nil {
		return err
	}

	return nil
}

func (lts *LocalTempStore) BlobPath(digest string) string {
	return path.Join(lts.rootPath + digest)
}
