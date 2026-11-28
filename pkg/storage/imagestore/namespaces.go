package imagestore

import (
	"path/filepath"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zreg "zotregistry.dev/zot/v2/pkg/regexp"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// PruneEmptyNamespaces removes empty namespace directories below the store root at startup.
func (is *ImageStore) PruneEmptyNamespaces() {
	is.pruneEmptyNamespaceDir(filepath.Clean(is.rootDir), true)
}

// pruneEmptyNamespaceDir visits children before attempting to remove their parent.
func (is *ImageStore) pruneEmptyNamespaceDir(dir string, preserveRoot bool) {
	children, err := is.storeDriver.ListSubDirs(dir)
	if err != nil {
		if !errclass.IsStorageObjectMissing(err) {
			is.log.Error().Err(err).Str("dir", dir).Msg("failed to list namespace directories")
		}

		return
	}

	for _, child := range children {
		if isNamespaceComponent(filepath.Base(child)) {
			is.pruneEmptyNamespaceDir(child, false)
		}
	}

	if preserveRoot {
		return
	}

	if err := is.storeDriver.RemoveEmptyDir(dir); err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to remove empty namespace directory")
	}
}

// isNamespaceComponent accepts repository path components outside the OCI layout.
func isNamespaceComponent(name string) bool {
	switch name {
	case ispec.ImageBlobsDir, ispec.ImageIndexFile, ispec.ImageLayoutFile:
		return false
	default:
		return zreg.FullNameRegexp.MatchString(name)
	}
}
