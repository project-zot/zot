package storage

import (
	godigest "github.com/opencontainers/go-digest"

	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

type Lint interface {
	Lint(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error)
}
