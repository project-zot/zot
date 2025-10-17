package storage

import (
	godigest "github.com/opencontainers/go-digest"

	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type Lint interface {
	Lint(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error)
}
