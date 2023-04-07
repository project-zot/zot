package common

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/storage"
)

type Lint interface {
	Lint(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error)
}
