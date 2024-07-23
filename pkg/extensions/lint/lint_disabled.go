//go:build !lint
// +build !lint

package lint

import (
	godigest "github.com/opencontainers/go-digest"

	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

type Linter struct{}

func (linter *Linter) Lint(repo string, manifestDigest godigest.Digest,
	imageStore storageTypes.ImageStore,
) (bool, error) {
	return true, nil
}
