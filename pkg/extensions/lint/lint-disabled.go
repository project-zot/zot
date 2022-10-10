//go:build !lint
// +build !lint

package lint

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/storage"
)

type Linter struct{}

func (linter *Linter) Lint(repo string, manifestDigest godigest.Digest,
	imageStore storage.ImageStore,
) (bool, error) {
	return true, nil
}
