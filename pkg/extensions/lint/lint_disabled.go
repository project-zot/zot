//go:build !lint

package lint

import (
	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/log"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

type Linter struct{}

func NewLinter(config *config.LintConfig, log log.Logger) *Linter {
	return &Linter{}
}

func (linter *Linter) Lint(repo string, manifestDigest godigest.Digest,
	imageStore storageTypes.ImageStore,
) (bool, error) {
	return true, nil
}
