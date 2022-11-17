//go:build !lint
// +build !lint

package lint

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/pkg/storage"
)

type Linter struct{}

func (linter *Linter) Lint(repo string, manifestDescriptor ispec.Descriptor,
	imageStore storage.ImageStore,
) (bool, error) {
	return true, nil
}
