//go:build lint
// +build lint

package extensions

import (
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/extensions/lint"
	"zotregistry.dev/zot/pkg/log"
)

func GetLinter(config *config.Config, log log.Logger) *lint.Linter {
	if config.Extensions == nil {
		return lint.NewLinter(nil, log)
	}

	return lint.NewLinter(config.Extensions.Lint, log)
}
