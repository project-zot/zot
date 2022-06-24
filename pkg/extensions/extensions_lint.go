//go:build lint
// +build lint

package extensions

import (
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/lint"
	"zotregistry.io/zot/pkg/log"
)

func GetLinter(config *config.Config, log log.Logger) *lint.Linter {
	if config.Extensions == nil {
		return lint.NewLinter(nil, log)
	}

	return lint.NewLinter(config.Extensions.Lint, log)
}
