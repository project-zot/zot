//go:build !lint
// +build !lint

package extensions

import (
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/lint"
	"zotregistry.io/zot/pkg/log"
)

func GetLinter(config *config.Config, log log.Logger) *lint.Linter {
	log.Warn().Msg("lint extension is disabled because given zot binary doesn't " +
		"include this feature please build a binary that does so")

	return nil
}
