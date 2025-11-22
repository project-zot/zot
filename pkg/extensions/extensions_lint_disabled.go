//go:build !lint

package extensions

import (
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/lint"
	"zotregistry.dev/zot/v2/pkg/log"
)

func GetLinter(config *config.Config, log log.Logger) *lint.Linter {
	log.Warn().Msg("lint extension is disabled because given zot binary doesn't " +
		"include this feature please build a binary that does so")

	return nil
}
