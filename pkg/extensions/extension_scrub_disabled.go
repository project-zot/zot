//go:build !scrub
// +build !scrub

package extensions

import (
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// EnableScrubExtension ...
func EnableScrubExtension(config *config.Config,
	log log.Logger, run bool,
	imgStore storage.ImageStore, repo string,
) {
	log.Warn().Msg("skipping enabling scrub extension because given zot binary doesn't include this feature," +
		"please build a binary that does so")
}
