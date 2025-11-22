//go:build !sync

package server

import (
	"zotregistry.dev/zot/v2/pkg/api/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	zlog "zotregistry.dev/zot/v2/pkg/log"
)

func validateRetentionSyncOverlaps(config *config.Config, content syncconf.Content, urls []string, log zlog.Logger) {
}
