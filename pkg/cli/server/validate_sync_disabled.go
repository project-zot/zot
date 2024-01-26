//go:build !sync
// +build !sync

package server

import (
	"zotregistry.dev/zot/pkg/api/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	zlog "zotregistry.dev/zot/pkg/log"
)

func validateRetentionSyncOverlaps(config *config.Config, content syncconf.Content, urls []string, log zlog.Logger) {
}
