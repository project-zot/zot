//go:build !sync
// +build !sync

package server

import (
	"zotregistry.io/zot/pkg/api/config"
	syncconf "zotregistry.io/zot/pkg/extensions/config/sync"
	zlog "zotregistry.io/zot/pkg/log"
)

func validateRetentionSyncOverlaps(config *config.Config, content syncconf.Content, urls []string, log zlog.Logger) {
}
