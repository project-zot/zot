//go:build sync
// +build sync

package server

import (
	"path"

	"zotregistry.dev/zot/pkg/api/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/extensions/sync"
	zlog "zotregistry.dev/zot/pkg/log"
)

func validateRetentionSyncOverlaps(config *config.Config, content syncconf.Content, urls []string, log zlog.Logger) {
	cm := sync.NewContentManager([]syncconf.Content{content}, log)

	prefix := content.Prefix
	if content.Destination != "" {
		prefix = cm.GetRepoDestination(content.Prefix)
	}

	repoPolicy := getRepoPolicyByPrefix(config, prefix)
	if repoPolicy == nil {
		return
	}

	if content.Tags != nil && content.Tags.Regex != nil {
		areTagsRetained := false

		for _, tagPolicy := range repoPolicy.KeepTags {
			for _, tagRegex := range tagPolicy.Patterns {
				if tagRegex == *content.Tags.Regex {
					areTagsRetained = true
				}
			}
		}

		if !areTagsRetained {
			log.Warn().Str("repositories pattern", prefix).
				Str("tags regex", *content.Tags.Regex).
				Interface("sync urls", urls).
				Interface("overlapping sync content", content).
				Interface("overlapping repo policy", repoPolicy).
				Msgf("retention policy can overlap with the sync config, "+
					"make sure retention doesn't remove syncing images with next tag regex: %s", *content.Tags.Regex)
		}
	} else {
		log.Warn().Str("repositories pattern", prefix).
			Interface("sync urls", urls).
			Interface("overlapping sync content", content).
			Interface("overlapping repo policy", repoPolicy).
			Msg("retention policy can overlap with the sync config, make sure retention doesn't remove syncing images")
	}
}

func getRepoPolicyByPrefixFromStorageConfig(config config.StorageConfig, subpath string, prefix string,
) *config.RetentionPolicy {
	for _, repoPolicy := range config.Retention.Policies {
		for _, repo := range repoPolicy.Repositories {
			if subpath != "" {
				repo = path.Join(subpath, repo)[1:] // remove startin '/'
			}

			if repo == prefix {
				return &repoPolicy
			}
		}
	}

	return nil
}

func getRepoPolicyByPrefix(config *config.Config, prefix string) *config.RetentionPolicy {
	if repoPolicy := getRepoPolicyByPrefixFromStorageConfig(config.Storage.StorageConfig, "", prefix); repoPolicy != nil {
		return repoPolicy
	}

	for subpath, subpathConfig := range config.Storage.SubPaths {
		if repoPolicy := getRepoPolicyByPrefixFromStorageConfig(subpathConfig, subpath, prefix); repoPolicy != nil {
			return repoPolicy
		}
	}

	return nil
}
