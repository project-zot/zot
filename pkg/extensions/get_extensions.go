package extensions

import (
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/scheduler"
)

func GetExtensions(config *config.Config) distext.ExtensionList {
	extensionList := distext.ExtensionList{}

	endpoints := []string{}
	extensions := []distext.Extension{}

	if config.IsNotationEnabled() && IsBuiltWithImageTrustExtension() {
		endpoints = append(endpoints, constants.FullNotation)
	}

	if config.IsCosignEnabled() && IsBuiltWithImageTrustExtension() {
		endpoints = append(endpoints, constants.FullCosign)
	}

	if config.IsSearchEnabled() && IsBuiltWithSearchExtension() {
		endpoints = append(endpoints, constants.FullSearchPrefix)
	}

	if config.AreUserPrefsEnabled() && IsBuiltWithUserPrefsExtension() {
		endpoints = append(endpoints, constants.FullUserPrefs)
	}

	if config.IsMgmtEnabled() && IsBuiltWithMGMTExtension() {
		endpoints = append(endpoints, constants.FullMgmt)
	}

	if len(endpoints) > 0 {
		extensions = append(extensions, distext.Extension{
			Name:        constants.BaseExtension,
			URL:         "https://github.com/project-zot/zot/blob/" + config.ReleaseTag + "/pkg/extensions/_zot.md",
			Description: "zot registry extensions",
			Endpoints:   endpoints,
		})
	}

	extensionList.Extensions = extensions

	return extensionList
}

func EnableScheduledTasks(conf *config.Config, taskScheduler *scheduler.Scheduler,
	metaDB mTypes.MetaDB, log log.Logger,
) {
	EnableImageTrustVerification(conf, taskScheduler, metaDB, log)
}

func SetupExtensions(conf *config.Config, metaDB mTypes.MetaDB, log log.Logger) error {
	return SetupImageTrustExtension(conf, metaDB, log)
}
