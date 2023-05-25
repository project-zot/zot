package extensions

import (
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
)

func GetExtensions(config *config.Config) distext.ExtensionList {
	extensionList := distext.ExtensionList{}

	endpoints := []string{}
	extensions := []distext.Extension{}

	if config.Extensions != nil && config.Extensions.Search != nil {
		if IsBuiltWithSearchExtension() {
			endpoints = append(endpoints, constants.FullSearchPrefix)
		}

		if IsBuiltWithUserPrefsExtension() {
			endpoints = append(endpoints, constants.FullUserPreferencesPrefix)
		}
	}

	if IsBuiltWithMGMTExtension() && config.Extensions != nil && config.Extensions.Mgmt != nil {
		endpoints = append(endpoints, constants.FullMgmtPrefix)
	}

	if len(endpoints) > 0 {
		extensions = append(extensions, distext.Extension{
			Name:        "_zot",
			URL:         "https://github.com/project-zot/zot/blob/" + config.ReleaseTag + "/pkg/extensions/_zot.md",
			Description: "zot registry extensions",
			Endpoints:   endpoints,
		})
	}

	extensionList.Extensions = extensions

	return extensionList
}
