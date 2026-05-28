//go:build lint

package extensions

import (
	"os"
	"path/filepath"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/imagetrust"
	"zotregistry.dev/zot/v2/pkg/extensions/lint"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	sconstants "zotregistry.dev/zot/v2/pkg/storage/constants"
)

func GetLinter(config *config.Config, log log.Logger) *lint.Linter {
	if config.Extensions == nil {
		return lint.NewLinter(nil, log)
	}

	linter := lint.NewLinter(config.Extensions.Lint, log)
	if config.Extensions.Lint == nil || len(config.Extensions.Lint.MandatorySignatures) == 0 {
		return linter
	}

	extensionsConfig := config.CopyExtensionsConfig()
	if !IsBuiltWithImageTrustExtension() || !extensionsConfig.IsImageTrustEnabled() {
		log.Warn().Msg("mandatory signatures lint requires image trust and trust store configuration")
		linter.SetSignatureVerifier(nil, false)

		return linter
	}

	var (
		imageTrustStore mTypes.ImageTrustStore
		err             error
	)

	if config.Storage.RemoteCache && config.Storage.CacheDriver["name"] == sconstants.DynamoDBDriverName {
		endpoint, _ := config.Storage.CacheDriver["endpoint"].(string)
		region, _ := config.Storage.CacheDriver["region"].(string)
		imageTrustStore, err = imagetrust.NewAWSImageTrustStore(region, endpoint)
	} else {
		imageTrustStore, err = imagetrust.NewLocalImageTrustStore(config.Storage.RootDirectory)
	}

	if err != nil {
		log.Warn().Err(err).Msg("mandatory signatures lint could not initialize trust store")
		linter.SetSignatureVerifier(nil, false)

		return linter
	}

	trustStoreReady := true
	if !config.Storage.RemoteCache && !hasLocalTrustStoreMaterial(config.Storage.RootDirectory) {
		log.Warn().Msg("mandatory signatures lint is enabled, but no trust store certificates or keys are configured")
		trustStoreReady = false
	}

	linter.SetSignatureVerifier(imageTrustStore, trustStoreReady)

	return linter
}

func hasLocalTrustStoreMaterial(rootDir string) bool {
	return hasFile(filepath.Join(rootDir, "_cosign")) ||
		hasFile(filepath.Join(rootDir, "_notation", "truststore", "x509"))
}

func hasFile(root string) bool {
	stat, err := os.Stat(root)
	if err != nil || !stat.IsDir() {
		return false
	}

	hasMaterial := false
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			hasMaterial = true
		}

		return nil
	})

	return hasMaterial
}
