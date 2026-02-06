package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

func New(config *config.Config, linter common.Lint, metrics monitoring.MetricServer,
	log log.Logger, recorder events.Recorder,
) (StoreController, error) {
	storeController := StoreController{}

	if config.Storage.RootDirectory == "" {
		// we can't proceed without global storage
		log.Error().Err(zerr.ErrImgStoreNotFound).Str("component", "controller").
			Msg("no storage config provided")

		return storeController, zerr.ErrImgStoreNotFound
	}

	// no need to validate hard links work on s3
	if config.Storage.Dedupe && config.Storage.StorageDriver == nil {
		err := local.ValidateHardLink(config.Storage.RootDirectory)
		if err != nil {
			log.Warn().Msg("input storage root directory filesystem does not supports hardlinking," +
				"disabling dedupe functionality")

			config.Storage.Dedupe = false
		}
	}

	var defaultStore storageTypes.ImageStore

	if config.Storage.StorageDriver == nil {
		cacheDriver, err := CreateCacheDatabaseDriver(config.Storage.StorageConfig, log)
		if err != nil {
			return storeController, err
		}

		// false positive lint - linter does not implement Lint method
		//nolint:typecheck,contextcheck
		rootDir := config.Storage.RootDirectory
		defaultStore = local.NewImageStore(rootDir,
			config.Storage.Dedupe, config.Storage.Commit, log, metrics, linter, cacheDriver, config.HTTP.Compat, recorder,
		)
	} else {
		storeName := fmt.Sprintf("%v", config.Storage.StorageDriver["name"])
		if storeName != constants.S3StorageDriverName && storeName != constants.GCSStorageDriverName {
			log.Error().Err(zerr.ErrBadConfig).Str("storageDriver", storeName).
				Msg("unsupported storage driver")

			return storeController, fmt.Errorf("storageDriver '%s' unsupported storage driver: %w", storeName, zerr.ErrBadConfig)
		}

		// Init a Storager from connection string.
		store, err := factory.Create(context.Background(), storeName, config.Storage.StorageDriver)
		if err != nil {
			log.Error().Err(err).Str("rootDir", config.Storage.RootDirectory).Msg("failed to create s3 service")

			return storeController, err
		}

		/* in the case of s3 config.Storage.RootDirectory is used for caching blobs locally and
		config.Storage.StorageDriver["rootdirectory"] is the actual rootDir in s3 */
		rootDir := "/"
		if config.Storage.StorageDriver["rootdirectory"] != nil {
			rootDir = fmt.Sprintf("%v", config.Storage.StorageDriver["rootdirectory"])
		}

		cacheDriver, err := CreateCacheDatabaseDriver(config.Storage.StorageConfig, log)
		if err != nil {
			return storeController, err
		}

		// false positive lint - linter does not implement Lint method
		//nolint: typecheck,contextcheck
		if storeName == constants.S3StorageDriverName {
			defaultStore = s3.NewImageStore(rootDir, config.Storage.RootDirectory,
				config.Storage.Dedupe, config.Storage.Commit, log, metrics, linter, store, cacheDriver,
				config.HTTP.Compat, recorder)
		} else {
			defaultStore = gcs.NewImageStore(rootDir, config.Storage.RootDirectory,
				config.Storage.Dedupe, config.Storage.Commit, log, metrics, linter, store, cacheDriver,
				config.HTTP.Compat, recorder)
		}
	}

	storeController.DefaultStore = defaultStore

	if config.Storage.SubPaths != nil {
		if len(config.Storage.SubPaths) > 0 {
			subPaths := config.Storage.SubPaths

			//nolint: contextcheck
			subImageStore, err := getSubStore(config, subPaths, linter, metrics, log, recorder)
			if err != nil {
				log.Error().Err(err).Str("component", "controller").Msg("failed to get sub image store")

				return storeController, err
			}

			storeController.SubStore = subImageStore
		}
	}

	return storeController, nil
}

func getSubStore(cfg *config.Config, subPaths map[string]config.StorageConfig,
	linter common.Lint, metrics monitoring.MetricServer, log log.Logger, recorder events.Recorder,
) (map[string]storageTypes.ImageStore, error) {
	imgStoreMap := make(map[string]storageTypes.ImageStore, 0)

	subImageStore := make(map[string]storageTypes.ImageStore)

	// creating image store per subpaths
	for route, storageConfig := range subPaths {
		// no need to validate hard links work on s3
		if storageConfig.Dedupe && storageConfig.StorageDriver == nil {
			err := local.ValidateHardLink(storageConfig.RootDirectory)
			if err != nil {
				log.Warn().Msg("input storage root directory filesystem does not supports hardlinking, " +
					"disabling dedupe functionality")

				storageConfig.Dedupe = false
			}
		}

		if storageConfig.StorageDriver == nil {
			// Compare if subpath root dir is same as default root dir
			isSame, _ := config.SameFile(cfg.Storage.RootDirectory, storageConfig.RootDirectory)

			if isSame {
				log.Error().Err(zerr.ErrBadConfig).
					Msg("invalid sub path storage directory, it must be different to the root directory")

				return nil, zerr.ErrBadConfig
			}

			isUnique := true

			// Compare subpath unique files
			for file := range imgStoreMap {
				// We already have image storage for this file
				if compareImageStore(file, storageConfig.RootDirectory) {
					subImageStore[route] = imgStoreMap[file]

					isUnique = false
				}
			}

			// subpath root directory is unique
			// add it to uniqueSubFiles
			// Create a new image store and assign it to imgStoreMap
			if isUnique {
				cacheDriver, err := CreateCacheDatabaseDriver(storageConfig, log)
				if err != nil {
					return nil, err
				}

				rootDir := storageConfig.RootDirectory
				imgStoreMap[storageConfig.RootDirectory] = local.NewImageStore(rootDir,
					storageConfig.Dedupe, storageConfig.Commit, log, metrics, linter, cacheDriver, cfg.HTTP.Compat, recorder,
				)

				subImageStore[route] = imgStoreMap[storageConfig.RootDirectory]
			}
		} else {
			storeName := fmt.Sprintf("%v", storageConfig.StorageDriver["name"])
			if storeName != constants.S3StorageDriverName && storeName != constants.GCSStorageDriverName {
				log.Error().Err(zerr.ErrBadConfig).Str("storageDriver", storeName).
					Msg("unsupported storage driver")

				return nil, fmt.Errorf("storageDriver '%s' unsupported storage driver: %w", storeName, zerr.ErrBadConfig)
			}

			// Init a Storager from connection string.
			store, err := factory.Create(context.Background(), storeName, storageConfig.StorageDriver)
			if err != nil {
				log.Error().Err(err).Str("rootDir", storageConfig.RootDirectory).Msg("failed to create s3 service")

				return nil, err
			}

			/* in the case of s3 c.Config.Storage.RootDirectory is used for caching blobs locally and
			c.Config.Storage.StorageDriver["rootdirectory"] is the actual rootDir in s3 */
			rootDir := "/"
			if cfg.Storage.StorageDriver["rootdirectory"] != nil {
				rootDir = fmt.Sprintf("%v", cfg.Storage.StorageDriver["rootdirectory"])
			}

			cacheDriver, err := CreateCacheDatabaseDriver(storageConfig, log)
			if err != nil {
				log.Error().Err(err).Any("config", storageConfig).
					Msg("failed to create storage driver")

				return nil, err
			}

			// false positive lint - linter does not implement Lint method
			//nolint: typecheck
			if storeName == constants.S3StorageDriverName {
				subImageStore[route] = s3.NewImageStore(rootDir, storageConfig.RootDirectory,
					storageConfig.Dedupe, storageConfig.Commit, log, metrics, linter, store, cacheDriver, cfg.HTTP.Compat, recorder,
				)
			} else {
				subImageStore[route] = gcs.NewImageStore(rootDir, storageConfig.RootDirectory,
					storageConfig.Dedupe, storageConfig.Commit, log, metrics, linter, store, cacheDriver, cfg.HTTP.Compat, recorder,
				)
			}
		}
	}

	return subImageStore, nil
}

func compareImageStore(root1, root2 string) bool {
	isSameFile, err := config.SameFile(root1, root2)
	if err != nil {
		// This error is path error that means either of root directory doesn't exist, in that case do string match
		return strings.EqualFold(root1, root2)
	}

	return isSameFile
}

// CheckIsImageSignature checks if the given image (repo:tag) represents a signature. The function
// returns:
//
// - bool: if the image is a signature or not
//
// - string: the type of signature
//
// - string: the digest of the image it signs
//
// - error: any errors that occur.
func CheckIsImageSignature(repoName string, manifestBlob []byte, reference string,
) (bool, string, godigest.Digest, error) {
	var manifestContent ispec.Manifest

	err := json.Unmarshal(manifestBlob, &manifestContent)
	if err != nil {
		return false, "", "", err
	}

	manifestArtifactType := zcommon.GetManifestArtifactType(manifestContent)

	// check notation signature
	if manifestArtifactType == zcommon.ArtifactTypeNotation && manifestContent.Subject != nil {
		return true, NotationType, manifestContent.Subject.Digest, nil
	}

	// check cosign signature (OCI 1.1 support)
	if manifestArtifactType == zcommon.ArtifactTypeCosign && manifestContent.Subject != nil {
		return true, CosignType, manifestContent.Subject.Digest, nil
	}

	if tag := reference; zcommon.IsCosignSignature(reference) {
		prefixLen := len("sha256-")
		digestLen := 64
		signedImageManifestDigestEncoded := tag[prefixLen : prefixLen+digestLen]

		signedImageManifestDigest := godigest.NewDigestFromEncoded(godigest.SHA256,
			signedImageManifestDigestEncoded)

		return true, CosignType, signedImageManifestDigest, nil
	}

	return false, "", "", nil
}
