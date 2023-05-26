package storage

import (
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/cache"
	"zotregistry.io/zot/pkg/storage/constants"
)

func CreateCacheDatabaseDriver(storageConfig config.StorageConfig, log zlog.Logger) cache.Cache {
	if !storageConfig.Dedupe && storageConfig.StorageDriver == nil {
		return nil
	}

	// local cache
	if !storageConfig.RemoteCache {
		params := cache.BoltDBDriverParameters{}
		params.RootDir = storageConfig.RootDirectory
		params.Name = constants.BoltdbName
		params.UseRelPaths = getUseRelPaths(&storageConfig)

		driver, _ := Create("boltdb", params, log)

		return driver
	}

	// remote cache
	if storageConfig.CacheDriver != nil {
		name, ok := storageConfig.CacheDriver["name"].(string)
		if !ok {
			log.Warn().Msg("remote cache driver name missing!")

			return nil
		}

		if name != constants.DynamoDBDriverName {
			log.Warn().Str("driver", name).Msg("remote cache driver unsupported!")

			return nil
		}

		// dynamodb
		dynamoParams := cache.DynamoDBDriverParameters{}
		dynamoParams.Endpoint, _ = storageConfig.CacheDriver["endpoint"].(string)
		dynamoParams.Region, _ = storageConfig.CacheDriver["region"].(string)
		dynamoParams.TableName, _ = storageConfig.CacheDriver["cachetablename"].(string)

		driver, _ := Create("dynamodb", dynamoParams, log)

		return driver
	}

	return nil
}

func Create(dbtype string, parameters interface{}, log zlog.Logger) (cache.Cache, error) {
	switch dbtype {
	case "boltdb":
		{
			return cache.NewBoltDBCache(parameters, log), nil
		}
	case "dynamodb":
		{
			return cache.NewDynamoDBCache(parameters, log), nil
		}
	default:
		{
			return nil, errors.ErrBadConfig
		}
	}
}

func getUseRelPaths(storageConfig *config.StorageConfig) bool {
	return storageConfig.StorageDriver == nil
}
