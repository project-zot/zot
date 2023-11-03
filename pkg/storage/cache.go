package storage

import (
	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage/cache"
	"zotregistry.dev/zot/pkg/storage/constants"
)

func CreateCacheDatabaseDriver(storageConfig config.StorageConfig, log zlog.Logger) (cache.Cache, error) {
	if !storageConfig.Dedupe && storageConfig.StorageDriver == nil {
		return nil, nil
	}

	// local cache
	if !storageConfig.RemoteCache {
		params := cache.BoltDBDriverParameters{}
		params.RootDir = storageConfig.RootDirectory
		params.Name = constants.BoltdbName
		params.UseRelPaths = getUseRelPaths(&storageConfig)

		return Create("boltdb", params, log)
	}

	// remote cache
	if storageConfig.CacheDriver != nil {
		name, ok := storageConfig.CacheDriver["name"].(string)
		if !ok {
			log.Warn().Msg("remote cache driver name missing!")

			return nil, nil
		}

		if name != constants.DynamoDBDriverName {
			log.Warn().Str("driver", name).Msg("remote cache driver unsupported!")

			return nil, nil
		}

		// dynamodb
		dynamoParams := cache.DynamoDBDriverParameters{}
		dynamoParams.Endpoint, _ = storageConfig.CacheDriver["endpoint"].(string)
		dynamoParams.Region, _ = storageConfig.CacheDriver["region"].(string)
		dynamoParams.TableName, _ = storageConfig.CacheDriver["cachetablename"].(string)

		return Create("dynamodb", dynamoParams, log)
	}

	return nil, nil
}

func Create(dbtype string, parameters interface{}, log zlog.Logger) (cache.Cache, error) {
	switch dbtype {
	case "boltdb":
		{
			return cache.NewBoltDBCache(parameters, log)
		}
	case "dynamodb":
		{
			return cache.NewDynamoDBCache(parameters, log)
		}
	case "redis":
		{
			return cache.NewRedisCache(parameters, log), nil
		}
	default:
		{
			return nil, zerr.ErrBadConfig
		}
	}
}

func getUseRelPaths(storageConfig *config.StorageConfig) bool {
	return storageConfig.StorageDriver == nil
}
