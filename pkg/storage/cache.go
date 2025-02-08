package storage

import (
	"fmt"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	rediscfg "zotregistry.dev/zot/pkg/api/config/redis"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage/cache"
	"zotregistry.dev/zot/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

func CreateCacheDatabaseDriver(storageConfig config.StorageConfig, log zlog.Logger) (storageTypes.Cache, error) {
	if !storageConfig.Dedupe && storageConfig.StorageDriver == nil {
		return nil, nil //nolint:nilnil
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

			return nil, nil //nolint:nilnil
		}

		if name != constants.DynamoDBDriverName &&
			name != constants.RedisDriverName {
			log.Warn().Str("driver", name).Msg("remote cache driver unsupported!")

			return nil, nil //nolint:nilnil
		}

		if name == constants.DynamoDBDriverName {
			// dynamodb
			dynamoParams, err := getDynamoParams(&storageConfig)
			if err != nil {
				return nil, err
			}

			return Create(name, dynamoParams, log)
		}

		if name == constants.RedisDriverName {
			// redis
			redisParams, err := getRedisParams(&storageConfig, log)
			if err != nil {
				return nil, err
			}

			return Create(name, redisParams, log)
		}
	}

	return nil, nil //nolint:nilnil
}

func Create(dbtype string, parameters interface{}, log zlog.Logger) (storageTypes.Cache, error) {
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
			return cache.NewRedisCache(parameters, log)
		}
	default:
		{
			return nil, zerr.ErrBadConfig
		}
	}
}

func getUseRelPaths(storageConfig *config.StorageConfig) bool {
	// In case of local storage we use rel paths, in case of S3 we don't
	return storageConfig.StorageDriver == nil
}

func getDynamoParams(storageConfig *config.StorageConfig) (cache.DynamoDBDriverParameters, error) {
	dynamoParams := cache.DynamoDBDriverParameters{}
	dynamoParams.Endpoint, _ = storageConfig.CacheDriver["endpoint"].(string)
	dynamoParams.Region, _ = storageConfig.CacheDriver["region"].(string)
	dynamoParams.TableName, _ = storageConfig.CacheDriver["cachetablename"].(string)

	cachetable, ok := storageConfig.CacheDriver["cachetablename"]
	if !ok {
		return dynamoParams, fmt.Errorf("%w: cachetablename key is mandatory for dynamodb cache driver", zerr.ErrBadConfig)
	}

	dynamoParams.TableName, ok = cachetable.(string)
	if !ok {
		return dynamoParams, fmt.Errorf("%w: failed to cast cachetablename %s to string type", zerr.ErrBadConfig, cachetable)
	}

	return dynamoParams, nil
}

func getRedisParams(storageConfig *config.StorageConfig, log zlog.Logger) (cache.RedisDriverParameters, error) {
	redisParams := cache.RedisDriverParameters{}

	client, err := rediscfg.GetRedisClient(storageConfig.CacheDriver, log)
	if err != nil {
		return redisParams, err
	}

	redisParams.RootDir = storageConfig.RootDirectory
	redisParams.Client = client
	redisParams.KeyPrefix, _ = storageConfig.CacheDriver["keyprefix"].(string)
	redisParams.UseRelPaths = getUseRelPaths(storageConfig)

	return redisParams, nil
}
