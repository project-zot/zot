package meta

import (
	"fmt"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	rediscfg "zotregistry.dev/zot/pkg/api/config/redis"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta/boltdb"
	mdynamodb "zotregistry.dev/zot/pkg/meta/dynamodb"
	"zotregistry.dev/zot/pkg/meta/redisdb"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	sconstants "zotregistry.dev/zot/pkg/storage/constants"
)

func New(storageConfig config.StorageConfig, log log.Logger) (mTypes.MetaDB, error) {
	if storageConfig.RemoteCache {
		if storageConfig.CacheDriver["name"] == sconstants.DynamoDBDriverName {
			dynamoParams := getDynamoParams(storageConfig.CacheDriver, log)

			client, err := mdynamodb.GetDynamoClient(dynamoParams)
			if err != nil {
				return nil, err
			}

			return mdynamodb.New(client, dynamoParams, log) //nolint:contextcheck
		}

		if storageConfig.CacheDriver["name"] == sconstants.RedisDriverName {
			redisParams := getRedisParams(storageConfig.CacheDriver, log)

			client, err := rediscfg.GetRedisClient(storageConfig.CacheDriver, log)
			if err != nil { //nolint:wsl
				return nil, err
			}

			return redisdb.New(client, redisParams, log) //nolint:contextcheck
		}

		// this behavior is also mentioned in the configuration validation logic inside the cli package
		return nil, fmt.Errorf("%w: cachedriver %s and remotecache %t", errors.ErrBadConfig,
			storageConfig.CacheDriver["name"], storageConfig.RemoteCache)
	}

	if driverName, ok := storageConfig.CacheDriver["name"]; ok && driverName != sconstants.BoltdbName {
		// this behavior is also mentioned in the configuration validation logic inside the cli package
		log.Warn().Interface("cachedriver", driverName).Bool("remotecache", storageConfig.RemoteCache).
			Msg("unsupported cachedriver for remotecache disabled, will default to boltdb")
	}

	params := boltdb.DBParameters{}
	params.RootDir = storageConfig.RootDirectory

	driver, err := boltdb.GetBoltDriver(params)
	if err != nil {
		return nil, err
	}

	return boltdb.New(driver, log) //nolint:contextcheck
}

func getDynamoParams(cacheDriverConfig map[string]interface{}, log log.Logger) mdynamodb.DBDriverParameters {
	allParametersOk := true

	endpoint, ok := toStringIfOk(cacheDriverConfig, "endpoint", "", log)
	allParametersOk = allParametersOk && ok

	region, ok := toStringIfOk(cacheDriverConfig, "region", "", log)
	allParametersOk = allParametersOk && ok

	repoMetaTablename, ok := toStringIfOk(cacheDriverConfig, "repometatablename", "", log)
	allParametersOk = allParametersOk && ok

	repoBlobsInfoTablename, ok := toStringIfOk(cacheDriverConfig, "repoblobsinfotablename", "", log)
	allParametersOk = allParametersOk && ok

	imageMetaTablename, ok := toStringIfOk(cacheDriverConfig, "imagemetatablename", "", log)
	allParametersOk = allParametersOk && ok

	apiKeyTablename, ok := toStringIfOk(cacheDriverConfig, "apikeytablename", "", log)
	allParametersOk = allParametersOk && ok

	versionTablename, ok := toStringIfOk(cacheDriverConfig, "versiontablename", "", log)
	allParametersOk = allParametersOk && ok

	userDataTablename, ok := toStringIfOk(cacheDriverConfig, "userdatatablename", "", log)
	allParametersOk = allParametersOk && ok

	if !allParametersOk {
		log.Panic().Msg("dynamo parameters are not specified correctly, can't proceed")
	}

	return mdynamodb.DBDriverParameters{
		Endpoint:               endpoint,
		Region:                 region,
		RepoMetaTablename:      repoMetaTablename,
		RepoBlobsInfoTablename: repoBlobsInfoTablename,
		ImageMetaTablename:     imageMetaTablename,
		UserDataTablename:      userDataTablename,
		APIKeyTablename:        apiKeyTablename,
		VersionTablename:       versionTablename,
	}
}

func getRedisParams(cacheDriverConfig map[string]interface{}, log log.Logger) redisdb.DBDriverParameters {
	keyPrefix, ok := toStringIfOk(cacheDriverConfig, "keyprefix", "zot", log)
	if !ok {
		log.Panic().Msg("redis parameters are not specified correctly, can't proceed")
	}

	return redisdb.DBDriverParameters{
		KeyPrefix: keyPrefix,
	}
}

func toStringIfOk(cacheDriverConfig map[string]interface{},
	param string,
	defaultVal string,
	log log.Logger,
) (string, bool) {
	val, ok := cacheDriverConfig[param]

	if !ok && defaultVal != "" {
		log.Info().Str("field", param).Str("default", defaultVal).
			Msg("field is not present in CacheDriver config, using default value")

		return defaultVal, true
	} else if !ok {
		log.Error().Str("field", param).Msg("failed to parse CacheDriver config, field is not present")

		return "", false
	}

	str, ok := val.(string)
	if !ok {
		log.Error().Str("parameter", param).Msg("failed to parse CacheDriver config, parameter isn't a string")

		return "", false
	}

	if str == "" {
		log.Error().Str("field", param).Msg("failed to parse CacheDriver config, field is empty")

		return "", false
	}

	return str, true
}
