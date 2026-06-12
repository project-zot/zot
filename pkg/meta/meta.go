package meta

import (
	"fmt"
	"strings"

	"zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	rediscfg "zotregistry.dev/zot/v2/pkg/api/config/redis"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/boltdb"
	mdynamodb "zotregistry.dev/zot/v2/pkg/meta/dynamodb"
	"zotregistry.dev/zot/v2/pkg/meta/redis"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	sconstants "zotregistry.dev/zot/v2/pkg/storage/constants"
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

			return redis.New(client, redisParams, log) //nolint:contextcheck
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

func getDynamoParams(cacheDriverConfig map[string]any, log log.Logger) mdynamodb.DBDriverParameters {
	allParametersOk := true

	endpoint, ok := toStringIfOk(cacheDriverConfig, "endpoint", "", log)
	allParametersOk = allParametersOk && ok

	region, ok := toStringIfOk(cacheDriverConfig, "region", "", log)
	allParametersOk = allParametersOk && ok

	tablenamePrefix, hasTablenamePrefix, ok := optionalStringIfOk(
		cacheDriverConfig, sconstants.DynamoDBTableNamePrefix, log)
	allParametersOk = allParametersOk && ok

	repoMetaTablename, ok := tableNameIfOk(cacheDriverConfig, sconstants.DynamoDBRepoMetaTable,
		sconstants.DynamoDBRepoMetaSuffix, tablenamePrefix, hasTablenamePrefix, log)
	allParametersOk = allParametersOk && ok

	repoBlobsInfoTablename, ok := tableNameIfOk(cacheDriverConfig, sconstants.DynamoDBRepoBlobsTable,
		sconstants.DynamoDBRepoBlobsSuffix, tablenamePrefix, hasTablenamePrefix, log)
	allParametersOk = allParametersOk && ok

	imageMetaTablename, ok := tableNameIfOk(cacheDriverConfig, sconstants.DynamoDBImageMetaTable,
		sconstants.DynamoDBImageMetaSuffix, tablenamePrefix, hasTablenamePrefix, log)
	allParametersOk = allParametersOk && ok

	apiKeyTablename, ok := tableNameIfOk(cacheDriverConfig, sconstants.DynamoDBAPIKeyTable,
		sconstants.DynamoDBAPIKeySuffix, tablenamePrefix, hasTablenamePrefix, log)
	allParametersOk = allParametersOk && ok

	versionTablename, ok := tableNameIfOk(cacheDriverConfig, sconstants.DynamoDBVersionTable,
		sconstants.DynamoDBVersionSuffix, tablenamePrefix, hasTablenamePrefix, log)
	allParametersOk = allParametersOk && ok

	userDataTablename, ok := tableNameIfOk(cacheDriverConfig, sconstants.DynamoDBUserDataTable,
		sconstants.DynamoDBUserDataSuffix, tablenamePrefix, hasTablenamePrefix, log)
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

func getRedisParams(cacheDriverConfig map[string]any, log log.Logger) redis.DBDriverParameters {
	keyPrefix, ok := toStringIfOk(cacheDriverConfig, "keyprefix", "zot", log)
	if !ok {
		log.Panic().Msg("redis parameters are not specified correctly, can't proceed")
	}

	return redis.DBDriverParameters{
		KeyPrefix: keyPrefix,
	}
}

func tableNameIfOk(cacheDriverConfig map[string]any,
	param string,
	tableSuffix string,
	tablenamePrefix string,
	hasTablenamePrefix bool,
	log log.Logger,
) (string, bool) {
	tableName, ok := configValue(cacheDriverConfig, param)
	if ok {
		return stringValueIfOk(tableName, param, log)
	}

	if hasTablenamePrefix {
		return tablenamePrefix + tableSuffix, true
	}

	log.Error().Str("field", param).Msg("failed to parse CacheDriver config, field is not present")

	return "", false
}

func optionalStringIfOk(cacheDriverConfig map[string]any,
	param string,
	log log.Logger,
) (string, bool, bool) {
	val, ok := configValue(cacheDriverConfig, param)
	if !ok {
		return "", false, true
	}

	str, ok := stringValueIfOk(val, param, log)

	return str, true, ok
}

func toStringIfOk(cacheDriverConfig map[string]any,
	param string,
	defaultVal string,
	log log.Logger,
) (string, bool) {
	val, ok := configValue(cacheDriverConfig, param)

	if !ok && defaultVal != "" {
		log.Info().Str("field", param).Str("default", defaultVal).
			Msg("field is not present in CacheDriver config, using default value")

		return defaultVal, true
	} else if !ok {
		log.Error().Str("field", param).Msg("failed to parse CacheDriver config, field is not present")

		return "", false
	}

	return stringValueIfOk(val, param, log)
}

func stringValueIfOk(val any, param string, log log.Logger) (string, bool) {
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

func configValue(cacheDriverConfig map[string]any, key string) (any, bool) {
	if val, ok := cacheDriverConfig[key]; ok {
		return val, true
	}

	for candidate, val := range cacheDriverConfig {
		if strings.EqualFold(candidate, key) {
			return val, true
		}
	}

	return nil, false
}

func Close(metadb mTypes.MetaDB) error {
	return metadb.Close()
}
