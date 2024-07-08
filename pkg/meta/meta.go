package meta

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/redis/go-redis/v9"
	"go.etcd.io/bbolt"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
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

			return Create(sconstants.DynamoDBDriverName, client, dynamoParams, log) //nolint:contextcheck
		}
		// go-redis supports connecting via the redis uri specification (more convenient than parameter parsing)
		redisURL := getRedisURL(storageConfig.CacheDriver, log)
		client, err := redisdb.GetRedisClient(redisURL)
		if err != nil { //nolint:wsl
			return nil, err
		}

		return Create(sconstants.RedisDriverName, client, &redisdb.RedisDB{Client: client}, log) //nolint:contextcheck
	}

	params := boltdb.DBParameters{}
	params.RootDir = storageConfig.RootDirectory

	driver, err := boltdb.GetBoltDriver(params)
	if err != nil {
		return nil, err
	}

	return Create("boltdb", driver, params, log) //nolint:contextcheck
}

func Create(dbtype string, dbDriver, parameters interface{}, log log.Logger, //nolint:contextcheck
) (mTypes.MetaDB, error,
) {
	switch dbtype {
	case "boltdb":
		{
			properDriver, ok := dbDriver.(*bbolt.DB)
			if !ok {
				log.Error().Err(errors.ErrTypeAssertionFailed).
					Msgf("failed to cast type, expected type '%T' but got '%T'", &bbolt.DB{}, dbDriver)

				return nil, errors.ErrTypeAssertionFailed
			}

			return boltdb.New(properDriver, log)
		}
	case "redis":
		{
			properDriver, ok := dbDriver.(*redis.Client)
			if !ok {
				log.Error().Err(errors.ErrTypeAssertionFailed).
					Msgf("failed to cast type, expected type '%T' but got '%T'", &redis.Client{}, dbDriver)

				return nil, errors.ErrTypeAssertionFailed
			}

			return redisdb.New(properDriver, log)
		}
	case "dynamodb":
		{
			properDriver, ok := dbDriver.(*dynamodb.Client)
			if !ok {
				log.Error().Err(errors.ErrTypeAssertionFailed).
					Msgf("failed to cast type, expected type '%T' but got '%T'", &dynamodb.Client{}, dbDriver)

				return nil, errors.ErrTypeAssertionFailed
			}

			properParameters, ok := parameters.(mdynamodb.DBDriverParameters)
			if !ok {
				log.Error().Err(errors.ErrTypeAssertionFailed).
					Msgf("failed to cast type, expected type '%T' but got '%T'", mdynamodb.DBDriverParameters{},
						parameters)

				return nil, errors.ErrTypeAssertionFailed
			}

			return mdynamodb.New(properDriver, properParameters, log)
		}
	default:
		{
			return nil, errors.ErrBadConfig
		}
	}
}

func getDynamoParams(cacheDriverConfig map[string]interface{}, log log.Logger) mdynamodb.DBDriverParameters {
	allParametersOk := true

	endpoint, ok := toStringIfOk(cacheDriverConfig, "endpoint", log)
	allParametersOk = allParametersOk && ok

	region, ok := toStringIfOk(cacheDriverConfig, "region", log)
	allParametersOk = allParametersOk && ok

	repoMetaTablename, ok := toStringIfOk(cacheDriverConfig, "repometatablename", log)
	allParametersOk = allParametersOk && ok

	repoBlobsInfoTablename, ok := toStringIfOk(cacheDriverConfig, "repoblobsinfotablename", log)
	allParametersOk = allParametersOk && ok

	imageMetaTablename, ok := toStringIfOk(cacheDriverConfig, "imagemetatablename", log)
	allParametersOk = allParametersOk && ok

	apiKeyTablename, ok := toStringIfOk(cacheDriverConfig, "apikeytablename", log)
	allParametersOk = allParametersOk && ok

	versionTablename, ok := toStringIfOk(cacheDriverConfig, "versiontablename", log)
	allParametersOk = allParametersOk && ok

	userDataTablename, ok := toStringIfOk(cacheDriverConfig, "userdatatablename", log)
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

func getRedisURL(cacheDriverConfig map[string]interface{}, log log.Logger) string {
	url, ok := toStringIfOk(cacheDriverConfig, "url", log)

	if !ok {
		log.Panic().Msg("redis parameters are not specified correctly, can't proceed")
	}

	return url
}

func toStringIfOk(cacheDriverConfig map[string]interface{}, param string, log log.Logger) (string, bool) {
	val, ok := cacheDriverConfig[param]

	if !ok {
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

	return str, ok
}
