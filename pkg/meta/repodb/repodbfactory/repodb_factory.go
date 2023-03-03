package repodbfactory

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/dynamo"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamodb_wrapper "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
	"zotregistry.io/zot/pkg/meta/signatures"
)

func New(storageConfig config.StorageConfig, log log.Logger) (repodb.RepoDB, error) {
	if storageConfig.RemoteCache {
		dynamoParams := getDynamoParams(storageConfig.CacheDriver, log)

		client, err := dynamo.GetDynamoClient(dynamoParams)
		if err != nil {
			return nil, err
		}

		return Create("dynamodb", client, dynamoParams, log) //nolint:contextcheck
	}

	params := bolt.DBParameters{}
	params.RootDir = storageConfig.RootDirectory

	driver, err := bolt.GetBoltDriver(params)
	if err != nil {
		return nil, err
	}

	err = signatures.InitCosignAndNotationDirs(params.RootDir)
	if err != nil {
		return nil, err
	}

	return Create("boltdb", driver, params, log) //nolint:contextcheck
}

func Create(dbtype string, dbDriver, parameters interface{}, log log.Logger, //nolint:contextcheck
) (repodb.RepoDB, error,
) {
	switch dbtype {
	case "boltdb":
		{
			properDriver, ok := dbDriver.(*bbolt.DB)
			if !ok {
				panic("failed type assertion")
			}

			return boltdb_wrapper.NewBoltDBWrapper(properDriver, log)
		}
	case "dynamodb":
		{
			properDriver, ok := dbDriver.(*dynamodb.Client)
			if !ok {
				panic("failed type assertion")
			}

			properParameters, ok := parameters.(dynamo.DBDriverParameters)
			if !ok {
				panic("failed type assertion")
			}

			return dynamodb_wrapper.NewDynamoDBWrapper(properDriver, properParameters, log)
		}
	default:
		{
			return nil, errors.ErrBadConfig
		}
	}
}

func getDynamoParams(cacheDriverConfig map[string]interface{}, log log.Logger) dynamo.DBDriverParameters {
	allParametersOk := true

	endpoint, ok := toStringIfOk(cacheDriverConfig, "endpoint", log)
	allParametersOk = allParametersOk && ok

	region, ok := toStringIfOk(cacheDriverConfig, "region", log)
	allParametersOk = allParametersOk && ok

	repoMetaTablename, ok := toStringIfOk(cacheDriverConfig, "repometatablename", log)
	allParametersOk = allParametersOk && ok

	manifestDataTablename, ok := toStringIfOk(cacheDriverConfig, "manifestdatatablename", log)
	allParametersOk = allParametersOk && ok

	indexDataTablename, ok := toStringIfOk(cacheDriverConfig, "indexdatatablename", log)
	allParametersOk = allParametersOk && ok

	versionTablename, ok := toStringIfOk(cacheDriverConfig, "versiontablename", log)
	allParametersOk = allParametersOk && ok

	userDataTablename, ok := toStringIfOk(cacheDriverConfig, "userdatatablename", log)
	allParametersOk = allParametersOk && ok

	if !allParametersOk {
		panic("dynamo parameters are not specified correctly, can't proceede")
	}

	return dynamo.DBDriverParameters{
		Endpoint:              endpoint,
		Region:                region,
		RepoMetaTablename:     repoMetaTablename,
		ManifestDataTablename: manifestDataTablename,
		IndexDataTablename:    indexDataTablename,
		UserDataTablename:     userDataTablename,
		VersionTablename:      versionTablename,
	}
}

func toStringIfOk(cacheDriverConfig map[string]interface{}, param string, log log.Logger) (string, bool) {
	val, ok := cacheDriverConfig[param]

	if !ok {
		log.Error().Str("field", param).Msg("parsing CacheDriver config failed, field is not present")

		return "", false
	}

	str, ok := val.(string)

	if !ok {
		log.Error().Str("parameter", param).Msg("parsing CacheDriver config failed, parameter isn't a string")

		return "", false
	}

	if str == "" {
		log.Error().Str("field", param).Msg("parsing CacheDriver config failed, field is empty")

		return "", false
	}

	return str, ok
}
