package api

import (
	"strings"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamoParams "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper/params"
	"zotregistry.io/zot/pkg/meta/repodb/repodbfactory"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	"zotregistry.io/zot/pkg/storage/constants"
)

func CreateCacheDBAndBuckets(cfg config.GlobalStorageConfig, log log.Logger) (cache.Cache, map[string]string, error) {
	var err error

	var cacheDB cache.Cache

	var dynamoTablePrefix string

	name, _ := cfg.CacheDriver["name"].(string)

	if name == constants.BoltDBDriverName || cfg.CacheDriver == nil {
		params := cache.BoltDBDriverParameters{}
		params.RootDir = cfg.RootDirectory
		params.Name = constants.BoltdbName

		if cacheDB, err = storage.Create(constants.BoltDBDriverName, params, log); err != nil {
			return nil, nil, err
		}
	} else {
		// dynamodb
		dynamoParams := cache.DynamoDBDriverParameters{}
		allParametersOk := true

		var ok bool

		name, ok := toStringIfOk(cfg.CacheDriver, "name", log)
		allParametersOk = allParametersOk && ok

		dynamoParams.Endpoint, ok = toStringIfOk(cfg.CacheDriver, "endpoint", log)
		allParametersOk = allParametersOk && ok

		dynamoParams.Region, ok = toStringIfOk(cfg.CacheDriver, "region", log)
		allParametersOk = allParametersOk && ok

		dynamoParams.TableNamePrefix, _ = cfg.CacheDriver["tablenameprefix"].(string)
		dynamoTablePrefix = dynamoParams.TableNamePrefix

		if !allParametersOk {
			log.Error().Err(errors.ErrTypeAssertionFailed).Msg("cache driver missing required parameters")

			return nil, nil, errors.ErrTypeAssertionFailed
		}

		if cacheDB, err = storage.Create(name, dynamoParams, log); err != nil {
			return nil, nil, err
		}
	}

	buckets := make(map[string]string)

	// first create default ImageStore bucket
	bucket := getBucketByRouteAndPrefix("", dynamoTablePrefix)

	if err := cacheDB.CreateBucket(bucket); err != nil {
		return nil, nil, err
	}

	buckets[""] = bucket

	// create subpaths buckets
	for route := range cfg.SubPaths {
		bucket := getBucketByRouteAndPrefix(route, dynamoTablePrefix)

		if err := cacheDB.CreateBucket(bucket); err != nil {
			return nil, nil, err
		}

		buckets[route] = bucket
	}

	return cacheDB, buckets, nil
}

func getBucketByRouteAndPrefix(route string, prefix string) string {
	bucketName := "main_bucket"
	if route != "" {
		// eg: /tmp/infra == tmp_infra_bucket
		bucketName = strings.Replace(strings.ReplaceAll(route, "/", "_")+"_bucket", "_", "", 1)
	}

	if prefix != "" {
		bucketName = prefix + "_" + bucketName
	}

	return bucketName
}

func CreateRepoDBDriver(storageConfig config.StorageConfig, log log.Logger) (repodb.RepoDB, error) {
	name, _ := toStringIfOk(storageConfig.CacheDriver, "name", log)

	if name == constants.BoltDBDriverName || storageConfig.CacheDriver == nil {
		params := bolt.DBParameters{}
		params.RootDir = storageConfig.RootDirectory

		return repodbfactory.Create(constants.BoltDBDriverName, params) //nolint:contextcheck
	}

	dynamoParams := getDynamoParams(storageConfig.CacheDriver, log)

	return repodbfactory.Create(constants.DynamoDBDriverName, dynamoParams) //nolint:contextcheck
}

func getDynamoParams(cacheDriverConfig map[string]interface{}, log log.Logger) dynamoParams.DBDriverParameters {
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

	if !allParametersOk {
		panic("dynamo parameters are not specified correctly, can't proceede")
	}

	return dynamoParams.DBDriverParameters{
		Endpoint:              endpoint,
		Region:                region,
		RepoMetaTablename:     repoMetaTablename,
		ManifestDataTablename: manifestDataTablename,
		IndexDataTablename:    indexDataTablename,
		VersionTablename:      versionTablename,
	}
}

func toStringIfOk(cacheDriverConfig map[string]interface{}, param string, log log.Logger) (string, bool) {
	val, ok := cacheDriverConfig[param]

	if !ok {
		log.Error().Msgf("parsing CacheDriver config failed, field '%s' is not present", param)

		return "", false
	}

	str, ok := val.(string)

	if !ok {
		log.Error().Msgf("parsing CacheDriver config failed, parameter '%s' isn't a string", param)

		return "", false
	}

	if str == "" {
		log.Error().Msgf("parsing CacheDriver config failed, field '%s' is empty", param)

		return "", false
	}

	return str, ok
}
