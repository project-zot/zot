package storage

import (
	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/cache"
)

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
