package storage

import (
	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/cache"
	"zotregistry.io/zot/pkg/storage/constants"
)

func Create(dbtype string, parameters interface{}, log zlog.Logger) (cache.Cache, error) {
	switch dbtype {
	case constants.BoltDBDriverName:
		{
			return cache.NewBoltDBCache(parameters, log)
		}
	case constants.DynamoDBDriverName:
		{
			return cache.NewDynamoDBCache(parameters, log)
		}
	default:
		{
			return nil, errors.ErrBadConfig
		}
	}
}
