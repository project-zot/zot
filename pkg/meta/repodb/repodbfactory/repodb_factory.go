package repodbfactory

import (
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamodb_wrapper "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
)

func Create(dbtype string, parameters interface{}) (repodb.RepoDB, error) { //nolint:contextcheck
	switch dbtype {
	case "boltdb":
		{
			properParameters, ok := parameters.(boltdb_wrapper.DBParameters)
			if !ok {
				panic("failed type assertion")
			}

			return boltdb_wrapper.NewBoltDBWrapper(properParameters)
		}
	case "dynamodb":
		{
			properParameters, ok := parameters.(dynamodb_wrapper.DBDriverParameters)
			if !ok {
				panic("failed type assertion")
			}

			return dynamodb_wrapper.NewDynamoDBWrapper(properParameters)
		}
	default:
		{
			return nil, errors.ErrBadConfig
		}
	}
}
