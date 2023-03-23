package repodbfactory

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/dynamo"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamodb_wrapper "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
)

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
