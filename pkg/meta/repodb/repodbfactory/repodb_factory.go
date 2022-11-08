package repodbfactory

import (
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/meta/repodb"
)

func Create(dbtype string, parameters interface{}) (repodb.RepoDB, error) {
	switch dbtype {
	case "boltdb":
		{
			properParameters, ok := parameters.(repodb.BoltDBParameters)
			if !ok {
				panic("Failed type assertion")
			}

			return repodb.NewBoltDBWrapper(properParameters)
		}
	default:
		{
			return nil, errors.ErrBadConfig
		}
	}
}
