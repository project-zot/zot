package repodbfactory

import (
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/meta/repodb"
)

type RepoDBDriverFactory interface {
	Create(parameters interface{}) (repodb.RepoDB, error)
}

func repoDBFactories() map[string]RepoDBDriverFactory {
	return map[string]RepoDBDriverFactory{
		"boltdb": repodb.BoltDBWrapperFactory{},
	}
}

func Create(name string, parameters interface{}) (repodb.RepoDB, error) {
	driverFactory, ok := repoDBFactories()[name]
	if !ok {
		return nil, errors.ErrBadConfig
	}

	return driverFactory.Create(parameters)
}
