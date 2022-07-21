package database

import (
	"fmt"

	"zotregistry.io/zot/errors"
	zlog "zotregistry.io/zot/pkg/log"
)

// nolint:gochecknoglobals
var driverFactories = make(map[string]DriverFactory)

type DriverFactory interface {
	Create(parameters interface{}, log zlog.Logger) (Driver, error)
}

// Create a new database Driver with the given name and
// parameters. To use a driver, the database DriverFactory must first be
// registered with the given name. If no drivers are found, an
// ErrBadConfig is returned.
func Create(name string, parameters interface{}, log zlog.Logger) (Driver, error) {
	driverFactory, ok := driverFactories[name]
	if !ok {
		return nil, errors.ErrBadConfig
	}

	return driverFactory.Create(parameters, log)
}

// Register makes a database driver available by the provided name.
// If Register is called twice with the same name or if driver factory is nil, it panics.
// Additionally, it is not concurrency safe. Most Database Drivers call this function
// in their init() functions.
func Register(name string, factory DriverFactory) {
	if factory == nil {
		panic("Must not provide nil database DriverFactory")
	}

	_, registered := driverFactories[name]
	if registered {
		panic(fmt.Sprintf("Database DriverFactory named %s already registered", name))
	}

	driverFactories[name] = factory
}
