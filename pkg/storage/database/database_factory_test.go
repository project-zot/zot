package database_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/database"
)

type mockDriverFactory struct{}

func (factory *mockDriverFactory) Create(parameters interface{}, log log.Logger) (database.Driver, error) {
	return nil, nil
}

func TestDatabaseFactory(t *testing.T) {
	Convey("Test database factory", t, func(c C) {
		log := log.NewLogger("debug", "")

		_, err := database.Create("", storage.BoltDBDriverParameters{}, log)
		So(err, ShouldNotBeNil)

		So(func() {
			database.Register("nilfactory", nil)
		}, ShouldPanic)

		So(func() {
			database.Register("boltdb", &mockDriverFactory{})
		}, ShouldPanic)
	})
}
