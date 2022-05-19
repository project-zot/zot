package database_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage/database"
	"zotregistry.io/zot/pkg/test"
)

func TestDatabase(t *testing.T) {
	Convey("Make a new database", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		store, err := database.New(dir, "db_test", "db_test", log)
		So(err, ShouldBeNil)
		So(store, ShouldNotBeNil)

		exists := store.Has("key")
		So(exists, ShouldBeFalse)

		err = store.Put("", "")
		So(err, ShouldEqual, errors.ErrEmptyValue)

		err = store.Put("key", "value")
		So(err, ShouldBeNil)

		exists = store.Has("key")
		So(exists, ShouldBeTrue)

		val, err := store.Get("key")
		So(err, ShouldBeNil)
		So(val, ShouldNotBeEmpty)

		err = store.Delete("bogusKey")
		So(err, ShouldBeNil)

		err = store.Delete("key")
		So(err, ShouldBeNil)

		err = store.Put("key1", "value1")
		So(err, ShouldBeNil)

		err = store.Put("key2", "value2")
		So(err, ShouldBeNil)

		// check deleteAll actually deletes all keys
		err = store.DeleteAll()
		So(err, ShouldBeNil)

		val, err = store.Get("key1")
		So(err, ShouldBeNil)
		So(val, ShouldBeEmpty)

		val, err = store.Get("key2")
		So(err, ShouldBeNil)
		So(val, ShouldBeEmpty)

		err = store.Close()
		So(err, ShouldBeNil)

		// trigger timeout error, open an already opened db
		_, err = database.New(dir, "db_test", "", log)
		So(err, ShouldNotBeNil)

		// trigger empty bucket name error
		_, err = database.New(dir, "db_test", "", log)
		So(err, ShouldNotBeNil)

		err = store.Close()
		So(err, ShouldBeNil)
	})
}

func TestInjectDatabaseErrs(t *testing.T) {
	Convey("Make a new database", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		store, err := database.New(dir, "db_test", "db_test", log)
		So(err, ShouldBeNil)
		So(store, ShouldNotBeNil)

		injected := test.InjectFailure(0)
		if injected {
			_, err = store.Get("key1")
			So(err, ShouldNotBeNil)
		}

		injected = test.InjectFailure(0)
		if injected {
			err = store.Put("key", "value")
			So(err, ShouldNotBeNil)
		}

		injected = test.InjectFailure(0)
		if injected {
			err = store.Delete("key")
			So(err, ShouldNotBeNil)
		}

		injected = test.InjectFailure(0)
		if injected {
			err = store.DeleteAll()
			So(err, ShouldNotBeNil)
		}
	})
}
