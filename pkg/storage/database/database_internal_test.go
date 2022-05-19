package database

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/log"
)

func TestDatabaseNilBucket(t *testing.T) {
	Convey("Make a new database", t, func() {
		dir := t.TempDir()

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		_, err := New("/deadBEEF", "db_test", "db_test", log)
		So(err, ShouldNotBeNil)

		store, err := New(dir, "db_test", "db_test", log)
		So(err, ShouldBeNil)
		So(store, ShouldNotBeNil)

		store.bucket = "unknown"

		exists := store.Has("key")
		So(exists, ShouldBeFalse)

		err = store.Put("key", "value")
		So(err, ShouldNotBeNil)

		val, err := store.Get("key")
		So(err, ShouldNotBeNil)
		So(val, ShouldBeEmpty)

		err = store.Delete("key")
		So(err, ShouldNotBeNil)

		err = store.DeleteAll()
		So(err, ShouldNotBeNil)
	})
}
