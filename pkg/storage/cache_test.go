package storage_test

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func TestCache(t *testing.T) {
	Convey("Make a new cache", t, func() {
		dir, err := ioutil.TempDir("", "cache_test")
		So(err, ShouldBeNil)
		So(dir, ShouldNotBeEmpty)
		defer os.RemoveAll(dir)

		log := log.NewLogger("debug", "")
		So(log, ShouldNotBeNil)

		So(storage.NewCache("/deadBEEF", "cache_test", log), ShouldBeNil)

		c := storage.NewCache(dir, "cache_test", log)
		So(c, ShouldNotBeNil)

		v, err := c.GetBlob("key")
		So(err, ShouldEqual, errors.ErrCacheMiss)
		So(v, ShouldBeEmpty)

		b := c.HasBlob("key", "value")
		So(b, ShouldBeFalse)

		err = c.PutBlob("key", path.Join(dir, "value"))
		So(err, ShouldBeNil)

		b = c.HasBlob("key", "value")
		So(b, ShouldBeTrue)

		v, err = c.GetBlob("key")
		So(err, ShouldBeNil)
		So(v, ShouldNotBeEmpty)

		err = c.DeleteBlob("bogusKey", "bogusValue")
		So(err, ShouldEqual, errors.ErrCacheMiss)

		err = c.DeleteBlob("key", "bogusValue")
		So(err, ShouldBeNil)

		// try to insert empty path
		err = c.PutBlob("key", "")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, errors.ErrEmptyValue)
	})
}
