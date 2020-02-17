package storage_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	. "github.com/smartystreets/goconvey/convey"
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

		err = c.PutBlob("key", "value")
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
	})
}
