package storage_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/anuvu/zot/pkg/storage"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
)

func TestRepoLayout(t *testing.T) {
	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	il := storage.NewImageStore(dir, zerolog.New(os.Stdout))

	Convey("Repo layout", t, func(c C) {
		repoName := "test"

		Convey("Validate repo without initialization", func() {
			v, err := il.ValidateRepo(repoName)
			So(v, ShouldEqual, false)
			So(err, ShouldNotBeNil)
		})

		Convey("Initialize repo", func() {
			err := il.InitRepo(repoName)
			So(err, ShouldBeNil)
		})

		Convey("Validate repo", func() {
			v, err := il.ValidateRepo(repoName)
			So(v, ShouldEqual, true)
			So(err, ShouldBeNil)
		})
	})
}
