package common_test

import (
	"os"
	"path"
	"testing"

	notreg "github.com/notaryproject/notation-go/registry"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/common"
)

func TestCommon(t *testing.T) {
	Convey("test Contains()", t, func() {
		first := []string{"apple", "biscuit"}
		So(common.Contains(first, "apple"), ShouldBeTrue)
		So(common.Contains(first, "peach"), ShouldBeFalse)
		So(common.Contains([]string{}, "apple"), ShouldBeFalse)
	})

	Convey("test MarshalThroughStruct()", t, func() {
		cfg := config.New()

		newCfg := struct {
			DistSpecVersion string
		}{}

		_, err := common.MarshalThroughStruct(cfg, &newCfg)
		So(err, ShouldBeNil)
		So(newCfg.DistSpecVersion, ShouldEqual, cfg.DistSpecVersion)

		// negative
		obj := make(chan int)
		toObj := config.New()

		_, err = common.MarshalThroughStruct(obj, &toObj)
		So(err, ShouldNotBeNil)

		_, err = common.MarshalThroughStruct(toObj, &obj)
		So(err, ShouldNotBeNil)
	})

	Convey("test dirExists()", t, func() {
		exists := common.DirExists("testdir")
		So(exists, ShouldBeFalse)
		tempDir := t.TempDir()

		file, err := os.Create(path.Join(tempDir, "file.txt"))
		So(err, ShouldBeNil)
		isDir := common.DirExists(file.Name())
		So(isDir, ShouldBeFalse)
	})

	Convey("Index func", t, func() {
		So(common.Index([]string{"a", "b"}, "b"), ShouldEqual, 1)
		So(common.Index([]string{"a", "b"}, "c"), ShouldEqual, -1)
	})

	Convey("Test ArtifactTypeNotation const has same value as in notaryproject", t, func() {
		So(common.ArtifactTypeNotation, ShouldEqual, notreg.ArtifactTypeNotation)
	})
}
