package config_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api/config"
)

func TestConfig(t *testing.T) {
	Convey("Test config utils", t, func() {
		firstStorageConfig := config.StorageConfig{
			GC: true, Dedupe: true,
			GCDelay: 1 * time.Minute, GCInterval: 1 * time.Hour,
		}
		secondStorageConfig := config.StorageConfig{
			GC: true, Dedupe: true,
			GCDelay: 1 * time.Minute, GCInterval: 1 * time.Hour,
		}

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeTrue)

		firstStorageConfig.GC = false

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.GC = true
		firstStorageConfig.Dedupe = false

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.Dedupe = true
		firstStorageConfig.GCDelay = 2 * time.Minute

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.GCDelay = 1 * time.Minute
		firstStorageConfig.GCInterval = 2 * time.Hour

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeFalse)

		firstStorageConfig.GCInterval = 1 * time.Hour

		So(firstStorageConfig.ParamsEqual(secondStorageConfig), ShouldBeTrue)

		isSame, err := config.SameFile("test-config", "test")
		So(err, ShouldNotBeNil)
		So(isSame, ShouldBeFalse)

		dir1 := t.TempDir()

		isSame, err = config.SameFile(dir1, "test")
		So(err, ShouldNotBeNil)
		So(isSame, ShouldBeFalse)

		dir2 := t.TempDir()

		isSame, err = config.SameFile(dir1, dir2)
		So(err, ShouldBeNil)
		So(isSame, ShouldBeFalse)

		isSame, err = config.SameFile(dir1, dir1)
		So(err, ShouldBeNil)
		So(isSame, ShouldBeTrue)
	})
}
