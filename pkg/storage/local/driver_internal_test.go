package local

import (
	"errors"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"
)

func TestFormatErr(t *testing.T) {
	Convey("Test formatErr error handling", t, func() {
		driver := New(true)

		Convey("Test formatErr with nil error", func() {
			err := driver.formatErr(nil)
			So(err, ShouldBeNil)
		})

		Convey("Test formatErr with PathNotFoundError", func() {
			pathErr := storagedriver.PathNotFoundError{Path: "/test"}
			formatted := driver.formatErr(pathErr)
			So(formatted, ShouldNotBeNil)

			// Check if it's still a PathNotFoundError with driver name set
			var pathNotFoundErr storagedriver.PathNotFoundError
			So(errors.As(formatted, &pathNotFoundErr), ShouldBeTrue)
			So(pathNotFoundErr.DriverName, ShouldEqual, "local")
		})

		Convey("Test formatErr with InvalidPathError", func() {
			invalidErr := storagedriver.InvalidPathError{Path: "/test"}
			formatted := driver.formatErr(invalidErr)
			So(formatted, ShouldNotBeNil)

			// Check if it's still an InvalidPathError with driver name set
			var invalidPathErr storagedriver.InvalidPathError
			So(errors.As(formatted, &invalidPathErr), ShouldBeTrue)
			So(invalidPathErr.DriverName, ShouldEqual, "local")
		})

		Convey("Test formatErr with InvalidOffsetError", func() {
			offsetErr := storagedriver.InvalidOffsetError{Path: "/test", Offset: 100}
			formatted := driver.formatErr(offsetErr)
			So(formatted, ShouldNotBeNil)

			// Check if it's still an InvalidOffsetError with driver name set
			var invalidOffsetErr storagedriver.InvalidOffsetError
			So(errors.As(formatted, &invalidOffsetErr), ShouldBeTrue)
			So(invalidOffsetErr.DriverName, ShouldEqual, "local")
		})

		Convey("Test formatErr with generic error", func() {
			genericErr := errors.New("generic error")
			formatted := driver.formatErr(genericErr)
			So(formatted, ShouldNotBeNil)

			// Check if it's wrapped in a storagedriver.Error
			var storageErr storagedriver.Error
			So(errors.As(formatted, &storageErr), ShouldBeTrue)
			So(storageErr.DriverName, ShouldEqual, "local")
			So(storageErr.Detail, ShouldEqual, genericErr)
		})
	})
}
