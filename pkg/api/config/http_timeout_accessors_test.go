package config_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
)

func TestHTTPTimeoutAccessorsWithSet(t *testing.T) {
	Convey("GetHTTPReadTimeoutWithSet distinguishes unset from explicit values", t, func() {
		cfg := config.New()

		readTimeout, set := cfg.GetHTTPReadTimeoutWithSet()
		So(set, ShouldBeFalse)
		So(readTimeout, ShouldEqual, 0)

		zero := time.Duration(0)
		cfg.HTTP.ReadTimeout = &zero
		readTimeout, set = cfg.GetHTTPReadTimeoutWithSet()
		So(set, ShouldBeTrue)
		So(readTimeout, ShouldEqual, 0)

		negative := -5 * time.Second
		cfg.HTTP.ReadTimeout = &negative
		readTimeout, set = cfg.GetHTTPReadTimeoutWithSet()
		So(set, ShouldBeTrue)
		So(readTimeout, ShouldEqual, negative)

		positive := 45 * time.Second
		cfg.HTTP.ReadTimeout = &positive
		readTimeout, set = cfg.GetHTTPReadTimeoutWithSet()
		So(set, ShouldBeTrue)
		So(readTimeout, ShouldEqual, positive)
	})

	Convey("GetHTTPWriteTimeoutWithSet distinguishes unset from explicit values", t, func() {
		cfg := config.New()

		writeTimeout, set := cfg.GetHTTPWriteTimeoutWithSet()
		So(set, ShouldBeFalse)
		So(writeTimeout, ShouldEqual, 0)

		zero := time.Duration(0)
		cfg.HTTP.WriteTimeout = &zero
		writeTimeout, set = cfg.GetHTTPWriteTimeoutWithSet()
		So(set, ShouldBeTrue)
		So(writeTimeout, ShouldEqual, 0)

		negative := -5 * time.Second
		cfg.HTTP.WriteTimeout = &negative
		writeTimeout, set = cfg.GetHTTPWriteTimeoutWithSet()
		So(set, ShouldBeTrue)
		So(writeTimeout, ShouldEqual, negative)

		positive := 1 * time.Minute
		cfg.HTTP.WriteTimeout = &positive
		writeTimeout, set = cfg.GetHTTPWriteTimeoutWithSet()
		So(set, ShouldBeTrue)
		So(writeTimeout, ShouldEqual, positive)
	})
}
