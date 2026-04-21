//go:build !metrics

package api

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestExporterTimeoutSelection(t *testing.T) {
	Convey("exporter uses default timeouts when configured value is nil or non-positive", t, func() {
		positive := 10 * time.Second
		zero := time.Duration(0)
		negative := -5 * time.Second

		So(selectedTimeout(nil), ShouldEqual, defaultReadTimeout)
		So(selectedTimeout(&zero), ShouldEqual, defaultReadTimeout)
		So(selectedTimeout(&negative), ShouldEqual, defaultReadTimeout)
		So(selectedTimeout(&positive), ShouldEqual, positive)
	})
}
