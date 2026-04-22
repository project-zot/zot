//go:build !metrics

package api

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestExporterTimeoutSelection(t *testing.T) {
	Convey("exporter uses the provided default timeout when configured value is nil or non-positive", t, func() {
		positive := 10 * time.Second
		zero := time.Duration(0)
		negative := -5 * time.Second

		So(selectedTimeout(nil, defaultReadTimeout), ShouldEqual, defaultReadTimeout)
		So(selectedTimeout(&zero, defaultWriteTimeout), ShouldEqual, defaultWriteTimeout)
		So(selectedTimeout(&negative, defaultWriteTimeout), ShouldEqual, defaultWriteTimeout)
		So(selectedTimeout(&positive, defaultWriteTimeout), ShouldEqual, positive)
	})
}
