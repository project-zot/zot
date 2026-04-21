//go:build !metrics

package api

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestExporterTimeoutSelection(t *testing.T) {
	Convey("exporter uses default timeouts when configured value is nil or non-positive", t, func() {
		resolve := func(configured *time.Duration, fallback time.Duration) time.Duration {
			if configured != nil && *configured > 0 {
				return *configured
			}

			return fallback
		}

		positive := 10 * time.Second
		zero := time.Duration(0)
		negative := -5 * time.Second

		So(resolve(nil, defaultReadTimeout), ShouldEqual, defaultReadTimeout)
		So(resolve(&zero, defaultReadTimeout), ShouldEqual, defaultReadTimeout)
		So(resolve(&negative, defaultReadTimeout), ShouldEqual, defaultReadTimeout)
		So(resolve(&positive, defaultReadTimeout), ShouldEqual, positive)
	})
}
