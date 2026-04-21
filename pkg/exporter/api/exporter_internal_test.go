//go:build !metrics

package api

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNormalizedTimeout(t *testing.T) {
	Convey("normalizedTimeout falls back to defaults for non-positive values", t, func() {
		positive := 10 * time.Second
		zero := time.Duration(0)
		negative := -5 * time.Second

		So(normalizedTimeout(nil, defaultReadTimeout), ShouldEqual, defaultReadTimeout)
		So(normalizedTimeout(&zero, defaultReadTimeout), ShouldEqual, defaultReadTimeout)
		So(normalizedTimeout(&negative, defaultReadTimeout), ShouldEqual, defaultReadTimeout)
		So(normalizedTimeout(&positive, defaultReadTimeout), ShouldEqual, positive)
	})
}
