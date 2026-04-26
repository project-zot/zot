package gc

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGCTimeWindow(t *testing.T) {
	Convey("Parse empty GC time window", t, func() {
		window, err := ParseTimeWindow("")

		So(err, ShouldBeNil)
		So(window.Contains(time.Date(2026, time.April, 26, 12, 0, 0, 0, time.Local)), ShouldBeTrue)
	})

	Convey("Parse same-day GC time window", t, func() {
		window, err := ParseTimeWindow("01.00 - 08.00")

		So(err, ShouldBeNil)
		So(window.Contains(time.Date(2026, time.April, 26, 1, 0, 0, 0, time.Local)), ShouldBeTrue)
		So(window.Contains(time.Date(2026, time.April, 26, 7, 59, 0, 0, time.Local)), ShouldBeTrue)
		So(window.Contains(time.Date(2026, time.April, 26, 0, 59, 0, 0, time.Local)), ShouldBeFalse)
		So(window.Contains(time.Date(2026, time.April, 26, 8, 0, 0, 0, time.Local)), ShouldBeFalse)
	})

	Convey("Parse GC time window crossing midnight", t, func() {
		window, err := ParseTimeWindow("23:30 - 02:15")

		So(err, ShouldBeNil)
		So(window.Contains(time.Date(2026, time.April, 26, 23, 30, 0, 0, time.Local)), ShouldBeTrue)
		So(window.Contains(time.Date(2026, time.April, 26, 1, 0, 0, 0, time.Local)), ShouldBeTrue)
		So(window.Contains(time.Date(2026, time.April, 26, 2, 15, 0, 0, time.Local)), ShouldBeFalse)
		So(window.Contains(time.Date(2026, time.April, 26, 12, 0, 0, 0, time.Local)), ShouldBeFalse)
	})

	Convey("Reject invalid GC time windows", t, func() {
		invalidWindows := []string{
			"24.00 - 08.00",
			"10.60 - 12.00",
			"10.00 12.00",
			"08.00 - 08.00",
			"bad - 08.00",
		}

		for _, raw := range invalidWindows {
			_, err := ParseTimeWindow(raw)
			So(err, ShouldNotBeNil)
		}
	})
}

func TestGCTaskGeneratorGCTimeWindow(t *testing.T) {
	Convey("GCTaskGenerator readiness respects GC time window", t, func() {
		window, err := ParseTimeWindow("01.00 - 02.00")
		So(err, ShouldBeNil)

		base := time.Date(2026, time.April, 26, 1, 30, 0, 0, time.Local)
		generator := &GCTaskGenerator{
			nextRun:    base.Add(-1 * time.Second),
			timeWindow: window,
		}

		So(generator.isReadyAt(base), ShouldBeTrue)
		So(generator.isReadyAt(time.Date(2026, time.April, 26, 2, 0, 0, 0, time.Local)), ShouldBeFalse)

		generator.nextRun = base.Add(1 * time.Second)
		So(generator.isReadyAt(base), ShouldBeFalse)
	})
}
