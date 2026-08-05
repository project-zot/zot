package config_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

// decodeGCTimeWindow runs data through config.GCTimeWindowDecodeHook the same way viper
// does when unmarshaling the config file.
func decodeGCTimeWindow(t *testing.T, data string) (config.GCTimeWindow, error) {
	t.Helper()

	var window config.GCTimeWindow

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: config.GCTimeWindowDecodeHook(),
		Result:     &window,
	})
	if err != nil {
		t.Fatalf("failed to create decoder: %v", err)
	}

	return window, decoder.Decode(data)
}

func TestGCTimeWindowDecodeHook(t *testing.T) {
	Convey("GCTimeWindowDecodeHook", t, func() {
		Convey("empty string decodes to the zero value", func() {
			window, err := decodeGCTimeWindow(t, "")
			So(err, ShouldBeNil)
			So(window.IsSet(), ShouldBeFalse)
		})

		Convey("valid window within the same day", func() {
			window, err := decodeGCTimeWindow(t, "01:00-08:00")
			So(err, ShouldBeNil)
			So(window.IsSet(), ShouldBeTrue)
			So(window.String(), ShouldEqual, "01:00-08:00")
		})

		Convey("valid window with surrounding whitespace", func() {
			window, err := decodeGCTimeWindow(t, " 01:00 - 08:00 ")
			So(err, ShouldBeNil)
			So(window.String(), ShouldEqual, "01:00-08:00")
		})

		Convey("valid window wrapping past midnight", func() {
			window, err := decodeGCTimeWindow(t, "22:00-06:00")
			So(err, ShouldBeNil)
			So(window.String(), ShouldEqual, "22:00-06:00")
		})

		Convey("missing separator is rejected", func() {
			_, err := decodeGCTimeWindow(t, "01:00 08:00")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBadConfig), ShouldBeTrue)
		})

		Convey("malformed start time of day is rejected", func() {
			_, err := decodeGCTimeWindow(t, "25:00-08:00")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBadConfig), ShouldBeTrue)
		})

		Convey("malformed end time of day is rejected", func() {
			_, err := decodeGCTimeWindow(t, "01:00-25:00")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBadConfig), ShouldBeTrue)
		})

		Convey("equal start and end is rejected", func() {
			_, err := decodeGCTimeWindow(t, "08:00-08:00")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBadConfig), ShouldBeTrue)
		})

		Convey("non-string data for the target type is passed through and fails to decode", func() {
			var window config.GCTimeWindow

			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				DecodeHook: config.GCTimeWindowDecodeHook(),
				Result:     &window,
			})
			So(err, ShouldBeNil)

			So(decoder.Decode(5), ShouldNotBeNil)
		})
	})
}

func TestGCTimeWindowContains(t *testing.T) {
	Convey("GCTimeWindow.Contains", t, func() {
		date := func(hour, minute int) time.Time {
			return time.Date(2024, 1, 1, hour, minute, 0, 0, time.UTC)
		}

		Convey("unset window contains every time", func() {
			var window config.GCTimeWindow

			So(window.Contains(date(0, 0)), ShouldBeTrue)
			So(window.Contains(date(23, 59)), ShouldBeTrue)
		})

		Convey("same-day window", func() {
			window, err := decodeGCTimeWindow(t, "01:00-08:00")
			So(err, ShouldBeNil)

			So(window.Contains(date(0, 30)), ShouldBeFalse)
			So(window.Contains(date(1, 0)), ShouldBeTrue)
			So(window.Contains(date(4, 0)), ShouldBeTrue)
			So(window.Contains(date(8, 0)), ShouldBeFalse)
			So(window.Contains(date(12, 0)), ShouldBeFalse)
		})

		Convey("window wrapping past midnight", func() {
			window, err := decodeGCTimeWindow(t, "22:00-06:00")
			So(err, ShouldBeNil)

			So(window.Contains(date(23, 0)), ShouldBeTrue)
			So(window.Contains(date(0, 30)), ShouldBeTrue)
			So(window.Contains(date(5, 59)), ShouldBeTrue)
			So(window.Contains(date(6, 0)), ShouldBeFalse)
			So(window.Contains(date(12, 0)), ShouldBeFalse)
		})
	})
}

func TestGCTimeWindowJSON(t *testing.T) {
	Convey("GCTimeWindow JSON round-trip", t, func() {
		Convey("unset window marshals to an empty string", func() {
			var window config.GCTimeWindow

			data, err := json.Marshal(window)
			So(err, ShouldBeNil)
			So(string(data), ShouldEqual, `""`)

			var decoded config.GCTimeWindow
			So(json.Unmarshal(data, &decoded), ShouldBeNil)
			So(decoded.IsSet(), ShouldBeFalse)
		})

		Convey("a set window round-trips through JSON", func() {
			window, err := decodeGCTimeWindow(t, "01:00-08:00")
			So(err, ShouldBeNil)

			data, err := json.Marshal(window)
			So(err, ShouldBeNil)
			So(string(data), ShouldEqual, `"01:00-08:00"`)

			var decoded config.GCTimeWindow
			So(json.Unmarshal(data, &decoded), ShouldBeNil)
			So(decoded, ShouldResemble, window)
		})

		Convey("an invalid JSON string is rejected", func() {
			var decoded config.GCTimeWindow
			err := json.Unmarshal([]byte(`"not-a-window"`), &decoded)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrBadConfig), ShouldBeTrue)
		})
	})
}
