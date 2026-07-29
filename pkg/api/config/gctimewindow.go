package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"

	zerr "zotregistry.dev/zot/v2/errors"
)

const minutesInHour = 60

// GCTimeWindow represents a daily recurring time-of-day window (in UTC), expressed in
// minutes since midnight, during which a new periodic GC sweep over all repositories may
// start. A sweep that starts inside the window is allowed to run to completion even past
// the window's end, so GC work stays amortized and orphaned blobs don't outpace a narrow
// window.
//
// The zero value means no restriction. A validly parsed window can never equal the zero
// value, because start == end is rejected, so IsSet can use plain equality.
type GCTimeWindow struct {
	startMin int
	endMin   int
}

// IsSet reports whether a time-of-day restriction is configured.
func (w GCTimeWindow) IsSet() bool {
	return w != GCTimeWindow{}
}

// Contains returns true if now, interpreted in UTC, falls inside the window, or if no
// window is configured. A window whose start is after its end (e.g. "22:00-06:00") is
// treated as wrapping past midnight.
func (w GCTimeWindow) Contains(now time.Time) bool {
	if !w.IsSet() {
		return true
	}

	now = now.UTC()
	minutes := now.Hour()*minutesInHour + now.Minute()

	if w.startMin <= w.endMin {
		return minutes >= w.startMin && minutes < w.endMin
	}

	return minutes >= w.startMin || minutes < w.endMin
}

// String renders the window back as "HH:MM-HH:MM", or "" if unset.
func (w GCTimeWindow) String() string {
	if !w.IsSet() {
		return ""
	}

	return formatTimeOfDay(w.startMin) + "-" + formatTimeOfDay(w.endMin)
}

func (w GCTimeWindow) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.String())
}

func (w *GCTimeWindow) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	parsed, err := parseGCTimeWindow(str)
	if err != nil {
		return err
	}

	*w = parsed

	return nil
}

// parseGCTimeWindow parses a "HH:MM-HH:MM" daily time-of-day window, e.g. "01:00-08:00".
// An empty string is valid and means no restriction.
func parseGCTimeWindow(window string) (GCTimeWindow, error) {
	if window == "" {
		return GCTimeWindow{}, nil
	}

	start, end, found := strings.Cut(window, "-")
	if !found {
		return GCTimeWindow{}, fmt.Errorf(
			"%w: invalid gcTimeWindow %q, expected format \"HH:MM-HH:MM\"", zerr.ErrBadConfig, window)
	}

	startMin, err := parseTimeOfDay(strings.TrimSpace(start))
	if err != nil {
		return GCTimeWindow{}, fmt.Errorf("%w: invalid gcTimeWindow %q: %w", zerr.ErrBadConfig, window, err)
	}

	endMin, err := parseTimeOfDay(strings.TrimSpace(end))
	if err != nil {
		return GCTimeWindow{}, fmt.Errorf("%w: invalid gcTimeWindow %q: %w", zerr.ErrBadConfig, window, err)
	}

	if startMin == endMin {
		return GCTimeWindow{}, fmt.Errorf(
			"%w: invalid gcTimeWindow %q: start and end of the window cannot be equal", zerr.ErrBadConfig, window)
	}

	return GCTimeWindow{startMin: startMin, endMin: endMin}, nil
}

func parseTimeOfDay(value string) (int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid time %q, expected 24h format \"HH:MM\"", zerr.ErrBadConfig, value)
	}

	return parsed.Hour()*minutesInHour + parsed.Minute(), nil
}

func formatTimeOfDay(minutes int) string {
	return fmt.Sprintf("%02d:%02d", minutes/minutesInHour, minutes%minutesInHour)
}

// GCTimeWindowDecodeHook decodes a "HH:MM-HH:MM" string into a GCTimeWindow at config
// unmarshal time, so an invalid value fails config loading instead of being silently
// ignored later when GC actually runs.
func GCTimeWindowDecodeHook() mapstructure.DecodeHookFunc {
	return func(_ reflect.Type, target reflect.Type, data any) (any, error) {
		if target != reflect.TypeFor[GCTimeWindow]() {
			return data, nil
		}

		str, ok := data.(string)
		if !ok {
			return data, nil
		}

		return parseGCTimeWindow(str)
	}
}
