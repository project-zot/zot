package gc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	hoursPerDay    = 24
	minutesPerHour = 60
)

var (
	errInvalidTimeWindow      = errors.New("invalid GC time window")
	errInvalidClockTime       = errors.New("invalid clock time")
	errClockSeparatorConflict = errors.New("use either ':' or '.' as the separator")
	errClockOutOfRange        = errors.New("clock value out of range")
)

// TimeWindow describes the local time range during which scheduled GC may run.
type TimeWindow struct {
	startMinute int
	endMinute   int
	configured  bool
}

// ParseTimeWindow parses a GC time window in HH.MM - HH.MM or HH:MM - HH:MM format.
func ParseTimeWindow(raw string) (TimeWindow, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return TimeWindow{}, nil
	}

	parts := strings.Split(raw, "-")
	if len(parts) != 2 { //nolint:mnd
		return TimeWindow{}, fmt.Errorf("%w: expected '<start> - <end>'", errInvalidTimeWindow)
	}

	start, err := parseClockMinute(parts[0])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("%w: invalid start time: %w", errInvalidTimeWindow, err)
	}

	end, err := parseClockMinute(parts[1])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("%w: invalid end time: %w", errInvalidTimeWindow, err)
	}

	if start == end {
		return TimeWindow{}, fmt.Errorf("%w: start and end time must be different", errInvalidTimeWindow)
	}

	return TimeWindow{startMinute: start, endMinute: end, configured: true}, nil
}

// Contains reports whether the provided local time falls inside the GC time window.
func (window TimeWindow) Contains(now time.Time) bool {
	if !window.configured {
		return true
	}

	minute := now.Hour()*minutesPerHour + now.Minute()
	if window.startMinute < window.endMinute {
		return minute >= window.startMinute && minute < window.endMinute
	}

	return minute >= window.startMinute || minute < window.endMinute
}

func parseClockMinute(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	hasColon := strings.Contains(raw, ":")
	hasDot := strings.Contains(raw, ".")

	var sep string
	switch {
	case hasColon && hasDot:
		return 0, errClockSeparatorConflict
	case hasColon:
		sep = ":"
	case hasDot:
		sep = "."
	default:
		return 0, fmt.Errorf("%w: expected HH.MM or HH:MM", errInvalidClockTime)
	}

	parts := strings.Split(raw, sep)
	if len(parts) != 2 { //nolint:mnd
		return 0, fmt.Errorf("%w: expected HH%sMM", errInvalidClockTime, sep)
	}

	hour, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, fmt.Errorf("%w: invalid hour: %w", errInvalidClockTime, err)
	}

	minute, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, fmt.Errorf("%w: invalid minute: %w", errInvalidClockTime, err)
	}

	if hour < 0 || hour >= hoursPerDay {
		return 0, fmt.Errorf("%w: hour must be between 0 and 23", errClockOutOfRange)
	}

	if minute < 0 || minute >= minutesPerHour {
		return 0, fmt.Errorf("%w: minute must be between 0 and 59", errClockOutOfRange)
	}

	return hour*minutesPerHour + minute, nil
}
