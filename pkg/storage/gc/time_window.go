package gc

import (
	"fmt"
	"strings"
	"time"
)

const gcTimeOfDayLayout = "15:04"

type TimeWindow struct {
	Start time.Duration
	End   time.Duration
}

func ParseTimeWindow(raw string) (TimeWindow, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return TimeWindow{}, nil
	}

	parts := strings.Split(raw, "-")
	if len(parts) != 2 { //nolint:mnd
		return TimeWindow{}, fmt.Errorf("expected time window format HH.MM - HH.MM")
	}

	start, err := parseTimeOfDay(parts[0])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("invalid start time: %w", err)
	}

	end, err := parseTimeOfDay(parts[1])
	if err != nil {
		return TimeWindow{}, fmt.Errorf("invalid end time: %w", err)
	}

	if start == end {
		return TimeWindow{}, fmt.Errorf("start and end times must differ")
	}

	return TimeWindow{Start: start, End: end}, nil
}

func (window TimeWindow) Contains(now time.Time) bool {
	if window == (TimeWindow{}) {
		return true
	}

	current := time.Duration(now.Hour())*time.Hour + time.Duration(now.Minute())*time.Minute

	if window.Start < window.End {
		return current >= window.Start && current < window.End
	}

	return current >= window.Start || current < window.End
}

func parseTimeOfDay(raw string) (time.Duration, error) {
	normalized := strings.ReplaceAll(strings.TrimSpace(raw), ".", ":")

	parsed, err := time.Parse(gcTimeOfDayLayout, normalized)
	if err != nil {
		return 0, err
	}

	return time.Duration(parsed.Hour())*time.Hour + time.Duration(parsed.Minute())*time.Minute, nil
}
