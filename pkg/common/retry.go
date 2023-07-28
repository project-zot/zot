package common

import (
	"context"
	"time"
)

func RetryWithContext(ctx context.Context, operation func(attempt int, retryIn time.Duration) error, maxRetries int,
	delay time.Duration,
) error {
	err := operation(1, delay)

	for attempt := 1; err != nil && attempt < maxRetries; attempt++ {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return err
		}

		err = operation(attempt+1, delay)
	}

	return err
}
