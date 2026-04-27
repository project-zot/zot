//go:build sync

package sync

import (
	"context"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	stdsync "sync"
	"time"

	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/blob"
)

type downloadRateLimiter struct {
	rateBytesPerSecond int64
	next               time.Time
	now                func() time.Time
	sleep              func(context.Context, time.Duration) error
	mu                 stdsync.Mutex
}

type rateLimitedBlobReader struct {
	ctx     context.Context
	source  *blob.BReader
	limiter *downloadRateLimiter
}

func newDownloadRateLimiter(downloadRate string) (*downloadRateLimiter, error) {
	rateBytesPerSecond, err := parseDownloadRate(downloadRate)
	if err != nil {
		return nil, err
	}

	if rateBytesPerSecond == 0 {
		return nil, nil //nolint:nilnil
	}

	return &downloadRateLimiter{
		rateBytesPerSecond: rateBytesPerSecond,
		now:                time.Now,
		sleep:              sleepWithContext,
	}, nil
}

func parseDownloadRate(downloadRate string) (int64, error) {
	value := strings.TrimSpace(downloadRate)
	if value == "" {
		return 0, nil
	}

	numberEnd := 0
	for numberEnd < len(value) {
		char := value[numberEnd]
		if (char < '0' || char > '9') && char != '.' {
			break
		}

		numberEnd++
	}

	if numberEnd == 0 {
		return 0, fmt.Errorf("invalid downloadRate %q: missing numeric value", downloadRate)
	}

	amount, err := strconv.ParseFloat(value[:numberEnd], 64)
	if err != nil || amount <= 0 {
		return 0, fmt.Errorf("invalid downloadRate %q: value must be greater than zero", downloadRate)
	}

	unit := strings.ReplaceAll(strings.TrimSpace(value[numberEnd:]), " ", "")
	multiplier, ok := downloadRateUnitMultiplier(unit)
	if !ok {
		return 0, fmt.Errorf("invalid downloadRate %q: unsupported unit %q", downloadRate, unit)
	}

	rate := amount * multiplier
	if rate < 1 || rate > math.MaxInt64 {
		return 0, fmt.Errorf("invalid downloadRate %q: value must be between 1 byte/sec and %d bytes/sec",
			downloadRate, int64(math.MaxInt64))
	}

	return int64(rate), nil
}

func downloadRateUnitMultiplier(unit string) (float64, bool) {
	switch unit {
	case "", "B", "Bps", "B/s", "byte/s", "bytes/s":
		return 1, true
	case "KB", "KBps", "KB/s":
		return 1000, true
	case "MB", "MBps", "MB/s":
		return 1000 * 1000, true
	case "GB", "GBps", "GB/s":
		return 1000 * 1000 * 1000, true
	case "TB", "TBps", "TB/s":
		return 1000 * 1000 * 1000 * 1000, true
	case "KiB", "KiBps", "KiB/s":
		return 1024, true
	case "MiB", "MiBps", "MiB/s":
		return 1024 * 1024, true
	case "GiB", "GiBps", "GiB/s":
		return 1024 * 1024 * 1024, true
	case "TiB", "TiBps", "TiB/s":
		return 1024 * 1024 * 1024 * 1024, true
	}

	switch strings.ToLower(unit) {
	case "bps", "b/s", "bit/s", "bits/s":
		return 1.0 / 8.0, true
	case "kbps", "kb/s", "kbit/s", "kbits/s":
		return 1000.0 / 8.0, true
	case "mbps", "mb/s", "mbit/s", "mbits/s":
		return 1000.0 * 1000.0 / 8.0, true
	case "gbps", "gb/s", "gbit/s", "gbits/s":
		return 1000.0 * 1000.0 * 1000.0 / 8.0, true
	case "tbps", "tb/s", "tbit/s", "tbits/s":
		return 1000.0 * 1000.0 * 1000.0 * 1000.0 / 8.0, true
	}

	return 0, false
}

func (limiter *downloadRateLimiter) imageCopyOptions(ctx context.Context) []regclient.ImageOpts {
	if limiter == nil {
		return nil
	}

	return []regclient.ImageOpts{
		regclient.ImageWithBlobReaderHook(limiter.blobReaderHook(ctx)),
	}
}

func (limiter *downloadRateLimiter) blobReaderHook(ctx context.Context) func(*blob.BReader) (*blob.BReader, error) {
	return func(reader *blob.BReader) (*blob.BReader, error) {
		if limiter == nil || reader == nil {
			return reader, nil
		}

		if ctx == nil {
			ctx = context.Background()
		}

		return blob.NewReader(
			blob.WithDesc(reader.GetDescriptor()),
			blob.WithHeader(reader.RawHeaders()),
			blob.WithResp(reader.Response()),
			blob.WithReader(&rateLimitedBlobReader{
				ctx:     ctx,
				source:  reader,
				limiter: limiter,
			}),
		), nil
	}
}

func (reader *rateLimitedBlobReader) Read(p []byte) (int, error) {
	n, err := reader.source.Read(p)
	if n <= 0 || reader.limiter == nil {
		return n, err
	}

	if waitErr := reader.limiter.waitN(reader.ctx, n); waitErr != nil {
		return n, waitErr
	}

	return n, err
}

func (reader *rateLimitedBlobReader) Close() error {
	return reader.source.Close()
}

func (reader *rateLimitedBlobReader) Seek(offset int64, whence int) (int64, error) {
	return reader.source.Seek(offset, whence)
}

func (limiter *downloadRateLimiter) waitN(ctx context.Context, n int) error {
	if limiter == nil || limiter.rateBytesPerSecond <= 0 || n <= 0 {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	delay := time.Duration(float64(n) * float64(time.Second) / float64(limiter.rateBytesPerSecond))
	if delay <= 0 {
		return nil
	}

	limiter.mu.Lock()
	now := limiter.now()
	if limiter.next.Before(now) {
		limiter.next = now
	}

	wakeAt := limiter.next.Add(delay)
	wait := wakeAt.Sub(now)
	limiter.next = wakeAt
	limiter.mu.Unlock()

	return limiter.sleep(ctx, wait)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ io.Reader = (*rateLimitedBlobReader)(nil)
var _ io.Closer = (*rateLimitedBlobReader)(nil)
var _ io.Seeker = (*rateLimitedBlobReader)(nil)
