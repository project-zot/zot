//go:build sync

package sync

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

func benchLogger() log.Logger {
	return log.NewLoggerWithWriter("error", io.Discard)
}

func benchAsyncService(async bool, contentFilters int) *BaseService {
	logger := benchLogger()
	content := make([]syncconf.Content, 0, contentFilters)

	for i := range contentFilters - 1 {
		content = append(content, syncconf.Content{Prefix: fmt.Sprintf("team%d/**", i)})
	}

	if contentFilters > 0 {
		content = append(content, syncconf.Content{Prefix: "library/**"})
	}

	return &BaseService{
		config:         syncconf.RegistryConfig{AsyncOnDemand: &async, Content: content},
		contentManager: NewContentManager(content, logger),
		log:            logger,
	}
}

func BenchmarkIsAsyncOnDemandEnabledForRepo(b *testing.B) {
	for _, benchCase := range []struct {
		name           string
		async          bool
		services       int
		contentFilters int
	}{
		{name: "AsyncOff/4svc-16filters", services: 4, contentFilters: 16},
		{name: "AsyncOn/1svc-nofilters", async: true, services: 1},
		{name: "AsyncOn/1svc-16filters", async: true, services: 1, contentFilters: 16},
		{name: "AsyncOn/4svc-16filters", async: true, services: 4, contentFilters: 16},
	} {
		b.Run(benchCase.name, func(b *testing.B) {
			onDemand := NewOnDemand(benchLogger())

			// Only the last service enables async, so the lookup walks every service first.
			for i := range benchCase.services {
				onDemand.Add(benchAsyncService(benchCase.async && i == benchCase.services-1, benchCase.contentFilters))
			}

			b.ReportAllocs()

			for b.Loop() {
				if onDemand.IsAsyncOnDemandEnabledForRepo("library/test") != benchCase.async {
					b.Fatal("unexpected async on-demand result")
				}
			}
		})
	}
}

// BenchmarkQueueImageSameKey models a burst of concurrent cache misses for one image while the
// background sync is still in flight: every call is expected to be absorbed by the in-flight sync.
func BenchmarkQueueImageSameKey(b *testing.B) {
	release := make(chan struct{})

	service := &mockCheckService{
		isAsyncOnDemandForRepoFn: func(string) bool { return true },
		syncImageFn: func(context.Context, string, string) error {
			<-release

			return nil
		},
	}
	onDemand := NewOnDemand(benchLogger())
	onDemand.Add(service)

	baseline := runtime.NumGoroutine()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		onDemand.QueueImage(ctx, "library/test", "latest")
	}

	b.StopTimer()

	// Give spawned goroutines a moment to park on the singleflight before sampling.
	time.Sleep(50 * time.Millisecond)
	b.ReportMetric(float64(runtime.NumGoroutine()-baseline)/float64(b.N), "goroutines/op")

	close(release)

	deadline := time.Now().Add(30 * time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}
