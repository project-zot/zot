//go:build sync

package api

import (
	"context"
	"runtime"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

// Benchmarks for the asyncOnDemand path. They depend on RegistryConfig.AsyncOnDemand, so unlike
// routes_manifest_bench_test.go they only build on this branch.

func enableAsyncOnDemand(regCfg *syncconf.RegistryConfig) {
	enabled := true
	regCfg.AsyncOnDemand = &enabled
}

func BenchmarkGetImageManifestAsyncOnDemand(b *testing.B) {
	digestRef := godigest.FromBytes(benchManifest()).String()

	for _, benchCase := range []struct {
		name           string
		services       int
		contentFilters int
		hit            bool
		reference      string
	}{
		{name: "1svc/DigestHit", services: 1, hit: true, reference: digestRef},
		{name: "1svc/TagHit", services: 1, hit: true, reference: benchTag},
		{name: "4svc-16filters/TagHit", services: 4, contentFilters: 16, hit: true, reference: benchTag},
		{name: "1svc/TagMiss", services: 1, reference: benchTag},
	} {
		b.Run(benchCase.name, func(b *testing.B) {
			handler, imgStore := benchRouteHandlerWith(b, true, benchCase.services, benchCase.contentFilters,
				benchCase.hit, enableAsyncOnDemand)

			baseline := runtime.NumGoroutine()
			peak := baseline
			ctx := context.Background()

			b.ReportAllocs()
			b.ResetTimer()

			iteration := 0

			for b.Loop() {
				_, _, _, err := getImageManifest(ctx, handler, imgStore, benchRepo, benchCase.reference)
				if (err != nil) == benchCase.hit {
					b.Fatalf("getImageManifest() err = %v, hit %t", err, benchCase.hit)
				}

				iteration++
				if iteration%64 == 0 {
					peak = max(peak, runtime.NumGoroutine())
				}
			}

			b.StopTimer()

			// Background fills spawned on a miss hold one goroutine each until the shared
			// singleflight sync returns; report how many piled up.
			b.ReportMetric(float64(peak-baseline), "peak-extra-goroutines")
			waitForGoroutines(b, baseline)
		})
	}
}

func waitForGoroutines(b *testing.B, baseline int) {
	b.Helper()

	// Leave headroom for idle keep-alive connection goroutines to the benchmark upstream.
	const idleConnSlack = 8

	deadline := time.Now().Add(30 * time.Second)
	for runtime.NumGoroutine() > baseline+idleConnSlack {
		if time.Now().After(deadline) {
			b.Logf("background goroutines did not drain: %d > %d", runtime.NumGoroutine(), baseline)

			return
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func BenchmarkAsyncOnDemandLookup(b *testing.B) {
	for _, benchCase := range []struct {
		name           string
		async          bool
		services       int
		contentFilters int
	}{
		{name: "AsyncOff/1svc", services: 1},
		{name: "AsyncOff/4svc-16filters", services: 4, contentFilters: 16},
		{name: "AsyncOn/1svc", async: true, services: 1},
		{name: "AsyncOn/4svc-16filters", async: true, services: 4, contentFilters: 16},
	} {
		b.Run(benchCase.name, func(b *testing.B) {
			var tweak func(*syncconf.RegistryConfig)
			if benchCase.async {
				tweak = enableAsyncOnDemand
			}

			handler, _ := benchRouteHandlerWith(b, true, benchCase.services, benchCase.contentFilters, true, tweak)

			b.ReportAllocs()

			for b.Loop() {
				if _, ok := handler.asyncOnDemand(benchRepo); ok != benchCase.async {
					b.Fatalf("asyncOnDemand() ok = %t, want %t", ok, benchCase.async)
				}
			}
		})
	}
}

func BenchmarkIsNilInterface(b *testing.B) {
	value := &asyncOnDemandMock{}

	b.ReportAllocs()

	for b.Loop() {
		if isNilInterface(value) {
			b.Fatal("expected non-nil")
		}
	}
}
