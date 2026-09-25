//go:build sync

package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// These benchmarks exercise getImageManifest with a real *sync.BaseOnDemand and only use config
// fields that exist upstream, so the file compiles unchanged on main for A/B comparison.

const (
	benchRepo = "library/test"
	benchTag  = "latest"
)

func benchManifest() []byte {
	return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
}

func benchImageStore(hit bool) *mocks.MockedImageStore {
	manifestDigest := godigest.FromBytes(benchManifest())

	return &mocks.MockedImageStore{
		GetImageManifestFn: func(string, string) ([]byte, godigest.Digest, string, error) {
			if !hit {
				return nil, "", "", zerr.ErrManifestNotFound
			}

			return benchManifest(), manifestDigest, "application/vnd.oci.image.manifest.v1+json", nil
		},
	}
}

// benchUpstream is a registry that answers every request with 404, so a blocking on-demand sync
// fails fast and deterministically without leaving the host.
func benchUpstream(b *testing.B) string {
	b.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(resp http.ResponseWriter, _ *http.Request) {
		resp.WriteHeader(http.StatusNotFound)
	}))
	b.Cleanup(server.Close)

	return server.URL
}

// benchContent builds count content filters; only the last one matches benchRepo, so matching a
// request walks every filter.
func benchContent(count int) []syncconf.Content {
	content := make([]syncconf.Content, 0, count)

	for i := range count - 1 {
		content = append(content, syncconf.Content{Prefix: fmt.Sprintf("team%d/**", i)})
	}

	if count > 0 {
		content = append(content, syncconf.Content{Prefix: "library/**"})
	}

	return content
}

func benchRouteHandler(b *testing.B, syncOn bool, services, contentFilters int, hit bool) (
	*RouteHandler, *mocks.MockedImageStore,
) {
	b.Helper()

	return benchRouteHandlerWith(b, syncOn, services, contentFilters, hit, nil)
}

// benchRouteHandlerWith lets tree-specific benchmarks adjust each registry config before the
// sync service is created.
func benchRouteHandlerWith(b *testing.B, syncOn bool, services, contentFilters int, hit bool,
	tweak func(*syncconf.RegistryConfig),
) (*RouteHandler, *mocks.MockedImageStore) {
	b.Helper()

	logger := log.NewLoggerWithWriter("error", io.Discard)
	imgStore := benchImageStore(hit)

	appConfig := config.New()
	ctlr := &Controller{Config: appConfig, Log: logger}

	if !syncOn {
		return &RouteHandler{c: ctlr}, imgStore
	}

	enabled := true
	tlsVerify := false
	maxRetries := 0
	upstreamURL := benchUpstream(b)
	storeController := storage.StoreController{DefaultStore: imgStore}
	onDemand := sync.NewOnDemand(logger)

	registries := make([]syncconf.RegistryConfig, 0, services)

	for range services {
		regCfg := syncconf.RegistryConfig{
			URLs:       []string{upstreamURL},
			OnDemand:   true,
			TLSVerify:  &tlsVerify,
			MaxRetries: &maxRetries,
			Content:    benchContent(contentFilters),
		}

		if tweak != nil {
			tweak(&regCfg)
		}

		registries = append(registries, regCfg)

		service, err := sync.New(regCfg, "", nil, b.TempDir(), storeController, nil, logger)
		if err != nil {
			b.Fatal(err)
		}

		onDemand.Add(service)
	}

	appConfig.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &enabled, Registries: registries},
	}
	ctlr.SyncOnDemand = onDemand

	return &RouteHandler{c: ctlr}, imgStore
}

func runGetImageManifestBench(b *testing.B, handler *RouteHandler, imgStore *mocks.MockedImageStore,
	reference string, wantErr bool,
) {
	b.Helper()

	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, _, _, err := getImageManifest(ctx, handler, imgStore, benchRepo, reference)
		if (err != nil) != wantErr {
			b.Fatalf("getImageManifest() err = %v, wantErr %t", err, wantErr)
		}
	}
}

func BenchmarkGetImageManifest(b *testing.B) {
	digestRef := godigest.FromBytes(benchManifest()).String()

	for _, benchCase := range []struct {
		name           string
		syncOn         bool
		services       int
		contentFilters int
		hit            bool
		reference      string
	}{
		{name: "SyncOff/DigestHit", hit: true, reference: digestRef},
		{name: "SyncOff/TagHit", hit: true, reference: benchTag},
		{name: "OnDemand/1svc/DigestHit", syncOn: true, services: 1, hit: true, reference: digestRef},
		{
			name: "OnDemand/4svc-16filters/DigestHit", syncOn: true, services: 4, contentFilters: 16,
			hit: true, reference: digestRef,
		},
		// Tag requests always consult upstream in blocking on-demand mode; upstream here is a local 404.
		{name: "OnDemand/1svc/TagHit", syncOn: true, services: 1, hit: true, reference: benchTag},
		{name: "OnDemand/1svc/TagMiss", syncOn: true, services: 1, reference: benchTag},
	} {
		b.Run(benchCase.name, func(b *testing.B) {
			handler, imgStore := benchRouteHandler(b, benchCase.syncOn, benchCase.services,
				benchCase.contentFilters, benchCase.hit)

			runGetImageManifestBench(b, handler, imgStore, benchCase.reference, !benchCase.hit)
		})
	}
}

// BenchmarkIsSyncOnDemandEnabled isolates the per-request config check shared by both trees.
func BenchmarkIsSyncOnDemandEnabled(b *testing.B) {
	handler, _ := benchRouteHandler(b, true, 4, 16, true)

	b.ReportAllocs()

	for b.Loop() {
		if !isSyncOnDemandEnabled(handler.c) {
			b.Fatal("expected sync on demand to be enabled")
		}
	}
}
