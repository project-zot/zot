//go:build sync

package api

import (
	"context"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errStorageUnavailable = errors.New("storage unavailable")

type asyncOnDemandMock struct {
	queueImageFn func(ctx context.Context, repo, reference string)
}

func (mock *asyncOnDemandMock) SyncImage(context.Context, string, string) error {
	return nil
}

func (mock *asyncOnDemandMock) SyncReferrers(context.Context, string, string, []string) error {
	return nil
}

func (mock *asyncOnDemandMock) ShouldCheckUpstreamManifest(string, string) bool {
	return true
}

func (mock *asyncOnDemandMock) IsAsyncOnDemandEnabledForRepo(string) bool {
	return true
}

func (mock *asyncOnDemandMock) QueueImage(ctx context.Context, repo, reference string) {
	if mock.queueImageFn != nil {
		mock.queueImageFn(ctx, repo, reference)
	}
}

func TestGetImageManifestAsyncOnDemand(t *testing.T) {
	t.Parallel()

	const (
		repo      = "library/test"
		reference = "latest"
	)

	enabled := true
	appConfig := config.New()
	appConfig.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &enabled},
	}

	for _, testCase := range []struct {
		name        string
		storageErr  error
		wantQueued  bool
		wantContent []byte
	}{
		{
			name:       "cache miss queues fill",
			storageErr: zerr.ErrManifestNotFound,
			wantQueued: true,
		},
		{
			name:        "cache hit returns immediately",
			wantContent: []byte("manifest"),
		},
		{
			name:       "storage failure is not queued",
			storageErr: errStorageUnavailable,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			queued := false
			onDemand := &asyncOnDemandMock{
				queueImageFn: func(_ context.Context, queuedRepo, queuedReference string) {
					queued = true
					if queuedRepo != repo || queuedReference != reference {
						t.Fatalf("queued %s:%s, want %s:%s", queuedRepo, queuedReference, repo, reference)
					}
				},
			}
			handler := &RouteHandler{c: &Controller{Config: appConfig, SyncOnDemand: onDemand}}
			store := mocks.MockedImageStore{
				GetImageManifestFn: func(_, _ string) ([]byte, godigest.Digest, string, error) {
					return testCase.wantContent, "", "", testCase.storageErr
				},
			}

			content, _, _, err := getImageManifest(context.Background(), handler, store, repo, reference)
			if !errors.Is(err, testCase.storageErr) {
				t.Fatalf("getImageManifest() error = %v, want %v", err, testCase.storageErr)
			}
			if string(content) != string(testCase.wantContent) {
				t.Fatalf("getImageManifest() content = %q, want %q", content, testCase.wantContent)
			}
			if queued != testCase.wantQueued {
				t.Fatalf("QueueImage() called = %t, want %t", queued, testCase.wantQueued)
			}
		})
	}
}

func TestIsManifestCacheMiss(t *testing.T) {
	t.Parallel()

	for _, cacheMiss := range []error{
		zerr.ErrRepoNotFound,
		zerr.ErrManifestNotFound,
		zerr.ErrBlobNotFound,
	} {
		if !isManifestCacheMiss(cacheMiss) {
			t.Errorf("isManifestCacheMiss(%v) = false, want true", cacheMiss)
		}
	}

	if isManifestCacheMiss(errStorageUnavailable) {
		t.Error("isManifestCacheMiss(storage error) = true, want false")
	}
}
