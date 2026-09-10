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
	queueImageFn     func(ctx context.Context, repo, reference string)
	enabledForRepoFn func(repo string) bool
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

func (mock *asyncOnDemandMock) IsAsyncOnDemandEnabledForRepo(repo string) bool {
	if mock.enabledForRepoFn != nil {
		return mock.enabledForRepoFn(repo)
	}

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

// plainSyncOnDemand implements ext.SyncOnDemand but not asyncSyncOnDemand (no QueueImage /
// IsAsyncOnDemandEnabledForRepo), matching a registry that has sync on-demand enabled without
// async on-demand.
type plainSyncOnDemand struct{}

func (plainSyncOnDemand) SyncImage(context.Context, string, string) error { return nil }

func (plainSyncOnDemand) SyncReferrers(context.Context, string, string, []string) error {
	return nil
}

func (plainSyncOnDemand) ShouldCheckUpstreamManifest(string, string) bool { return true }

func TestAsyncOnDemand(t *testing.T) {
	t.Parallel()

	const repo = "library/test"

	t.Run("nil SyncOnDemand", func(t *testing.T) {
		t.Parallel()

		handler := &RouteHandler{c: &Controller{}}

		asyncSync, ok := handler.asyncOnDemand(repo)
		if ok || asyncSync != nil {
			t.Fatalf("asyncOnDemand() = %v, %t, want nil, false", asyncSync, ok)
		}
	})

	t.Run("SyncOnDemand does not implement async interface", func(t *testing.T) {
		t.Parallel()

		handler := &RouteHandler{c: &Controller{SyncOnDemand: plainSyncOnDemand{}}}

		asyncSync, ok := handler.asyncOnDemand(repo)
		if ok || asyncSync != nil {
			t.Fatalf("asyncOnDemand() = %v, %t, want nil, false", asyncSync, ok)
		}
	})

	t.Run("async on-demand disabled for repo", func(t *testing.T) {
		t.Parallel()

		onDemand := &asyncOnDemandMock{enabledForRepoFn: func(string) bool { return false }}
		handler := &RouteHandler{c: &Controller{SyncOnDemand: onDemand}}

		asyncSync, ok := handler.asyncOnDemand(repo)
		if ok || asyncSync != nil {
			t.Fatalf("asyncOnDemand() = %v, %t, want nil, false", asyncSync, ok)
		}
	})

	t.Run("async on-demand enabled for repo", func(t *testing.T) {
		t.Parallel()

		onDemand := &asyncOnDemandMock{}
		handler := &RouteHandler{c: &Controller{SyncOnDemand: onDemand}}

		asyncSync, ok := handler.asyncOnDemand(repo)
		if !ok || asyncSync == nil {
			t.Fatalf("asyncOnDemand() = %v, %t, want non-nil, true", asyncSync, ok)
		}
	})
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
