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
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errStorageUnavailable = errors.New("storage unavailable")

type onDemandInBackgroundMock struct {
	queueImageFn     func(ctx context.Context, repo, reference string)
	enabledForRepoFn func(repo string) bool
	syncImageFn      func(ctx context.Context, repo, reference string) error
	syncImageCalls   int
}

func (mock *onDemandInBackgroundMock) SyncImage(ctx context.Context, repo, reference string) error {
	mock.syncImageCalls++

	if mock.syncImageFn != nil {
		return mock.syncImageFn(ctx, repo, reference)
	}

	return nil
}

func (mock *onDemandInBackgroundMock) SyncReferrers(context.Context, string, string, []string) error {
	return nil
}

func (mock *onDemandInBackgroundMock) ShouldCheckUpstreamManifest(string, string) bool {
	return true
}

func (mock *onDemandInBackgroundMock) ShouldQueueOnDemandSync(repo string) bool {
	if mock.enabledForRepoFn != nil {
		return mock.enabledForRepoFn(repo)
	}

	return true
}

func (mock *onDemandInBackgroundMock) QueueImage(ctx context.Context, repo, reference string) {
	if mock.queueImageFn != nil {
		mock.queueImageFn(ctx, repo, reference)
	}
}

func TestGetImageManifestOnDemandInBackground(t *testing.T) {
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
			name:       "missing manifest queues sync",
			storageErr: zerr.ErrManifestNotFound,
			wantQueued: true,
		},
		{
			name:        "local hit returns immediately without sync",
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
			onDemand := &onDemandInBackgroundMock{
				queueImageFn: func(_ context.Context, queuedRepo, queuedReference string) {
					queued = true
					if queuedRepo != repo || queuedReference != reference {
						t.Fatalf("queued %s:%s, want %s:%s", queuedRepo, queuedReference, repo, reference)
					}
				},
			}
			handler := &RouteHandler{c: &Controller{
				Config:       appConfig,
				SyncOnDemand: onDemand,
				Log:          log.NewTestLogger(),
			}}
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
			if onDemand.syncImageCalls != 0 {
				t.Fatalf("SyncImage() called %d times, want 0", onDemand.syncImageCalls)
			}
		})
	}
}

func TestGetImageManifestOnDemandInBackgroundDigestMiss(t *testing.T) {
	t.Parallel()

	const (
		repo      = "library/test"
		reference = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	)

	enabled := true
	appConfig := config.New()
	appConfig.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &enabled},
	}

	queued := false
	onDemand := &onDemandInBackgroundMock{
		queueImageFn: func(_ context.Context, queuedRepo, queuedReference string) {
			queued = true
			if queuedRepo != repo || queuedReference != reference {
				t.Fatalf("queued %s:%s, want %s:%s", queuedRepo, queuedReference, repo, reference)
			}
		},
	}
	handler := &RouteHandler{c: &Controller{
		Config:       appConfig,
		SyncOnDemand: onDemand,
		Log:          log.NewTestLogger(),
	}}
	store := mocks.MockedImageStore{
		GetImageManifestFn: func(_, _ string) ([]byte, godigest.Digest, string, error) {
			return nil, "", "", zerr.ErrManifestNotFound
		},
	}

	_, _, _, err := getImageManifest(context.Background(), handler, store, repo, reference)
	if !errors.Is(err, zerr.ErrManifestNotFound) {
		t.Fatalf("getImageManifest() error = %v, want %v", err, zerr.ErrManifestNotFound)
	}
	if !queued {
		t.Fatal("expected QueueImage on digest miss")
	}
	if onDemand.syncImageCalls != 0 {
		t.Fatalf("SyncImage() called %d times, want 0", onDemand.syncImageCalls)
	}
}

func TestGetImageManifestBlockingWhenBackgroundDisabledForRepo(t *testing.T) {
	t.Parallel()

	enabled := true
	appConfig := config.New()
	appConfig.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &enabled},
	}

	synced := false
	onDemand := &onDemandInBackgroundMock{
		enabledForRepoFn: func(string) bool { return false },
		syncImageFn: func(context.Context, string, string) error {
			synced = true

			return nil
		},
		queueImageFn: func(context.Context, string, string) {
			t.Fatal("QueueImage should not be called when onDemandInBackground is disabled for repo")
		},
	}
	handler := &RouteHandler{c: &Controller{
		Config:       appConfig,
		SyncOnDemand: onDemand,
		Log:          log.NewTestLogger(),
	}}
	store := mocks.MockedImageStore{
		GetImageManifestFn: func(_, _ string) ([]byte, godigest.Digest, string, error) {
			return nil, "", "", zerr.ErrManifestNotFound
		},
	}

	_, _, _, err := getImageManifest(context.Background(), handler, store, "library/test", "latest")
	if !errors.Is(err, zerr.ErrManifestNotFound) {
		t.Fatalf("getImageManifest() error = %v, want %v", err, zerr.ErrManifestNotFound)
	}
	if !synced {
		t.Fatal("expected blocking SyncImage when onDemandInBackground is disabled for repo")
	}
}

func TestIsManifestNotFound(t *testing.T) {
	t.Parallel()

	for _, notFound := range []error{
		zerr.ErrRepoNotFound,
		zerr.ErrManifestNotFound,
	} {
		if !isManifestNotFound(notFound) {
			t.Errorf("isManifestNotFound(%v) = false, want true", notFound)
		}
	}

	if isManifestNotFound(errStorageUnavailable) {
		t.Error("isManifestNotFound(storage error) = true, want false")
	}
}
