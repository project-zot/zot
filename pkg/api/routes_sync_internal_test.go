//go:build sync

package api

import (
	"context"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errStorageUnavailable = errors.New("storage unavailable")

type onDemandInBackgroundMock struct {
	queueImageFn     func(ctx context.Context, repo, reference string)
	enabledForRepoFn func(repo string) bool
	syncImageFn      func(ctx context.Context, repo, reference string) error
	syncImageCalls   int
	// streaming makes IsStreamingEnabledForRepo true, as if a separate stream registry also matched
	// the repo.
	streaming           bool
	fetchForStreamFn    func(ctx context.Context) (manifest.Manifest, error)
	fetchForStreamCalls int
	// streamManager is what StreamManager returns (nil by default).
	streamManager sync.StreamManager
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

func (mock *onDemandInBackgroundMock) FetchManifestForStream(ctx context.Context, _, _ string,
	_ func(manifest.Manifest),
) (manifest.Manifest, error) {
	mock.fetchForStreamCalls++

	if mock.fetchForStreamFn != nil {
		return mock.fetchForStreamFn(ctx)
	}

	return nil, zerr.ErrSyncOnDemandDisabled
}

func (mock *onDemandInBackgroundMock) StreamManager() sync.StreamManager {
	return mock.streamManager
}

// stagedRefsStreamManager is a sync.StreamManager that only reports which repo:references are
// staged, e.g. by a sync from before a config reload.
type stagedRefsStreamManager struct {
	sync.StreamManager

	staged map[string]bool
}

func (sm *stagedRefsStreamManager) StreamingImageManifest(repo, reference string,
) (*sync.StreamableManifest, bool) {
	if sm.staged[repo+":"+reference] {
		return &sync.StreamableManifest{}, true
	}

	return nil, false
}

func (mock *onDemandInBackgroundMock) IsStreamingEnabledForRepo(string) bool {
	return mock.streaming
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

			content, _, _, _, err := getImageManifest(context.Background(), handler, store, repo, reference, nil)
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

	_, _, _, _, err := getImageManifest(context.Background(), handler, store, repo, reference, nil)
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

	_, _, _, _, err := getImageManifest(context.Background(), handler, store, "library/test", "latest", nil)
	if !errors.Is(err, zerr.ErrManifestNotFound) {
		t.Fatalf("getImageManifest() error = %v, want %v", err, zerr.ErrManifestNotFound)
	}
	if !synced {
		t.Fatal("expected blocking SyncImage when onDemandInBackground is disabled for repo")
	}
}

// TestGetImageManifestOnDemandInBackgroundWinsOverStreaming: with a background registry and a
// separate stream registry matching the repo, a local miss is queued and gets 404; streaming is
// never tried.
func TestGetImageManifestOnDemandInBackgroundWinsOverStreaming(t *testing.T) {
	t.Parallel()

	const repo = "library/test"

	enabled := true
	appConfig := config.New()
	appConfig.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &enabled},
	}

	for _, reference := range []string{
		"latest",
		"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	} {
		t.Run(reference, func(t *testing.T) {
			t.Parallel()

			queued := false
			onDemand := &onDemandInBackgroundMock{
				streaming: true,
				queueImageFn: func(context.Context, string, string) {
					queued = true
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

			_, _, _, _, err := getImageManifest(context.Background(), handler, store, repo, reference, nil)
			if !errors.Is(err, zerr.ErrManifestNotFound) {
				t.Fatalf("getImageManifest() error = %v, want %v", err, zerr.ErrManifestNotFound)
			}
			if !queued {
				t.Fatal("expected QueueImage when onDemandInBackground and streaming both match repo")
			}
			if onDemand.fetchForStreamCalls != 0 {
				t.Fatalf("FetchManifestForStream() called %d times, want 0", onDemand.fetchForStreamCalls)
			}
			if onDemand.syncImageCalls != 0 {
				t.Fatalf("SyncImage() called %d times, want 0", onDemand.syncImageCalls)
			}
		})
	}
}

func TestGetImageManifestStreamed(t *testing.T) {
	t.Parallel()

	enabled := true
	appConfig := config.New()
	appConfig.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &enabled},
	}

	newHandler := func(onDemand *onDemandInBackgroundMock) *RouteHandler {
		return &RouteHandler{c: &Controller{
			Config:       appConfig,
			SyncOnDemand: onDemand,
			Log:          log.NewTestLogger(),
		}}
	}

	// The tag is local at an older digest: the streamed manifest must still be reported as streamed,
	// so GetManifest leaves counting it to onStreamSynced rather than the old digest's metadata.
	staleStore := mocks.MockedImageStore{
		GetImageManifestFn: func(_, _ string) ([]byte, godigest.Digest, string, error) {
			return []byte("{}"), godigest.FromString("older"), ispec.MediaTypeImageManifest, nil
		},
	}

	t.Run("streamed manifest", func(t *testing.T) {
		t.Parallel()

		upstream, err := manifest.New(manifest.WithRaw([]byte(`{"schemaVersion":2,` +
			`"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
			`"config":{"mediaType":"application/vnd.oci.image.config.v1+json",` +
			`"digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},` +
			`"layers":[]}`)))
		if err != nil {
			t.Fatal(err)
		}

		onDemand := &onDemandInBackgroundMock{
			streaming:        true,
			enabledForRepoFn: func(string) bool { return false },
			fetchForStreamFn: func(context.Context) (manifest.Manifest, error) {
				return upstream, nil
			},
		}

		_, digest, _, streamed, err := getImageManifest(context.Background(), newHandler(onDemand), staleStore,
			"library/test", "latest", nil)
		if err != nil {
			t.Fatalf("getImageManifest() error = %v", err)
		}

		if !streamed {
			t.Fatal("getImageManifest() streamed = false, want true")
		}

		if digest != upstream.GetDescriptor().Digest {
			t.Fatalf("getImageManifest() digest = %s, want upstream %s", digest, upstream.GetDescriptor().Digest)
		}
	})

	t.Run("canceled while waiting", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		onDemand := &onDemandInBackgroundMock{
			streaming:        true,
			enabledForRepoFn: func(string) bool { return false },
			fetchForStreamFn: func(ctx context.Context) (manifest.Manifest, error) {
				return nil, ctx.Err()
			},
		}

		_, _, _, streamed, err := getImageManifest(ctx, newHandler(onDemand), staleStore, "library/test", "latest",
			nil)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("getImageManifest() error = %v, want %v", err, context.Canceled)
		}

		if streamed {
			t.Fatal("getImageManifest() streamed = true, want false")
		}

		// The client is gone: it must not wait on the sync again through SyncImage.
		if onDemand.syncImageCalls != 0 {
			t.Fatalf("SyncImage() called %d times, want 0", onDemand.syncImageCalls)
		}
	})
}

func TestIsManifestNotFound(t *testing.T) {
	t.Parallel()

	for _, notFound := range []error{
		zerr.ErrRepoNotFound,
		zerr.ErrManifestNotFound,
		errors.Join(zerr.ErrRepoNotFound, zerr.ErrStorageMissing),
	} {
		if !isManifestNotFound(notFound) {
			t.Errorf("isManifestNotFound(%v) = false, want true", notFound)
		}
	}

	for _, storageErr := range []error{
		errStorageUnavailable,
		zerr.ErrStorageTransient,
		zerr.ErrStoragePermanent,
		errors.Join(zerr.ErrRepoNotFound, zerr.ErrStorageTransient),
	} {
		if isManifestNotFound(storageErr) {
			t.Errorf("isManifestNotFound(%v) = true, want false", storageErr)
		}
	}
}

func TestDownloadRecorderCountsOnce(t *testing.T) {
	t.Parallel()

	t.Run("a second successful attempt is not counted", func(t *testing.T) {
		t.Parallel()

		calls := 0
		downloads := &downloadRecorder{}
		update := func() error {
			calls++

			return nil
		}

		downloads.record(update) // immediate GetManifest attempt
		downloads.record(update) // streaming-sync replay

		if calls != 1 {
			t.Fatalf("update called %d times, want 1", calls)
		}
	})

	t.Run("a failed attempt leaves the download to the next one", func(t *testing.T) {
		t.Parallel()

		calls := 0
		downloads := &downloadRecorder{}

		downloads.record(func() error {
			calls++

			return zerr.ErrImageMetaNotFound
		})
		downloads.record(func() error {
			calls++

			return nil
		})
		downloads.record(func() error {
			calls++

			return nil
		})

		if calls != 2 {
			t.Fatalf("update called %d times, want 2", calls)
		}
	})
}

// TestGetImageManifestJoinsInFlightStream: a reference still staged for streaming (here, by a sync
// from before a reload that made the repo plain or background-only) is joined through
// FetchManifestForStream rather than synced or queued a second time beside it.
func TestGetImageManifestJoinsInFlightStream(t *testing.T) {
	t.Parallel()

	const repo = "library/test"

	enabled := true
	appConfig := config.New()
	appConfig.Extensions = &extconf.ExtensionConfig{
		Sync: &syncconf.Config{Enable: &enabled},
	}

	upstream, err := manifest.New(manifest.WithRaw([]byte(`{"schemaVersion":2,` +
		`"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
		`"config":{"mediaType":"application/vnd.oci.image.config.v1+json",` +
		`"digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},` +
		`"layers":[]}`)))
	if err != nil {
		t.Fatal(err)
	}

	missingStore := mocks.MockedImageStore{
		GetImageManifestFn: func(_, _ string) ([]byte, godigest.Digest, string, error) {
			return nil, "", "", zerr.ErrManifestNotFound
		},
	}

	for _, reference := range []string{
		"latest",
		"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	} {
		for name, backgroundOnly := range map[string]bool{"plain": false, "background-only": true} {
			t.Run(name+" "+reference, func(t *testing.T) {
				t.Parallel()

				queued := false
				onDemand := &onDemandInBackgroundMock{
					// The reloaded config no longer streams the repo.
					streaming:        false,
					enabledForRepoFn: func(string) bool { return backgroundOnly },
					queueImageFn:     func(context.Context, string, string) { queued = true },
					fetchForStreamFn: func(context.Context) (manifest.Manifest, error) { return upstream, nil },
					streamManager: &stagedRefsStreamManager{
						staged: map[string]bool{repo + ":" + reference: true},
					},
				}
				handler := &RouteHandler{c: &Controller{
					Config:       appConfig,
					SyncOnDemand: onDemand,
					Log:          log.NewTestLogger(),
				}}

				_, digest, _, streamed, err := getImageManifest(context.Background(), handler, missingStore,
					repo, reference, nil)
				if err != nil {
					t.Fatalf("getImageManifest() error = %v", err)
				}

				if !streamed || digest != upstream.GetDescriptor().Digest {
					t.Fatalf("getImageManifest() = %s streamed=%t, want the in-flight stream's manifest", digest, streamed)
				}

				if onDemand.fetchForStreamCalls != 1 {
					t.Fatalf("FetchManifestForStream() called %d times, want 1", onDemand.fetchForStreamCalls)
				}

				if onDemand.syncImageCalls != 0 || queued {
					t.Fatalf("SyncImage() called %d times, queued %t: want neither beside the stream",
						onDemand.syncImageCalls, queued)
				}
			})
		}

		t.Run("background-only, nothing staged "+reference, func(t *testing.T) {
			t.Parallel()

			queued := false
			onDemand := &onDemandInBackgroundMock{
				queueImageFn:  func(context.Context, string, string) { queued = true },
				streamManager: &stagedRefsStreamManager{staged: map[string]bool{repo + ":other": true}},
			}
			handler := &RouteHandler{c: &Controller{
				Config:       appConfig,
				SyncOnDemand: onDemand,
				Log:          log.NewTestLogger(),
			}}

			_, _, _, _, err := getImageManifest(context.Background(), handler, missingStore, repo, reference, nil)
			if !errors.Is(err, zerr.ErrManifestNotFound) {
				t.Fatalf("getImageManifest() error = %v, want %v", err, zerr.ErrManifestNotFound)
			}

			if !queued || onDemand.fetchForStreamCalls != 0 {
				t.Fatalf("queued %t, FetchManifestForStream() called %d times: want a queued sync only",
					queued, onDemand.fetchForStreamCalls)
			}
		})
	}
}
