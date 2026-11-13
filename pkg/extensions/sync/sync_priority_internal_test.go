//go:build sync

package sync

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/regclient/regclient/types/manifest"
	"github.com/stretchr/testify/require"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
)

func priorityReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()

	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sync priority transition")

		var zero T

		return zero
	}
}

func TestSyncPriorityCancelsAndJoinsBackground(t *testing.T) {
	t.Parallel()

	var priority syncPriority

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	started := make(chan context.Context, 1)
	unwind := make(chan struct{})
	defer close(unwind)
	retried := make(chan struct{}, 1)
	backgroundDone := make(chan error, 1)
	var attempts atomic.Int32

	go func() {
		backgroundDone <- priority.runBackground(ctx, log.NewTestLogger(), func(workCtx context.Context) error {
			if attempts.Add(1) == 1 {
				started <- workCtx
				<-workCtx.Done()
				select {
				case <-unwind:
				case <-ctx.Done():
				}

				return workCtx.Err()
			}

			retried <- struct{}{}

			return nil
		})
	}()

	workCtx := priorityReceive(t, started)
	streamStarted := make(chan func(), 1)
	go func() {
		release, err := priority.startStream(ctx)
		if err == nil {
			streamStarted <- release
		}
	}()

	priorityReceive(t, workCtx.Done())
	require.ErrorIs(t, context.Cause(workCtx), errBackgroundSyncPreempted)

	select {
	case release := <-streamStarted:
		release()
		t.Fatal("stream started before background attempt unwound")
	default:
	}

	unwind <- struct{}{}
	release := priorityReceive(t, streamStarted)
	select {
	case <-retried:
		t.Fatal("background retry overlapped streaming")
	default:
	}
	release()

	priorityReceive(t, retried)
	require.NoError(t, priorityReceive(t, backgroundDone))
	require.EqualValues(t, 2, attempts.Load())
}

func TestSyncPriorityBacksOffUntilLastStreamFinishes(t *testing.T) {
	t.Parallel()

	var priority syncPriority

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	releaseFirst, err := priority.startStream(ctx)
	require.NoError(t, err)
	releaseLast, err := priority.startStream(ctx)
	require.NoError(t, err)

	attempted := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- priority.runBackground(ctx, log.NewTestLogger(), func(context.Context) error {
			attempted <- struct{}{}

			return nil
		})
	}()

	releaseFirst()
	priority.mu.Lock()
	require.Len(t, priority.background, 0)
	priority.mu.Unlock()
	releaseLast()
	priorityReceive(t, attempted)
	require.NoError(t, priorityReceive(t, done))
}

func TestSyncPriorityCanceledWaitsReleaseReservation(t *testing.T) {
	t.Parallel()

	var priority syncPriority

	ctx, cancel := context.WithCancel(context.Background())
	release, err := priority.startStream(ctx)
	require.NoError(t, err)
	cancel()

	var called bool
	err = priority.runBackground(ctx, log.NewTestLogger(), func(context.Context) error {
		called = true

		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
	release()

	workCtx, cancelWork := context.WithCancelCause(context.Background())
	defer cancelWork(nil)
	work := &backgroundSync{cancel: cancelWork}
	priority.mu.Lock()
	priority.background = map[*backgroundSync]struct{}{work: {}}
	priority.mu.Unlock()

	waitCtx, cancelWait := context.WithCancel(context.Background())
	streamDone := make(chan error, 1)
	go func() {
		_, err := priority.startStream(waitCtx)
		streamDone <- err
	}()
	priorityReceive(t, workCtx.Done())
	cancelWait()
	require.ErrorIs(t, priorityReceive(t, streamDone), context.Canceled)

	priority.mu.Lock()
	require.Zero(t, priority.streams)
	delete(priority.background, work)
	priority.mu.Unlock()

	require.NoError(t, priority.runBackground(context.Background(), log.NewTestLogger(),
		func(context.Context) error { return nil }))
}

func TestSyncPriorityDoesNotRetryRealErrors(t *testing.T) {
	t.Parallel()

	var priority syncPriority
	wantErr := errors.New("upstream failed")
	attempts := 0
	err := priority.runBackground(context.Background(), log.NewTestLogger(), func(context.Context) error {
		attempts++

		return wantErr
	})
	require.ErrorIs(t, err, wantErr)
	require.Equal(t, 1, attempts)
}

func TestSyncPriorityStreamingFlightPreemptsSameKeyRetry(t *testing.T) {
	t.Parallel()

	_, store := newTestStore(t)
	sm := newTestStreamManager(t, store, 0)
	syncBlock := make(chan struct{})
	defer close(syncBlock)
	imageManifest := newTestManifestForStream(t)
	svc := &fakeStreamService{
		fetchManifestFn: func(context.Context, string, string) (manifest.Manifest, error) {
			return imageManifest, nil
		},
		syncImageBlock: syncBlock,
	}
	onDemand := NewOnDemand(log.NewTestLogger())
	onDemand.SetStreamManager(sm)
	onDemand.Add(svc)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	retryStarted := make(chan context.Context, 1)
	retryFinished := make(chan struct{}, 1)
	var attempts atomic.Int32
	maxRetries := 1
	retryService := &BaseService{config: syncconf.RegistryConfig{MaxRetries: &maxRetries}}
	onDemand.maybeRetryInBackground(ctx, onDemandKindImage, "streamed", predictTestTag,
		"shared retry", retryService, errors.New("initial failure"), func(retryCtx context.Context) error {
			retryCtx, cancel := context.WithTimeout(retryCtx, 5*time.Second)
			defer cancel()

			return sm.priority.runBackground(retryCtx, log.NewTestLogger(), func(workCtx context.Context) error {
				if attempts.Add(1) == 1 {
					retryStarted <- workCtx
					<-workCtx.Done()

					return workCtx.Err()
				}

				retryFinished <- struct{}{}

				return nil
			})
		})
	workCtx := priorityReceive(t, retryStarted)

	fetched, err := onDemand.FetchManifestForStream(ctx, "streamed", predictTestTag, nil)
	require.NoError(t, err)
	require.NotEmpty(t, fetched.GetDescriptor().Digest)
	require.ErrorIs(t, context.Cause(workCtx), errBackgroundSyncPreempted)
	require.EqualValues(t, 1, attempts.Load())
	staged, ok := sm.StreamingImageManifest("streamed", predictTestTag)
	require.True(t, ok)

	backgroundCtx, cancelBackground := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancelBackground()
	backgroundDone := make(chan error, 1)
	go func() {
		backgroundDone <- sm.priority.runBackground(backgroundCtx, log.NewTestLogger(),
			func(context.Context) error {
				return errors.New("background attempt ran during streaming")
			})
	}()
	require.ErrorIs(t, priorityReceive(t, backgroundDone), context.DeadlineExceeded)

	sm.priority.mu.Lock()
	streams := sm.priority.streams
	sm.priority.mu.Unlock()
	require.Positive(t, streams)

	syncBlock <- struct{}{}
	priorityReceive(t, staged.done)

	require.NoError(t, sm.priority.runBackground(ctx, log.NewTestLogger(),
		func(context.Context) error { return nil }))
	priorityReceive(t, retryFinished)
}

func TestSyncPriorityPreemptsRegistryHTTPBeforeManifestFetch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/background/tags/list" {
			w.WriteHeader(http.StatusOK)

			return
		}

		if requests.Add(1) == 1 {
			started <- struct{}{}
			select {
			case <-r.Context().Done():
				canceled <- struct{}{}
			case <-ctx.Done():
			}

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"background","tags":[]}`))
	}))
	defer server.Close()

	root, store := newTestStore(t)
	writeOCISingleManifest(t, store, "streamed")
	sm := newTestStreamManager(t, store, 0)
	streamService := newFetchManifestTestService(root, nil, nil)
	streamService.priority = priorityFor(sm)
	concrete, ok := store.(storage.StoreController)
	require.True(t, ok)
	backgroundService, err := New(syncconf.RegistryConfig{URLs: []string{server.URL}},
		"", nil, "", concrete, sm, nil, log.NewTestLogger())
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- backgroundService.SyncRepo(ctx, "background")
	}()
	priorityReceive(t, started)

	// The outer lease models the staging flight, which holds priority between
	// FetchManifest and SyncImageForStream and through stream teardown.
	release, err := priorityFor(sm).startStream(ctx)
	require.NoError(t, err)
	priorityReceive(t, canceled)
	fetched, err := streamService.FetchManifest(ctx, "streamed", predictTestTag)
	require.NoError(t, err)
	require.NotEmpty(t, fetched.GetDescriptor().Digest)
	require.EqualValues(t, 1, requests.Load())
	release()

	require.NoError(t, priorityReceive(t, done))
	require.EqualValues(t, 2, requests.Load())
}
