package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"

	zerr "zotregistry.dev/zot/v2/errors"
)

func TestLazyRelyingPartyRetriesUntilInitialized(t *testing.T) {
	t.Parallel()

	errUnreachable := errors.New("issuer unreachable")
	relyingParty := &fakeEndSessionRP{clientID: "zot-client"}
	calls := 0
	available := false

	lazyRelyingParty := NewLazyRelyingParty(func(ctx context.Context) (rp.RelyingParty, error) {
		calls++

		if !available {
			return nil, errUnreachable
		}

		return relyingParty, nil
	})

	// failures are not cached
	for range 2 {
		got, err := lazyRelyingParty.Get(context.Background())
		require.ErrorIs(t, err, errUnreachable)
		assert.Nil(t, got)
	}

	assert.Equal(t, 2, calls)

	available = true

	// a successful initialization is cached
	for range 2 {
		got, err := lazyRelyingParty.Get(context.Background())
		require.NoError(t, err)
		assert.Same(t, relyingParty, got)
	}

	assert.Equal(t, 3, calls)
}

func TestLogoutWithUnavailableRelyingParty(t *testing.T) {
	t.Parallel()

	// An OIDC provider which isn't initialized yet must not break or delay logout:
	// logout never contacts the issuer, the response just doesn't include an end session url.
	rh := newTestRouteHandler(t)

	var calls atomic.Int32

	rh.c.RelyingParties["oidc"] = NewLazyRelyingParty(func(ctx context.Context) (rp.RelyingParty, error) {
		calls.Add(1)

		return nil, errors.New("issuer unreachable")
	})

	cookies := seedSessionProvider(t, rh, "oidc")

	req := httptest.NewRequest(http.MethodPost, "/zot/auth/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	rh.Logout(rec, req)

	res := rec.Result()
	defer res.Body.Close()

	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.JSONEq(t, "{}", rec.Body.String())
	assert.Zero(t, calls.Load())
}

func TestLazyRelyingPartySharesInitialization(t *testing.T) {
	t.Parallel()

	relyingParty := &fakeEndSessionRP{clientID: "zot-client"}
	release := make(chan struct{})
	started := make(chan struct{}, 1)

	var calls atomic.Int32

	lazyRelyingParty := NewLazyRelyingParty(func(ctx context.Context) (rp.RelyingParty, error) {
		calls.Add(1)
		started <- struct{}{}
		<-release

		return relyingParty, nil
	})

	const callers = 5

	var wg sync.WaitGroup

	results := make(chan rp.RelyingParty, callers)

	for range callers {
		wg.Go(func() {
			got, err := lazyRelyingParty.Get(context.Background())
			assert.NoError(t, err)

			results <- got
		})
	}

	<-started

	// the lock is not held while the initialization is in flight
	got, ok := lazyRelyingParty.GetIfInitialized()
	assert.False(t, ok)
	assert.Nil(t, got)

	// a caller which gives up doesn't wait for the initialization, nor abort it for the others
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := lazyRelyingParty.Get(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, got)

	close(release)
	wg.Wait()
	close(results)

	for got := range results {
		assert.Same(t, relyingParty, got)
	}

	assert.Equal(t, int32(1), calls.Load())

	got, ok = lazyRelyingParty.GetIfInitialized()
	assert.True(t, ok)
	assert.Same(t, relyingParty, got)
}

func TestLazyRelyingPartyPublishesOnlySuccess(t *testing.T) {
	t.Parallel()

	errUnreachable := errors.New("issuer unreachable")
	relyingParty := &fakeEndSessionRP{clientID: "zot-client"}

	results := []struct {
		relyingParty rp.RelyingParty
		err          error
	}{
		// a client returned together with an error must not be cached
		{relyingParty, errUnreachable},
		// no client and no error is treated as a failure
		{nil, nil},
		{relyingParty, nil},
	}
	calls := 0

	lazyRelyingParty := NewLazyRelyingParty(func(ctx context.Context) (rp.RelyingParty, error) {
		result := results[calls]
		calls++

		return result.relyingParty, result.err
	})

	got, err := lazyRelyingParty.Get(context.Background())
	require.ErrorIs(t, err, errUnreachable)
	assert.Nil(t, got)

	_, ok := lazyRelyingParty.GetIfInitialized()
	assert.False(t, ok)

	got, err = lazyRelyingParty.Get(context.Background())
	require.ErrorIs(t, err, zerr.ErrOpenIDRelyingPartyNil)
	assert.Nil(t, got)

	got, err = lazyRelyingParty.Get(context.Background())
	require.NoError(t, err)
	assert.Same(t, relyingParty, got)
	assert.Equal(t, 3, calls)
}

func TestLazyRelyingPartyInitializationIsBounded(t *testing.T) {
	t.Parallel()

	assert.Equal(t, relyingPartyInitTimeout, NewLazyRelyingParty(nil).initTimeout)

	lazyRelyingParty := NewLazyRelyingParty(func(ctx context.Context) (rp.RelyingParty, error) {
		if _, ok := ctx.Deadline(); !ok {
			return nil, errors.New("initialization context has no deadline")
		}

		<-ctx.Done()

		return nil, ctx.Err()
	})
	lazyRelyingParty.initTimeout = 100 * time.Millisecond

	// the caller has no deadline, the initialization still gives up on its own
	_, err := lazyRelyingParty.Get(context.Background())
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
