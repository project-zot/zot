package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
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

	// An OIDC provider which can't be initialized must not break logout,
	// the response just doesn't include an end session url.
	rh := newTestRouteHandler(t)
	rh.c.RelyingParties["oidc"] = NewLazyRelyingParty(func(ctx context.Context) (rp.RelyingParty, error) {
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
}
