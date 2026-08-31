package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestParseRangeHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		size    int64
		want    []httpRange
		wantErr bool
	}{
		{
			name:   "open ended range",
			header: "bytes=0-",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "range end is capped to size",
			header: "bytes=0-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "suffix range",
			header: "bytes=-3",
			size:   10,
			want:   []httpRange{{start: 7, end: 9}},
		},
		{
			name:   "oversized suffix range returns whole blob",
			header: "bytes=-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "ranges are sorted",
			header: "bytes=7-8, 0-1",
			size:   10,
			want: []httpRange{
				{start: 0, end: 1},
				{start: 7, end: 8},
			},
		},
		{
			name:   "overlapping and adjacent ranges are coalesced",
			header: "bytes=0-2,3-4,6-8,7-9",
			size:   10,
			want: []httpRange{
				{start: 0, end: 4},
				{start: 6, end: 9},
			},
		},
		{name: "zero size", header: "bytes=0-", wantErr: true},
		{name: "wrong unit", header: "byte=0-1", size: 10, wantErr: true},
		{name: "empty range set", header: "bytes=", size: 10, wantErr: true},
		{name: "empty range spec", header: "bytes=0-1,", size: 10, wantErr: true},
		{name: "zero suffix", header: "bytes=-0", size: 10, wantErr: true},
		{name: "bad suffix", header: "bytes=-x", size: 10, wantErr: true},
		{name: "bad start", header: "bytes=x-1", size: 10, wantErr: true},
		{name: "bad end", header: "bytes=1-x", size: 10, wantErr: true},
		{name: "inverted range", header: "bytes=2-1", size: 10, wantErr: true},
		{name: "range starts at size", header: "bytes=10-", size: 10, wantErr: true},
		{name: "range without dash", header: "bytes=0", size: 10, wantErr: true},
		{
			name:    "too many ranges",
			header:  "bytes=" + strings.TrimSuffix(strings.Repeat("0-0,", maxRangeSpecCount+1), ","),
			size:    10,
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseRangeHeader(test.header, test.size)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected parse error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("expected ranges %v, got %v", test.want, got)
			}
		})
	}
}

func TestNormalizeBlobRedirectURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		wantURL string
		wantOK  bool
	}{
		{
			name:    "preserves signed url bytes unchanged",
			rawURL:  "HTTPS://storage.example.com/blob?X-Amz-Signature=a%2Fb%2Bc",
			wantURL: "HTTPS://storage.example.com/blob?X-Amz-Signature=a%2Fb%2Bc",
			wantOK:  true,
		},
		{
			name:    "allows http scheme",
			rawURL:  "http://storage.example.com/blob",
			wantURL: "http://storage.example.com/blob",
			wantOK:  true,
		},
		{
			name:   "rejects disallowed scheme",
			rawURL: "javascript:alert(1)",
			wantOK: false,
		},
		{
			name:   "rejects parse failure",
			rawURL: "https://storage.example.com/%zz",
			wantOK: false,
		},
		{
			name:   "rejects missing host",
			rawURL: "https:///blob",
			wantOK: false,
		},
		{
			name:   "rejects crlf injection",
			rawURL: "https://storage.example.com/blob?sig=abc\r\nX-Test: y",
			wantOK: false,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			gotURL, gotOK := normalizeBlobRedirectURL(test.rawURL)
			if gotOK != test.wantOK {
				t.Fatalf("expected ok=%v, got %v", test.wantOK, gotOK)
			}

			if gotURL != test.wantURL {
				t.Fatalf("expected url %q, got %q", test.wantURL, gotURL)
			}
		})
	}
}

func TestIsBlobRedirectEnabled(t *testing.T) {
	t.Parallel()

	routeHandler := &RouteHandler{
		c: &Controller{
			Config: &config.Config{
				Storage: config.GlobalStorageConfig{
					StorageConfig: config.StorageConfig{
						RedirectBlobURL: false,
					},
					SubPaths: map[string]config.StorageConfig{
						"/a": {
							RedirectBlobURL: true,
						},
					},
				},
			},
			StoreController: storage.StoreController{
				SubStore: map[string]storageTypes.ImageStore{
					"/a": nil,
				},
			},
		},
	}

	if !routeHandler.isBlobRedirectEnabled("a/repo") {
		t.Fatal("expected redirect to be enabled for /a subpath repo")
	}

	// Default storage remains disabled even when a specific subpath enables redirect.
	if routeHandler.isBlobRedirectEnabled("b/repo") {
		t.Fatal("expected redirect to be disabled for default storage")
	}
}

func TestCanMountTraditionalBearer(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}
	imgStore := mocks.MockedImageStore{
		GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
			return []string{"src/repo"}, nil
		},
	}
	digest := godigest.FromString("bearer-mount-test")
	emptyUser := reqCtx.NewUserAccessControl()

	req := httptest.NewRequest(http.MethodPost, "/v2/dest/blobs/uploads/", nil)
	ok, err := rh.canMount(req, emptyUser, imgStore, digest, "dest")
	require.NoError(t, err)
	require.False(t, ok)

	acCtrlr := NewAccessController(conf)
	bearerReq := req.WithContext(acCtrlr.getAuthnMiddlewareContext(BEARER, req))
	ok, err = rh.canMount(bearerReq, emptyUser, imgStore, digest, "dest")
	require.NoError(t, err)
	require.True(t, ok)

	oidcReq := req.WithContext(acCtrlr.getAuthnMiddlewareContext(BEARER_OIDC, req))
	ok, err = rh.canMount(oidcReq, emptyUser, imgStore, digest, "dest")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestCanMountDedupeCandidatesError(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	candidatesErr := errors.New("candidates failed")
	rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}
	imgStore := mocks.MockedImageStore{
		GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
			return nil, candidatesErr
		},
	}

	userAc := reqCtx.NewUserAccessControl()
	userAc.SetUsername("alice")
	req := httptest.NewRequest(http.MethodPost, "/v2/dest/blobs/uploads/", nil)

	ok, err := rh.canMount(req, userAc, imgStore, godigest.FromString("candidates-err"), "dest")
	require.ErrorIs(t, err, candidatesErr)
	require.False(t, ok)
}

func TestUserMayMountBlobErrorPaths(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	rh := &RouteHandler{c: &Controller{Config: conf, Log: log.NewTestLogger()}}
	digest := godigest.FromString("user-may-mount-err")

	t.Run("bad user access control type", func(t *testing.T) {
		t.Parallel()

		ctx := context.WithValue(context.Background(), reqCtx.GetContextKey(), "not-a-user-ac")
		req := httptest.NewRequestWithContext(ctx, http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)

		ok, err := rh.userMayMountBlob(req, mocks.MockedImageStore{}, digest, "dest")
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("canMount candidates error is denied", func(t *testing.T) {
		t.Parallel()

		userAc := reqCtx.NewUserAccessControl()
		userAc.SetUsername("alice")
		req := httptest.NewRequest(http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)
		userAc.SaveOnRequest(req)

		candidatesErr := errors.New("candidates failed")
		imgStore := mocks.MockedImageStore{
			GetAllDedupeReposCandidatesFn: func(_ godigest.Digest) ([]string, error) {
				return nil, candidatesErr
			},
		}

		ok, err := rh.userMayMountBlob(req, imgStore, digest, "dest")
		require.NoError(t, err)
		require.False(t, ok)
	})
}

func TestResolveBlobPresenceUserMayMountError(t *testing.T) {
	t.Parallel()

	conf := config.New()
	conf.Storage.HydrateBlobOnRead = true
	conf.HTTP.AccessControl = &config.AccessControlConfig{
		Repositories: config.Repositories{
			"**": config.PolicyGroup{
				Policies: []config.Policy{
					{
						Users: []string{"alice"},
						Actions: []string{
							constants.ReadPermission,
							constants.CreatePermission,
						},
					},
				},
			},
		},
	}

	rh := &RouteHandler{
		c: &Controller{
			Config:          conf,
			Log:             log.NewTestLogger(),
			StoreController: storage.StoreController{},
		},
	}

	digest := godigest.FromString("resolve-presence-err")
	ctx := context.WithValue(context.Background(), reqCtx.GetContextKey(), "not-a-user-ac")
	req := httptest.NewRequestWithContext(ctx, http.MethodHead, "/v2/dest/blobs/"+digest.String(), nil)

	ok, size, err := rh.resolveBlobPresence(req, mocks.MockedImageStore{}, "dest", digest)
	require.Error(t, err)
	require.False(t, ok)
	require.Equal(t, int64(-1), size)
}
