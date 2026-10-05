package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestWritePutImageManifestErrorMissingBlob(t *testing.T) {
	t.Parallel()

	routeHandler := &RouteHandler{c: &Controller{Log: log.NewTestLogger()}}

	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{fmt.Errorf("%w: %w", zerr.ErrBadManifest, zerr.ErrBlobNotFound), http.StatusBadRequest, "MANIFEST_BLOB_UNKNOWN"},
		{fmt.Errorf("%w: %w", zerr.ErrManifestCacheLookup, zerr.ErrBlobNotFound), http.StatusInternalServerError, ""},
	} {
		response := httptest.NewRecorder()
		routeHandler.writePutImageManifestError(response, "repo", "tag", tc.err)

		if response.Code != tc.status {
			t.Errorf("writePutImageManifestError(%v) status = %d, want %d", tc.err, response.Code, tc.status)
		}

		if !strings.Contains(response.Body.String(), tc.code) {
			t.Errorf("writePutImageManifestError(%v) body = %q, want %s", tc.err, response.Body.String(), tc.code)
		}
	}
}
