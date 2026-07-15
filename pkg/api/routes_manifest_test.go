//go:build sync && scrub && metrics && search && lint && mgmt

package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	rcmanifest "github.com/regclient/regclient/types/manifest"
	rcOCIV1 "github.com/regclient/regclient/types/oci/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func newTestManifest(t *testing.T) rcmanifest.Manifest {
	t.Helper()

	origMan := rcOCIV1.Manifest{
		Versioned: rcOCIV1.ManifestSchemaVersion,
	}

	m, err := rcmanifest.New(rcmanifest.WithOrig(origMan))
	if err != nil {
		t.Fatalf("failed to create test manifest: %v", err)
	}

	return m
}

func TestGetManifestStreaming(t *testing.T) {
	Convey("GetManifest streaming path", t, func() {
		const reference = "v1.0"

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				"http://example.com/v2/test/manifests/"+reference,
				http.NoBody,
			)

			return mux.SetURLVars(req, map[string]string{
				"name":      "test",
				"reference": reference,
			})
		}

		Convey("falls through to 404 when streaming is not enabled for repo", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return false },
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.MANIFEST_UNKNOWN.String())
		})

		Convey("directly returns manifest from upstream when FetchManifestForStream succeeds", func() {
			testManifest := newTestManifest(t)

			rawBody, err := testManifest.RawBody()
			So(err, ShouldBeNil)

			desc := testManifest.GetDescriptor()

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				fetchManifestForStreamFn: func(_ context.Context, _, _ string) (rcmanifest.Manifest, error) {
					return testManifest, nil
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Length"), ShouldEqual, strconv.Itoa(len(rawBody)))
			So(resp.Header.Get("Content-Type"), ShouldEqual, desc.MediaType)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, desc.Digest.String())

			body, readErr := io.ReadAll(resp.Body)
			So(readErr, ShouldBeNil)
			So(body, ShouldResemble, rawBody)
		})

		Convey("falls back to 404 when FetchManifestForStream fails and GetImageManifest also fails", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				fetchManifestForStreamFn: func(_ context.Context, _, _ string) (rcmanifest.Manifest, error) {
					return nil, zerr.ErrSyncMissingCatalog
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.GetManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.MANIFEST_UNKNOWN.String())
		})
	})
}

func TestCheckManifestStreaming(t *testing.T) {
	Convey("CheckManifest streaming path", t, func() {
		const reference = "v1.0"

		newReq := func() *http.Request {
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodHead,
				"http://example.com/v2/test/manifests/"+reference,
				http.NoBody,
			)

			return mux.SetURLVars(req, map[string]string{
				"name":      "test",
				"reference": reference,
			})
		}

		Convey("falls through to 404 when streaming is not enabled for repo", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return false },
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.MANIFEST_UNKNOWN.String())
		})

		Convey("returns 200 with manifest headers when FetchManifestForStream succeeds", func() {
			testManifest := newTestManifest(t)

			rawBody, err := testManifest.RawBody()
			So(err, ShouldBeNil)

			desc := testManifest.GetDescriptor()

			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				fetchManifestForStreamFn: func(_ context.Context, _, _ string) (rcmanifest.Manifest, error) {
					return testManifest, nil
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
			So(resp.Header.Get("Content-Length"), ShouldEqual, strconv.Itoa(len(rawBody)))
			So(resp.Header.Get("Content-Type"), ShouldEqual, desc.MediaType)
			So(resp.Header.Get(constants.DistContentDigestKey), ShouldEqual, desc.Digest.String())
		})

		Convey("falls back to 404 when FetchManifestForStream fails and GetImageManifest also fails", func() {
			syncOnDemand := &mockSyncOnDemand{
				isStreamingEnabledForRepoFn: func(_ string) bool { return true },
				fetchManifestForStreamFn: func(_ context.Context, _, _ string) (rcmanifest.Manifest, error) {
					return nil, zerr.ErrSyncMissingCatalog
				},
			}
			handler := newStreamingBlobTestRouteHandler(t, mocks.MockedImageStore{
				GetImageManifestFn: func(_ string, _ string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", zerr.ErrManifestNotFound
				},
			}, syncOnDemand)

			rec := httptest.NewRecorder()
			handler.CheckManifest(rec, newReq())

			resp := rec.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			var errList apiErr.ErrorList
			So(json.NewDecoder(resp.Body).Decode(&errList), ShouldBeNil)
			So(errList.Errors, ShouldHaveLength, 1)
			So(errList.Errors[0].Code, ShouldEqual, apiErr.MANIFEST_UNKNOWN.String())
		})
	})
}
