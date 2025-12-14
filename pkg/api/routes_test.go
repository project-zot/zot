//go:build sync && scrub && metrics && search && lint && mgmt

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-zot/mockoidc"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

const sessionStr = "session"

func TestRoutes(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		mockOIDCServer, err := mockoidc.Run()
		if err != nil {
			panic(err)
		}

		defer func() {
			err := mockOIDCServer.Shutdown()
			if err != nil {
				panic(err)
			}
		}()

		mockOIDCConfig := mockOIDCServer.Config()
		defaultVal := true

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email"},
					},
				},
			},
			APIKey: defaultVal,
		}

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.Commit = true

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		rthdlr := api.NewRouteHandler(ctlr)

		// NOTE: the url or method itself doesn't matter below since we are calling the handlers directly,
		// so path routing is bypassed

		Convey("Test GithubCodeExchangeCallback", func() {
			callback := rthdlr.GithubCodeExchangeCallback()
			ctx := context.TODO()

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			response := httptest.NewRecorder()

			tokens := &oidc.Tokens[*oidc.IDTokenClaims]{}
			relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{})
			So(err, ShouldBeNil)

			callback(response, request, tokens, "state", relyingParty)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
		})

		Convey("Test OpenIDCodeExchangeCallback", func() {
			callback := rthdlr.OpenIDCodeExchangeCallback()
			ctx := context.TODO()

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			response := httptest.NewRecorder()

			tokens := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						"groups": []any{"group1", "group3"},
					},
				},
			}
			relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{})
			So(err, ShouldBeNil)

			userinfo := &oidc.UserInfo{
				Subject: "sub",
				Claims: map[string]any{
					"email":  "test@test.com",
					"groups": []any{"group1", "group2"},
				},
				UserInfoEmail: oidc.UserInfoEmail{Email: "test@test.com"},
			}

			callback(response, request, tokens, "state", relyingParty, userinfo)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusUnauthorized)
		})

		Convey("Test OAuth2Callback errors", func() {
			ctx := context.TODO()

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			response := httptest.NewRecorder()

			_, err := api.OAuth2Callback(ctlr, response, request, "state", "email", []string{"group"})
			So(err, ShouldEqual, zerr.ErrInvalidStateCookie)

			session, _ := ctlr.CookieStore.Get(request, "statecookie")

			session.Options.Secure = true
			session.Options.HttpOnly = true
			session.Options.SameSite = http.SameSiteDefaultMode

			state := uuid.New().String()

			session.Values["state"] = state

			// let the session set its own id
			err = session.Save(request, response)
			So(err, ShouldBeNil)

			_, err = api.OAuth2Callback(ctlr, response, request, "state", "email", []string{"group"})
			So(err, ShouldEqual, zerr.ErrInvalidStateCookie)
		})

		Convey("List repositories authz error", func() {
			var invalid struct{}

			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, invalid)

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{
				"name":      "test",
				"reference": "b8b1231908844a55c251211c7a67ae3c809fb86a081a8eeb4a715e6d7d65625c",
			})
			response := httptest.NewRecorder()

			rthdlr.ListRepositories(response, request)

			resp := response.Result()

			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("Delete manifest authz error", func() {
			var invalid struct{}

			uacKey := reqCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), uacKey, invalid)

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{
				"name":      "test",
				"reference": "b8b1231908844a55c251211c7a67ae3c809fb86a081a8eeb4a715e6d7d65625c",
			})
			response := httptest.NewRecorder()

			rthdlr.DeleteManifest(response, request)

			resp := response.Result()

			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("Get manifest", func() {
			// overwrite controller storage
			ctlr.StoreController.DefaultStore = &mocks.MockedImageStore{
				GetImageManifestFn: func(repo string, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte{}, "", "", zerr.ErrRepoBadVersion
				},
			}

			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{
				"name":      "test",
				"reference": "b8b1231908844a55c251211c7a67ae3c809fb86a081a8eeb4a715e6d7d65625c",
			})
			response := httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp := response.Result()

			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("UpdateManifest ", func() {
			testUpdateManifest := func(urlVars map[string]string, ism *mocks.MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				str := []byte("test")
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, bytes.NewBuffer(str))
				request = mux.SetURLVars(request, urlVars)
				request.Header.Add("Content-Type", ispec.MediaTypeImageManifest)
				response := httptest.NewRecorder()

				rthdlr.UpdateManifest(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}
			// repo not found
			statusCode := testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
			// ErrManifestNotFound
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},

				&mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", zerr.ErrManifestNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
			// ErrBadManifest
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", zerr.ErrBadManifest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)
			// ErrBlobNotFound
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", zerr.ErrBlobNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrRepoBadVersion
			statusCode = testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", zerr.ErrRepoBadVersion
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("DeleteManifest", func() {
			testDeleteManifest := func(headers map[string]string, urlVars map[string]string, ism *mocks.MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, baseURL, nil)
				request = mux.SetURLVars(request, urlVars)

				for k, v := range headers {
					request.Header.Add(k, v)
				}
				response := httptest.NewRecorder()

				rthdlr.DeleteManifest(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrRepoNotFound
			statusCode := testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrManifestNotFound",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					DeleteImageManifestFn: func(repo, reference string, detectCollision bool) error {
						return zerr.ErrRepoNotFound
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrManifestNotFound
			statusCode = testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrManifestNotFound",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					DeleteImageManifestFn: func(repo, reference string, detectCollision bool) error {
						return zerr.ErrManifestNotFound
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUnexpectedError
			statusCode = testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrUnexpectedError",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					DeleteImageManifestFn: func(repo, reference string, detectCollision bool) error {
						return ErrUnexpectedError
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// ErrBadManifest
			statusCode = testDeleteManifest(
				map[string]string{},
				map[string]string{
					"name":      "ErrBadManifest",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					DeleteImageManifestFn: func(repo, reference string, detectCollision bool) error {
						return zerr.ErrBadManifest
					},
				},
			)
			So(statusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("DeleteBlob", func() {
			testDeleteBlob := func(urlVars map[string]string, ism *mocks.MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
				request = mux.SetURLVars(request, urlVars)
				response := httptest.NewRecorder()

				rthdlr.DeleteBlob(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrUnexpectedError
			statusCode := testDeleteBlob(
				map[string]string{
					"name":   "ErrUnexpectedError",
					"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&mocks.MockedImageStore{
					DeleteBlobFn: func(repo string, digest godigest.Digest) error {
						return ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			statusCode = testDeleteBlob(
				map[string]string{
					"name":   "ErrBadBlobDigest",
					"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&mocks.MockedImageStore{
					DeleteBlobFn: func(repo string, digest godigest.Digest) error {
						return zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrBlobNotFound
			statusCode = testDeleteBlob(
				map[string]string{
					"name":   "ErrBlobNotFound",
					"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&mocks.MockedImageStore{
					DeleteBlobFn: func(repo string, digest godigest.Digest) error {
						return zerr.ErrBlobNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrRepoNotFound
			statusCode = testDeleteBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&mocks.MockedImageStore{
					DeleteBlobFn: func(repo string, digest godigest.Digest) error {
						return zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
		})

		// Check Blob
		Convey("CheckBlob", func() {
			testCheckBlob := func(urlVars map[string]string, ism *mocks.MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodHead, baseURL, nil)
				request = mux.SetURLVars(request, urlVars)
				response := httptest.NewRecorder()

				rthdlr.CheckBlob(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrBadBlobDigest
			statusCode := testCheckBlob(
				map[string]string{
					"name":   "ErrBadBlobDigest",
					"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				},
				&mocks.MockedImageStore{
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return true, 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrRepoNotFound
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				},
				&mocks.MockedImageStore{
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrBlobNotFound
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "ErrBlobNotFound",
					"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				},
				&mocks.MockedImageStore{
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return true, 0, zerr.ErrBlobNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUnexpectedError
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "ErrUnexpectedError",
					"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				},
				&mocks.MockedImageStore{
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return true, 0, ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// Error Check Blob is not ok
			statusCode = testCheckBlob(
				map[string]string{
					"name":   "Check Blob Not Ok",
					"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				},
				&mocks.MockedImageStore{
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return false, 0, nil
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("GetBlob", func() {
			testGetBlob := func(urlVars map[string]string, ism *mocks.MockedImageStore) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
				request = mux.SetURLVars(request, urlVars)
				response := httptest.NewRecorder()

				rthdlr.GetBlob(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}
			// ErrRepoNotFound
			statusCode := testGetBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&mocks.MockedImageStore{
					GetBlobFn: func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
						return io.NopCloser(bytes.NewBufferString("")), 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrRepoNotFound
			statusCode = testGetBlob(
				map[string]string{
					"name":   "ErrRepoNotFound",
					"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
				},
				&mocks.MockedImageStore{
					GetBlobFn: func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
						return io.NopCloser(bytes.NewBufferString("")), 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("CreateBlobUpload", func() {
			testCreateBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPost, baseURL, nil)
				request = mux.SetURLVars(request,
					map[string]string{
						"name":  "test",
						"mount": "1234",
					})

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.CreateBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrRepoNotFound
			statusCode := testCreateBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				&mocks.MockedImageStore{
					NewBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
					CheckBlobForMountFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// a full blob upload if multiple digests are present
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "1234"},
					{"digest", "5234"},
				},
				map[string]string{},
				&mocks.MockedImageStore{
					NewBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
					CheckBlobForMountFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// a full blob upload if content type is wrong
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "1234"},
				},
				map[string]string{
					"Content-Type": "badContentType",
				},
				&mocks.MockedImageStore{
					NewBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
					CheckBlobForMountFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
						return true, 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusUnsupportedMediaType)

			// digest prezent imgStore err
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "1234"},
				},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest) (string, int64, error) {
						return sessionStr, 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// digest prezent bad length
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
				},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest) (string, int64, error) {
						return sessionStr, 20, nil
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// newBlobUpload not found
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&mocks.MockedImageStore{
					NewBlobUploadFn: func(repo string) (string, error) {
						return "", zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// newBlobUpload unexpected error
			statusCode = testCreateBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Type":   constants.BinaryMediaType,
					"Content-Length": "100",
				},
				&mocks.MockedImageStore{
					NewBlobUploadFn: func(repo string) (string, error) {
						return "", ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("GetBlobUpload", func() {
			testGetBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.GetBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			// ErrBadUploadRange
			statusCode := testGetBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&mocks.MockedImageStore{
					GetBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrBadUploadRange
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrBadBlobDigest
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&mocks.MockedImageStore{
					GetBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrBadBlobDigest
					},
				})
			So(statusCode, ShouldEqual, http.StatusBadRequest)

			// ErrRepoNotFound
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&mocks.MockedImageStore{
					GetBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrRepoNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUploadNotFound
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&mocks.MockedImageStore{
					GetBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, zerr.ErrUploadNotFound
					},
				})
			So(statusCode, ShouldEqual, http.StatusNotFound)

			// ErrUploadNotFound
			statusCode = testGetBlobUpload(
				[]struct{ k, v string }{
					{"mount", "1234"},
				},
				map[string]string{},
				map[string]string{
					"name":       "test",
					"session_id": "1234",
				},
				&mocks.MockedImageStore{
					GetBlobUploadFn: func(repo, uuid string) (int64, error) {
						return 0, ErrUnexpectedError
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("PatchBlobUpload", func() {
			testPatchBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPatch, baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.PatchBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "abc",
					"Content-Range":  "abc",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-50",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					PutBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 100, zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					PutBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 100, zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testPatchBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					PutBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 100, ErrUnexpectedError
					},
					DeleteBlobUploadFn: func(repo, uuid string) error {
						return ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("UpdateBlobUpload", func() {
			testUpdateBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPatch, baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.UpdateBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "badRange",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					PutBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, zerr.ErrBadUploadRange
					},
				},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					PutBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					PutBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "1-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					PutBlobChunkFn: func(repo, uuid string, from, to int64, body io.Reader) (int64, error) {
						return 0, ErrUnexpectedError
					},
					DeleteBlobUploadFn: func(repo, uuid string) error {
						return ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return zerr.ErrBadBlobDigest
					},
				},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return zerr.ErrBadUploadRange
					},
				},
			)
			So(status, ShouldEqual, http.StatusBadRequest)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return ErrUnexpectedError
					},
					DeleteBlobUploadFn: func(repo, uuid string) error {
						return ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("DeleteBlobUpload", func() {
			testDeleteBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPatch, baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.DeleteBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testDeleteBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					DeleteBlobUploadFn: func(repo, uuid string) error {
						return zerr.ErrRepoNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testDeleteBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					DeleteBlobUploadFn: func(repo, uuid string) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusNotFound)

			status = testDeleteBlobUpload(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					DeleteBlobUploadFn: func(repo, uuid string) error {
						return ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("ListRepositories", func() {
			testListRepositoriesWithSubstores := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				ctlr.StoreController.SubStore = map[string]storageTypes.ImageStore{
					"test": &mocks.MockedImageStore{
						GetRepositoriesFn: func() ([]string, error) {
							return []string{}, ErrUnexpectedError
						},
					},
				}
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.ListRepositories(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			testListRepositories := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				ctlr.StoreController.SubStore = map[string]storageTypes.ImageStore{}
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPatch, baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.ListRepositories(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}
			// with substores
			status := testListRepositoriesWithSubstores(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					GetNextRepositoriesFn: func(lastRepo string, maxEntries int,
						fn storageTypes.FilterRepoFunc,
					) ([]string, bool, error) {
						return []string{}, false, ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)

			status = testListRepositories(
				[]struct{ k, v string }{},
				map[string]string{},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					GetNextRepositoriesFn: func(lastRepo string, maxEntries int,
						fn storageTypes.FilterRepoFunc,
					) ([]string, bool, error) {
						return []string{}, false, ErrUnexpectedError
					},
				},
			)
			So(status, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("ListRepositories with Authz", func() {
			ctlr.StoreController.DefaultStore = &mocks.MockedImageStore{
				GetNextRepositoriesFn: func(lastRepo string, maxEntries int,
					fn storageTypes.FilterRepoFunc,
				) ([]string, bool, error) {
					return []string{"repo"}, false, nil
				},
			}
			ctlr.StoreController.SubStore = map[string]storageTypes.ImageStore{
				"test1": &mocks.MockedImageStore{
					GetNextRepositoriesFn: func(lastRepo string, maxEntries int,
						fn storageTypes.FilterRepoFunc,
					) ([]string, bool, error) {
						return []string{"repo1"}, false, nil
					},
				},
				"test2": &mocks.MockedImageStore{
					GetNextRepositoriesFn: func(lastRepo string, maxEntries int,
						fn storageTypes.FilterRepoFunc,
					) ([]string, bool, error) {
						return []string{"repo2"}, false, nil
					},
				},
			}

			// make the user an admin
			// acCtx := api.NewAccessControlContext(map[string]bool{}, true)
			// ctx := context.WithValue(context.Background(), "ctx", acCtx)
			ctx := context.Background()
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{
				"name":       "repo",
				"session_id": "test",
			})
			response := httptest.NewRecorder()

			rthdlr.ListRepositories(response, request)

			resp := response.Result()
			defer resp.Body.Close()

			So(resp.StatusCode, ShouldEqual, http.StatusOK)
		})

		Convey("Test API keys", func() {
			Convey("CreateAPIKey invalid access control context", func() {
				var invalid struct{}

				uacKey := reqCtx.GetContextKey()
				ctx := context.WithValue(context.Background(), uacKey, invalid)

				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader([]byte{}))
				response := httptest.NewRecorder()

				rthdlr.CreateAPIKey(response, request)

				resp := response.Result()
				defer resp.Body.Close()
				So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

				request, _ = http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
				response = httptest.NewRecorder()

				rthdlr.GetAPIKeys(response, request)

				resp = response.Result()
				defer resp.Body.Close()
				So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
			})

			Convey("CreateAPIKey bad request body", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")
				ctx := userAc.DeriveContext(context.Background())

				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader([]byte{}))
				response := httptest.NewRecorder()

				rthdlr.CreateAPIKey(response, request)

				resp := response.Result()
				defer resp.Body.Close()
				So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)
			})

			Convey("CreateAPIKey error on AddUserAPIKey", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")
				ctx := userAc.DeriveContext(context.Background())

				payload := api.APIKeyPayload{
					Label:  "test",
					Scopes: []string{"test"},
				}
				reqBody, err := json.Marshal(payload)
				So(err, ShouldBeNil)

				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(reqBody))
				response := httptest.NewRecorder()

				ctlr.MetaDB = mocks.MetaDBMock{
					AddUserAPIKeyFn: func(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
						return ErrUnexpectedError
					},
				}

				rthdlr.CreateAPIKey(response, request)

				resp := response.Result()
				defer resp.Body.Close()
				So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
			})

			Convey("Revoke error on DeleteUserAPIKeyFn", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")
				ctx := userAc.DeriveContext(context.Background())

				request, _ := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL, bytes.NewReader([]byte{}))
				response := httptest.NewRecorder()

				q := request.URL.Query()
				q.Add("id", "apikeyid")
				request.URL.RawQuery = q.Encode()

				ctlr.MetaDB = mocks.MetaDBMock{
					DeleteUserAPIKeyFn: func(ctx context.Context, id string) error {
						return ErrUnexpectedError
					},
				}

				rthdlr.RevokeAPIKey(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
			})
		})

		Convey("Helper functions", func() {
			testUpdateBlobUpload := func(
				query []struct{ k, v string },
				headers map[string]string,
				vars map[string]string,
				ism *mocks.MockedImageStore,
			) int {
				ctlr.StoreController.DefaultStore = ism
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPatch, baseURL, nil)

				request = mux.SetURLVars(request, vars)

				q := request.URL.Query()
				for _, qe := range query {
					q.Add(qe.k, qe.v)
				}
				request.URL.RawQuery = q.Encode()

				for k, v := range headers {
					request.Header.Add(k, v)
				}

				response := httptest.NewRecorder()

				rthdlr.UpdateBlobUpload(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				return resp.StatusCode
			}

			status := testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "a-100",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "20-a",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "0",
					"Content-Range":  "20-1",
				},
				map[string]string{
					"name":       "repo",
					"session_id": "test",
				},
				&mocks.MockedImageStore{
					FinishBlobUploadFn: func(repo, uuid string, body io.Reader, digest godigest.Digest) error {
						return zerr.ErrUploadNotFound
					},
				},
			)
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)
		})
	})
}

type readerThatFails struct{}

func (r readerThatFails) Read(p []byte) (int, error) {
	return 0, zerr.ErrInjected
}

func TestWriteDataFromReader(t *testing.T) {
	Convey("", t, func() {
		response := httptest.NewRecorder()
		api.WriteDataFromReader(response, 200, 100, ispec.MediaTypeImageManifest, readerThatFails{},
			log.NewTestLogger())

		So(response.Code, ShouldEqual, 200)
	})
}
