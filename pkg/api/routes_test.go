//go:build sync && scrub && metrics && search && lint && mgmt

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-zot/mockoidc"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	apiErr "zotregistry.dev/zot/v2/pkg/api/errors"
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
		conf := config.New()
		conf.HTTP.Port = "0"

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
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		baseURL := test.GetBaseURL(strconv.Itoa(ctlr.GetPort()))
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

			_, err := api.OAuth2Callback(ctlr, response, request, "state", "email", "", []string{"group"})
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

			_, err = api.OAuth2Callback(ctlr, response, request, "state", "email", "", []string{"group"})
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
			So(resp.Header.Get("Access-Control-Allow-Credentials"), ShouldEqual, "")
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Get manifest with explicit AllowOrigin emits credentials header", func() {
			ctlr.StoreController.DefaultStore = &mocks.MockedImageStore{
				GetImageManifestFn: func(repo string, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte{}, "", "", zerr.ErrRepoBadVersion
				},
			}

			originalAllowOrigin := ctlr.Config.HTTP.AllowOrigin
			ctlr.Config.HTTP.AllowOrigin = "https://example.com"

			defer func() {
				ctlr.Config.HTTP.AllowOrigin = originalAllowOrigin
			}()

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
			So(resp.Header.Get("Access-Control-Allow-Credentials"), ShouldEqual, "true")
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

			Convey("body exceeds MaxManifestBodySize returns 413 with MANIFEST_INVALID error payload", func() {
				ctlr.StoreController.DefaultStore = &mocks.MockedImageStore{}
				oversized := make([]byte, constants.MaxManifestBodySize+1)
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL,
					bytes.NewReader(oversized))
				request = mux.SetURLVars(request, map[string]string{"name": "test", "reference": "v1"})
				request.Header.Add("Content-Type", ispec.MediaTypeImageManifest)
				response := httptest.NewRecorder()

				rthdlr.UpdateManifest(response, request)

				So(response.Code, ShouldEqual, http.StatusRequestEntityTooLarge)

				var errList apiErr.ErrorList
				err := json.NewDecoder(response.Body).Decode(&errList)
				So(err, ShouldBeNil)
				So(errList.Errors, ShouldHaveLength, 1)
				So(errList.Errors[0].Code, ShouldEqual, apiErr.MANIFEST_INVALID.String())
				So(errList.Errors[0].Detail["reason"], ShouldContainSubstring, "exceeds maximum allowed size")
			})
			// repo not found
			statusCode := testUpdateManifest(
				map[string]string{
					"name":      "test",
					"reference": "reference",
				},
				&mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte, _ []string) (godigest.Digest,
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
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte, _ []string) (godigest.Digest,
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
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte, _ []string) (godigest.Digest,
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
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte, _ []string) (godigest.Digest,
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
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte, _ []string) (godigest.Digest,
						godigest.Digest, error,
					) {
						return "", "", zerr.ErrRepoBadVersion
					},
				})
			So(statusCode, ShouldEqual, http.StatusInternalServerError)
		})

		Convey("UpdateManifest digest query tags with MetaDB", func() {
			defer func() {
				ctlr.MetaDB = nil
			}()

			configBlob := []byte(`{"architecture":"amd64","os":"linux"}`)
			configDigest := godigest.FromBytes(configBlob)

			manifest := ispec.Manifest{
				Versioned: specs.Versioned{SchemaVersion: 2},
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    configDigest,
					Size:      int64(len(configBlob)),
				},
				Layers: []ispec.Descriptor{},
			}

			mcontent, mErr := json.Marshal(manifest)
			So(mErr, ShouldBeNil)

			manifestDigest := godigest.FromBytes(mcontent)
			digestRef := manifestDigest.String()

			ism := &mocks.MockedImageStore{
				PutImageManifestFn: func(repo, reference, mediaType string, body []byte, extraTags []string) (
					godigest.Digest, godigest.Digest, error,
				) {
					So(extraTags, ShouldResemble, []string{"meta-a", "meta-b"})
					So(string(body), ShouldEqual, string(mcontent))

					return manifestDigest, godigest.Digest(""), nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == configDigest {
						return configBlob, nil
					}

					return nil, zerr.ErrBlobNotFound
				},
			}
			ctlr.StoreController.DefaultStore = ism

			runDigestMultiTag := func(metaDB mTypes.MetaDB) *httptest.ResponseRecorder {
				ctlr.MetaDB = metaDB

				reqURL := baseURL + "?tag=meta-a&tag=meta-b"
				request, reqErr := http.NewRequestWithContext(context.Background(), http.MethodPut, reqURL,
					bytes.NewBuffer(mcontent))
				So(reqErr, ShouldBeNil)

				request = mux.SetURLVars(request, map[string]string{
					"name":      "test",
					"reference": digestRef,
				})
				request.Header.Add("Content-Type", ispec.MediaTypeImageManifest)

				response := httptest.NewRecorder()
				rthdlr.UpdateManifest(response, request)

				return response
			}

			Convey("SetRepoReference succeeds", func() {
				rec := runDigestMultiTag(mocks.MetaDBMock{
					SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
						return nil
					},
				})

				So(rec.Code, ShouldEqual, http.StatusCreated)
				So(rec.Header().Values(constants.OCITagResponseKey), ShouldResemble, []string{"meta-a", "meta-b"})
				So(rec.Header().Get(constants.DistContentDigestKey), ShouldEqual, manifestDigest.String())
			})

			Convey("SetRepoReference fails for a later tag returns 500", func() {
				var calls int

				rec := runDigestMultiTag(mocks.MetaDBMock{
					SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
						calls++

						if reference == "meta-b" {
							return ErrUnexpectedError
						}

						return nil
					},
				})

				So(calls, ShouldEqual, 2)
				So(rec.Code, ShouldEqual, http.StatusInternalServerError)
			})
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
					"digest": "1234",
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
					"digest": "1234",
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
					"digest": "1234",
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
					"digest": "1234",
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
					"digest": "1234",
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
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
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
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
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
					CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
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
			So(statusCode, ShouldEqual, http.StatusInternalServerError)

			// digest prezent bad length
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

			// ErrBadBlobDigest
			statusCode := testGetBlobUpload(
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

			// Malformed Content-Range (no hyphen): must return 416, not panic.
			status = testUpdateBlobUpload(
				[]struct{ k, v string }{
					{"digest", "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621"},
				},
				map[string]string{
					"Content-Length": "100",
					"Content-Range":  "100",
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
			So(status, ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

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

			Convey("CreateAPIKey body exceeds MaxAPIKeyBodySize returns 413", func() {
				userAc := reqCtx.NewUserAccessControl()
				userAc.SetUsername("test")
				ctx := userAc.DeriveContext(context.Background())

				oversized := make([]byte, constants.MaxAPIKeyBodySize+1)
				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(oversized))
				response := httptest.NewRecorder()

				rthdlr.CreateAPIKey(response, request)

				resp := response.Result()
				defer resp.Body.Close()
				So(resp.StatusCode, ShouldEqual, http.StatusRequestEntityTooLarge)
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

// Descriptor-aware Content-Type tests for blob HEAD/GET.
//
// The blob endpoints derive the response Content-Type from the OCI
// descriptor associated with the blob (via the repo's index/manifest
// chain), and fall back to application/octet-stream when no such
// descriptor is available. These tests use mock image stores to drive
// both branches independently of the on-disk storage layer.

// descriptorTestDigests returns deterministic layer, manifest, and
// config digests (in that order) used by the descriptor-aware
// Content-Type tests.
func descriptorTestDigests() (godigest.Digest, godigest.Digest, godigest.Digest) {
	return godigest.FromString("layer"), godigest.FromString("manifest"), godigest.FromString("config")
}

// newBlobTestRouteHandler returns a fresh RouteHandler whose default
// store is the supplied mock. It does not start a server; handlers are
// invoked directly via httptest. The Router is initialized manually
// because NewRouteHandler->SetupRoutes dereferences it but the server
// (which would normally do that) is never started here.
func newBlobTestRouteHandler(t *testing.T, store mocks.MockedImageStore) *api.RouteHandler {
	t.Helper()

	ctlr := api.NewController(config.New())
	ctlr.Router = mux.NewRouter()
	ctlr.StoreController.DefaultStore = store

	return api.NewRouteHandler(ctlr)
}

// descriptorFixture builds a minimal index -> manifest -> layer chain
// that resolves the layer digest from descriptorTestDigests to
// MediaTypeImageLayerGzip.
func descriptorFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()

	layerDigest, manifestDigest, configDigest := descriptorTestDigests()

	manifest := ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      1,
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
				Size:      4,
			},
		},
	}
	manifest.SchemaVersion = 2

	manifestJSON, err := json.Marshal(manifest)
	require.NoError(t, err)

	index := ispec.Index{
		Manifests: []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(manifestJSON)),
				Annotations: map[string]string{
					ispec.AnnotationRefName: "latest",
				},
			},
		},
	}
	index.SchemaVersion = 2

	indexJSON, err := json.Marshal(index)
	require.NoError(t, err)

	return indexJSON, manifestJSON
}

// descriptorStore returns a mock store backed by descriptorFixture.
// Looking up the layer digest from descriptorTestDigests resolves to a
// layer with media type MediaTypeImageLayerGzip via the index walk;
// other digests fall through to the binary fallback.
func descriptorStore(t *testing.T) mocks.MockedImageStore {
	t.Helper()

	indexJSON, manifestJSON := descriptorFixture(t)
	layerDigest, manifestDigest, _ := descriptorTestDigests()

	return mocks.MockedImageStore{
		RootDirFn: func() string { return t.TempDir() },
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			if digest == layerDigest {
				return true, 4, nil
			}

			return true, 0, nil
		},
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return indexJSON, nil
		},
		GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
			require.Equal(t, manifestDigest, digest, "unexpected blob content lookup")

			return manifestJSON, nil
		},
	}
}

func TestCheckBlobUsesDescriptorContentType(t *testing.T) {
	store := descriptorStore(t)
	store.CheckBlobFn = func(repo string, digest godigest.Digest) (bool, int64, error) {
		return true, 42, nil
	}

	handler := newBlobTestRouteHandler(t, store)

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodHead, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Accept", "application/vnd.oci.image.layer.v1.tar+gzip, */*")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": layerDigest.String(),
	})

	rec := httptest.NewRecorder()
	handler.CheckBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, ispec.MediaTypeImageLayerGzip, resp.Header.Get("Content-Type"))
	assert.Equal(t, "bytes", resp.Header.Get("Accept-Ranges"))
	assert.Equal(t, layerDigest.String(), resp.Header.Get(constants.DistContentDigestKey))
}

func TestCheckBlobFallsBackToBinaryContentType(t *testing.T) {
	// No index/manifest at all: descriptor lookup fails and the handler
	// must fall back to application/octet-stream so OCI clients get a
	// well-formed Content-Type.
	handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, 1024, nil
		},
	})

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodHead, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Accept", "*/*")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": layerDigest.String(),
	})

	rec := httptest.NewRecorder()
	handler.CheckBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, constants.BinaryMediaType, resp.Header.Get("Content-Type"))
}

func TestGetBlobUsesDescriptorContentType(t *testing.T) {
	store := descriptorStore(t)
	store.GetBlobFn = func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
		// The mediaType argument forwarded to the storage layer is a
		// hint and is currently ignored; we still feed it the resolved
		// value so the surface stays consistent.
		assert.Equal(t, ispec.MediaTypeImageLayerGzip, mediaType)

		return io.NopCloser(strings.NewReader("blob")), 4, nil
	}

	handler := newBlobTestRouteHandler(t, store)

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	// Wildcard / mixed Accept must not leak into the response.
	req.Header.Set("Accept", "application/vnd.oci.image.layer.v1.tar+gzip, */*")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": layerDigest.String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, ispec.MediaTypeImageLayerGzip, resp.Header.Get("Content-Type"))
}

func TestGetBlobFallsBackToBinaryContentType(t *testing.T) {
	// Repository has no index/manifest: full GET must respond with
	// application/octet-stream rather than echoing Accept.
	handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
		GetBlobFn: func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
			assert.Equal(t, constants.BinaryMediaType, mediaType)

			return io.NopCloser(strings.NewReader("blob")), 4, nil
		},
	})

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	// Comma-separated Accept must not produce a malformed Content-Type.
	req.Header.Set("Accept", "typeA, typeB")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": layerDigest.String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, constants.BinaryMediaType, resp.Header.Get("Content-Type"))
}

func TestGetBlobPartialUsesDescriptorContentType(t *testing.T) {
	store := descriptorStore(t)
	store.GetBlobPartialFn = func(
		repo string,
		digest godigest.Digest,
		mediaType string,
		from,
		to int64,
	) (io.ReadCloser, int64, int64, error) {
		assert.Equal(t, ispec.MediaTypeImageLayerGzip, mediaType)
		assert.Equal(t, int64(0), from)
		assert.Equal(t, int64(1), to)

		return io.NopCloser(strings.NewReader("bl")), 2, 4, nil
	}

	handler := newBlobTestRouteHandler(t, store)

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": layerDigest.String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	assert.Equal(t, ispec.MediaTypeImageLayerGzip, resp.Header.Get("Content-Type"))
	assert.Equal(t, "bytes 0-1/4", resp.Header.Get("Content-Range"))
	assert.Equal(t, layerDigest.String(), resp.Header.Get(constants.DistContentDigestKey))
}

func TestGetBlobPartialFallsBackToBinaryContentType(t *testing.T) {
	// Single-range request for a blob whose repo has no index — same
	// fallback behaviour as the full-GET case.
	handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, 4, nil
		},
		GetBlobPartialFn: func(
			repo string,
			digest godigest.Digest,
			mediaType string,
			from,
			to int64,
		) (io.ReadCloser, int64, int64, error) {
			assert.Equal(t, constants.BinaryMediaType, mediaType)

			return io.NopCloser(strings.NewReader("bl")), 2, 4, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req.Header.Set("Accept", "application/vnd.oci.image.layer.v1.tar+gzip, */*")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	assert.Equal(t, constants.BinaryMediaType, resp.Header.Get("Content-Type"))
}

// TestGetBlobMultipartPartHasDescriptorContentType verifies that each
// part of a multipart/byteranges response carries the descriptor-
// derived Content-Type alongside the per-part Content-Range.
func TestGetBlobMultipartPartHasDescriptorContentType(t *testing.T) {
	const blobBody = "0123456789"

	store := descriptorStore(t)
	store.CheckBlobFn = func(repo string, digest godigest.Digest) (bool, int64, error) {
		return true, int64(len(blobBody)), nil
	}
	store.GetBlobPartialFn = func(
		repo string,
		digest godigest.Digest,
		mediaType string,
		from,
		to int64,
	) (io.ReadCloser, int64, int64, error) {
		assert.Equal(t, ispec.MediaTypeImageLayerGzip, mediaType)

		return io.NopCloser(strings.NewReader(blobBody[from : to+1])), to - from + 1, int64(len(blobBody)), nil
	}

	handler := newBlobTestRouteHandler(t, store)

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1,5-7")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": layerDigest.String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusPartialContent, resp.StatusCode)

	contentType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	require.NoError(t, err)
	require.Equal(t, "multipart/byteranges", contentType)
	require.NotEmpty(t, params["boundary"])

	reader := multipart.NewReader(resp.Body, params["boundary"])

	expected := []struct {
		body         string
		contentRange string
	}{
		{body: "01", contentRange: "bytes 0-1/10"},
		{body: "567", contentRange: "bytes 5-7/10"},
	}

	for i, want := range expected {
		part, err := reader.NextPart()
		require.NoError(t, err, "read part %d", i)

		assert.Equal(t, want.contentRange, part.Header.Get("Content-Range"), "part %d content-range", i)
		assert.Equal(t, ispec.MediaTypeImageLayerGzip, part.Header.Get("Content-Type"),
			"part %d content-type", i)

		body, err := io.ReadAll(part)
		require.NoError(t, err, "read part %d body", i)
		assert.Equal(t, want.body, string(body), "part %d body", i)
	}

	_, err = reader.NextPart()
	require.ErrorIs(t, err, io.EOF)

	assert.Equal(t, layerDigest.String(), resp.Header.Get(constants.DistContentDigestKey))
}
