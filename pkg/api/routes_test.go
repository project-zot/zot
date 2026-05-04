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
	"sync/atomic"
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

		Convey("Test OpenIDCodeExchangeCallback with claim mapping", func() {
			authConfig := conf.HTTP.Auth.OpenID.Providers["oidc"]
			authConfig.ClaimMapping = &config.ClaimMapping{
				Username: "preferred_username",
				Groups:   "roles",
			}
			conf.HTTP.Auth.OpenID.Providers["oidc"] = authConfig

			var capturedGroups []string
			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					capturedGroups = append(capturedGroups, groups...)

					return nil
				},
			}

			callback := rthdlr.OpenIDCodeExchangeCallbackWithProvider("oidc")
			ctx := context.TODO()

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			response := httptest.NewRecorder()

			state := uuid.New().String()
			session, _ := ctlr.CookieStore.Get(request, "statecookie")
			session.Values["state"] = state
			So(session.Save(request, response), ShouldBeNil)

			tokens := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						"groups": []any{"ignored-token-group"},
						"roles":  []any{"ops", "admin"},
					},
				},
			}
			relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{})
			So(err, ShouldBeNil)

			userinfo := &oidc.UserInfo{
				Subject:         "sub",
				UserInfoProfile: oidc.UserInfoProfile{PreferredUsername: "mapped-user"},
				Claims: map[string]any{
					"email":  "test@test.com",
					"groups": []any{"ignored-userinfo-group"},
					"roles":  []any{"dev", "ops"},
				},
				UserInfoEmail: oidc.UserInfoEmail{Email: "test@test.com"},
			}

			callback(response, request, tokens, state, relyingParty, userinfo)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusCreated)
			So(capturedGroups, ShouldResemble, []string{"admin", "dev", "ops"})

			userAc, err := reqCtx.UserAcFromContext(request.Context())
			So(err, ShouldBeNil)
			So(userAc.GetUsername(), ShouldEqual, "mapped-user")
			So(userAc.GetGroups(), ShouldResemble, []string{"admin", "dev", "ops"})
		})

		Convey("Test OpenIDCodeExchangeCallback falls back to email when mapped username is missing", func() {
			authConfig := conf.HTTP.Auth.OpenID.Providers["oidc"]
			authConfig.ClaimMapping = &config.ClaimMapping{
				Username: "missing_username",
				Groups:   "roles",
			}
			conf.HTTP.Auth.OpenID.Providers["oidc"] = authConfig

			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					return nil
				},
			}

			callback := rthdlr.OpenIDCodeExchangeCallbackWithProvider("oidc")
			ctx := context.TODO()

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			response := httptest.NewRecorder()

			state := uuid.New().String()
			session, _ := ctlr.CookieStore.Get(request, "statecookie")
			session.Values["state"] = state
			So(session.Save(request, response), ShouldBeNil)

			tokens := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						"roles": []any{"admin"},
					},
				},
			}
			relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{})
			So(err, ShouldBeNil)

			userinfo := &oidc.UserInfo{
				Subject: "sub",
				Claims: map[string]any{
					"roles": []any{"dev"},
				},
				UserInfoEmail: oidc.UserInfoEmail{Email: "fallback@test.com"},
			}

			callback(response, request, tokens, state, relyingParty, userinfo)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusCreated)

			userAc, err := reqCtx.UserAcFromContext(request.Context())
			So(err, ShouldBeNil)
			So(userAc.GetUsername(), ShouldEqual, "fallback@test.com")
			So(userAc.GetGroups(), ShouldResemble, []string{"admin", "dev"})
		})

		Convey("Test OpenIDCodeExchangeCallback continues when mapped groups are missing", func() {
			authConfig := conf.HTTP.Auth.OpenID.Providers["oidc"]
			authConfig.ClaimMapping = &config.ClaimMapping{
				Username: "preferred_username",
				Groups:   "roles",
			}
			conf.HTTP.Auth.OpenID.Providers["oidc"] = authConfig

			var capturedGroups []string
			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					capturedGroups = append(capturedGroups, groups...)

					return nil
				},
			}

			callback := rthdlr.OpenIDCodeExchangeCallbackWithProvider("oidc")
			ctx := context.TODO()

			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
			response := httptest.NewRecorder()

			state := uuid.New().String()
			session, _ := ctlr.CookieStore.Get(request, "statecookie")
			session.Values["state"] = state
			So(session.Save(request, response), ShouldBeNil)

			tokens := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{},
				},
			}
			relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{})
			So(err, ShouldBeNil)

			userinfo := &oidc.UserInfo{
				Subject:         "sub",
				UserInfoProfile: oidc.UserInfoProfile{PreferredUsername: "mapped-user"},
				Claims:          map[string]any{},
				UserInfoEmail:   oidc.UserInfoEmail{Email: "mapped@test.com"},
			}

			callback(response, request, tokens, state, relyingParty, userinfo)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusCreated)
			So(capturedGroups, ShouldBeEmpty)

			userAc, err := reqCtx.UserAcFromContext(request.Context())
			So(err, ShouldBeNil)
			So(userAc.GetUsername(), ShouldEqual, "mapped-user")
			So(userAc.GetGroups(), ShouldBeEmpty)
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
					PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string,
						body []byte, extraTags []string,
					) (godigest.Digest, godigest.Digest, error) {
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
					PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string,
						body []byte, extraTags []string,
					) (godigest.Digest, godigest.Digest, error) {
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
					PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string,
						body []byte, extraTags []string,
					) (godigest.Digest, godigest.Digest, error) {
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
					PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string,
						body []byte, extraTags []string,
					) (godigest.Digest, godigest.Digest, error) {
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
					PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string,
						body []byte, extraTags []string,
					) (godigest.Digest, godigest.Digest, error) {
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
				PutImageManifestFn: func(ctx context.Context, repo, reference, mediaType string,
					body []byte, extraTags []string,
				) (godigest.Digest, godigest.Digest, error) {
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
					DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error {
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
					DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error {
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
					DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error {
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
					DeleteImageManifestFn: func(ctx context.Context, repo, reference string, detectCollision bool) error {
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
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return nil, zerr.ErrManifestNotFound
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

func TestGetBlobFallsBackOnInvalidDescriptorContentType(t *testing.T) {
	// Descriptor media types are user-supplied and may be invalid as HTTP
	// header values. resolveBlobResponseMediaType must sanitize/validate
	// and fall back to application/octet-stream on parse failure.
	store := descriptorStore(t)
	store.GetBlobFn = func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
		assert.Equal(t, constants.BinaryMediaType, mediaType)

		return io.NopCloser(strings.NewReader("blob")), 4, nil
	}

	// Force descriptor lookup success but with an invalid media type string.
	store.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
		_, manifestJSON := descriptorFixture(t)

		var manifest ispec.Manifest
		require.NoError(t, json.Unmarshal(manifestJSON, &manifest))
		require.Len(t, manifest.Layers, 1)
		manifest.Layers[0].MediaType = "bad\r\nvalue"

		out, err := json.Marshal(manifest)
		require.NoError(t, err)

		return out, nil
	}

	handler := newBlobTestRouteHandler(t, store)

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
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

func TestGetBlobFallsBackToBinaryContentType(t *testing.T) {
	// Repository has no index/manifest: full GET must respond with
	// application/octet-stream rather than echoing Accept.
	handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
		GetBlobFn: func(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
			assert.Equal(t, constants.BinaryMediaType, mediaType)

			return io.NopCloser(strings.NewReader("blob")), 4, nil
		},
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return nil, zerr.ErrManifestNotFound
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
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return nil, zerr.ErrManifestNotFound
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

// Streaming-multipart tests for the lazy-fan-out path.
//
// The multipart 206 response is written from a producer goroutine that
// opens range readers one at a time, with the response Content-Length
// precomputed up front. These tests cover:
//   - Content-Length matches the actual body length on the wire.
//   - At most one range reader is ever open at any instant (the
//     fan-out improvement that motivated the rewrite).
//   - A reader-error mid-stream truncates the body (since the 206
//     headers have already been flushed) and is logged.

// partialReaderOpenTracker records how many partial-blob readers are open at once and
// the peak concurrent count. The multipart test's GetBlobPartial mock calls NewReadCloser
// per range; overlapping opens show up as PeakOpens() > 1.
type partialReaderOpenTracker struct {
	live atomic.Int32
	peak atomic.Int32
}

// NewReadCloser returns a reader that registers in the tracker until Close.
func (t *partialReaderOpenTracker) NewReadCloser(body string) io.ReadCloser {
	t.beginOpen()

	return &partialReaderReadCloser{
		Reader:  strings.NewReader(body),
		tracker: t,
	}
}

func (t *partialReaderOpenTracker) LiveOpens() int32 { return t.live.Load() }

func (t *partialReaderOpenTracker) PeakOpens() int32 { return t.peak.Load() }

func (t *partialReaderOpenTracker) endClose() { t.live.Add(-1) }

// beginOpen increments the live-open count and sets peak := max(peak, newLiveCount).
//
// The for loop retries when CompareAndSwap fails: another goroutine can change peak
// after Load but before CompareAndSwap, so one attempt is not enough under contention.
func (t *partialReaderOpenTracker) beginOpen() {
	cur := t.live.Add(1)

	for {
		observedPeak := t.peak.Load()
		if cur <= observedPeak {
			return
		}
		if t.peak.CompareAndSwap(observedPeak, cur) {
			return
		}
	}
}

// partialReaderReadCloser wraps a strings.Reader and only notifies the tracker on Close.
type partialReaderReadCloser struct {
	*strings.Reader

	tracker *partialReaderOpenTracker
	closed  bool
}

func (r *partialReaderReadCloser) Close() error {
	if r.closed {
		return nil
	}

	r.closed = true
	r.tracker.endClose()

	return nil
}

// drainResponseBody reads until EOF and returns the bytes plus any
// non-EOF error that occurred. The httptest recorder's body is fully
// buffered so this never blocks.
func drainResponseBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return body
}

func TestGetBlobMultipartContentLengthMatchesBody(t *testing.T) {
	const blobBody = "0123456789abcdef" // 16 bytes

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
		return io.NopCloser(strings.NewReader(blobBody[from : to+1])), to - from + 1, int64(len(blobBody)), nil
	}

	handler := newBlobTestRouteHandler(t, store)

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1,5-7,12-15")
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

	advertisedLen, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	require.NoError(t, err, "Content-Length must be a valid integer")
	require.Positive(t, advertisedLen, "Content-Length must be set on multipart responses")

	body := drainResponseBody(t, resp)
	assert.Equal(t, advertisedLen, int64(len(body)),
		"advertised Content-Length must match the actual body length")

	// Sanity-check the multipart structure is parseable end-to-end so
	// the byte count above isn't masking a malformed body.
	multipartReader := multipart.NewReader(bytes.NewReader(body), params["boundary"])

	const wantParts = 3
	for i := range wantParts {
		part, err := multipartReader.NextPart()
		require.NoError(t, err, "part %d", i)

		_, err = io.Copy(io.Discard, part)
		require.NoError(t, err, "part %d body", i)
	}

	_, err = multipartReader.NextPart()
	require.ErrorIs(t, err, io.EOF)
}

func TestGetBlobMultipartOpensOneReaderAtATime(t *testing.T) {
	const blobBody = "0123456789abcdef0123456789abcdef" // 32 bytes

	var opens partialReaderOpenTracker

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
		// opens tracks live readers; Close decrements. writeMultipartRanges should fully
		// consume each reader before opening the next.
		reader := opens.NewReadCloser(blobBody[from : to+1])

		return reader, to - from + 1, int64(len(blobBody)), nil
	}

	handler := newBlobTestRouteHandler(t, store)

	layerDigest, _, _ := descriptorTestDigests()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	// Four non-coalescing ranges so the producer must open four
	// distinct readers in sequence.
	req.Header.Set("Range", "bytes=0-3,8-11,16-19,24-27")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": layerDigest.String(),
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusPartialContent, resp.StatusCode)

	// Drain the body so the producer goroutine completes and decrements
	// the open counter on every reader.
	_ = drainResponseBody(t, resp)

	assert.Equal(t, int32(0), opens.LiveOpens(), "all readers must be closed by the time the body is drained")
	assert.Equal(t, int32(1), opens.PeakOpens(),
		"writeMultipartRanges must open at most one range reader at a time")
}

func TestGetBlobMultipartTruncatesOnReaderError(t *testing.T) {
	const blobBody = "0123456789abcdef" // 16 bytes

	var calls atomic.Int32

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
		// First range succeeds, second fails. The 206 status and
		// Content-Length have already been written by the time the
		// producer hits the failure, so we expect a truncated body
		// rather than a 5xx.
		if calls.Add(1) == 1 {
			return io.NopCloser(strings.NewReader(blobBody[from : to+1])), to - from + 1, int64(len(blobBody)), nil
		}

		return nil, 0, 0, ErrUnexpectedError
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

	// 206 was already in flight when the 2nd-range error fired; the
	// connection just truncates.
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)

	advertisedLen, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	require.NoError(t, err)

	body := drainResponseBody(t, resp)
	assert.Less(t, int64(len(body)), advertisedLen,
		"body must be truncated relative to the advertised Content-Length on mid-stream error")
}

func TestGetBlobRangeUnsatisfiable(t *testing.T) {
	// A Range header that lies entirely past the end of the blob must
	// produce 416 with `Content-Range: bytes */<size>` so clients can
	// retry with a valid range. parseRangeHeader rejects the header
	// before the handler reaches GetBlobPartial.
	handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return true, 4, nil
		},
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return nil, zerr.ErrManifestNotFound
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=999-1000")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusRequestedRangeNotSatisfiable, resp.StatusCode)
	assert.Equal(t, "bytes */4", resp.Header.Get("Content-Range"))
}

func TestGetBlobRangeCheckBlobError(t *testing.T) {
	// CheckBlob returning a non-zerr error must surface as 500 via
	// writeBlobError's default branch.
	handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return false, 0, ErrUnexpectedError
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestGetBlobRangeCheckBlobMissing(t *testing.T) {
	// CheckBlob succeeding with ok=false (e.g. a deleted blob whose
	// repo still exists) must short-circuit to 404 BLOB_UNKNOWN before
	// any range parsing or descriptor lookup.
	handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
		CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
			return false, 0, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	var errList apiErr.ErrorList

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errList))
	require.Len(t, errList.Errors, 1)
	assert.Equal(t, apiErr.BLOB_UNKNOWN.String(), errList.Errors[0].Code)
}

func TestGetBlobSingleRangePartialBlobNotFound(t *testing.T) {
	// Single-range path: GetBlobPartial returning ErrBlobNotFound after
	// a successful CheckBlob (a blob deleted between the two calls)
	// must surface as 404 with the BLOB_UNKNOWN error body. CheckBlob
	// has already returned ok=true so we get past the length check;
	// the response is still recoverable because no body bytes have
	// been written yet.
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
			return nil, 0, 0, zerr.ErrBlobNotFound
		},
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return nil, zerr.ErrManifestNotFound
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	var errList apiErr.ErrorList

	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errList))
	require.Len(t, errList.Errors, 1)
	assert.Equal(t, apiErr.BLOB_UNKNOWN.String(), errList.Errors[0].Code)
}

func TestGetBlobSingleRangePartialUnexpectedError(t *testing.T) {
	// Single-range path: GetBlobPartial returning a non-zerr error
	// hits writeBlobError's default branch and produces a 500.
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
			return nil, 0, 0, ErrUnexpectedError
		},
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return nil, zerr.ErrManifestNotFound
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Empty(t, resp.Header.Get(constants.DistContentDigestKey),
		"Docker-Content-Digest must not be set on error responses")
}

func TestGetBlobSingleRangeLengthMismatch(t *testing.T) {
	// Single-range path: storage returns a reader claiming a different
	// length than the request asked for. The handler must reject this
	// with 500 rather than streaming an under- or over-sized body,
	// since on the single-range path the headers haven't been flushed
	// yet and 5xx is still possible.
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
			// Caller asked for [0,1] (2 bytes); we hand back a reader
			// claiming 3 bytes. blen != rng.length() so the handler
			// should bail out with 500.
			return io.NopCloser(strings.NewReader("xyz")), 3, 4, nil
		},
		GetIndexContentFn: func(repo string) ([]byte, error) {
			return nil, zerr.ErrManifestNotFound
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
	req.Header.Set("Range", "bytes=0-1")
	req = mux.SetURLVars(req, map[string]string{
		"name":   "test",
		"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
	})

	rec := httptest.NewRecorder()
	handler.GetBlob(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestGetBlobMultipartShortReaderTruncates(t *testing.T) {
	// Multipart path: the second range's reader is short — it claims
	// rng.length() bytes but EOFs after one. io.CopyN inside the
	// producer goroutine returns ErrUnexpectedEOF, which the handler
	// surfaces as a truncated body (the 206 is already on the wire).
	// This exercises the copyErr branch of writeMultipartRanges,
	// distinct from the openRange-error path covered above.
	const blobBody = "0123456789abcdef" // 16 bytes

	var calls atomic.Int32

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
		if calls.Add(1) == 1 {
			return io.NopCloser(strings.NewReader(blobBody[from : to+1])), to - from + 1, int64(len(blobBody)), nil
		}

		// Second range: announce the requested length but only deliver
		// 1 byte. io.CopyN will return ErrUnexpectedEOF.
		return io.NopCloser(strings.NewReader("x")), to - from + 1, int64(len(blobBody)), nil
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

	advertisedLen, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	require.NoError(t, err)

	body := drainResponseBody(t, resp)
	assert.Less(t, int64(len(body)), advertisedLen,
		"a short reader on the second range must truncate the body")
}

func TestGetBlobRangeCheckBlobNamedErrors(t *testing.T) {
	// CheckBlob is the first storage call on the range branch and the
	// only place where named storage errors can be turned into proper
	// 4xx OCI error responses (once the 206 is in flight on the
	// multipart path it's too late). Each case in the table maps a
	// zerr.* return to the OCI status code + error code the handler
	// must produce via writeBlobError.
	type expect struct {
		status int
		code   string
	}

	cases := map[string]struct {
		err    error
		expect expect
	}{
		"bad digest": {
			err:    zerr.ErrBadBlobDigest,
			expect: expect{status: http.StatusBadRequest, code: apiErr.DIGEST_INVALID.String()},
		},
		"repo not found": {
			err:    zerr.ErrRepoNotFound,
			expect: expect{status: http.StatusNotFound, code: apiErr.NAME_UNKNOWN.String()},
		},
		"blob not found": {
			err:    zerr.ErrBlobNotFound,
			expect: expect{status: http.StatusNotFound, code: apiErr.BLOB_UNKNOWN.String()},
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			handler := newBlobTestRouteHandler(t, mocks.MockedImageStore{
				CheckBlobFn: func(repo string, digest godigest.Digest) (bool, int64, error) {
					return false, 0, testCase.err
				},
			})

			req := httptest.NewRequest(http.MethodGet, "http://example.com/v2/test/blobs/sha256:test", nil)
			req.Header.Set("Range", "bytes=0-1")
			req = mux.SetURLVars(req, map[string]string{
				"name":   "test",
				"digest": "sha256:7b8437f04f83f084b7ed68ad8c4a4947e12fc4e1b006b38129bac89114ec3621",
			})

			rec := httptest.NewRecorder()
			handler.GetBlob(rec, req)

			resp := rec.Result()
			defer resp.Body.Close()

			require.Equal(t, testCase.expect.status, resp.StatusCode)

			var errList apiErr.ErrorList

			require.NoError(t, json.NewDecoder(resp.Body).Decode(&errList))
			require.Len(t, errList.Errors, 1)
			assert.Equal(t, testCase.expect.code, errList.Errors[0].Code)
		})
	}
}

// erroringCloseReader wraps an io.Reader and returns a fixed error
// from Close(). It exists to exercise the closeErr branch of
// writeMultipartRanges' producer goroutine, which the recent deferred-
// CloseWithError refactor introduced as a distinct code path.
type erroringCloseReader struct {
	io.Reader

	err error
}

func (e *erroringCloseReader) Close() error { return e.err }

func TestGetBlobMultipartReaderCloseError(t *testing.T) {
	// A range reader whose Close() errors after a full read must
	// still truncate the body — the 206 is on the wire, so we can
	// only tear the pipe down. This drives the closeErr branch of
	// writeMultipartRanges; the open/copy paths already succeeded.
	const blobBody = "0123456789abcdef" // 16 bytes

	var calls atomic.Int32

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
		// First range: clean reader; second range: a reader whose
		// content is fine but Close() errors.
		body := blobBody[from : to+1]
		if calls.Add(1) == 1 {
			return io.NopCloser(strings.NewReader(body)), to - from + 1, int64(len(blobBody)), nil
		}

		return &erroringCloseReader{
			Reader: strings.NewReader(body),
			err:    ErrUnexpectedError,
		}, to - from + 1, int64(len(blobBody)), nil
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

	advertisedLen, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	require.NoError(t, err)

	body := drainResponseBody(t, resp)
	assert.Less(t, int64(len(body)), advertisedLen,
		"a Close() error on the second range must truncate the body")
}
