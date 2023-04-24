//go:build userprefs
// +build userprefs

package extensions_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

const UserprefsBaseURL = "http://127.0.0.1:8080/v2/_zot/ext/userprefs"

func TestHandlers(t *testing.T) {
	log := log.NewLogger("debug", "")
	mockrepoDB := mocks.RepoDBMock{}

	Convey("No repo in request", t, func() {
		request := httptest.NewRequest("GET", UserprefsBaseURL+"", strings.NewReader("My string"))
		response := httptest.NewRecorder()

		extensions.PutStar(response, request, mockrepoDB, log)
		res := response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusBadRequest)
		defer res.Body.Close()

		extensions.PutBookmark(response, request, mockrepoDB, log)
		res = response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusBadRequest)
		defer res.Body.Close()
	})

	Convey("Empty repo in request", t, func() {
		request := httptest.NewRequest("GET", UserprefsBaseURL+"?repo=", strings.NewReader("My string"))
		response := httptest.NewRecorder()

		extensions.PutStar(response, request, mockrepoDB, log)
		res := response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusNotFound)
		defer res.Body.Close()

		extensions.PutBookmark(response, request, mockrepoDB, log)
		res = response.Result()
		So(res.StatusCode, ShouldEqual, http.StatusNotFound)
		defer res.Body.Close()
	})

	Convey("ToggleStarRepo different errors", t, func() {
		request := httptest.NewRequest("GET", UserprefsBaseURL+"?repo=test",
			strings.NewReader("My string"))

		Convey("ErrRepoMetaNotFound", func() {
			mockrepoDB.ToggleStarRepoFn = func(ctx context.Context, repo string) (repodb.ToggleState, error) {
				return repodb.NotChanged, zerr.ErrRepoMetaNotFound
			}

			mockrepoDB.ToggleBookmarkRepoFn = func(ctx context.Context, repo string) (repodb.ToggleState, error) {
				return repodb.NotChanged, zerr.ErrRepoMetaNotFound
			}

			response := httptest.NewRecorder()
			extensions.PutBookmark(response, request, mockrepoDB, log)
			res := response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusNotFound)
			defer res.Body.Close()

			response = httptest.NewRecorder()
			extensions.PutStar(response, request, mockrepoDB, log)
			res = response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusNotFound)
			defer res.Body.Close()
		})

		Convey("ErrUserDataNotAllowed", func() {
			request = mux.SetURLVars(request, map[string]string{
				"name": "repo",
			})

			mockrepoDB.ToggleBookmarkRepoFn = func(ctx context.Context, repo string) (repodb.ToggleState, error) {
				return repodb.NotChanged, zerr.ErrUserDataNotAllowed
			}

			mockrepoDB.ToggleStarRepoFn = func(ctx context.Context, repo string) (repodb.ToggleState, error) {
				return repodb.NotChanged, zerr.ErrUserDataNotAllowed
			}

			response := httptest.NewRecorder()
			extensions.PutBookmark(response, request, mockrepoDB, log)
			res := response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusForbidden)
			defer res.Body.Close()

			response = httptest.NewRecorder()
			extensions.PutStar(response, request, mockrepoDB, log)
			res = response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusForbidden)
			defer res.Body.Close()
		})

		Convey("ErrUnexpectedError", func() {
			request = mux.SetURLVars(request, map[string]string{
				"name": "repo",
			})

			mockrepoDB.ToggleBookmarkRepoFn = func(ctx context.Context, repo string) (repodb.ToggleState, error) {
				return repodb.NotChanged, ErrTestError
			}

			mockrepoDB.ToggleStarRepoFn = func(ctx context.Context, repo string) (repodb.ToggleState, error) {
				return repodb.NotChanged, ErrTestError
			}
			response := httptest.NewRecorder()
			extensions.PutBookmark(response, request, mockrepoDB, log)
			res := response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusInternalServerError)
			defer res.Body.Close()

			response = httptest.NewRecorder()
			extensions.PutStar(response, request, mockrepoDB, log)
			res = response.Result()
			So(res.StatusCode, ShouldEqual, http.StatusInternalServerError)
			defer res.Body.Close()
		})
	})
}
