package s3_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/storage/s3"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errRedirect = errors.New("redirect error")

func TestDriverRedirectURL(t *testing.T) {
	Convey("S3 Driver RedirectURL", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		s3Driver := s3.New(storeMock)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"http://localhost/v2/repo/blobs/sha256:abc", nil)

		Convey("Success", func() {
			storeMock.RedirectURLFn = func(r *http.Request, path string) (string, error) {
				So(r, ShouldEqual, req)
				So(path, ShouldEqual, "/blob/path")

				return "https://example.com/signed", nil
			}

			url, err := s3Driver.RedirectURL(req, "/blob/path")
			So(err, ShouldBeNil)
			So(url, ShouldEqual, "https://example.com/signed")
		})

		Convey("Error", func() {
			storeMock.RedirectURLFn = func(_ *http.Request, _ string) (string, error) {
				return "", errRedirect
			}

			url, err := s3Driver.RedirectURL(req, "/blob/path")
			So(url, ShouldEqual, "")
			So(errors.Is(err, errRedirect), ShouldBeTrue)
		})
	})
}

func TestDriverLink(t *testing.T) {
	Convey("S3 Driver Link", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		s3Driver := s3.New(storeMock)

		Convey("writes empty content to dest", func() {
			putCalls := 0
			storeMock.PutContentFn = func(ctx context.Context, path string, content []byte) error {
				putCalls++
				So(path, ShouldEqual, "/dst")
				So(content, ShouldBeEmpty)

				return nil
			}

			So(s3Driver.Link("/src", "/dst"), ShouldBeNil)
			So(putCalls, ShouldEqual, 1)
		})

		Convey("src equals dest is a no-op", func() {
			putCalls := 0
			storeMock.PutContentFn = func(ctx context.Context, path string, content []byte) error {
				putCalls++

				return nil
			}

			So(s3Driver.Link("/same", "/same"), ShouldBeNil)
			So(putCalls, ShouldEqual, 0)
		})
	})
}
