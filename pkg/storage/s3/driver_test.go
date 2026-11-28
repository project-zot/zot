package s3_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/storage/s3"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// multipartContentSize is the smallest content WriteFile sends through the multipart writer.
const multipartContentSize = 5 * 1024 * 1024

var (
	errRedirect = errors.New("redirect error")
	errPut      = errors.New("put error")
)

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

func TestDriverWriteFile(t *testing.T) {
	Convey("S3 Driver WriteFile", t, func() {
		putCalls, writerCalls := 0, 0

		var (
			putPath    string
			putContent []byte
		)

		storeMock := &mocks.StorageDriverMock{
			PutContentFn: func(ctx context.Context, path string, content []byte) error {
				putCalls++
				putPath, putContent = path, content

				return nil
			},
			WriterFn: func(ctx context.Context, path string, isAppend bool) (storagedriver.FileWriter, error) {
				writerCalls++

				return &mocks.FileWriterMock{
					WriteFn: func(p []byte) (int, error) { return len(p), nil },
				}, nil
			},
		}
		s3Driver := s3.New(storeMock)

		Convey("content smaller than a multipart chunk is one PutContent", func() {
			content := bytes.Repeat([]byte("a"), multipartContentSize-1)

			n, err := s3Driver.WriteFile("/dst", content)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(content))
			So(putCalls, ShouldEqual, 1)
			So(writerCalls, ShouldEqual, 0)
			So(putPath, ShouldEqual, "/dst")
			So(bytes.Equal(putContent, content), ShouldBeTrue)
		})

		Convey("empty content is one PutContent", func() {
			n, err := s3Driver.WriteFile("/dst", []byte{})
			So(err, ShouldBeNil)
			So(n, ShouldEqual, 0)
			So(putCalls, ShouldEqual, 1)
			So(writerCalls, ShouldEqual, 0)
			So(putPath, ShouldEqual, "/dst")
			So(putContent, ShouldBeEmpty)
		})

		Convey("larger content goes through the writer", func() {
			content := make([]byte, multipartContentSize)

			n, err := s3Driver.WriteFile("/dst", content)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(content))
			So(putCalls, ShouldEqual, 0)
			So(writerCalls, ShouldEqual, 1)
		})

		Convey("PutContent error", func() {
			storeMock.PutContentFn = func(ctx context.Context, path string, content []byte) error {
				return errPut
			}

			n, err := s3Driver.WriteFile("/dst", []byte("x"))
			So(n, ShouldEqual, -1)
			So(errors.Is(err, errPut), ShouldBeTrue)
		})
	})
}

func TestEmptyDirectoryOperationsAreNoOps(t *testing.T) {
	driver := s3.New(nil)

	dirs, err := driver.ListSubDirs("/")
	if err != nil || len(dirs) != 0 {
		t.Fatalf("expected no physical directories, got %v, %v", dirs, err)
	}

	if err := driver.RemoveEmptyDir("/namespace"); err != nil {
		t.Fatal(err)
	}
}
