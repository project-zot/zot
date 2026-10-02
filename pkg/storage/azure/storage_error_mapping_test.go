package azure_test

// Zot Azure wrapper formatErr / Mark* mapping (not upstream SDK / Azurite surfaces).
// See pkg/storage/errclass/driver-error-matrix.md.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/azure"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestFormatErrClassification(t *testing.T) {
	Convey("Azure formatErr classification", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		azureDriver := azure.New(storeMock)

		type outcome int

		const (
			pathNotFound outcome = iota
			driverError
		)

		cases := []struct {
			name string
			msg  string
			want outcome
			note string
		}{
			{
				name: "BlobNotFound",
				msg:  "BlobNotFound",
				want: pathNotFound,
				note: "Missing",
			},
			{
				name: "ResourceNotFound",
				msg:  "ResourceNotFound",
				want: pathNotFound,
				note: "Missing",
			},
			{
				name: "Error 404",
				msg:  "Error 404",
				want: pathNotFound,
				note: "Missing",
			},
			{
				name: "404 The specified blob does not exist",
				msg:  "404 The specified blob does not exist",
				want: pathNotFound,
				note: "Missing — Azure blob 404 wording",
			},
			{
				name: "timeout containing does not exist",
				msg:  "OperationTimedOut: blob does not exist yet",
				want: driverError,
				note: "Transient — bare does-not-exist text is not Missing",
			},
			{
				name: "resource does not exist",
				msg:  "The specified resource does not exist",
				want: driverError,
				note: "Transient — bare does-not-exist text is not Missing",
			},
			{
				name: "context deadline",
				msg:  "context deadline exceeded",
				want: driverError,
				note: "Transient",
			},
			{
				name: "connection reset",
				msg:  "read: connection reset by peer",
				want: driverError,
				note: "Transient",
			},
			{
				name: "503 Service Unavailable",
				msg:  "ServiceUnavailable: 503",
				want: driverError,
				note: "Transient",
			},
			{
				name: "429 Too Many Requests",
				msg:  "TooManyRequests: 429",
				want: driverError,
				note: "Transient",
			},
		}

		for _, testCase := range cases {
			Convey(testCase.name+": "+testCase.note, func() {
				storeMock.GetContentFn = func(_ context.Context, _ string) ([]byte, error) {
					//nolint:err113 // mapping needs exact message text
					return nil, fmt.Errorf("%s", testCase.msg)
				}

				_, err := azureDriver.ReadFile("/blobs/sha256/abc")
				So(err, ShouldNotBeNil)

				var pnf storagedriver.PathNotFoundError

				var derr storagedriver.Error

				switch testCase.want {
				case pathNotFound:
					So(errors.As(err, &pnf), ShouldBeTrue)
					So(pnf.DriverName, ShouldEqual, "azure")
					So(pnf.Path, ShouldEqual, "/blobs/sha256/abc")
					So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
					So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
				case driverError:
					So(errors.As(err, &pnf), ShouldBeFalse)
					So(errors.As(err, &derr), ShouldBeTrue)
					So(derr.DriverName, ShouldEqual, "azure")
					So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
					So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
				}
			})
		}

		Convey("InvalidPathError → ErrStoragePermanent + DriverName", func() {
			storeMock.StatFn = func(_ context.Context, path string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.InvalidPathError{Path: path}
			}
			_, err := azureDriver.Stat("/bad")
			So(err, ShouldNotBeNil)

			var inv storagedriver.InvalidPathError
			So(errors.As(err, &inv), ShouldBeTrue)
			So(inv.DriverName, ShouldEqual, "azure")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("typed BlobNotFound ResponseError → ErrStorageMissing", func() {
			cause := &azcore.ResponseError{
				ErrorCode:  string(bloberror.BlobNotFound),
				StatusCode: http.StatusNotFound,
			}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := azureDriver.Stat("/missing")
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("typed AuthorizationFailure → ErrStoragePermanent", func() {
			cause := &azcore.ResponseError{
				ErrorCode:  string(bloberror.AuthorizationFailure),
				StatusCode: http.StatusForbidden,
			}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("%v-erased AuthenticationFailed (distribution Reader) → Permanent", func() {
			// Upstream azure.Reader: fmt.Errorf("failed to get blob properties: %v", err)
			typed := &azcore.ResponseError{
				ErrorCode:  string(bloberror.AuthenticationFailed),
				StatusCode: http.StatusForbidden,
			}
			//nolint:err113,errorlint // simulate distribution %v erase
			erased := fmt.Errorf("failed to get blob properties: %v", typed)
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, erased
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)

			var respErr *azcore.ResponseError
			So(errors.As(err, &respErr), ShouldBeFalse)
		})

		Convey("typed AuthorizationProtocolMismatch → ErrStoragePermanent", func() {
			cause := &azcore.ResponseError{
				ErrorCode:  string(bloberror.AuthorizationProtocolMismatch),
				StatusCode: http.StatusForbidden,
			}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
			So(errors.Is(err, cause), ShouldBeTrue)
		})

		Convey("typed ResponseError 401 without known ErrorCode → Permanent", func() {
			cause := &azcore.ResponseError{
				ErrorCode:  "SomeNewAuthCode",
				StatusCode: http.StatusUnauthorized,
			}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("%v-erased NoAuthenticationInformation → Permanent", func() {
			typed := &azcore.ResponseError{
				ErrorCode:  string(bloberror.NoAuthenticationInformation),
				StatusCode: http.StatusUnauthorized,
			}
			//nolint:err113,errorlint // simulate distribution %v erase
			erased := fmt.Errorf("failed to get blob properties: %v", typed)
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, erased
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("context.DeadlineExceeded → ErrStorageTransient", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, context.DeadlineExceeded
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("typed ServerBusy → ErrStorageTransient", func() {
			cause := &azcore.ResponseError{
				ErrorCode:  string(bloberror.ServerBusy),
				StatusCode: http.StatusServiceUnavailable,
			}
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, cause
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("net.Error Timeout → ErrStorageTransient", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, timeoutNetError{}
			}
			_, err := azureDriver.Stat("/key")
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("BlobNotFound string inside storagedriver.Error.Detail → Missing", func() {
			storeMock.StatFn = func(_ context.Context, _ string) (storagedriver.FileInfo, error) {
				return nil, storagedriver.Error{
					DriverName: "azure",
					Detail:     errors.New("BlobNotFound"), //nolint:err113 // mapping
				}
			}
			_, err := azureDriver.Stat("/missing")
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
		})

		Convey("InvalidOffsetError → ErrStoragePermanent + DriverName", func() {
			storeMock.ReaderFn = func(_ context.Context, path string, offset int64) (io.ReadCloser, error) {
				return nil, storagedriver.InvalidOffsetError{Path: path, Offset: offset}
			}
			_, err := azureDriver.Reader("/blob", 99)
			So(err, ShouldNotBeNil)

			var inv storagedriver.InvalidOffsetError
			So(errors.As(err, &inv), ShouldBeTrue)
			So(inv.DriverName, ShouldEqual, "azure")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
		})

		Convey("ErrUnsupportedMethod → ErrStoragePermanent", func() {
			storeMock.RedirectURLFn = func(_ *http.Request, _ string) (string, error) {
				return "", storagedriver.ErrUnsupportedMethod{DriverName: "azure"}
			}
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example/", nil)
			So(err, ShouldBeNil)
			_, err = azureDriver.RedirectURL(req, "/blob")
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("Writer Commit failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CommitFn: func() error {
						return &azcore.ResponseError{
							ErrorCode:  string(bloberror.AuthorizationFailure),
							StatusCode: http.StatusForbidden,
						}
					},
				}, nil
			}
			fw, err := azureDriver.Writer("/key", false)
			So(err, ShouldBeNil)
			err = fw.Commit(context.Background())
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
		})

		Convey("WriteFile Write failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					WriteFn: func(_ []byte) (int, error) {
						return 0, &azcore.ResponseError{
							ErrorCode:  string(bloberror.ServerBusy),
							StatusCode: http.StatusServiceUnavailable,
						}
					},
				}, nil
			}
			_, err := azureDriver.WriteFile("/key", []byte("x"))
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("WriteFile Close failure → classified via WrapFileWriter", func() {
			storeMock.WriterFn = func(_ context.Context, _ string, _ bool) (storagedriver.FileWriter, error) {
				return &mocks.FileWriterMock{
					CloseFn: func() error {
						return &azcore.ResponseError{
							ErrorCode:  string(bloberror.ServerBusy),
							StatusCode: http.StatusServiceUnavailable,
						}
					},
				}, nil
			}
			_, err := azureDriver.WriteFile("/key", []byte("x"))
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})
	})
}

func TestDeleteIdempotentPathNotFound(t *testing.T) {
	Convey("Azure Delete PathNotFound → nil (idempotent wrapper)", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		azureDriver := azure.New(storeMock)

		storeMock.DeleteFn = func(_ context.Context, path string) error {
			return storagedriver.PathNotFoundError{Path: path}
		}
		So(azureDriver.Delete("/already-gone"), ShouldBeNil)
	})
}

func TestWalkEOFPeeled(t *testing.T) {
	Convey("Azure Walk peels io.EOF before formatErr", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		azureDriver := azure.New(storeMock)

		storeMock.WalkFn = func(_ context.Context, _ string, _ storagedriver.WalkFn,
			_ ...func(*storagedriver.WalkOptions),
		) error {
			return storagedriver.Error{DriverName: "azure", Detail: io.EOF}
		}

		err := azureDriver.Walk("/repo", func(_ storagedriver.FileInfo) error { return nil })
		So(errors.Is(err, io.EOF), ShouldBeTrue)

		var derr storagedriver.Error
		So(errors.As(err, &derr), ShouldBeFalse)
	})
}

func TestWalkCallbackErrorNotTransient(t *testing.T) {
	Convey("Azure WalkFn application error → unchanged (not Transient)", t, func() {
		storeMock := &mocks.StorageDriverMock{}
		azureDriver := azure.New(storeMock)
		boom := errors.New("filter boom") //nolint:err113 // test

		storeMock.WalkFn = func(_ context.Context, _ string, f storagedriver.WalkFn,
			_ ...func(*storagedriver.WalkOptions),
		) error {
			err := f(nil)

			return storagedriver.Error{DriverName: "azure", Detail: err}
		}

		err := azureDriver.Walk("/repo", func(_ storagedriver.FileInfo) error { return boom })
		So(err, ShouldEqual, boom)
		So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeFalse)
	})
}

type timeoutNetError struct{}

func (timeoutNetError) Error() string   { return "i/o timeout" }
func (timeoutNetError) Timeout() bool   { return true }
func (timeoutNetError) Temporary() bool { return true }
