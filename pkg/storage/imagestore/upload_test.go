package imagestore_test

import (
	"context"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestS3DeleteBlobUploadErrors(t *testing.T) {
	failure := assert.AnError
	missing := driver.PathNotFoundError{Path: "/store/repo/.uploads/upload"}

	for _, test := range []struct {
		name                                              string
		size                                              int64
		statErr, writerErr, cancelErr, deleteErr, wantErr error
		wantWriter, wantCancel, wantDelete                bool
	}{
		{name: "stat error", statErr: failure, wantErr: failure},
		{name: "committed delete error", size: 4, deleteErr: failure, wantErr: failure, wantDelete: true},
		{name: "writer error", writerErr: failure, wantErr: failure, wantWriter: true},
		{name: "cancel error", cancelErr: failure, wantErr: failure, wantWriter: true, wantCancel: true},
		{
			name: "empty delete error", deleteErr: failure, wantErr: failure,
			wantWriter: true, wantCancel: true, wantDelete: true,
		},
		{
			name: "multipart without object", statErr: missing, deleteErr: missing,
			wantWriter: true, wantCancel: true, wantDelete: true,
		},
		{name: "missing upload", statErr: missing, writerErr: missing, wantErr: zerr.ErrUploadNotFound, wantWriter: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var opened, canceled, closed, deleted bool
			backend := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, path string) (driver.FileInfo, error) {
					require.Equal(t, missing.Path, path)

					return driver.FileInfoInternal{FileInfoFields: driver.FileInfoFields{Path: path, Size: test.size}}, test.statErr
				},
				WriterFn: func(_ context.Context, path string, appendMode bool) (driver.FileWriter, error) {
					require.Equal(t, missing.Path, path)
					require.True(t, appendMode)
					opened = true

					return &mocks.FileWriterMock{
						CancelFn: func() error {
							canceled = true

							return test.cancelErr
						},
						CloseFn: func() error {
							closed = true

							return nil
						},
					}, test.writerErr
				},
				DeleteFn: func(_ context.Context, path string) error {
					require.Equal(t, missing.Path, path)
					deleted = true

					return test.deleteErr
				},
			}
			store := imagestore.NewImageStore("/store", "", false, false, log.NewTestLogger(),
				monitoring.NewNopMetricServer(), nil, s3.New(backend), nil, nil, nil)
			err := store.DeleteBlobUpload("repo", "upload")
			require.ErrorIs(t, err, test.wantErr)
			assert.Equal(t, test.wantWriter, opened)
			assert.Equal(t, test.wantCancel, canceled)
			assert.Equal(t, test.wantCancel, closed)
			assert.Equal(t, test.wantDelete, deleted)
		})
	}
}
