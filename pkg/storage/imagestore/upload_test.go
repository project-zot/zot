package imagestore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	"zotregistry.dev/zot/v2/pkg/storage/s3"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errAppendUnsupported = errors.New("append to zero-size path /store/repo/.uploads/upload unsupported")

func TestS3DeleteBlobUploadErrors(t *testing.T) {
	failure := assert.AnError
	missing := driver.PathNotFoundError{Path: "/store/repo/.uploads/upload"}
	appendUnsupported := driver.Error{DriverName: "s3aws", Detail: errAppendUnsupported}

	for _, test := range []struct {
		name                                                        string
		size                                                        int64
		isDir                                                       bool
		statErr, writerErr, cancelErr, closeErr, deleteErr, wantErr error
		wantWriter, wantCancel, wantDelete                          bool
	}{
		{name: "stat error", statErr: failure, wantErr: failure},
		{name: "directory", isDir: true, wantDelete: true},
		{name: "writer error", size: 4, writerErr: failure, wantErr: failure, wantWriter: true},
		{name: "cancel error", size: 4, cancelErr: failure, wantErr: failure, wantWriter: true, wantCancel: true},
		{name: "close error", size: 4, closeErr: failure, wantErr: failure, wantWriter: true, wantCancel: true},
		{name: "committed object", size: 4, writerErr: appendUnsupported, wantWriter: true, wantDelete: true},
		{
			name: "committed delete error", size: 4, writerErr: appendUnsupported, deleteErr: failure,
			wantErr: failure, wantWriter: true, wantDelete: true,
		},
		{name: "committed object with multipart", size: 4, wantWriter: true, wantCancel: true, wantDelete: true},
		{
			name: "aborted delete error", size: 4, deleteErr: failure, wantErr: failure,
			wantWriter: true, wantCancel: true, wantDelete: true,
		},
		{
			name: "multipart without object", statErr: missing, deleteErr: missing,
			wantWriter: true, wantCancel: true, wantDelete: true,
		},
		{
			name: "missing upload", statErr: missing, writerErr: missing, deleteErr: missing,
			wantErr: zerr.ErrUploadNotFound, wantWriter: true, wantDelete: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var opened, canceled, closed, deleted bool

			backend := &mocks.StorageDriverMock{
				StatFn: func(_ context.Context, path string) (driver.FileInfo, error) {
					require.Equal(t, missing.Path, path)

					return driver.FileInfoInternal{
						FileInfoFields: driver.FileInfoFields{Path: path, Size: test.size, IsDir: test.isDir},
					}, test.statErr
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

							return test.closeErr
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

func TestDeleteBlobUploadRejectsPathLikeSessionIDs(t *testing.T) {
	rootDir := t.TempDir()
	store := imagestore.NewImageStore(rootDir, "", false, false, log.NewTestLogger(),
		monitoring.NewNopMetricServer(), nil, local.New(true), nil, nil, nil)

	blobPath := filepath.Join(rootDir, "repo", "blobs", "sha256", "0123")
	uploadPath := filepath.Join(rootDir, "repo", storageConstants.BlobUploadDir, "pending")
	indexPath := filepath.Join(rootDir, "repo", "index.json")

	for _, file := range []string{blobPath, uploadPath, indexPath} {
		require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
		require.NoError(t, os.WriteFile(file, []byte("data"), 0o600))
	}

	for _, sessionID := range []string{".", "..", "../blobs", "../../repo", "..\\blobs", "nested/pending", ""} {
		err := store.DeleteBlobUpload("repo", sessionID)
		require.ErrorIs(t, err, zerr.ErrUploadNotFound, sessionID)

		deleted, err := store.DeleteBlobUploadIfIdle("repo", sessionID)
		require.NoError(t, err, sessionID)
		require.False(t, deleted, sessionID)
	}

	for _, file := range []string{blobPath, uploadPath, indexPath} {
		_, err := os.Stat(file)
		require.NoError(t, err)
	}

	require.NoError(t, store.DeleteBlobUpload("repo", "pending"))
	_, err := os.Stat(uploadPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}
