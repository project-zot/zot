package imagestore_test

import (
	"bytes"
	"context"
	"io"
	"path"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestNewImageStoreUpgradeStreamsRemoteBlob(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	rootDir := "/oci-repo-test/migration-stream"
	repo := "repo"
	content := []byte("blob-content-stream")
	digest := godigest.FromBytes(content)
	blobsAlgoDir := path.Join(rootDir, repo, ispec.ImageBlobsDir, digest.Algorithm().String())
	blobPath := path.Join(blobsAlgoDir, digest.Encoded())
	markerPath := path.Join(rootDir, constants.BlobstoreMigratedMarker)
	globalBlobPath := path.Join(rootDir, constants.GlobalBlobsRepo, ispec.ImageBlobsDir,
		digest.Algorithm().String(), digest.Encoded())

	var (
		readFileCalled bool
		readerCalled   bool
		writtenBlob    bytes.Buffer
	)

	storeMock := &mocks.StorageDriverMock{
		GetContentFn: func(_ context.Context, _ string) ([]byte, error) {
			readFileCalled = true

			return content, nil
		},
		ReaderFn: func(_ context.Context, filePath string, _ int64) (io.ReadCloser, error) {
			if filePath == blobPath {
				readerCalled = true
			}

			return io.NopCloser(bytes.NewReader(content)), nil
		},
		WriterFn: func(_ context.Context, filePath string, _ bool) (driver.FileWriter, error) {
			writer := &mocks.FileWriterMock{
				WriteFn: func(p []byte) (int, error) {
					if filePath == globalBlobPath {
						_, _ = writtenBlob.Write(p)
					}

					return len(p), nil
				},
			}

			return writer, nil
		},
		StatFn: func(_ context.Context, filePath string) (driver.FileInfo, error) {
			if filePath == markerPath {
				return nil, driver.PathNotFoundError{Path: filePath}
			}

			if filePath == blobPath {
				return &mocks.FileInfoMock{SizeFn: func() int64 { return int64(len(content)) }}, nil
			}

			return &mocks.FileInfoMock{}, nil
		},
		ListFn: func(_ context.Context, filePath string) ([]string, error) {
			switch filePath {
			case rootDir, path.Join(rootDir, repo):
				return []string{
					path.Join(rootDir, repo, ispec.ImageLayoutFile),
					path.Join(rootDir, repo, ispec.ImageIndexFile),
					path.Join(rootDir, repo, ispec.ImageBlobsDir),
				}, nil
			case path.Join(rootDir, repo, ispec.ImageBlobsDir):
				return []string{blobsAlgoDir}, nil
			case blobsAlgoDir:
				return []string{blobPath}, nil
			}

			return []string{}, nil
		},
		WalkFn: func(_ context.Context, filePath string, walkFn driver.WalkFn,
			_ ...func(*driver.WalkOptions),
		) error {
			if filePath != rootDir {
				return nil
			}

			return walkFn(&mocks.FileInfoMock{
				IsDirFn: func() bool { return true },
				PathFn:  func() string { return path.Join(rootDir, repo) },
			})
		},
	}

	store := imagestore.NewImageStore(rootDir, "", true, false, log, metrics, nil,
		gcs.New(storeMock), nil, nil, nil)
	if store == nil {
		t.Fatal("expected image store initialization to succeed")
	}

	if !readerCalled {
		t.Fatal("expected migration to use streaming reader for remote blob copy")
	}

	if readFileCalled {
		t.Fatal("did not expect migration to read full blob content into memory")
	}

	if !bytes.Equal(writtenBlob.Bytes(), content) {
		t.Fatal("expected migrated global blob to match streamed content")
	}
}
