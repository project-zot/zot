//go:build sync

package sync

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestLocalTempStoreBlobPath(t *testing.T) {
	t.Parallel()

	digest := godigest.FromString("blob")
	remoteStore := mocks.MockedImageStore{
		NameFn:    func() string { return "s3" },
		RootDirFn: func() string { return "/zot" },
	}

	t.Run("remote store without downloadDir fails instead of using the CWD", func(t *testing.T) {
		t.Parallel()

		lts := NewLocalTempStore(storage.StoreController{DefaultStore: remoteStore}, log.NewTestLogger())

		blobPath, err := lts.BlobPath("repo", digest)
		require.ErrorIs(t, err, zerr.ErrSyncNoStagingRoot)
		require.Empty(t, blobPath)

		_, statErr := os.Stat(streamTempSubdir)
		require.ErrorIs(t, statErr, os.ErrNotExist)
	})

	t.Run("invalid digest is rejected before touching the filesystem", func(t *testing.T) {
		t.Parallel()

		downloadDir := t.TempDir()
		storeController := storage.StoreController{DefaultStore: remoteStore, SyncDownloadDir: downloadDir}
		lts := NewLocalTempStore(storeController, log.NewTestLogger())

		escaping := godigest.Digest("../../escaped:" + digest.Encoded())

		_, err := lts.BlobPath("repo", escaping)
		require.Error(t, err)

		entries, err := os.ReadDir(downloadDir)
		require.NoError(t, err)
		require.Empty(t, entries)
	})

	t.Run("remote store with downloadDir stages there", func(t *testing.T) {
		t.Parallel()

		downloadDir := t.TempDir()
		storeController := storage.StoreController{DefaultStore: remoteStore, SyncDownloadDir: downloadDir}
		lts := NewLocalTempStore(storeController, log.NewTestLogger())

		blobPath, err := lts.BlobPath("repo", digest)
		require.NoError(t, err)

		parentDir := path.Join(downloadDir, streamTempSubdir, digest.Algorithm().String())
		require.Equal(t, path.Join(parentDir, digest.Encoded()), blobPath)
		require.DirExists(t, parentDir)
	})

	t.Run("parent directory creation failure is returned", func(t *testing.T) {
		t.Parallel()

		// A file where the staging root's _stream directory should go.
		downloadDir := t.TempDir()
		require.NoError(t, os.WriteFile(path.Join(downloadDir, streamTempSubdir), nil, 0o600))

		storeController := storage.StoreController{DefaultStore: remoteStore, SyncDownloadDir: downloadDir}
		lts := NewLocalTempStore(storeController, log.NewTestLogger())

		_, err := lts.BlobPath("repo", digest)
		require.Error(t, err)
	})
}

func TestLinkOrCopyFile(t *testing.T) {
	t.Parallel()

	content := []byte("streamed blob")

	t.Run("same filesystem links", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		src := path.Join(dir, "stream")
		dst := path.Join(dir, "layout", "blobs", "sha256", "blob")
		require.NoError(t, os.WriteFile(src, content, 0o600))

		require.NoError(t, linkOrCopyFile(src, dst))

		srcInfo, err := os.Stat(src)
		require.NoError(t, err)
		dstInfo, err := os.Stat(dst)
		require.NoError(t, err)
		require.True(t, os.SameFile(srcInfo, dstInfo), "dst must be a hard link of src")

		// The link outlives the stream's own name, as when teardown deletes the stream file.
		require.NoError(t, os.Remove(src))

		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		require.Equal(t, content, got)
	})

	t.Run("existing dst is kept", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		src := path.Join(dir, "stream")
		dst := path.Join(dir, "blob")
		require.NoError(t, os.WriteFile(src, content, 0o600))
		require.NoError(t, os.WriteFile(dst, []byte("seeded"), 0o600))

		require.NoError(t, linkOrCopyFile(src, dst))

		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		require.Equal(t, []byte("seeded"), got)
	})

	t.Run("another filesystem copies", func(t *testing.T) {
		t.Parallel()

		// /dev/shm is tmpfs on Linux; skip where it isn't a different filesystem from TempDir.
		shm, err := os.MkdirTemp("/dev/shm", "zot-link-test-")
		if err != nil {
			t.Skip("no /dev/shm:", err)
		}

		t.Cleanup(func() { _ = os.RemoveAll(shm) })

		src := path.Join(shm, "stream")
		dst := path.Join(t.TempDir(), "blob")
		require.NoError(t, os.WriteFile(src, content, 0o600))

		if err := os.Link(src, path.Join(path.Dir(dst), "probe")); err == nil {
			t.Skip("/dev/shm and TempDir share a filesystem")
		}

		require.NoError(t, linkOrCopyFile(src, dst))

		got, err := os.ReadFile(dst)
		require.NoError(t, err)
		require.Equal(t, content, got)

		leftovers, err := filepath.Glob(dst + ".*.tmp")
		require.NoError(t, err)
		require.Empty(t, leftovers, "the temp copy must be renamed into place")
	})

	t.Run("missing src fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.Error(t, linkOrCopyFile(path.Join(dir, "missing"), path.Join(dir, "blob")))
	})
}
