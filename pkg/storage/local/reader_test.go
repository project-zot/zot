package local_test

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

func TestReaderFileDescriptor(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "blob")
	require.NoError(t, os.WriteFile(path, []byte("0123456789"), 0o600))
	reader, err := local.New(false).Reader(path, 3)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	conn, ok := reader.(syscall.Conn)
	require.True(t, ok)
	raw, err := conn.SyscallConn()
	require.NoError(t, err)
	require.NoError(t, raw.Control(func(uintptr) {}))

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "3456789", string(data))
	require.NoError(t, reader.Close())
	require.Error(t, raw.Control(func(uintptr) {}))

	// Descriptor access must not remove error classification from ordinary reads and closes.
	_, err = reader.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrClosed)
	require.ErrorIs(t, err, zerr.ErrStoragePermanent)
	err = reader.Close()
	require.ErrorIs(t, err, os.ErrClosed)
	require.ErrorIs(t, err, zerr.ErrStoragePermanent)
}
