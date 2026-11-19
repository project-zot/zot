//go:build linux

package ktls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// SOL_TLS option names and cmsg types from include/uapi/linux/tls.h; x/sys
// only exports SOL_TLS and TCP_ULP.
const (
	optTLSTX            = 1 // TLS_TX
	optTLSRX            = 2 // TLS_RX
	optTLSRXExpectNoPad = 4 // TLS_RX_EXPECT_NO_PAD
	cmsgSetRecordType   = 1 // TLS_SET_RECORD_TYPE
	cmsgGetRecordType   = 2 // TLS_GET_RECORD_TYPE
)

// tlsULPPresent is probed once per process: the kernel loads a module only at
// a privileged request, so the answer does not change while zot runs unless
// someone loads the module by hand (picked up on restart).
var tlsULPPresent = sync.OnceValue(probeTLSULP) //nolint:gochecknoglobals // process-wide cached probe

// probeTLSULP asks the kernel to attach the "tls" upper layer protocol to a
// fresh, unconnected TCP socket. A kernel that has the ULP refuses with
// ENOTCONN (it only attaches to established connections); one without it
// answers ENOENT.
func probeTLSULP() bool {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false
	}

	defer func() { _ = unix.Close(sock) }()

	err = unix.SetsockoptString(sock, unix.IPPROTO_TCP, unix.TCP_ULP, "tls")

	return err == nil || errors.Is(err, unix.ENOTCONN)
}

// Available reports whether this kernel supports kTLS.
func Available() bool {
	return tlsULPPresent()
}

// enableKernelTLS installs the session keys on raw's socket and returns the
// connection that reads and writes plaintext through the kernel.
//
// Until TLS_TX succeeds the socket is still plain TCP carrying userspace TLS,
// so errors leave the *tls.Conn usable. Once TX is installed the kernel owns
// the send side for good; a later failure wraps errConnUnusable and the
// connection must be closed.
func enableKernelTLS(raw net.Conn, state tls.ConnectionState, txInfo, rxInfo []byte) (net.Conn, error) {
	sysConn, ok := raw.(syscall.Conn)
	if !ok {
		return nil, errNoFileDescriptor
	}

	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var (
		opErr   error
		txArmed bool
	)

	ctlErr := rawConn.Control(func(fd uintptr) {
		sock := int(fd)

		if err := unix.SetsockoptString(sock, unix.IPPROTO_TCP, unix.TCP_ULP, "tls"); err != nil {
			opErr = fmt.Errorf("ktls: TCP_ULP: %w", err)

			return
		}

		if err := unix.SetsockoptString(sock, unix.SOL_TLS, optTLSTX, string(txInfo)); err != nil {
			opErr = fmt.Errorf("ktls: TLS_TX: %w", err)

			return
		}

		txArmed = true

		if err := unix.SetsockoptString(sock, unix.SOL_TLS, optTLSRX, string(rxInfo)); err != nil {
			opErr = fmt.Errorf("ktls: TLS_RX: %w", err)

			return
		}

		// Optional (Linux 6.0+): promise the kernel that the peer does not pad
		// records, so it can decrypt straight into the caller's buffer. A peer
		// that pads anyway costs the kernel a retry, never correctness.
		_ = unix.SetsockoptInt(sock, unix.SOL_TLS, optTLSRXExpectNoPad, 1)
	})

	switch {
	case ctlErr != nil:
		return nil, ctlErr
	case opErr != nil && txArmed:
		return nil, fmt.Errorf("%w: %w", errConnUnusable, opErr)
	case opErr != nil:
		return nil, opErr
	}

	return newKernelConn(raw, rawConn, state), nil
}
