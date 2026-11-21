//go:build linux

package ktls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Alert values (RFC 8446 section 6).
const (
	alertLevelWarning = 1
	alertCloseNotify  = 0
	alertUserCanceled = 90
)

// maxControlRecords bounds how many non-data records one Read skips over
// before giving up, so a peer cannot keep a reader spinning on alerts.
const maxControlRecords = 16

// kernelConn is a connection whose TLS records the kernel encrypts and
// decrypts. The embedded connection carries plaintext.
type kernelConn struct {
	net.Conn

	rawConn syscall.RawConn
	state   tls.ConnectionState

	// readMu serializes Read. net.Conn lets goroutines call Read
	// concurrently, and recv publishes recvBuf before rawConn.Read takes the
	// descriptor's read lock, so without it a second Read could swap the
	// buffer under one parked in the netpoller. It also guards everything
	// below it, including alert reassembly.
	readMu   sync.Mutex
	recvBuf  []byte
	recvN    int
	recvType byte
	recvErr  error
	oob      [32]byte // room for one TLS_GET_RECORD_TYPE cmsg
	recvOnce func(fd uintptr) bool
	alerts   alertBuffer
	// readErr is the first terminal Read error (close_notify's io.EOF, a
	// fatal alert, a KeyUpdate, a socket error), returned by every later
	// Read as crypto/tls does. Without it, the Reads after close_notify
	// would park in recvmsg: a half-closed peer sends nothing more, so they
	// would block forever instead of seeing io.EOF.
	readErr error

	notifyOnce sync.Once
	closeOnce  sync.Once
	closeErr   error
}

func newKernelConn(raw net.Conn, rawConn syscall.RawConn, state tls.ConnectionState) *kernelConn {
	kc := &kernelConn{Conn: raw, rawConn: rawConn, state: state}
	// Bound once: a method value made per Read would allocate every time.
	kc.recvOnce = kc.recvmsg

	return kc
}

// Read returns decrypted application data.
//
// It reads with recvmsg and a control buffer because the kernel fails a
// plain read(2) with EIO when the next record is not application data; that
// would turn the peer's close_notify into an I/O error instead of io.EOF.
func (kc *kernelConn) Read(buf []byte) (int, error) {
	// Held across the netpoller wait, as crypto/tls holds its input lock; a
	// read deadline still wakes the holder, which then releases it.
	kc.readMu.Lock()
	defer kc.readMu.Unlock()

	if kc.readErr != nil {
		return 0, kc.readErr
	}

	if len(buf) == 0 {
		return 0, nil
	}

	n, err := kc.read(buf)
	if err != nil && !isTimeout(err) {
		// Deadline errors stay transient: the caller may extend the
		// deadline and read again, and no record was consumed.
		kc.readErr = err
	}

	return n, err
}

func isTimeout(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

// read is Read without the sticky error; readMu is held.
func (kc *kernelConn) read(buf []byte) (int, error) {
	for range maxControlRecords {
		n, recType, err := kc.recv(buf)
		if err != nil {
			// The kernel stops RX after a KeyUpdate it cannot follow.
			if errors.Is(err, unix.EKEYEXPIRED) {
				return 0, errKeyUpdate
			}

			return 0, err
		}

		switch recType {
		case contentAppData:
			if n > 0 {
				return n, nil
			}
			// An empty application_data record is legal; wait for the next one.
		case contentAlert:
			closed, err := kc.alerts.push(buf[:n])
			if err != nil {
				return 0, err
			}

			if closed {
				return 0, io.EOF
			}
		case contentHandshake:
			// A post-handshake message from the client can only be KeyUpdate
			// (zot never requests client certificates on an offloaded
			// connection, so no post-handshake auth). Rekeying is deliberately
			// not implemented, see errKeyUpdate: the connection is closed,
			// which net/http treats like any dropped keep-alive. Registry
			// clients (Go's crypto/tls, used by docker, containerd, oras,
			// skopeo) never initiate KeyUpdate, so in practice this only
			// affects clients that rekey on purpose (e.g. OpenSSL's
			// SSL_key_update), and only after the offload, which cannot be
			// undone.
			return 0, errKeyUpdate
		default:
			return 0, fmt.Errorf("%w %d", errUnexpectedRecord, recType)
		}
	}

	return 0, errTooManyControl
}

// recv runs one recvmsg through the netpoller, which honours read deadlines.
func (kc *kernelConn) recv(buf []byte) (int, byte, error) {
	kc.recvBuf = buf
	defer func() { kc.recvBuf = nil }()

	if err := kc.rawConn.Read(kc.recvOnce); err != nil {
		return 0, 0, err
	}

	return kc.recvN, kc.recvType, kc.recvErr
}

// recvmsg is the RawConn.Read callback: false means "not ready, wait".
func (kc *kernelConn) recvmsg(fd uintptr) bool {
	for {
		n, oobn, flags, _, err := unix.Recvmsg(int(fd), kc.recvBuf, kc.oob[:], 0)

		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EAGAIN):
			return false
		case err != nil:
			kc.recvN, kc.recvType, kc.recvErr = 0, 0, err
		default:
			kc.recvN, kc.recvType, kc.recvErr = parseRecordType(n, kc.oob[:oobn], flags)
		}

		return true
	}
}

// parseRecordType reads the record type the kernel attached to a recvmsg.
func parseRecordType(n int, oob []byte, flags int) (int, byte, error) {
	// A cut-off control message could hide that the data is an alert.
	if flags&unix.MSG_CTRUNC != 0 {
		return 0, 0, errTruncatedControl
	}

	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, 0, err
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_TLS && msg.Header.Type == cmsgGetRecordType && len(msg.Data) > 0 {
			return n, msg.Data[0], nil
		}
	}

	// No record type and no data: the peer closed TCP without close_notify.
	if n == 0 {
		return 0, 0, io.EOF
	}

	return n, contentAppData, nil
}

// alertBuffer reassembles alerts. Each is two bytes, level then description,
// and they may be split across records or several may share one.
type alertBuffer struct {
	pending []byte
}

func (ab *alertBuffer) push(data []byte) (bool, error) {
	const maxPending = 64

	if len(ab.pending)+len(data) > maxPending {
		return false, errOversizedAlert
	}

	ab.pending = append(ab.pending, data...)

	for ; len(ab.pending) >= 2; ab.pending = ab.pending[2:] {
		switch level, desc := ab.pending[0], ab.pending[1]; desc {
		case alertCloseNotify:
			return true, nil
		case alertUserCanceled:
			// Precedes a close_notify (RFC 8446 section 6.1); keep reading.
		default:
			return false, fmt.Errorf("%w %d (level %d)", errPeerAlert, desc, level)
		}
	}

	return false, nil
}

// ReadFrom lets net/http's response writer hand over the blob file: the TCP
// connection turns that into sendfile(2), and the kernel encrypts the pages
// on their way out. Anything written to this socket is plaintext the kernel
// encrypts, so every ReadFrom strategy the TCP connection picks is correct.
func (kc *kernelConn) ReadFrom(src io.Reader) (int64, error) {
	if rf, ok := kc.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}

	return io.Copy(struct{ io.Writer }{kc.Conn}, src)
}

// Close sends close_notify if it can, then closes the socket.
func (kc *kernelConn) Close() error {
	kc.closeOnce.Do(func() {
		kc.sendCloseNotify()
		kc.closeErr = kc.Conn.Close()
	})

	return kc.closeErr
}

// CloseWrite sends close_notify and shuts down the sending side (net/http
// uses it to flush a final response before closing).
func (kc *kernelConn) CloseWrite() error {
	halfCloser, ok := kc.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}

	kc.sendCloseNotify()

	return halfCloser.CloseWrite()
}

// sendCloseNotify writes a close_notify alert record. It makes a single
// non-blocking attempt: with a full send buffer it gives up rather than let
// Close wait on a client that stopped reading.
func (kc *kernelConn) sendCloseNotify() {
	kc.notifyOnce.Do(func() {
		oob := make([]byte, unix.CmsgSpace(1))
		hdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		hdr.Level = unix.SOL_TLS
		hdr.Type = cmsgSetRecordType
		hdr.SetLen(unix.CmsgLen(1))
		oob[unix.CmsgLen(0)] = contentAlert

		_ = kc.rawConn.Control(func(fd uintptr) {
			_ = unix.Sendmsg(int(fd), []byte{alertLevelWarning, alertCloseNotify}, oob, nil, unix.MSG_DONTWAIT)
		})
	})
}

// SyscallConn exposes the socket.
func (kc *kernelConn) SyscallConn() (syscall.RawConn, error) {
	return kc.rawConn, nil
}

// ConnectionState lets net/http fill in Request.TLS.
func (kc *kernelConn) ConnectionState() tls.ConnectionState {
	return kc.state
}

// NetConn returns the TCP connection, like (*tls.Conn).NetConn.
func (kc *kernelConn) NetConn() net.Conn {
	return kc.Conn
}
