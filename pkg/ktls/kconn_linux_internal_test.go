//go:build linux

package ktls

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestAlertBuffer(t *testing.T) {
	t.Run("close_notify split across records", func(t *testing.T) {
		var ab alertBuffer

		if closed, err := ab.push([]byte{alertLevelWarning}); closed || err != nil {
			t.Fatalf("half an alert: closed %v, err %v", closed, err)
		}

		if closed, err := ab.push([]byte{alertCloseNotify}); !closed || err != nil {
			t.Fatalf("close_notify: closed %v, err %v", closed, err)
		}
	})

	t.Run("user_canceled then close_notify in one record", func(t *testing.T) {
		var ab alertBuffer

		closed, err := ab.push([]byte{alertLevelWarning, alertUserCanceled, alertLevelWarning, alertCloseNotify})
		if !closed || err != nil {
			t.Fatalf("closed %v, err %v", closed, err)
		}
	})

	t.Run("fatal alert", func(t *testing.T) {
		var ab alertBuffer

		if _, err := ab.push([]byte{2, 40}); !errors.Is(err, errPeerAlert) { // handshake_failure
			t.Fatalf("err %v, want errPeerAlert", err)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		var ab alertBuffer

		if _, err := ab.push(make([]byte, 65)); !errors.Is(err, errOversizedAlert) {
			t.Fatalf("err %v, want errOversizedAlert", err)
		}
	})
}

// offloadedPair returns the server side of a kernel-offloaded connection and
// the userspace-TLS client talking to it. It skips without kTLS.
func offloadedPair(t *testing.T) (*kernelConn, *tls.Conn) {
	t.Helper()

	if !Available() {
		if os.Getenv("ZOT_KTLS_REQUIRE") == "1" {
			t.Fatal("ZOT_KTLS_REQUIRE=1 but kTLS is unavailable (is the tls module loaded?)")
		}

		t.Skip("kTLS unavailable: modprobe tls to run")
	}

	cert, pool := selfSigned(t)

	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	listener := NewListener(inner, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	t.Cleanup(func() { _ = listener.Close() })

	client, err := tls.Dial("tcp", inner.Addr().String(),
		&tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = client.Close() })

	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	kc, ok := conn.(*kernelConn)
	if !ok {
		t.Fatalf("connection not offloaded: %T", conn)
	}

	return kc, client
}

// TestConcurrentReads runs several Reads at once on one offloaded
// connection, which net.Conn allows. Each reader's buffer starts as 0xff,
// a byte the client never sends: if Reads shared receive state, a reader
// would be told about bytes the kernel put in another reader's buffer, and
// see 0xff where data should be (the race detector flags it as well).
func TestConcurrentReads(t *testing.T) {
	const (
		readers = 8
		total   = 1 << 20
	)

	server, client := offloadedPair(t)

	// A reader stuck after close_notify then fails with a timeout instead
	// of hanging the test binary.
	_ = server.SetReadDeadline(time.Now().Add(30 * time.Second))

	var (
		mu       sync.Mutex
		received int
		wg       sync.WaitGroup
	)

	errs := make(chan error, readers)

	for range readers {
		wg.Go(func() {
			buf := make([]byte, 4096)

			for {
				for i := range buf {
					buf[i] = 0xff
				}

				n, err := server.Read(buf)
				if bytes.IndexByte(buf[:n], 0xff) >= 0 {
					errs <- fmt.Errorf("read %d bytes, but the buffer holds bytes it was never given", n)

					return
				}

				mu.Lock()
				received += n
				mu.Unlock()

				if err != nil {
					if !errors.Is(err, io.EOF) {
						errs <- err
					}

					return
				}
			}
		})
	}

	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i % 251) // never 0xff
	}

	// Many small records, so readers keep contending for the socket.
	for off := 0; off < total; off += 1000 {
		if _, err := client.Write(payload[off:min(off+1000, total)]); err != nil {
			t.Fatal(err)
		}
	}

	_ = client.CloseWrite() // close_notify: every reader then gets io.EOF

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	if received != total {
		t.Fatalf("received %d bytes, want %d", received, total)
	}

	// EOF is sticky: a later Read returns it without touching the socket.
	if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after EOF: %v, want io.EOF", err)
	}
}
