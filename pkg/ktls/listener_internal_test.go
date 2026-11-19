package ktls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const blobSize = 8<<20 + 12345 // a few sendfile chunks, not a multiple of the record size

// decision is one connection's outcome as seen by the observer and test hook.
type decision struct {
	reason string
	txSeq  uint64
	err    error
}

type harness struct {
	t        *testing.T
	url      string
	pool     *x509.CertPool
	blob     []byte
	mu       sync.Mutex
	outcomes []decision
}

// newHarness serves a blob over HTTPS through a ktls Listener. kernel decides
// whether the real kernel check runs (true) or is forced unavailable (false).
func newHarness(t *testing.T, kernel bool, mutate func(*tls.Config)) *harness {
	t.Helper()

	cert, pool := selfSigned(t)
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	if mutate != nil {
		mutate(serverCfg)
	}

	blob := make([]byte, blobSize)
	_, _ = rand.Read(blob)

	blobPath := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	hrn := &harness{t: t, pool: pool, blob: blob}

	var pending sync.Map // remote addr -> txSeq from the test hook

	opts := []Option{
		WithObserver(func(reason string, remote net.Addr, _ tls.ConnectionState, err error) {
			seq, _ := pending.LoadAndDelete(remote.String())
			txSeq, _ := seq.(uint64)

			hrn.mu.Lock()
			hrn.outcomes = append(hrn.outcomes, decision{reason: reason, txSeq: txSeq, err: err})
			hrn.mu.Unlock()
		}),
		func(l *Listener) {
			// Runs on the handshake goroutine just before the observer.
			l.testHookDecided = func(remote net.Addr, _ string, txSeq uint64) {
				pending.Store(remote.String(), txSeq)
			}
		},
	}

	if !kernel {
		opts = append(opts, func(l *Listener) { l.kernelAvailable = func() bool { return false } })
	}

	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	listener := NewListener(inner, serverCfg, opts...)

	mux := http.NewServeMux()
	mux.HandleFunc("/blob", func(w http.ResponseWriter, r *http.Request) {
		blobFile, err := os.Open(blobPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}
		defer blobFile.Close()

		// ServeContent copies the *os.File through response.ReadFrom, which is the
		// sendfile path zot's blob GETs take.
		http.ServeContent(w, r, "blob", time.Time{}, blobFile)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	})

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, TLSConfig: serverCfg}
	go func() { _ = server.Serve(listener) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = server.Shutdown(ctx)
	})

	hrn.url = "https://" + inner.Addr().String()

	return hrn
}

func (h *harness) client(mutate func(*tls.Config), forceH2 bool) *http.Client {
	cfg := &tls.Config{RootCAs: h.pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	if mutate != nil {
		mutate(cfg)
	}

	transport := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: forceH2, DisableKeepAlives: false}
	h.t.Cleanup(transport.CloseIdleConnections)

	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func (h *harness) outcome() decision {
	h.t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		if len(h.outcomes) > 0 {
			out := h.outcomes[0]
			h.outcomes = h.outcomes[1:]
			h.mu.Unlock()

			return out
		}
		h.mu.Unlock()

		time.Sleep(5 * time.Millisecond)
	}

	h.t.Fatal("no offload outcome reported")

	return decision{}
}

// exercise checks a whole-blob GET, a range GET and a request body on one
// keep-alive connection, so both kernel TX (sendfile and writes) and RX are used.
func (h *harness) exercise(client *http.Client) {
	h.t.Helper()

	req, _ := http.NewRequestWithContext(h.t.Context(), http.MethodGet, h.url+"/blob", nil)

	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}

	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		h.t.Fatal(err)
	}

	if !bytes.Equal(got, h.blob) {
		h.t.Fatalf("whole blob mismatch: got %d bytes sha256 %x, want %d bytes sha256 %x",
			len(got), sha256.Sum256(got), len(h.blob), sha256.Sum256(h.blob))
	}

	const rangeStart, rangeEnd = 1<<20 + 7, 5<<20 + 3

	req, _ = http.NewRequestWithContext(h.t.Context(), http.MethodGet, h.url+"/blob", nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd))

	resp, err = client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}

	got, err = io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil || resp.StatusCode != http.StatusPartialContent || !bytes.Equal(got, h.blob[rangeStart:rangeEnd+1]) {
		h.t.Fatalf("range GET: status %d, %d bytes, err %v", resp.StatusCode, len(got), err)
	}

	payload := strings.Repeat("zot-ktls-", 100000)

	req, _ = http.NewRequestWithContext(h.t.Context(), http.MethodPost, h.url+"/echo", strings.NewReader(payload))
	req.Header.Set("Content-Type", "text/plain")

	resp, err = client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}

	got, err = io.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil || string(got) != payload {
		h.t.Fatalf("echo: %d bytes, err %v", len(got), err)
	}
}

type tlsCase struct {
	name       string
	server     func(*tls.Config)
	client     func(*tls.Config)
	forceH2    bool
	wantReason string // with a kernel: ReasonOffloaded replaces ReasonKernel
	wantSeq    uint64
}

var tlsCases = []tlsCase{ //nolint:gochecknoglobals // shared by TestFallback and TestOffload
	{
		// Go registry clients (docker, containerd, oras) have no session cache.
		name:       "tls13-no-ticket",
		wantReason: ReasonKernel,
		wantSeq:    0,
	},
	{
		name:       "tls13-with-ticket",
		client:     func(c *tls.Config) { c.ClientSessionCache = tls.NewLRUClientSessionCache(4) },
		wantReason: ReasonKernel,
		wantSeq:    1,
	},
	{
		name:       "tls13-tickets-disabled",
		server:     func(c *tls.Config) { c.SessionTicketsDisabled = true },
		client:     func(c *tls.Config) { c.ClientSessionCache = tls.NewLRUClientSessionCache(4) },
		wantReason: ReasonKernel,
		wantSeq:    0,
	},
	{
		name:       "tls12",
		client:     func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 },
		wantReason: ReasonTLSVersion,
	},
	{
		name:       "h2",
		forceH2:    true,
		wantReason: ReasonALPN,
	},
	{
		name:       "client-auth",
		server:     func(c *tls.Config) { c.ClientAuth = tls.VerifyClientCertIfGiven },
		wantReason: ReasonClientAuth,
	},
}

func runCases(t *testing.T, kernel bool) {
	t.Helper()

	for _, tcase := range tlsCases {
		t.Run(tcase.name, func(t *testing.T) {
			hrn := newHarness(t, kernel, tcase.server)
			hrn.exercise(hrn.client(tcase.client, tcase.forceH2))

			out := hrn.outcome()

			want := tcase.wantReason
			if kernel && want == ReasonKernel {
				want = ReasonOffloaded
			}

			if out.reason != want {
				t.Fatalf("reason %q (err %v), want %q", out.reason, out.err, want)
			}

			if tcase.wantReason == ReasonKernel && out.txSeq != tcase.wantSeq {
				t.Fatalf("tx sequence %d, want %d", out.txSeq, tcase.wantSeq)
			}
		})
	}
}

// TestFallback runs every case with kTLS forced unavailable: connections must
// work through userspace TLS, and offloadable ones must still have had their
// keys and TX sequence derived (ReasonKernel is only reported after that).
func TestFallback(t *testing.T) {
	runCases(t, false)
}

// TestOffload runs the same cases against the real kernel. It skips when the
// tls module is not loaded, unless ZOT_KTLS_REQUIRE=1 (set in the CI job that
// loads it), so a broken probe cannot turn the job green by skipping.
func TestOffload(t *testing.T) {
	if !Available() {
		if os.Getenv("ZOT_KTLS_REQUIRE") == "1" {
			t.Fatal("ZOT_KTLS_REQUIRE=1 but kTLS is unavailable (is the tls module loaded?)")
		}

		t.Skip("kTLS unavailable: modprobe tls to run")
	}

	runCases(t, true)
}

// TestTicketResumption checks that tickets issued on one connection's config
// clone resume on the next one (WrapSession/UnwrapSession route through the
// shared base config).
func TestTicketResumption(t *testing.T) {
	hrn := newHarness(t, false, nil)
	cache := tls.NewLRUClientSessionCache(4)

	for i := range 2 {
		cfg := &tls.Config{RootCAs: hrn.pool, ServerName: "localhost", ClientSessionCache: cache}

		dialer := &tls.Dialer{Config: cfg}

		conn, err := dialer.DialContext(t.Context(), "tcp", strings.TrimPrefix(hrn.url, "https://"))
		if err != nil {
			t.Fatal(err)
		}

		// TLS 1.3 tickets arrive after the handshake; a round trip reads them.
		_, _ = conn.Write([]byte("GET /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		_, _ = io.ReadAll(conn)

		if resumed := conn.(*tls.Conn).ConnectionState().DidResume; resumed != (i == 1) {
			t.Fatalf("connection %d: DidResume=%v", i, resumed)
		}

		conn.Close()
		hrn.outcome()
	}
}

// TestPlainHTTPGets400 keeps net/http's reply to plain HTTP on an HTTPS port.
func TestPlainHTTPGets400(t *testing.T) {
	hrn := newHarness(t, false, nil)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+strings.TrimPrefix(hrn.url, "https://")+"/echo", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", resp.StatusCode)
	}

	if out := hrn.outcome(); out.reason != ReasonHandshakeError {
		t.Fatalf("reason %q, want %q", out.reason, ReasonHandshakeError)
	}
}

func TestNextServerSeqRejectsGarbage(t *testing.T) {
	spec, _ := lookupSuite(tls.TLS_AES_128_GCM_SHA256)
	secrets := sessionSecrets{
		serverHandshake: bytes.Repeat([]byte{1}, 32),
		serverApp:       bytes.Repeat([]byte{2}, 32),
		clientApp:       bytes.Repeat([]byte{3}, 32),
	}

	record := append([]byte{contentAppData, 3, 3, 0, 32}, bytes.Repeat([]byte{9}, 32)...)

	if _, err := nextServerSeq(spec, secrets, record, 3); err == nil {
		t.Fatal("garbage record accepted")
	}

	if _, err := nextServerSeq(spec, secrets, nil, 0); err == nil {
		t.Fatal("missing record accepted")
	}
}

// TestKernelCryptoInfoLayout pins the sizes of the kernel's
// tls12_crypto_info_* structs and the big-endian rec_seq at their end.
func TestKernelCryptoInfoLayout(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)

	for suite, size := range map[uint16]int{
		tls.TLS_AES_128_GCM_SHA256:       40,
		tls.TLS_AES_256_GCM_SHA384:       56,
		tls.TLS_CHACHA20_POLY1305_SHA256: 56,
	} {
		spec, ok := lookupSuite(suite)
		if !ok {
			t.Fatalf("suite %#x not supported", suite)
		}

		info, err := kernelCryptoInfo(spec, secret, 0x0102030405060708)
		if err != nil {
			t.Fatal(err)
		}

		if len(info) != size {
			t.Fatalf("suite %#x: %d bytes, want %d", suite, len(info), size)
		}

		if !bytes.HasSuffix(info, []byte{1, 2, 3, 4, 5, 6, 7, 8}) {
			t.Fatalf("suite %#x: rec_seq not big-endian at the end: %x", suite, info)
		}
	}
}

// TestRecordScanner feeds the same stream whole and one byte at a time: the
// counts, the captured last record and the read limits must not depend on
// how the bytes arrive.
func TestRecordScanner(t *testing.T) {
	record := func(typ byte, body string) []byte {
		return append([]byte{typ, 3, 3, 0, byte(len(body))}, body...)
	}

	var stream []byte
	stream = append(stream, record(contentHandshake, "hello")...)
	stream = append(stream, record(contentAppData, "")...) // empty body
	stream = append(stream, record(contentAppData, "first")...)
	stream = append(stream, record(20, "x")...) // change_cipher_spec
	stream = append(stream, record(contentAppData, "last")...)

	check := func(t *testing.T, scanner *recordScanner) {
		t.Helper()

		if !scanner.idle() || scanner.appData != 3 {
			t.Fatalf("idle %v, appData %d; want idle, 3", scanner.idle(), scanner.appData)
		}

		if want := record(contentAppData, "last"); !bytes.Equal(scanner.lastAppData, want) {
			t.Fatalf("last record %x, want %x", scanner.lastAppData, want)
		}
	}

	t.Run("whole", func(t *testing.T) {
		scanner := &recordScanner{capture: true}
		scanner.feed(stream)
		check(t, scanner)
	})

	t.Run("byte-by-byte", func(t *testing.T) {
		scanner := &recordScanner{capture: true}
		for i := range stream {
			if scanner.limit() < 1 {
				t.Fatalf("limit %d at offset %d", scanner.limit(), i)
			}

			scanner.feed(stream[i : i+1])
		}

		check(t, scanner)
	})
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// TestCloseCancelsHandshakes connects without sending a ClientHello, then
// closes the listener: the pending handshake must end (and its socket be
// closed) right away, not when the handshake timeout fires. net/http never
// saw that connection, so Server.Shutdown could not close it.
func TestCloseCancelsHandshakes(t *testing.T) {
	cert, _ := selfSigned(t)

	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	reasons := make(chan string, 1)
	listener := NewListener(inner, &tls.Config{Certificates: []tls.Certificate{cert}},
		WithHandshakeTimeout(time.Minute),
		WithObserver(func(reason string, _ net.Addr, _ tls.ConnectionState, _ error) { reasons <- reason }))

	silent, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	time.Sleep(100 * time.Millisecond) // let the handshake goroutine start waiting

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case reason := <-reasons:
		if reason != ReasonHandshakeError {
			t.Fatalf("reason %q, want %q", reason, ReasonHandshakeError)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handshake still pending after Close")
	}

	// The server closed its end, so the client reads EOF (or a reset).
	_ = silent.SetReadDeadline(time.Now().Add(5 * time.Second))

	if _, err := silent.Read(make([]byte, 1)); err == nil || os.IsTimeout(err) {
		t.Fatalf("client socket still open after Close: %v", err)
	}
}
