// Package ktls moves TLS 1.3 record encryption into the Linux kernel (kTLS)
// once crypto/tls has finished the handshake, so net/http's sendfile path for
// blob GETs also works over HTTPS. Connections that cannot be moved stay
// ordinary *tls.Conn connections.
package ktls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"syscall"
	"time"
)

const defaultHandshakeTimeout = 10 * time.Second

// Offload outcomes passed to the Observer.
const (
	ReasonOffloaded      = "offloaded"       // kTLS active
	ReasonHandshakeError = "handshake-error" // handshake failed, connection closed
	ReasonPanic          = "panic"           // handshake goroutine panicked, connection closed
	ReasonTLSVersion     = "tls-version"     // not TLS 1.3
	ReasonALPN           = "alpn"            // h2 negotiated; net/http serves it on the *tls.Conn
	ReasonClientAuth     = "client-auth"     // client certificates requested
	ReasonCipher         = "cipher"          // cipher suite the kernel cannot take
	ReasonFraming        = "framing"         // records not laid out as expected
	ReasonSecrets        = "secrets"         // traffic secrets missing or unusable
	ReasonKernel         = "kernel"          // no kTLS in this kernel (tls module not loaded, or not Linux)
	ReasonSetsockopt     = "setsockopt"      // kernel refused the keys before TX was installed
	ReasonConnUnusable   = "conn-unusable"   // TX installed but RX refused, connection closed
)

// Observer receives every accepted connection's outcome. It is called from
// handshake goroutines, so it must be safe for concurrent use.
type Observer func(reason string, remoteAddr net.Addr, state tls.ConnectionState, err error)

// Option configures a Listener.
type Option func(*Listener)

// WithHandshakeTimeout bounds each handshake (default 10s).
func WithHandshakeTimeout(timeout time.Duration) Option {
	return func(l *Listener) { l.handshakeTimeout = timeout }
}

// WithObserver sets the outcome callback.
func WithObserver(observer Observer) Option {
	return func(l *Listener) { l.observer = observer }
}

// Listener is a net.Listener whose Accept returns connections that already
// completed the TLS handshake: kernel-offloaded ones where possible, *tls.Conn
// otherwise. Handshakes run on their own goroutines, so a slow client never
// holds up Accept.
type Listener struct {
	net.Listener // the TCP listener; provides Addr

	base             *tls.Config
	handshakeTimeout time.Duration
	observer         Observer
	kernelAvailable  func() bool

	// testHookDecided sees each decision with the TX sequence worked out for
	// it, just before the observer. Tests only.
	testHookDecided func(remoteAddr net.Addr, reason string, txSeq uint64)

	// Unbuffered, so no established connection is left behind on Close.
	ready  chan net.Conn
	failed chan error
	quit   chan struct{}

	// handshakeCtx parents every in-flight handshake and is cancelled by
	// Close. The connections it covers have not reached Accept's caller, so
	// net/http's Shutdown cannot see or close them; without this, a client
	// that connects and never sends a ClientHello would hold its socket and
	// goroutine until the handshake timeout, after Shutdown has returned.
	handshakeCtx    context.Context //nolint:containedctx // listener-lifetime cancellation, not a request context
	cancelHandshake context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

// NewListener wraps inner. cfg must provide a certificate; it is cloned, so
// later changes to it have no effect (callbacks such as GetCertificate are
// kept, so certificate reloading still works).
func NewListener(inner net.Listener, cfg *tls.Config, opts ...Option) *Listener {
	listener := &Listener{
		Listener:         inner,
		base:             cfg.Clone(),
		handshakeTimeout: defaultHandshakeTimeout,
		kernelAvailable:  Available,
		ready:            make(chan net.Conn),
		failed:           make(chan error),
		quit:             make(chan struct{}),
	}

	listener.handshakeCtx, listener.cancelHandshake = context.WithCancel(context.Background())

	for _, opt := range opts {
		opt(listener)
	}

	go listener.acceptTCP()

	return listener
}

// Accept returns the next established connection. Failed handshakes are
// reported to the observer only.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case err := <-l.failed:
		return nil, err
	case <-l.quit:
		return nil, net.ErrClosed
	}
}

// Close stops accepting and cancels handshakes in flight, which closes
// their sockets. Connections already returned by Accept stay open: they
// belong to the caller (net/http closes them on Shutdown).
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.quit)
		// Interrupts HandshakeContext, which closes the connection. A
		// handshake that already finished is caught by establish's select
		// on quit instead, so nothing established is leaked either way.
		l.cancelHandshake()
		l.closeErr = l.Listener.Close()
	})

	return l.closeErr
}

func (l *Listener) acceptTCP() {
	for {
		raw, err := l.Listener.Accept()
		if err == nil {
			go l.establish(raw)

			continue
		}

		select {
		case l.failed <- err:
		case <-l.quit:
			return
		}

		// net/http's Serve retries only on running out of file descriptors and
		// returns on anything else; match it so this goroutine does not outlive it.
		if !errors.Is(err, syscall.EMFILE) && !errors.Is(err, syscall.ENFILE) {
			_ = l.Close()

			return
		}
	}
}

// establish completes one connection and queues it for Accept.
func (l *Listener) establish(raw net.Conn) {
	// The handshake parses untrusted input outside net/http's per-connection
	// recover; a panic here must cost one connection, not the process.
	defer func() {
		if r := recover(); r != nil {
			l.report(ReasonPanic, raw, tls.ConnectionState{},
				fmt.Errorf("%w: %v\n%s", errHandshakePanic, r, debug.Stack()))

			_ = raw.Close()
		}
	}()

	conn, err := l.secure(raw)
	if err != nil {
		_ = raw.Close()

		return
	}

	select {
	case l.ready <- conn:
	case <-l.quit:
		_ = conn.Close()
	}
}

// secure runs the handshake and returns the connection to serve. An error
// means the connection is to be closed.
func (l *Listener) secure(raw net.Conn) (net.Conn, error) {
	hconn := newHandshakeConn(raw)
	collector := &secretCollector{}
	tlsConn := tls.Server(hconn, l.configFor(collector))

	// Bounded by the timeout and cut short by Close (see handshakeCtx).
	ctx, cancel := context.WithTimeout(l.handshakeCtx, l.handshakeTimeout)
	err := tlsConn.HandshakeContext(ctx)

	cancel()

	if err != nil {
		answerPlainHTTP(raw, err)
		l.report(ReasonHandshakeError, raw, tls.ConnectionState{}, err)

		return nil, err
	}

	state := tlsConn.ConnectionState()
	plan := l.plan(state, hconn, collector)

	if l.testHookDecided != nil {
		l.testHookDecided(raw.RemoteAddr(), plan.reason, plan.txSeq)
	}

	if plan.reason != "" {
		hconn.detach()
		l.report(plan.reason, raw, state, plan.err)

		return tlsConn, nil
	}

	// From here the kernel drives raw directly; tlsConn and hconn are
	// abandoned and must not touch the socket again.
	kconn, err := enableKernelTLS(raw, state, plan.txInfo, plan.rxInfo)

	switch {
	case err == nil:
		l.report(ReasonOffloaded, raw, state, nil)

		return kconn, nil
	case errors.Is(err, errConnUnusable):
		l.report(ReasonConnUnusable, raw, state, err)

		return nil, err
	default:
		// Nothing installed: the socket is still plain TCP under tlsConn.
		hconn.detach()
		l.report(ReasonSetsockopt, raw, state, err)

		return tlsConn, nil
	}
}

// configFor clones the base config for one handshake, so the key log goes to
// that connection's collector.
func (l *Listener) configFor(collector *secretCollector) *tls.Config {
	cfg := l.base.Clone()
	cfg.KeyLogWriter = collector

	// A Config generates its session ticket keys on first use, so tickets from
	// one clone would not decrypt on the next. Seal and open them with the
	// base config, which then owns the shared (and rotated) ticket keys.
	if !cfg.SessionTicketsDisabled && cfg.WrapSession == nil && cfg.UnwrapSession == nil {
		cfg.WrapSession = l.base.EncryptTicket
		cfg.UnwrapSession = l.base.DecryptTicket
	}

	return cfg
}

// offloadPlan is the decision for one connection: a reason to stay in
// userspace TLS, or the kernel crypto_info for both directions.
type offloadPlan struct {
	reason string
	err    error

	txInfo, rxInfo []byte
	txSeq          uint64
}

func (l *Listener) plan(state tls.ConnectionState, hconn *handshakeConn, collector *secretCollector) offloadPlan {
	// net/http serves h2 itself, and sendfile does not apply to h2 frames.
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return offloadPlan{reason: ReasonALPN}
	}

	// A client Certificate flight adds encrypted client records the framing
	// check below does not account for.
	if l.base.ClientAuth != tls.NoClientCert {
		return offloadPlan{reason: ReasonClientAuth}
	}

	if state.Version != tls.VersionTLS13 {
		return offloadPlan{reason: ReasonTLSVersion}
	}

	spec, ok := lookupSuite(state.CipherSuite)
	if !ok {
		return offloadPlan{reason: ReasonCipher}
	}

	// The client's only encrypted handshake record is its Finished. It must
	// have been read whole, with nothing of a later record consumed, so the
	// kernel's RX sequence starts at 0 on the next record in the socket.
	if !hconn.in.idle() || hconn.in.appData != 1 {
		return offloadPlan{reason: ReasonFraming}
	}

	secrets, err := collector.secrets()
	if err != nil {
		return offloadPlan{reason: ReasonSecrets, err: err}
	}

	txSeq, err := nextServerSeq(spec, secrets, hconn.out.lastAppData, hconn.out.appData)
	if err != nil {
		return offloadPlan{reason: ReasonFraming, err: err}
	}

	txInfo, err := kernelCryptoInfo(spec, secrets.serverApp, txSeq)
	if err != nil {
		return offloadPlan{reason: ReasonSecrets, err: err}
	}

	rxInfo, err := kernelCryptoInfo(spec, secrets.clientApp, 0)
	if err != nil {
		return offloadPlan{reason: ReasonSecrets, err: err}
	}

	// Checked last on purpose: the derivation above still runs, and can be
	// tested through txSeq, on machines without kTLS.
	if !l.kernelAvailable() {
		return offloadPlan{reason: ReasonKernel, txSeq: txSeq}
	}

	return offloadPlan{txInfo: txInfo, rxInfo: rxInfo, txSeq: txSeq}
}

func (l *Listener) report(reason string, raw net.Conn, state tls.ConnectionState, err error) {
	if l.observer != nil {
		l.observer(reason, raw.RemoteAddr(), state, err)
	}
}

// Plain-HTTP-on-the-TLS-port handling.
const (
	plainHTTPDrainTimeout = 500 * time.Millisecond
	plainHTTPDrainLimit   = 256 << 10
)

// answerPlainHTTP keeps net/http's reply to a client that sends plain HTTP to
// the HTTPS port. net/http cannot give it any more, because the handshake now
// happens here.
func answerPlainHTTP(raw net.Conn, err error) {
	var headerErr tls.RecordHeaderError
	if !errors.As(err, &headerErr) || headerErr.Conn == nil || !looksLikeHTTP(headerErr.RecordHeader) {
		return
	}

	_, _ = io.WriteString(raw, "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")

	// Only the first five bytes of the request were read. Closing with unread
	// input makes the kernel send RST, which can discard the 400 before the
	// client reads it, so half-close and drain for a moment first.
	if cw, ok := raw.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		_ = raw.SetReadDeadline(time.Now().Add(plainHTTPDrainTimeout))
		_, _ = io.Copy(io.Discard, io.LimitReader(raw, plainHTTPDrainLimit))
	}
}

// looksLikeHTTP matches the request prefixes net/http recognises.
func looksLikeHTTP(header [5]byte) bool {
	switch string(header[:]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	default:
		return false
	}
}
