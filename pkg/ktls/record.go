package ktls

import (
	"encoding/binary"
	"net"
)

// TLS record layer (RFC 8446 section 5.1): a 5-byte header (content type,
// legacy version, big-endian length) followed by the body.
const (
	recordHeaderLen = 5

	contentAlert     = 21
	contentHandshake = 22
	contentAppData   = 23
)

// recordScanner follows record boundaries in a byte stream that arrives in
// arbitrary chunks. In TLS 1.3 every encrypted record carries the outer type
// application_data, so counting those counts encrypted records.
type recordScanner struct {
	header    [recordHeaderLen]byte
	filled    int  // header bytes of the record in progress
	inBody    bool // header complete, body bytes pending
	remaining int  // body bytes still to come

	appData int // completed application_data records

	// capture keeps a copy of each application_data record, header included,
	// so lastAppData is the most recent complete one.
	capture     bool
	current     []byte
	lastAppData []byte
}

// limit is how many more bytes belong to the current header or body.
func (s *recordScanner) limit() int {
	if s.inBody {
		return s.remaining
	}

	return recordHeaderLen - s.filled
}

// idle reports whether the stream sits between two records.
func (s *recordScanner) idle() bool {
	return !s.inBody && s.filled == 0
}

func (s *recordScanner) feed(data []byte) {
	for len(data) > 0 {
		if s.inBody {
			n := min(len(data), s.remaining)
			if s.current != nil {
				s.current = append(s.current, data[:n]...)
			}

			s.remaining -= n
			data = data[n:]
		} else {
			n := copy(s.header[s.filled:], data)
			s.filled += n
			data = data[n:]

			if s.filled < recordHeaderLen {
				return
			}

			s.filled, s.inBody = 0, true
			s.remaining = int(binary.BigEndian.Uint16(s.header[3:]))

			if s.capture && s.header[0] == contentAppData {
				s.current = append(make([]byte, 0, recordHeaderLen+s.remaining), s.header[:]...)
			}
		}

		// Also reached right after a header that announces an empty body.
		if s.inBody && s.remaining == 0 {
			s.finish()
		}
	}
}

func (s *recordScanner) finish() {
	s.inBody = false

	if s.header[0] == contentAppData {
		s.appData++

		if s.capture {
			s.lastAppData = s.current
		}
	}

	s.current = nil
}

// handshakeConn sits between crypto/tls and the TCP socket during the
// handshake.
//
// Reads never cross a record boundary: crypto/tls consumes exactly the records
// it processes, and whatever the client sends after its Finished stays queued
// in the socket, where the kernel decrypts it starting at sequence 0.
//
// Writes are watched so the last encrypted server record can be examined to
// find the kernel's starting TX sequence (see nextServerSeq).
//
// Only the handshake goroutine uses it until detach or offload.
type handshakeConn struct {
	net.Conn

	in, out     recordScanner
	passthrough bool
}

func newHandshakeConn(conn net.Conn) *handshakeConn {
	hc := &handshakeConn{Conn: conn}
	hc.out.capture = true

	return hc
}

func (hc *handshakeConn) Read(buf []byte) (int, error) {
	if hc.passthrough {
		return hc.Conn.Read(buf)
	}

	if lim := hc.in.limit(); len(buf) > lim {
		buf = buf[:lim]
	}

	n, err := hc.Conn.Read(buf)
	hc.in.feed(buf[:n])

	return n, err
}

func (hc *handshakeConn) Write(buf []byte) (int, error) {
	if !hc.passthrough {
		hc.out.feed(buf)
	}

	return hc.Conn.Write(buf)
}

// detach stops all tracking; the connection stays in userspace TLS for good,
// so record-sized reads and record copies would only cost throughput.
func (hc *handshakeConn) detach() {
	hc.passthrough = true
	hc.out = recordScanner{}
}

// NetConn returns the TCP connection, like (*tls.Conn).NetConn.
func (hc *handshakeConn) NetConn() net.Conn {
	return hc.Conn
}
