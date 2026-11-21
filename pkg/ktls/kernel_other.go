//go:build !linux

package ktls

import (
	"crypto/tls"
	"errors"
	"net"
)

// Available reports whether this kernel supports kTLS; only Linux does.
func Available() bool {
	return false
}

func enableKernelTLS(net.Conn, tls.ConnectionState, []byte, []byte) (net.Conn, error) {
	return nil, errors.ErrUnsupported
}
