//go:build linux

package ktls

import "errors"

var (
	// errKeyUpdate ends connections whose client sends a post-handshake
	// message. The only one a client may send is KeyUpdate, and rekeying is not
	// implemented: it would cost key derivation plus syscalls per message, an
	// easy CPU lever for a hostile peer, for a feature clients rarely use.
	errKeyUpdate = errors.New("ktls: post-handshake message (KeyUpdate) not supported")

	errNoFileDescriptor = errors.New("ktls: connection does not expose a file descriptor")
	errUnexpectedRecord = errors.New("ktls: unexpected TLS record type")
	errTooManyControl   = errors.New("ktls: too many consecutive TLS control records")
	errTruncatedControl = errors.New("ktls: truncated TLS control message")
	errOversizedAlert   = errors.New("ktls: oversized TLS alert record")
	errPeerAlert        = errors.New("ktls: received TLS alert")
)
