package ktls

import "errors"

// Static errors; call sites wrap them with details. Linux-only ones are in
// errors_linux.go.
var (
	errConnUnusable      = errors.New("ktls: connection unusable after partial offload")
	errNoHandshakeRecord = errors.New("ktls: no encrypted server record seen during the handshake")
	errTXSeqUnknown      = errors.New("ktls: last server record matches neither traffic key")
	errSecretMissing     = errors.New("ktls: traffic secret not in key log")
	errSecretMalformed   = errors.New("ktls: malformed key log line")
	errHandshakePanic    = errors.New("ktls: panic during handshake")
)
