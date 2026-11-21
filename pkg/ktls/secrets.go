package ktls

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Key log labels crypto/tls uses for TLS 1.3 (NSS key log format).
const (
	keyLogServerHandshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogServerApp       = "SERVER_TRAFFIC_SECRET_0"
	keyLogClientApp       = "CLIENT_TRAFFIC_SECRET_0"
)

// sessionSecrets are the TLS 1.3 traffic secrets needed to move a session into
// the kernel.
type sessionSecrets struct {
	serverHandshake []byte // only to recognise the server's handshake records
	serverApp       []byte // kernel TX
	clientApp       []byte // kernel RX
}

// secretCollector is one connection's tls.Config.KeyLogWriter. crypto/tls
// formats each secret as a complete line and hands it over in a single Write.
type secretCollector struct {
	got sessionSecrets
	err error
}

func (sc *secretCollector) Write(line []byte) (int, error) {
	// "<label> <client random, hex> <secret, hex>"
	fields := strings.Fields(string(line))
	if len(fields) != 3 { //nolint:mnd // three fields per key log line
		return len(line), nil
	}

	var dst *[]byte

	switch fields[0] {
	case keyLogServerHandshake:
		dst = &sc.got.serverHandshake
	case keyLogServerApp:
		dst = &sc.got.serverApp
	case keyLogClientApp:
		dst = &sc.got.clientApp
	default:
		return len(line), nil
	}

	secret, err := hex.DecodeString(fields[2])
	if err != nil && sc.err == nil {
		sc.err = fmt.Errorf("%w: %s: %w", errSecretMalformed, fields[0], err)
	}

	*dst = secret

	// Never fail the handshake over the key log; a missing secret only keeps
	// the connection in userspace TLS.
	return len(line), nil
}

// secrets returns the collected secrets, or why they are unusable.
func (sc *secretCollector) secrets() (sessionSecrets, error) {
	if sc.err != nil {
		return sessionSecrets{}, sc.err
	}

	for label, secret := range map[string][]byte{
		keyLogServerHandshake: sc.got.serverHandshake,
		keyLogServerApp:       sc.got.serverApp,
		keyLogClientApp:       sc.got.clientApp,
	} {
		if len(secret) == 0 {
			return sessionSecrets{}, fmt.Errorf("%w: %s", errSecretMissing, label)
		}
	}

	return sc.got, nil
}
