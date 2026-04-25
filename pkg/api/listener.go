package api

import (
	"fmt"
	"net"

	"github.com/coreos/go-systemd/v22/activation"

	"zotregistry.dev/zot/v2/errors"
)

var systemdActivationListeners = activation.Listeners

func (c *Controller) createListener(addr, port string) (net.Listener, string, error) {
	listener, activated, err := c.systemdListener()
	if err != nil {
		return nil, "", err
	}

	if activated {
		return listener, listener.Addr().String(), c.setChosenPort(listener, port, true)
	}

	listener, err = net.Listen("tcp", addr) //nolint: noctx
	if err != nil {
		return nil, "", err
	}

	if err := c.setChosenPort(listener, port, false); err != nil {
		_ = listener.Close()

		return nil, "", err
	}

	return listener, addr, nil
}

func (c *Controller) systemdListener() (net.Listener, bool, error) {
	listeners, err := systemdActivationListeners()
	if err != nil {
		return nil, false, fmt.Errorf("failed to get systemd socket activation listeners: %w", err)
	}

	if len(listeners) == 0 {
		return nil, false, nil
	}

	if len(listeners) != 1 {
		closeListeners(listeners)

		return nil, false, fmt.Errorf("expected exactly one systemd socket activation listener, got %d", len(listeners))
	}

	listener := listeners[0]
	if listener == nil {
		return nil, false, fmt.Errorf("systemd socket activation listener is not a stream listener")
	}

	if _, ok := listener.Addr().(*net.TCPAddr); !ok {
		_ = listener.Close()
		c.Log.Error().Str("addr", listener.Addr().String()).Msg("systemd socket activation listener is not TCP")

		return nil, false, errors.ErrBadType
	}

	return listener, true, nil
}

func (c *Controller) setChosenPort(listener net.Listener, port string, systemd bool) error {
	chosenAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		c.Log.Error().Str("port", port).Msg("invalid addr type")

		return errors.ErrBadType
	}

	c.chosenPort.Store(int64(chosenAddr.Port))

	if systemd {
		c.Log.Info().Int("port", chosenAddr.Port).IPAddr("address", chosenAddr.IP).
			Msg("using systemd socket activation listener")
	} else if port == "0" || port == "" {
		c.Log.Info().Int("port", chosenAddr.Port).IPAddr("address", chosenAddr.IP).Msg(
			"port is unspecified, listening on kernel chosen port",
		)
	}

	return nil
}

func closeListeners(listeners []net.Listener) {
	for _, listener := range listeners {
		if listener != nil {
			_ = listener.Close()
		}
	}
}
