package api

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-systemd/v22/activation"

	"zotregistry.dev/zot/v2/errors"
)

var systemdActivationListeners = activation.Listeners //nolint:gochecknoglobals // test hook for activation.Listeners

func (c *Controller) createListener(addr, port string) (net.Listener, string, error) {
	listener, activated, err := c.systemdListener()
	if err != nil {
		return nil, "", err
	}

	if activated {
		if err := validateActivatedPort(listener, port); err != nil {
			_ = listener.Close()

			return nil, "", err
		}

		if err := c.setChosenPort(listener, port, true); err != nil {
			_ = listener.Close()

			return nil, "", err
		}

		return listener, listener.Addr().String(), nil
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

// validateActivatedPort fails startup when http.port is set to a specific port
// and the systemd-activated listener is bound to a different one.
// Empty or "0" means "systemd owns the bind", so any port is accepted.
func validateActivatedPort(listener net.Listener, port string) error {
	if port == "" || port == "0" {
		return nil
	}

	configPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrSystemdActivationPortMismatch, err)
	}

	addr := listener.Addr()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		addrStr := ""
		network := ""
		if addr != nil {
			addrStr = addr.String()
			network = addr.Network()
		}

		return fmt.Errorf("%w: listener address %q, network %q",
			errors.ErrBadType, addrStr, network)
	}

	if tcpAddr.Port != configPort {
		return fmt.Errorf("%w: activated port %d, configured port %d",
			errors.ErrSystemdActivationPortMismatch, tcpAddr.Port, configPort)
	}

	return nil
}

func (c *Controller) systemdListener() (net.Listener, bool, error) {
	listeners, err := systemdActivationListeners()
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", errors.ErrFailedSystemdActivationListeners, err)
	}

	if len(listeners) == 0 {
		return nil, false, nil
	}

	if len(listeners) != 1 {
		closeListeners(listeners)

		return nil, false, fmt.Errorf("%w, got %d", errors.ErrExpectedOneSystemdListener, len(listeners))
	}

	listener := listeners[0]
	if listener == nil {
		return nil, false, errors.ErrSystemdListenerNotStream
	}

	addr := listener.Addr()
	if _, ok := addr.(*net.TCPAddr); !ok {
		addrStr := ""
		network := ""
		if addr != nil {
			addrStr = addr.String()
			network = addr.Network()
		}

		_ = listener.Close()

		return nil, false, fmt.Errorf("%w: listener address %q, network %q",
			errors.ErrBadType, addrStr, network)
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
