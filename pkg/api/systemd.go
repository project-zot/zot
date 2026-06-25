package api

import "github.com/coreos/go-systemd/v22/daemon"

var systemdNotify = daemon.SdNotify

func (c *Controller) markReady() {
	c.Healthz.Ready()
	c.notifySystemdReady()
}

func (c *Controller) notifySystemdReady() {
	sent, err := systemdNotify(false, daemon.SdNotifyReady)
	if err != nil {
		c.Log.Warn().Err(err).Msg("failed to notify systemd readiness")

		return
	}

	if sent {
		c.Log.Debug().Msg("notified systemd readiness")
	}
}
