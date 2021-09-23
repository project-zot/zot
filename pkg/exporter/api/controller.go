// +build minimal

package api

import (
	"github.com/anuvu/zot/pkg/log"
)

type Controller struct {
	config *Config
	log    log.Logger
}

func NewController(cfg *Config) *Controller {
	logger := log.NewLogger(cfg.ZotExporter.Log.Level, cfg.ZotExporter.Log.Output)
	return &Controller{config: cfg, log: logger}
}

func (c *Controller) Run() {
	runZotExporter(c)
}
