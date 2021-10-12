// +build minimal

package api

import (
	"github.com/anuvu/zot/pkg/log"
)

type Controller struct {
	Config *Config
	Log    log.Logger
}

func NewController(cfg *Config) *Controller {
	logger := log.NewLogger(cfg.ZotExporter.Log.Level, cfg.ZotExporter.Log.Output)
	return &Controller{Config: cfg, Log: logger}
}

func (c *Controller) Run() {
	runZotExporter(c)
}
