package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/anuvu/zot/pkg/storage"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

type Controller struct {
	Config     *Config
	Router     *gin.Engine
	ImageStore *storage.ImageStore
	Log        zerolog.Logger
	Server     *http.Server
}

func NewController(config *Config) *Controller {
	return &Controller{Config: config, Log: NewLogger(config)}
}

func (c *Controller) Run() error {
	if c.Config.Log.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	engine := gin.New()
	engine.Use(gin.Recovery(), Logger(c.Log))
	c.Router = engine
	_ = NewRouteHandler(c)

	c.Log.Info().Interface("params", c.Config).Msg("configuration settings")
	c.ImageStore = storage.NewImageStore(c.Config.Storage.RootDirectory, c.Log)

	addr := fmt.Sprintf("%s:%s", c.Config.HTTP.Address, c.Config.HTTP.Port)
	server := &http.Server{Addr: addr, Handler: c.Router}
	c.Server = server

	// Create the listener
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if c.Config.HTTP.TLS.Key != "" && c.Config.HTTP.TLS.Cert != "" {
		if c.Config.HTTP.TLS.CACert != "" {
			caCert, err := ioutil.ReadFile(c.Config.HTTP.TLS.CACert)
			if err != nil {
				panic(err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			server.TLSConfig = &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
				ClientCAs:  caCertPool,
			}
		}

		return server.ServeTLS(l, c.Config.HTTP.TLS.Cert, c.Config.HTTP.TLS.Key)
	}
	return server.Serve(l)
}
