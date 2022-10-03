//go:build debug
// +build debug

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

package debug

import (
	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log" // nolint:goimports
	// as required by swaggo.
	_ "zotregistry.io/zot/swagger"
)

func SetupSwaggerRoutes(conf *config.Config, router *mux.Router, log log.Logger,
) {
	log.Info().Msg("setting up swagger route")
	// swagger swagger "/swagger/v2/index.html"
	router.PathPrefix("/swagger/v2/").Methods("GET").Handler(httpSwagger.WrapHandler)
}
