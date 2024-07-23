//go:build debug
// +build debug

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

package debug

import (
	"github.com/gorilla/mux"
	httpSwagger "github.com/swaggo/http-swagger"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/log" //nolint:goimports
	// as required by swaggo.
	_ "zotregistry.dev/zot/swagger"
)

func SetupSwaggerRoutes(conf *config.Config, router *mux.Router, authFunc mux.MiddlewareFunc,
	log log.Logger,
) {
	log.Info().Msg("setting up swagger route")
	// swagger "/swagger/v2/index.html"
	swgRouter := router.PathPrefix("/swagger/v2/").Subrouter()
	swgRouter.Use(authFunc)
	swgRouter.Methods("GET").Handler(httpSwagger.WrapHandler)
}
