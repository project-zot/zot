//go:build search && ui
// +build search,ui

package extensions

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// content is our static web server content.
//
//go:embed build/*
var content embed.FS

type uiHandler struct {
	log log.Logger
}

func (uih uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	buf, _ := content.ReadFile("build/index.html")

	_, err := w.Write(buf)
	if err != nil {
		uih.log.Error().Err(err).Msg("unable to serve index.html")
	}
}

func SetupUIRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	log log.Logger,
) {
	if config.Extensions.UI != nil {
		fsub, _ := fs.Sub(content, "build")
		uih := uiHandler{log: log}

		router.PathPrefix("/login").Handler(uih)
		router.PathPrefix("/home").Handler(uih)
		router.PathPrefix("/explore").Handler(uih)
		router.PathPrefix("/image").Handler(uih)
		router.PathPrefix("/").Handler(http.FileServer(http.FS(fsub)))

		log.Info().Msg("setting up ui routes")
	}
}
