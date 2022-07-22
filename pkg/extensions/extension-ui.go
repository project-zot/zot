//go:build search && ui
// +build search,ui

package extensions

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gorilla/mux"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"

	"zotregistry.io/zot/pkg/api/config"
)

// content is our static web server content.
//go:embed build/*
var content embed.FS

func SetupUIRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	log log.Logger,
) {
	if config.Extensions.UI != nil {
		fsub, _ := fs.Sub(content, "build")

		router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
			buf, _ := content.ReadFile("build/index.html")

			_, err := w.Write(buf)
			if err != nil {
				log.Error().Err(err).Msg("unable to serve index.html")
			}
		})

		router.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
			buf, _ := content.ReadFile("build/index.html")

			_, err := w.Write(buf)
			if err != nil {
				log.Error().Err(err).Msg("unable to serve index.html")
			}
		})

		router.PathPrefix("/").Handler(http.FileServer(http.FS(fsub)))
		log.Info().Msg("setting up ui routes")
	}
}
