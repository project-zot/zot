//go:build search && gqlplayground
// +build search,gqlplayground

package extensions

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

//go:embed gqlplayground/index.html.tmpl
var playgroundHTML embed.FS

// SetupGQLPlaygroundRoutes ...
func SetupGQLPlaygroundRoutes(conf *config.Config, router *mux.Router,
	storeController storage.StoreController, l log.Logger,
) {
	log := log.Logger{Logger: l.With().Caller().Timestamp().Logger()}
	log.Info().Msg("setting up graphql playground route")

	t, err := template.ParseFS(playgroundHTML, "gqlplayground/index.html.tmpl")
	if err != nil {
		log.Fatal().Err(err)
	}

	router.PathPrefix(constants.ExtGQLPlaygroundEndpoint).HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Content-Type", "text/html")

		target := "http://" + conf.HTTP.Address + ":" + conf.HTTP.Port + constants.ExtSearchPrefix

		// respond with the output of template execution
		t.Execute(w, struct {
			Target    string
		}{Target: target})})
}
