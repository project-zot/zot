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
		var proto string
		if req.TLS == nil {
			proto = "http://"
		} else {
			proto = "https://"
		}

		target := proto + req.Host + constants.ExtSearchPrefix
		log.Info().Str("target", target).Msg("setting up graphql playground route")
		// respond with the output of template execution
		t.Execute(w, struct {
			Target string
		}{Target: target})
	})
}

func PlaygroundFactory(gqlLocation string) func(http.ResponseWriter, *http.Request) {
	t, err := template.ParseFS(playgroundHTML, "gqlplayground/index.html.tmpl")

	if err == nil {
		return func(w http.ResponseWriter, req *http.Request) {
			w.Header().Add("Content-Type", "text/html")
			var proto string
			if req.TLS == nil {
				proto = "http://"
			} else {
				proto = "https://"
			}

			target := struct {
				Target string
			}{Target: proto + gqlLocation}

			// respond with the output of template execution
			t.Execute(w, target)
		}
	}
	return nil
}
