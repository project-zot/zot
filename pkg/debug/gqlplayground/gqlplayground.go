//go:build debug
// +build debug

package debug

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/constants"
	debugCst "zotregistry.dev/zot/pkg/debug/constants"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
)

//go:embed index.html.tmpl
var playgroundHTML embed.FS

// SetupGQLPlaygroundRoutes ...
func SetupGQLPlaygroundRoutes(router *mux.Router,
	storeController storage.StoreController, log log.Logger,
) {
	log.Info().Msg("setting up graphql playground route")

	templ, err := template.ParseFS(playgroundHTML, "index.html.tmpl")
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	//nolint:lll
	router.PathPrefix(debugCst.GQLPlaygroundEndpoint).HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		writer.Header().Add("Content-Type", "text/html")

		proto := ""

		if req.TLS == nil {
			proto += "http://"
		} else {
			proto += "https://"
		}

		target := proto + req.Host + constants.FullSearchPrefix

		// respond with the output of template execution
		_ = templ.Execute(writer, struct {
			Target string
		}{Target: target})
	})
}
