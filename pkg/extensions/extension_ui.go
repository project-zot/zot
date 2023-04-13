//go:build search && ui
// +build search,ui

package extensions

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

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

func addUISecurityHeaders(h http.Handler) http.HandlerFunc { //nolint:varnamelen
	return func(w http.ResponseWriter, r *http.Request) {
		permissionsPolicy := "microphone=(), geolocation=(), battery=(), camera=(), autoplay=(), gyroscope=(), payment=()"
		w.Header().Set("Permissions-Policy", permissionsPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		cspDirectives := []string{
			"default-src 'none'",
			"script-src 'self' 'unsafe-inline'",
			"style-src 'self' 'unsafe-inline'",
			"font-src 'self'",
			"connect-src 'self'",
			"img-src 'self'",
			"manifest-src 'self'",
			"base-uri 'self'",
		}
		w.Header().Set("Content-Security-Policy", strings.Join(cspDirectives, "; "))

		h.ServeHTTP(w, r)
	}
}

func SetupUIRoutes(config *config.Config, router *mux.Router, storeController storage.StoreController,
	log log.Logger,
) {
	if config.Extensions.UI != nil {
		fsub, _ := fs.Sub(content, "build")
		uih := uiHandler{log: log}

		router.PathPrefix("/login").Handler(addUISecurityHeaders(uih))
		router.PathPrefix("/home").Handler(addUISecurityHeaders(uih))
		router.PathPrefix("/explore").Handler(addUISecurityHeaders(uih))
		router.PathPrefix("/image").Handler(addUISecurityHeaders(uih))
		router.PathPrefix("/").Handler(addUISecurityHeaders(http.FileServer(http.FS(fsub))))

		log.Info().Msg("setting up ui routes")
	}
}
