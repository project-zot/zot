//go:build search && ui

package extensions

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

// content is our static web server content.
//
//go:embed build/*
var content embed.FS

type uiHandler struct {
	conf *config.Config
	log  log.Logger
}

func (uih uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	buf, _ := content.ReadFile("build/index.html")
	buf = injectVersionInfoScript(buf)

	_, err := w.Write(buf)
	if err != nil {
		uih.log.Error().Err(err).Msg("failed to serve index.html")
	}
}

func (uih uiHandler) HandleVersionInfoScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")

	if _, err := w.Write([]byte(uiVersionInfoScript)); err != nil {
		uih.log.Error().Err(err).Msg("failed to serve UI version info script")
	}
}

func (uih uiHandler) HandleVersionInfo(w http.ResponseWriter, r *http.Request) {
	sanitizedConfig := uih.conf.Sanitize()
	versionInfo := uiVersionInfo{}

	if sanitizedConfig != nil {
		versionInfo.Commit = sanitizedConfig.Commit
		versionInfo.ReleaseTag = sanitizedConfig.ReleaseTag
		versionInfo.BinaryType = sanitizedConfig.BinaryType
		versionInfo.GoVersion = sanitizedConfig.GoVersion
		versionInfo.DistSpecVersion = sanitizedConfig.DistSpecVersion
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(versionInfo); err != nil {
		uih.log.Error().Err(err).Msg("failed to serve UI version info")
	}
}

func addUISecurityHeaders(h http.Handler) http.HandlerFunc { //nolint:varnamelen
	return func(w http.ResponseWriter, r *http.Request) {
		permissionsPolicy := "microphone=(), geolocation=(), battery=(), camera=(), autoplay=(), gyroscope=(), payment=()"
		w.Header().Set("Permissions-Policy", permissionsPolicy)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")

		cspDirectives := []string{
			"default-src 'none'",
			"script-src 'self' 'unsafe-inline'",
			"style-src 'self' 'unsafe-inline'",
			"font-src 'self'",
			"connect-src 'self'",
			"img-src 'self' data:",
			"manifest-src 'self'",
			"base-uri 'self'",
		}
		w.Header().Set("Content-Security-Policy", strings.Join(cspDirectives, "; "))

		h.ServeHTTP(w, r)
	}
}

func SetupUIRoutes(conf *config.Config, router *mux.Router,
	log log.Logger,
) {
	extensionsConfig := conf.CopyExtensionsConfig()
	if !extensionsConfig.IsUIEnabled() {
		log.Info().Msg("skip enabling the ui route as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up ui routes")

	fsub, _ := fs.Sub(content, "build")
	uih := uiHandler{conf: conf, log: log}

	// See https://go-review.googlesource.com/c/go/+/482635/2/src/net/http/fs.go
	// See https://github.com/golang/go/issues/59469
	// In go 1.20.4 they decided to allow any method in the FileServer handler.
	// In order to be consistent with the status codes returned when the UI is disabled
	// we need to be explicit about the methods we allow on UI routes.
	// If we don't add this, all unmatched http methods on any urls would match the UI routes.
	allowedMethods := zcommon.AllowedMethods(http.MethodGet)

	router.Path(uiVersionInfoScriptPath).Methods(allowedMethods...).
		Handler(addUISecurityHeaders(http.HandlerFunc(uih.HandleVersionInfoScript)))
	router.Path(uiVersionInfoJSONPath).Methods(allowedMethods...).
		Handler(addUISecurityHeaders(http.HandlerFunc(uih.HandleVersionInfo)))
	router.PathPrefix("/login").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(uih))
	router.PathPrefix("/home").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(uih))
	router.PathPrefix("/explore").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(uih))
	router.PathPrefix("/image").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(uih))
	router.PathPrefix("/user").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(uih))
	router.Path("/").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(uih))
	router.Path("/index.html").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(uih))
	router.PathPrefix("/").Methods(allowedMethods...).
		Handler(addUISecurityHeaders(http.FileServer(http.FS(fsub))))

	log.Info().Msg("finished setting up ui routes")
}
