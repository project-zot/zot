//go:build mgmt
// +build mgmt

package extensions

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	zcommon "zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
)

type HTPasswd struct {
	Path string `json:"path,omitempty"`
}

type BearerConfig struct {
	Realm   string `json:"realm,omitempty"`
	Service string `json:"service,omitempty"`
}

type OpenIDProviderConfig struct {
	Name string `json:"name,omitempty" mapstructure:"name"`
}

type OpenIDConfig struct {
	Providers map[string]OpenIDProviderConfig `json:"providers,omitempty" mapstructure:"providers"`
}

type Auth struct {
	HTPasswd *HTPasswd     `json:"htpasswd,omitempty" mapstructure:"htpasswd"`
	Bearer   *BearerConfig `json:"bearer,omitempty"   mapstructure:"bearer"`
	LDAP     *struct {
		Address string `json:"address,omitempty" mapstructure:"address"`
	} `json:"ldap,omitempty"   mapstructure:"ldap"`
	OpenID *OpenIDConfig `json:"openid,omitempty" mapstructure:"openid"`
	APIKey bool          `json:"apikey,omitempty" mapstructure:"apikey"`
}

type StrippedConfig struct {
	DistSpecVersion string `json:"distSpecVersion" mapstructure:"distSpecVersion"`
	Commit          string `json:"commit"          mapstructure:"commit"`
	ReleaseTag      string `json:"releaseTag"      mapstructure:"releaseTag"`
	BinaryType      string `json:"binaryType"      mapstructure:"binaryType"`

	HTTP struct {
		Auth *Auth `json:"auth,omitempty" mapstructure:"auth"`
	} `json:"http" mapstructure:"http"`
}

func IsBuiltWithMGMTExtension() bool {
	return true
}

func (auth Auth) MarshalJSON() ([]byte, error) {
	type localAuth Auth

	if auth.Bearer == nil && auth.LDAP == nil &&
		auth.HTPasswd.Path == "" &&
		(auth.OpenID == nil || len(auth.OpenID.Providers) == 0) {
		auth.HTPasswd = nil
		auth.OpenID = nil

		return json.Marshal((localAuth)(auth))
	}

	if auth.HTPasswd.Path == "" && auth.LDAP == nil {
		auth.HTPasswd = nil
	} else {
		auth.HTPasswd.Path = ""
	}

	if auth.OpenID != nil && len(auth.OpenID.Providers) == 0 {
		auth.OpenID = nil
	}

	auth.LDAP = nil

	return json.Marshal((localAuth)(auth))
}

func SetupMgmtRoutes(conf *config.Config, router *mux.Router, log log.Logger) {
	if !conf.IsMgmtEnabled() {
		log.Info().Msg("skip enabling the mgmt route as the config prerequisites are not met")

		return
	}

	log.Info().Msg("setting up mgmt routes")

	mgmt := Mgmt{Conf: conf, Log: log}

	// The endpoint for reading configuration should be available to all users
	allowedMethods := zcommon.AllowedMethods(http.MethodGet)

	mgmtRouter := router.PathPrefix(constants.ExtMgmt).Subrouter()
	mgmtRouter.Use(zcommon.CORSHeadersMiddleware(conf.HTTP.AllowOrigin))
	mgmtRouter.Use(zcommon.AddExtensionSecurityHeaders())
	mgmtRouter.Use(zcommon.ACHeadersMiddleware(conf, allowedMethods...))
	mgmtRouter.Methods(allowedMethods...).HandlerFunc(mgmt.HandleGetConfig)

	log.Info().Msg("finished setting up mgmt routes")
}

type Mgmt struct {
	Conf *config.Config
	Log  log.Logger
}

// mgmtHandler godoc
// @Summary Get current server configuration
// @Description Get current server configuration
// @Router  /v2/_zot/ext/mgmt [get]
// @Accept  json
// @Produce json
// @Param   resource       query     string   false   "specify resource" Enums(config)
// @Success 200 {object}   extensions.StrippedConfig
// @Failure 500 {string}   string   "internal server error".
func (mgmt *Mgmt) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	sanitizedConfig := mgmt.Conf.Sanitize()

	buf, err := zcommon.MarshalThroughStruct(sanitizedConfig, &StrippedConfig{})
	if err != nil {
		mgmt.Log.Error().Err(err).Str("component", "mgmt").Msg("failed to marshal config response")
		w.WriteHeader(http.StatusInternalServerError)
	}

	_, _ = w.Write(buf)
}
