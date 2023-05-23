//go:build mgmt
// +build mgmt

package extensions

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
)

type HTPasswd struct {
	Path string `json:"path,omitempty"`
}

type BearerConfig struct {
	Realm   string `json:"realm,omitempty"`
	Service string `json:"service,omitempty"`
}

type Auth struct {
	HTPasswd *HTPasswd     `json:"htpasswd,omitempty" mapstructure:"htpasswd"`
	Bearer   *BearerConfig `json:"bearer,omitempty" mapstructure:"bearer"`
	LDAP     *struct {
		Address string `json:"address,omitempty" mapstructure:"address"`
	} `json:"ldap,omitempty" mapstructure:"ldap"`
}

type AccessControl struct {
	AnonymousPolicy bool `json:"anonymousPolicy,omitempty" mapstructure:"anonymousPolicy"`
}

type HTTP struct {
	Auth          *Auth          `json:"auth,omitempty" mapstructure:"auth"`
	AccessControl *AccessControl `json:"accessControl,omitempty" mapstructure:"accessControl"`
}
type StrippedConfig struct {
	DistSpecVersion string `json:"distSpecVersion" mapstructure:"distSpecVersion"`
	BinaryType      string `json:"binaryType" mapstructure:"binaryType"`
	HTTP            *HTTP  `json:"http" mapstructure:"http"`
}

func (http *HTTP) UnmarshalJSON(data []byte) error {
	type Alias HTTP
	// var internalHTTP Alias
	internalHTTP := (*Alias)(http)

	err := json.Unmarshal(data, &internalHTTP)
	if err != nil {
		return err
	}
	http.Auth = internalHTTP.Auth
	http.AccessControl = internalHTTP.AccessControl

	return nil
}

func (auth Auth) MarshalJSON() ([]byte, error) {
	type localAuth Auth

	if auth.Bearer == nil && auth.LDAP == nil &&
		auth.HTPasswd.Path == "" {
		auth.HTPasswd = nil

		return json.Marshal((localAuth)(auth))
	}

	if auth.HTPasswd.Path == "" && auth.LDAP == nil {
		auth.HTPasswd = nil
	} else {
		auth.HTPasswd.Path = ""
	}

	auth.LDAP = nil

	return json.Marshal((localAuth)(auth))
}

type mgmt struct {
	config *config.Config
	log    log.Logger
}

func (mgmt *mgmt) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sanitizedConfig := mgmt.config.Sanitize()
		strippedConfig := &StrippedConfig{
			HTTP: &HTTP{
				AccessControl: &AccessControl{
					AnonymousPolicy: anonymousPolicyExists(mgmt.config.HTTP.AccessControl),
				},
			},
		}
		buf, err := common.MarshalThroughStruct(sanitizedConfig, strippedConfig)
		if err != nil {
			mgmt.log.Error().Err(err).Msg("mgmt: couldn't marshal config response")
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = w.Write(buf)
	})
}

func addMgmtSecurityHeaders(h http.Handler) http.HandlerFunc { //nolint:varnamelen
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")

		h.ServeHTTP(w, r)
	}
}

func SetupMgmtRoutes(config *config.Config, router *mux.Router, log log.Logger) {
	if config.Extensions.Mgmt != nil && *config.Extensions.Mgmt.Enable {
		log.Info().Msg("setting up mgmt routes")

		mgmt := mgmt{config: config, log: log}

		router.PathPrefix(constants.ExtMgmt).Methods("GET").Handler(addMgmtSecurityHeaders(mgmt.handler()))
	}
}

func anonymousPolicyExists(config *config.AccessControlConfig) bool {
	if config == nil {
		return false
	}

	for _, repository := range config.Repositories {
		if len(repository.AnonymousPolicy) > 0 {
			return true
		}
	}

	return false
}
