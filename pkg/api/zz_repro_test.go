package api_test

import (
	"net/http"
	"testing"

	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestZZRepro(t *testing.T) {
	conf := config.New()
	conf.HTTP.Port = "0"
	conf.Storage.RootDirectory = t.TempDir()
	p := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString("user", "pass"))
	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd: config.AuthHTPasswd{Path: p},
		OpenID: &config.OpenIDConfig{Providers: map[string]config.OpenIDProviderConfig{
			"oidc": {ClientID: "x", ClientSecret: "y", Issuer: "http://127.0.0.1:1/unreachable", Scopes: []string{"openid"}},
		}},
	}
	ctlr := api.NewController(conf)
	cm := test.NewControllerManager(ctlr)
	baseURL := cm.StartAndWait()
	defer cm.StopServer()
	resp, err := resty.R().SetBasicAuth("user", "pass").Get(baseURL + "/v2/")
	if err != nil || resp.StatusCode() != http.StatusOK {
		t.Fatalf("%v %v", err, resp)
	}
}
