//go:build sync && metrics && mgmt && userprefs && search
// +build sync,metrics,mgmt,userprefs,search

package extensions_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/extensions"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	authutils "zotregistry.dev/zot/pkg/test/auth"
	test "zotregistry.dev/zot/pkg/test/common"
)

const (
	ServerCert = "../../test/data/server.cert"
	ServerKey  = "../../test/data/server.key"
)

func TestEnableExtension(t *testing.T) {
	Convey("Verify log if sync disabled in config", t, func() {
		globalDir := t.TempDir()
		port := test.GetFreePort()
		conf := config.New()
		falseValue := false

		syncConfig := &syncconf.Config{
			Enable:     &falseValue,
			Registries: []syncconf.RegistryConfig{},
		}

		// conf.Extensions.Sync.Enable = &falseValue
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Sync = syncConfig
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Level = "info"
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		defer ctlrManager.StopServer()

		ctlr.Config.Storage.RootDirectory = globalDir

		ctlrManager.StartAndWait(port)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"sync config not provided or disabled, so not enabling sync")
	})
}

func TestMetricsExtension(t *testing.T) {
	Convey("Verify Metrics enabled for storage subpaths", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Metrics = &extconf.MetricsConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultValue},
			Prometheus: &extconf.PrometheusConfig{},
		}
		conf.Log.Level = "info"
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{
			Dedupe:        false,
			RootDirectory: t.TempDir(),
		}

		ctlr.Config.Storage.RootDirectory = globalDir
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager.StartAndWait(port)

		data, _ := os.ReadFile(logFile.Name())

		So(string(data), ShouldContainSubstring,
			"prometheus instrumentation path not set, changing to '/metrics'.")
	})
}

func TestMgmtExtension(t *testing.T) {
	globalDir := t.TempDir()
	conf := config.New()
	port := test.GetFreePort()
	conf.HTTP.Port = port
	baseURL := test.GetBaseURL(port)

	logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
	if err != nil {
		panic(err)
	}
	mgmtReadyTimeout := 5 * time.Second

	defaultValue := true

	mockOIDCServer, err := authutils.MockOIDCRun()
	if err != nil {
		panic(err)
	}

	defer func() {
		err := mockOIDCServer.Shutdown()
		if err != nil {
			panic(err)
		}
	}()

	mockOIDCConfig := mockOIDCServer.Config()

	Convey("Verify mgmt auth info route enabled with htpasswd", t, func() {
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))

		defer func() {
			conf.HTTP.Auth.HTPasswd.Path = ""
			os.Remove(htpasswdPath)
		}()

		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = globalDir
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		So(err, ShouldBeNil)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Patch(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		// without credentials
		resp, err = resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)

		// with credentials
		resp, err = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)

		// with wrong credentials
		resp, err = resty.R().SetBasicAuth(username, "wrong").Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})

	Convey("Verify mgmt auth info route enabled with ldap", t, func() {
		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			BaseDN:  "basedn",
			Address: "ldapexample",
		}).SetBindDN("binddn")

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		// ldap is always nil, htpasswd should be populated when ldap is used
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Verify mgmt auth info route enabled with ldap + apikey", t, func() {
		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			BaseDN:  "basedn",
			Address: "ldapexample",
		}).SetBindDN("binddn")
		conf.HTTP.Auth.APIKey = true

		defer func() {
			conf.HTTP.Auth.APIKey = false
		}()

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		// ldap is always nil, htpasswd should be populated when ldap is used
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeTrue)
	})

	Convey("Verify mgmt auth info route enabled with htpasswd + ldap", t, func() {
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))

		defer func() {
			conf.HTTP.Auth.HTPasswd.Path = ""
			os.Remove(htpasswdPath)
		}()

		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			BaseDN:  "basedn",
			Address: "ldapexample",
		}).SetBindDN("binddn")

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)

		// with credentials
		resp, err = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Verify mgmt auth info route enabled with htpasswd + ldap + bearer", t, func() {
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))

		defer func() {
			conf.HTTP.Auth.HTPasswd.Path = ""
			os.Remove(htpasswdPath)
		}()

		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			BaseDN:  "basedn",
			Address: "ldapexample",
		}).SetBindDN("binddn")

		conf.HTTP.Auth.Bearer = &config.BearerConfig{
			Realm:   "realm",
			Service: "service",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)

		// with credentials
		resp, err = resty.R().SetBasicAuth(username, password).Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Verify mgmt auth info route enabled with ldap + bearer", t, func() {
		conf.HTTP.Auth.HTPasswd.Path = ""
		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			BaseDN:  "basedn",
			Address: "ldapexample",
		}).SetBindDN("binddn")

		conf.HTTP.Auth.Bearer = &config.BearerConfig{
			Realm:   "realm",
			Service: "service",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{RootDirectory: t.TempDir()}

		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.SubPaths = subPaths

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd.Path, ShouldEqual, "")
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Verify mgmt auth info route enabled with bearer", t, func() {
		conf.HTTP.Auth.HTPasswd.Path = ""
		conf.HTTP.Auth.LDAP = nil
		conf.HTTP.Auth.Bearer = &config.BearerConfig{
			Realm:   "realm",
			Service: "service",
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, "realm")
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, "service")
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Verify mgmt auth info route enabled with openID", t, func() {
		conf.HTTP.Auth.HTPasswd.Path = ""
		conf.HTTP.Auth.LDAP = nil
		conf.HTTP.Auth.Bearer = nil

		openIDProviders := make(map[string]config.OpenIDProviderConfig)
		openIDProviders["oidc"] = config.OpenIDProviderConfig{
			ClientID:     mockOIDCConfig.ClientID,
			ClientSecret: mockOIDCConfig.ClientSecret,
			Issuer:       mockOIDCConfig.Issuer,
		}

		conf.HTTP.Auth.OpenID = &config.OpenIDConfig{
			Providers: openIDProviders,
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		t.Logf("resp: %v", mgmtResp.HTTP.Auth.OpenID)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.OpenID, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.OpenID.Providers, ShouldNotBeEmpty)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Verify mgmt auth info route enabled with empty openID provider list", t, func() {
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))

		defer func() {
			conf.HTTP.Auth.HTPasswd.Path = ""
			os.Remove(htpasswdPath)
		}()

		conf.HTTP.Auth.HTPasswd.Path = htpasswdPath
		conf.HTTP.Auth.LDAP = nil
		conf.HTTP.Auth.Bearer = nil

		openIDProviders := make(map[string]config.OpenIDProviderConfig)

		conf.HTTP.Auth.OpenID = &config.OpenIDConfig{
			Providers: openIDProviders,
		}

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		// without credentials
		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		t.Logf("resp: %v", mgmtResp.HTTP.Auth.OpenID)
		So(err, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.OpenID, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})

	Convey("Verify mgmt auth info route enabled without any auth", t, func() {
		globalDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		baseURL := test.GetBaseURL(port)

		logFile, err := os.CreateTemp(globalDir, "zot-log*.txt")
		So(err, ShouldBeNil)
		defaultValue := true

		conf.Commit = "v1.0.0"

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // cleanup

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		resp, err := resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.DistSpecVersion, ShouldResemble, conf.DistSpecVersion)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)

		found, err := test.ReadLogFileAndSearchString(logFile.Name(),
			"setting up mgmt routes", mgmtReadyTimeout)
		defer func() {
			if !found {
				data, err := os.ReadFile(logFile.Name())
				So(err, ShouldBeNil)
				t.Log(string(data))
			}
		}()
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)

		found, err = test.ReadLogFileAndSearchString(logFile.Name(),
			"finished setting up mgmt routes", mgmtReadyTimeout)
		So(found, ShouldBeTrue)
		So(err, ShouldBeNil)
	})
}

func TestMgmtWithBearer(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authorizedNamespace := "allowedrepo"
		unauthorizedNamespace := "notallowedrepo"
		authTestServer := authutils.MakeAuthTestServer(ServerKey, unauthorizedNamespace)
		defer authTestServer.Close()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		aurl, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		conf.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    ServerCert,
				Realm:   authTestServer.URL + "/auth/token",
				Service: aurl.Host,
			},
		}

		defaultValue := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultValue
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultValue

		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader := authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var goodToken authutils.AccessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().SetHeader("Authorization",
			fmt.Sprintf("Bearer %s", goodToken.AccessToken)).Options(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		resp, err = resty.R().Post(baseURL + "/v2/" + authorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Post(baseURL + "/v2/" + authorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		resp, err = resty.R().
			Post(baseURL + "/v2/" + unauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var badToken authutils.AccessTokenResponse
		err = json.Unmarshal(resp.Body(), &badToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", badToken.AccessToken)).
			Post(baseURL + "/v2/" + unauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// test mgmt route
		resp, err = resty.R().Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp := extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.DistSpecVersion, ShouldResemble, conf.DistSpecVersion)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, conf.HTTP.Auth.Bearer.Realm)
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, conf.HTTP.Auth.Bearer.Service)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)

		resp, err = resty.R().SetBasicAuth("", "").Get(baseURL + constants.FullMgmt)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		mgmtResp = extensions.StrippedConfig{}
		err = json.Unmarshal(resp.Body(), &mgmtResp)
		So(err, ShouldBeNil)
		So(mgmtResp.DistSpecVersion, ShouldResemble, conf.DistSpecVersion)
		So(mgmtResp.HTTP.Auth.Bearer, ShouldNotBeNil)
		So(mgmtResp.HTTP.Auth.Bearer.Realm, ShouldEqual, conf.HTTP.Auth.Bearer.Realm)
		So(mgmtResp.HTTP.Auth.Bearer.Service, ShouldEqual, conf.HTTP.Auth.Bearer.Service)
		So(mgmtResp.HTTP.Auth.HTPasswd, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.LDAP, ShouldBeNil)
		So(mgmtResp.HTTP.Auth.APIKey, ShouldBeFalse)
	})
}

func TestAllowedMethodsHeaderMgmt(t *testing.T) {
	defaultVal := true

	Convey("Test http options response", t, func() {
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultVal
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultVal

		baseURL := test.GetBaseURL(port)

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)
		defer ctrlManager.StopServer()

		resp, _ := resty.R().Options(baseURL + constants.FullMgmt)
		So(resp, ShouldNotBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
	})
}
