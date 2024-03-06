//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui
// +build sync,scrub,metrics,search,lint,userprefs,mgmt,imagetrust,ui

package api_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v52/github"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/migueleliasweb/go-github-mock/src/mock"
	vldap "github.com/nmcclain/ldap"
	notreg "github.com/notaryproject/notation-go/registry"
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-zot/mockoidc"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	apiErr "zotregistry.dev/zot/pkg/api/errors"
	"zotregistry.dev/zot/pkg/cli/server"
	"zotregistry.dev/zot/pkg/common"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	"zotregistry.dev/zot/pkg/storage"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/storage/gc"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
	authutils "zotregistry.dev/zot/pkg/test/auth"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/inject"
	"zotregistry.dev/zot/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
	"zotregistry.dev/zot/pkg/test/signature"
	tskip "zotregistry.dev/zot/pkg/test/skip"
)

const (
	ServerCert             = "../../test/data/server.cert"
	ServerKey              = "../../test/data/server.key"
	CACert                 = "../../test/data/ca.crt"
	UnauthorizedNamespace  = "fortknox/notallowed"
	AuthorizationNamespace = "authz/image"
	LDAPAddress            = "127.0.0.1"
)

var (
	username         = "test"                    //nolint: gochecknoglobals
	password         = "test"                    //nolint: gochecknoglobals
	group            = "test"                    //nolint: gochecknoglobals
	LDAPBaseDN       = "ou=" + username          //nolint: gochecknoglobals
	LDAPBindDN       = "cn=reader," + LDAPBaseDN //nolint: gochecknoglobals
	LDAPBindPassword = "ldappass"                //nolint: gochecknoglobals
)

func TestNew(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()
		So(conf, ShouldNotBeNil)
		So(api.NewController(conf), ShouldNotBeNil)
	})
}

func TestCreateCacheDatabaseDriver(t *testing.T) {
	Convey("Test CreateCacheDatabaseDriver boltdb", t, func() {
		log := log.NewLogger("debug", "")

		// fail create db, no perm
		dir := t.TempDir()
		conf := config.New()
		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = true
		conf.Storage.RemoteCache = false

		err := os.Chmod(dir, 0o000)
		if err != nil {
			panic(err)
		}

		driver, err := storage.CreateCacheDatabaseDriver(conf.Storage.StorageConfig, log)
		So(err, ShouldNotBeNil)
		So(driver, ShouldBeNil)

		conf.Storage.RemoteCache = true
		conf.Storage.RootDirectory = t.TempDir()

		driver, err = storage.CreateCacheDatabaseDriver(conf.Storage.StorageConfig, log)
		So(err, ShouldBeNil)
		So(driver, ShouldBeNil)
	})
	tskip.SkipDynamo(t)
	tskip.SkipS3(t)
	Convey("Test CreateCacheDatabaseDriver dynamodb", t, func() {
		log := log.NewLogger("debug", "")
		dir := t.TempDir()
		// good config
		conf := config.New()
		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = true
		conf.Storage.RemoteCache = true
		conf.Storage.StorageDriver = map[string]interface{}{
			"name":          "s3",
			"rootdirectory": "/zot",
			"region":        "us-east-2",
			"bucket":        "zot-storage",
			"secure":        true,
			"skipverify":    false,
		}

		endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")
		conf.Storage.CacheDriver = map[string]interface{}{
			"name":                   "dynamodb",
			"endpoint":               endpoint,
			"region":                 "us-east-2",
			"cachetablename":         "BlobTable",
			"repometatablename":      "RepoMetadataTable",
			"imagemetatablename":     "ZotImageMetaTable",
			"repoblobsinfotablename": "ZotRepoBlobsInfoTable",
			"userdatatablename":      "ZotUserDataTable",
			"versiontablename":       "Version",
		}

		driver, err := storage.CreateCacheDatabaseDriver(conf.Storage.StorageConfig, log)
		So(err, ShouldBeNil)
		So(driver, ShouldNotBeNil)

		// negative test cases

		conf.Storage.CacheDriver = map[string]interface{}{
			"endpoint":               endpoint,
			"region":                 "us-east-2",
			"cachetablename":         "BlobTable",
			"repometatablename":      "RepoMetadataTable",
			"imagemetatablename":     "ZotImageMetaTable",
			"repoblobsinfotablename": "ZotRepoBlobsInfoTable",
			"userdatatablename":      "ZotUserDataTable",
			"versiontablename":       "Version",
		}

		driver, err = storage.CreateCacheDatabaseDriver(conf.Storage.StorageConfig, log)
		So(err, ShouldBeNil)
		So(driver, ShouldBeNil)

		conf.Storage.CacheDriver = map[string]interface{}{
			"name":                   "dummy",
			"endpoint":               endpoint,
			"region":                 "us-east-2",
			"cachetablename":         "BlobTable",
			"repometatablename":      "RepoMetadataTable",
			"imagemetatablename":     "ZotImageMetaTable",
			"repoblobsinfotablename": "ZotRepoBlobsInfoTable",
			"userdatatablename":      "ZotUserDataTable",
			"versiontablename":       "Version",
		}

		driver, err = storage.CreateCacheDatabaseDriver(conf.Storage.StorageConfig, log)
		So(err, ShouldBeNil)
		So(driver, ShouldBeNil)
	})
}

func TestCreateMetaDBDriver(t *testing.T) {
	Convey("Test CreateCacheDatabaseDriver dynamo", t, func() {
		log := log.NewLogger("debug", "")
		dir := t.TempDir()
		conf := config.New()
		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = true
		conf.Storage.RemoteCache = true
		conf.Storage.StorageDriver = map[string]interface{}{
			"name":          "s3",
			"rootdirectory": "/zot",
			"region":        "us-east-2",
			"bucket":        "zot-storage",
			"secure":        true,
			"skipverify":    false,
		}

		conf.Storage.CacheDriver = map[string]interface{}{
			"name":                   "dummy",
			"endpoint":               "http://localhost:4566",
			"region":                 "us-east-2",
			"cachetablename":         "BlobTable",
			"repometatablename":      "RepoMetadataTable",
			"imageMetaTablename":     "ZotImageMetaTable",
			"repoBlobsInfoTablename": "ZotRepoBlobsInfoTable",
			"userdatatablename":      "UserDatatable",
		}

		testFunc := func() { _, _ = meta.New(conf.Storage.StorageConfig, log) }
		So(testFunc, ShouldPanic)

		conf.Storage.CacheDriver = map[string]interface{}{
			"name":                   "dummy",
			"endpoint":               "http://localhost:4566",
			"region":                 "us-east-2",
			"cachetablename":         "",
			"repometatablename":      "RepoMetadataTable",
			"imageMetaTablename":     "ZotImageMetaTable",
			"repoBlobsInfoTablename": "ZotRepoBlobsInfoTable",
			"userDataTablename":      "ZotUserDataTable",
			"versiontablename":       1,
		}

		testFunc = func() { _, _ = meta.New(conf.Storage.StorageConfig, log) }
		So(testFunc, ShouldPanic)

		conf.Storage.CacheDriver = map[string]interface{}{
			"name":                   "dummy",
			"endpoint":               "http://localhost:4566",
			"region":                 "us-east-2",
			"cachetablename":         "test",
			"repometatablename":      "RepoMetadataTable",
			"imagemetatablename":     "ZotImageMetaTable",
			"repoblobsinfotablename": "ZotRepoBlobsInfoTable",
			"userdatatablename":      "ZotUserDataTable",
			"apikeytablename":        "APIKeyTable",
			"versiontablename":       "1",
		}

		testFunc = func() { _, _ = meta.New(conf.Storage.StorageConfig, log) }
		So(testFunc, ShouldNotPanic)
	})

	Convey("Test CreateCacheDatabaseDriver bolt", t, func() {
		log := log.NewLogger("debug", "")
		dir := t.TempDir()
		conf := config.New()
		conf.Storage.RootDirectory = dir
		conf.Storage.Dedupe = true
		conf.Storage.RemoteCache = false

		const perms = 0o600

		boltDB, err := bbolt.Open(path.Join(dir, "meta.db"), perms, &bbolt.Options{Timeout: time.Second * 10})
		So(err, ShouldBeNil)

		err = boltDB.Close()
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "meta.db"), 0o200)
		So(err, ShouldBeNil)

		_, err = meta.New(conf.Storage.StorageConfig, log)
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "meta.db"), 0o600)
		So(err, ShouldBeNil)

		defer os.Remove(path.Join(dir, "meta.db"))
	})
}

func TestRunAlreadyRunningServer(t *testing.T) {
	Convey("Run server on unavailable port", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := makeController(conf, t.TempDir())
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		err := ctlr.Init()
		So(err, ShouldNotBeNil)

		err = ctlr.Run()
		So(err, ShouldNotBeNil)
	})
}

func TestAutoPortSelection(t *testing.T) {
	Convey("Run server with specifying a port", t, func() {
		conf := config.New()
		conf.HTTP.Port = "0"

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartServer()
		time.Sleep(1000 * time.Millisecond)
		defer cm.StopServer()

		file, err := os.Open(logFile.Name())
		So(err, ShouldBeNil)
		defer file.Close()

		scanner := bufio.NewScanner(file)

		var contents bytes.Buffer
		start := time.Now()

		for scanner.Scan() {
			if time.Since(start) < time.Second*30 {
				t.Logf("Exhausted: Controller did not print the expected log within 30 seconds")
			}
			text := scanner.Text()
			contents.WriteString(text)
			if strings.Contains(text, "Port unspecified") {
				break
			}
			t.Logf(scanner.Text())
		}
		So(scanner.Err(), ShouldBeNil)
		So(contents.String(), ShouldContainSubstring,
			"port is unspecified, listening on kernel chosen port",
		)
		So(contents.String(), ShouldContainSubstring, "\"address\":\"127.0.0.1\"")
		So(contents.String(), ShouldContainSubstring, "\"port\":")

		So(ctlr.GetPort(), ShouldBeGreaterThan, 0)
		So(ctlr.GetPort(), ShouldBeLessThan, 65536)
	})
}

func TestObjectStorageController(t *testing.T) {
	tskip.SkipS3(t)
	tskip.SkipDynamo(t)

	bucket := "zot-storage-test"

	Convey("Negative make a new object storage controller", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		tmp := t.TempDir()

		storageDriverParams := map[string]interface{}{
			"rootdirectory": tmp,
			"name":          storageConstants.S3StorageDriverName,
		}
		conf.Storage.StorageDriver = storageDriverParams
		ctlr := makeController(conf, tmp)
		So(ctlr, ShouldNotBeNil)

		err := ctlr.Init()
		So(err, ShouldNotBeNil)
	})

	Convey("Make a new object storage controller", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		endpoint := os.Getenv("S3MOCK_ENDPOINT")
		tmp := t.TempDir()

		storageDriverParams := map[string]interface{}{
			"rootdirectory":  tmp,
			"name":           storageConstants.S3StorageDriverName,
			"region":         "us-east-2",
			"bucket":         bucket,
			"regionendpoint": endpoint,
			"secure":         false,
			"skipverify":     false,
		}

		conf.Storage.StorageDriver = storageDriverParams
		ctlr := makeController(conf, tmp)
		So(ctlr, ShouldNotBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
	})

	Convey("Make a new object storage controller with openid", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		endpoint := os.Getenv("S3MOCK_ENDPOINT")

		storageDriverParams := map[string]interface{}{
			"rootdirectory":  "/zot",
			"name":           storageConstants.S3StorageDriverName,
			"region":         "us-east-2",
			"bucket":         bucket,
			"regionendpoint": endpoint,
			"secure":         false,
			"skipverify":     false,
		}
		conf.Storage.RemoteCache = true
		conf.Storage.StorageDriver = storageDriverParams

		conf.Storage.CacheDriver = map[string]interface{}{
			"name":                   "dynamodb",
			"endpoint":               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			"region":                 "us-east-2",
			"cachetablename":         "test",
			"repometatablename":      "RepoMetadataTable",
			"imagemetatablename":     "ZotImageMetaTable",
			"repoblobsinfotablename": "ZotRepoBlobsInfoTable",
			"userdatatablename":      "ZotUserDataTable",
			"apikeytablename":        "APIKeyTable1",
			"versiontablename":       "Version",
		}

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

		conf.HTTP.Auth = &config.AuthConfig{
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email"},
					},
				},
			},
		}

		// create s3 bucket
		_, err = resty.R().Put("http://" + os.Getenv("S3MOCK_ENDPOINT") + "/" + bucket)
		if err != nil {
			panic(err)
		}

		ctlr := makeController(conf, "/")
		So(ctlr, ShouldNotBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
	})
}

func TestObjectStorageControllerSubPaths(t *testing.T) {
	tskip.SkipS3(t)

	bucket := "zot-storage-test"

	Convey("Make a new object storage controller", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		endpoint := os.Getenv("S3MOCK_ENDPOINT")
		tmp := t.TempDir()

		storageDriverParams := map[string]interface{}{
			"rootdirectory":  tmp,
			"name":           storageConstants.S3StorageDriverName,
			"region":         "us-east-2",
			"bucket":         bucket,
			"regionendpoint": endpoint,
			"secure":         false,
			"skipverify":     false,
		}
		conf.Storage.StorageDriver = storageDriverParams
		ctlr := makeController(conf, tmp)
		So(ctlr, ShouldNotBeNil)

		subPathMap := make(map[string]config.StorageConfig)
		subPathMap["/a"] = config.StorageConfig{
			RootDirectory: t.TempDir(),
			StorageDriver: storageDriverParams,
		}
		ctlr.Config.Storage.SubPaths = subPathMap

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
	})
}

func TestHtpasswdSingleCred(t *testing.T) {
	Convey("Single cred", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		singleCredtests := []string{}
		user, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		singleCredtests = append(singleCredtests, test.GetCredString(user, password))
		singleCredtests = append(singleCredtests, test.GetCredString(user, password))

		for _, testString := range singleCredtests {
			func() {
				conf := config.New()
				conf.HTTP.Port = port

				htpasswdPath := test.MakeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				conf.HTTP.Auth = &config.AuthConfig{
					HTPasswd: config.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}

				conf.HTTP.AllowOrigin = conf.HTTP.Address

				ctlr := makeController(conf, t.TempDir())
				ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

				cm := test.NewControllerManager(ctlr)
				cm.StartAndWait(port)
				defer cm.StopServer()

				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				header := []string{"Authorization,content-type," + constants.SessionClientHeaderName}

				resp, _ = resty.R().SetBasicAuth(user, password).Options(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
				So(len(resp.Header()), ShouldEqual, 5)
				So(resp.Header()["Access-Control-Allow-Headers"], ShouldResemble, header)
				So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")

				// with invalid creds, it should fail
				resp, _ = resty.R().SetBasicAuth("chuck", "chuck").Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			}()
		}
	})
}

func TestAllowMethodsHeader(t *testing.T) {
	Convey("Options request", t, func() {
		dir := t.TempDir()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir
		conf.HTTP.AllowOrigin = "someOrigin"

		simpleUser := "simpleUser"
		simpleUserPassword := "simpleUserPass"
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(simpleUser, simpleUserPassword))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"**": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{simpleUser},
							Actions: []string{"read", "create"},
						},
					},
				},
			},
		}

		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		simpleUserClient := resty.R().SetBasicAuth(simpleUser, simpleUserPassword)

		digest := godigest.FromString("digest")

		// /v2
		resp, err := simpleUserClient.Options(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")

		// /v2/{name}/tags/list
		resp, err = simpleUserClient.Options(baseURL + "/v2/reponame/tags/list")
		So(err, ShouldBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")

		// /v2/{name}/manifests/{reference}
		resp, err = simpleUserClient.Options(baseURL + "/v2/reponame/manifests/" + digest.String())
		So(err, ShouldBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "HEAD,GET,DELETE,OPTIONS")

		// /v2/{name}/referrers/{digest}
		resp, err = simpleUserClient.Options(baseURL + "/v2/reponame/referrers/" + digest.String())
		So(err, ShouldBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")

		// /v2/_catalog
		resp, err = simpleUserClient.Options(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")

		// /v2/_oci/ext/discover
		resp, err = simpleUserClient.Options(baseURL + "/v2/_oci/ext/discover")
		So(err, ShouldBeNil)
		So(resp.Header().Get("Access-Control-Allow-Methods"), ShouldResemble, "GET,OPTIONS")
	})
}

func TestHtpasswdTwoCreds(t *testing.T) {
	Convey("Two creds", t, func() {
		twoCredTests := []string{}
		user1 := "alicia"
		password1 := "aliciapassword"
		user2 := "bob"
		password2 := "robert"
		twoCredTests = append(twoCredTests, test.GetCredString(user1, password1)+"\n"+
			test.GetCredString(user2, password2))

		twoCredTests = append(twoCredTests, test.GetCredString(user1, password1)+"\n"+
			test.GetCredString(user2, password2)+"\n")

		twoCredTests = append(twoCredTests, test.GetCredString(user1, password1)+"\n\n"+
			test.GetCredString(user2, password2)+"\n\n")

		for _, testString := range twoCredTests {
			func() {
				port := test.GetFreePort()
				baseURL := test.GetBaseURL(port)
				conf := config.New()
				conf.HTTP.Port = port
				htpasswdPath := test.MakeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				conf.HTTP.Auth = &config.AuthConfig{
					HTPasswd: config.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				ctlr := makeController(conf, t.TempDir())
				cm := test.NewControllerManager(ctlr)
				cm.StartAndWait(port)
				defer cm.StopServer()

				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user1, password1).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				resp, _ = resty.R().SetBasicAuth(user2, password2).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				// with invalid creds, it should fail
				resp, _ = resty.R().SetBasicAuth("chuck", "chuck").Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			}()
		}
	})
}

func TestHtpasswdFiveCreds(t *testing.T) {
	Convey("Five creds", t, func() {
		tests := map[string]string{
			"michael": "scott",
			"jim":     "halpert",
			"dwight":  "shrute",
			"pam":     "bessley",
			"creed":   "bratton",
		}
		credString := strings.Builder{}
		for key, val := range tests {
			credString.WriteString(test.GetCredString(key, val) + "\n")
		}

		func() {
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port
			htpasswdPath := test.MakeHtpasswdFileFromString(credString.String())
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}
			ctlr := makeController(conf, t.TempDir())

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// with creds, should get expected status code
			for key, val := range tests {
				resp, _ := resty.R().SetBasicAuth(key, val).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			}

			// with invalid creds, it should fail
			resp, _ := resty.R().SetBasicAuth("chuck", "chuck").Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		}()
	})
}

func TestRatelimit(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		rate := 1
		conf.HTTP.Ratelimit = &config.RatelimitConfig{
			Rate: &rate,
		}
		ctlr := makeController(conf, t.TempDir())
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		Convey("Ratelimit", func() {
			client := resty.New()
			// first request should succeed
			resp, err := client.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			// second request back-to-back should fail
			resp, err = client.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusTooManyRequests)
		})
	})

	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		conf.HTTP.Ratelimit = &config.RatelimitConfig{
			Methods: []config.MethodRatelimitConfig{
				{
					Method: http.MethodGet,
					Rate:   1,
				},
			},
		}
		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
		Convey("Method Ratelimit", func() {
			client := resty.New()
			// first request should succeed
			resp, err := client.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			// second request back-to-back should fail
			resp, err = client.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusTooManyRequests)
		})
	})

	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		rate := 1
		conf.HTTP.Ratelimit = &config.RatelimitConfig{
			Rate: &rate, // this dominates
			Methods: []config.MethodRatelimitConfig{
				{
					Method: http.MethodGet,
					Rate:   100,
				},
			},
		}
		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()
		Convey("Global and Method Ratelimit", func() {
			client := resty.New()
			// first request should succeed
			resp, err := client.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			// second request back-to-back should fail
			resp, err = client.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusTooManyRequests)
		})
	})
}

func TestBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := makeController(conf, t.TempDir())
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e apiErr.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestBlobReferenced(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		repoName, seed := test.GenerateRandomName()
		ctlr.Log.Info().Int64("seed", seed).Msg("random seed for repoName")

		img := CreateRandomImage()

		err = UploadImage(img, baseURL, repoName, "1.0")
		So(err, ShouldBeNil)

		manifestDigest := img.ManifestDescriptor.Digest
		configDigest := img.ConfigDescriptor.Digest

		// delete manifest blob
		resp, err = resty.R().Delete(baseURL + "/v2/" + repoName + "/blobs/" + manifestDigest.String())
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		// delete config blob
		resp, err = resty.R().Delete(baseURL + "/v2/" + repoName + "/blobs/" + configDigest.String())
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		// delete manifest with manifest api method
		resp, err = resty.R().Delete(baseURL + "/v2/" + repoName + "/manifests/" + manifestDigest.String())
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// delete blob should work after manifest is deleted
		resp, err = resty.R().Delete(baseURL + "/v2/" + repoName + "/blobs/" + configDigest.String())
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
	})
}

func TestPrintTracebackOnPanic(t *testing.T) {
	Convey("Run server on unavailable port", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := makeController(conf, t.TempDir())
		cm := test.NewControllerManager(ctlr)

		cm.StartAndWait(port)
		defer cm.StopServer()

		ctlr.StoreController.SubStore = make(map[string]storageTypes.ImageStore)
		ctlr.StoreController.SubStore["/a"] = nil

		resp, err := resty.R().Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "invalid memory address or nil pointer dereference")
	})
}

func TestInterruptedBlobUpload(t *testing.T) {
	Convey("Successfully cleaning interrupted blob uploads", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		client := resty.New()
		blob := make([]byte, 200*1024*1024)
		digest := godigest.FromBytes(blob).String()

		//nolint: dupl
		Convey("Test interrupt PATCH blob upload", func() {
			s1, seed1 := test.GenerateRandomName()
			s2, seed2 := test.GenerateRandomName()
			repoName := s1 + "/" + s2
			ctlr.Log.Info().Int64("seed1", seed1).Int64("seed2", seed2).Msg("random seeds for repoName")
			resp, err := client.R().Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			loc := resp.Header().Get("Location")
			splittedLoc := strings.Split(loc, "/")
			sessionID := splittedLoc[len(splittedLoc)-1]

			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)

			// patch blob
			go func(ctx context.Context) {
				for i := 0; i < 3; i++ {
					_, _ = client.R().
						SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
						SetHeader("Content-Type", "application/octet-stream").
						SetQueryParam("digest", digest).
						SetBody(blob).
						SetContext(ctx).
						Patch(baseURL + loc)

					time.Sleep(500 * time.Millisecond)
				}
			}(ctx)

			// if the blob upload has started then interrupt by running cancel()
			for {
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(repoName, sessionID)
				if n > 0 && err == nil {
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + repoName + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		//nolint: dupl
		Convey("Test negative interrupt PATCH blob upload", func() {
			s1, seed1 := test.GenerateRandomName()
			s2, seed2 := test.GenerateRandomName()
			repoName := s1 + "/" + s2
			ctlr.Log.Info().Int64("seed1", seed1).Int64("seed2", seed2).Msg("random seeds for repoName")
			resp, err := client.R().Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			loc := resp.Header().Get("Location")
			splittedLoc := strings.Split(loc, "/")
			sessionID := splittedLoc[len(splittedLoc)-1]

			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)

			// patch blob
			go func(ctx context.Context) {
				for i := 0; i < 3; i++ {
					_, _ = client.R().
						SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
						SetHeader("Content-Type", "application/octet-stream").
						SetQueryParam("digest", digest).
						SetBody(blob).
						SetContext(ctx).
						Patch(baseURL + loc)

					time.Sleep(500 * time.Millisecond)
				}
			}(ctx)

			// if the blob upload has started then interrupt by running cancel()
			for {
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(repoName, sessionID)
				if n > 0 && err == nil {
					// cleaning blob uploads, so that zot fails to clean up, +code coverage
					err = ctlr.StoreController.DefaultStore.DeleteBlobUpload(repoName, sessionID)
					So(err, ShouldBeNil)
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + repoName + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		//nolint: dupl
		Convey("Test interrupt PUT blob upload", func() {
			s1, seed1 := test.GenerateRandomName()
			s2, seed2 := test.GenerateRandomName()
			repoName := s1 + "/" + s2
			ctlr.Log.Info().Int64("seed1", seed1).Int64("seed2", seed2).Msg("random seeds for repoName")
			resp, err := client.R().Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			loc := resp.Header().Get("Location")
			splittedLoc := strings.Split(loc, "/")
			sessionID := splittedLoc[len(splittedLoc)-1]

			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)

			// put blob
			go func(ctx context.Context) {
				for i := 0; i < 3; i++ {
					_, _ = client.R().
						SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
						SetHeader("Content-Type", "application/octet-stream").
						SetQueryParam("digest", digest).
						SetBody(blob).
						SetContext(ctx).
						Put(baseURL + loc)

					time.Sleep(500 * time.Millisecond)
				}
			}(ctx)

			// if the blob upload has started then interrupt by running cancel()
			for {
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(repoName, sessionID)
				if n > 0 && err == nil {
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to try to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + repoName + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		//nolint: dupl
		Convey("Test negative interrupt PUT blob upload", func() {
			s1, seed1 := test.GenerateRandomName()
			s2, seed2 := test.GenerateRandomName()
			repoName := s1 + "/" + s2
			ctlr.Log.Info().Int64("seed1", seed1).Int64("seed2", seed2).Msg("random seeds for repoName")
			resp, err := client.R().Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

			loc := resp.Header().Get("Location")
			splittedLoc := strings.Split(loc, "/")
			sessionID := splittedLoc[len(splittedLoc)-1]

			ctx := context.Background()
			ctx, cancel := context.WithCancel(ctx)

			// push blob
			go func(ctx context.Context) {
				for i := 0; i < 3; i++ {
					_, _ = client.R().
						SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
						SetHeader("Content-Type", "application/octet-stream").
						SetQueryParam("digest", digest).
						SetBody(blob).
						SetContext(ctx).
						Put(baseURL + loc)

					time.Sleep(500 * time.Millisecond)
				}
			}(ctx)

			// if the blob upload has started then interrupt by running cancel()
			for {
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(repoName, sessionID)
				if n > 0 && err == nil {
					// cleaning blob uploads, so that zot fails to clean up, +code coverage
					err = ctlr.StoreController.DefaultStore.DeleteBlobUpload(repoName, sessionID)
					So(err, ShouldBeNil)
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to try to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + repoName + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})
	})
}

func TestMultipleInstance(t *testing.T) {
	Convey("Negative test zot multiple instance", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		err := ctlr.Init()
		So(err, ShouldEqual, errors.ErrImgStoreNotFound)

		globalDir := t.TempDir()
		subDir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = globalDir

		subPathMap := make(map[string]config.StorageConfig)

		subPathMap["/a"] = config.StorageConfig{RootDirectory: subDir}

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		client := resty.New()

		tagResponse, err := client.R().SetBasicAuth(username, password).
			Get(baseURL + "/v2/zot-test/tags/list")
		So(err, ShouldBeNil)
		So(tagResponse.StatusCode(), ShouldEqual, http.StatusNotFound)
	})

	Convey("Test zot multiple instance", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		globalDir := t.TempDir()
		subDir := t.TempDir()
		ctlr := makeController(conf, globalDir)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		subPathMap := make(map[string]config.StorageConfig)
		subPathMap["/a"] = config.StorageConfig{RootDirectory: subDir}

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e apiErr.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})

	Convey("Test zot multiple subpath with same root directory", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		globalDir := t.TempDir()
		subDir := t.TempDir()

		ctlr := makeController(conf, globalDir)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		subPathMap := make(map[string]config.StorageConfig)
		subPathMap["/a"] = config.StorageConfig{RootDirectory: globalDir, Dedupe: true, GC: true}
		subPathMap["/b"] = config.StorageConfig{RootDirectory: subDir, Dedupe: true, GC: true}

		ctlr.Config.Storage.SubPaths = subPathMap

		err := ctlr.Init()
		So(err, ShouldNotBeNil)

		// subpath root directory does not exist.
		subPathMap["/a"] = config.StorageConfig{RootDirectory: globalDir, Dedupe: true, GC: true}
		subPathMap["/b"] = config.StorageConfig{RootDirectory: subDir, Dedupe: false, GC: true}

		ctlr.Config.Storage.SubPaths = subPathMap

		err = ctlr.Init()
		So(err, ShouldNotBeNil)

		subPathMap["/a"] = config.StorageConfig{RootDirectory: subDir, Dedupe: true, GC: true}
		subPathMap["/b"] = config.StorageConfig{RootDirectory: subDir, Dedupe: true, GC: true}

		ctlr.Config.Storage.SubPaths = subPathMap

		err = ctlr.Init()
		So(err, ShouldNotBeNil)
	})
}

func TestTLSWithBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert: ServerCert,
			Key:  ServerKey,
		}
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := makeController(conf, t.TempDir())
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without creds, should get access error
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e apiErr.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSWithBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.TLS = &config.TLSConfig{
			Cert: ServerCert,
			Key:  ServerKey,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := makeController(conf, t.TempDir())
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without creds, should still be allowed to access
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// without creds, writes should fail
		resp, err = resty.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestMutualTLSAuthWithUserPermissions(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port

		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"*"},
							Actions: []string{"read"},
						},
					},
				},
			},
		}

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		repoPolicy := conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos]

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should succeed
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(secureBaseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with creds, should get expected status code
		resp, _ = resty.R().Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// reading a repo should not get 403
		resp, err = resty.R().Get(secureBaseURL + "/v2/repo/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// without creds, writes should fail
		resp, err = resty.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// empty default authorization and give user the permission to create
		repoPolicy.Policies[0].Actions = append(repoPolicy.Policies[0].Actions, "create")
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos] = repoPolicy
		resp, err = resty.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
	})
}

func TestAuthnErrors(t *testing.T) {
	Convey("ldap CA certs fail", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		tmpDir := t.TempDir()
		tmpFile := path.Join(tmpDir, "test-file.txt")

		err := os.WriteFile(tmpFile, []byte("test"), 0o000)
		So(err, ShouldBeNil)

		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			Insecure:      true,
			Address:       LDAPAddress,
			Port:          9000,
			BaseDN:        LDAPBaseDN,
			UserAttribute: "uid",
			CACert:        tmpFile,
		}).SetBindDN(LDAPBindDN).SetBindPassword(LDAPBindPassword)

		ctlr := makeController(conf, t.TempDir())

		So(func() {
			api.AuthHandler(ctlr)
		}, ShouldPanic)

		err = os.Chmod(tmpFile, 0o644)
		So(err, ShouldBeNil)
	})

	Convey("ldap CA certs is empty", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		tmpDir := t.TempDir()
		tmpFile := path.Join(tmpDir, "test-file.txt")
		err := os.WriteFile(tmpFile, []byte(""), 0o600)
		So(err, ShouldBeNil)

		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			Insecure:      true,
			Address:       LDAPAddress,
			Port:          9000,
			BaseDN:        LDAPBaseDN,
			UserAttribute: "uid",
			CACert:        tmpFile,
		}).SetBindDN(LDAPBindDN).SetBindPassword(LDAPBindPassword)

		ctlr := makeController(conf, t.TempDir())

		So(func() {
			api.AuthHandler(ctlr)
		}, ShouldPanic)

		So(err, ShouldBeNil)
	})

	Convey("ldap CA certs is empty", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		conf.HTTP.Auth.LDAP = (&config.LDAPConfig{
			Insecure:      true,
			Address:       LDAPAddress,
			Port:          9000,
			BaseDN:        LDAPBaseDN,
			UserAttribute: "uid",
			CACert:        CACert,
		}).SetBindDN(LDAPBindDN).SetBindPassword(LDAPBindPassword)

		ctlr := makeController(conf, t.TempDir())

		So(func() {
			api.AuthHandler(ctlr)
		}, ShouldNotPanic)
	})

	Convey("Htpasswd file fail", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		tmpDir := t.TempDir()
		tmpFile := path.Join(tmpDir, "test-file.txt")

		err := os.WriteFile(tmpFile, []byte("test"), 0o000)
		So(err, ShouldBeNil)

		conf.HTTP.Auth.HTPasswd = config.AuthHTPasswd{
			Path: tmpFile,
		}

		ctlr := makeController(conf, t.TempDir())

		So(func() {
			api.AuthHandler(ctlr)
		}, ShouldPanic)

		err = os.Chmod(tmpFile, 0o644)
		So(err, ShouldBeNil)
	})

	Convey("NewRelyingPartyGithub fail", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		tmpDir := t.TempDir()
		tmpFile := path.Join(tmpDir, "test-file.txt")

		err := os.WriteFile(tmpFile, []byte("test"), 0o000)
		So(err, ShouldBeNil)

		conf.HTTP.Auth.HTPasswd = config.AuthHTPasswd{
			Path: tmpFile,
		}

		So(func() {
			api.NewRelyingPartyGithub(conf, "prov", log.NewLogger("debug", ""))
		}, ShouldPanic)

		err = os.Chmod(tmpFile, 0o644)
		So(err, ShouldBeNil)
	})
}

func TestMutualTLSAuthWithoutCN(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile("../../test/data/noidentity/ca.crt")
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		port := test.GetFreePort()
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port

		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   "../../test/data/noidentity/server.cert",
			Key:    "../../test/data/noidentity/server.key",
			CACert: "../../test/data/noidentity/ca.crt",
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{"*"},
							Actions: []string{"read"},
						},
					},
				},
			},
		}

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/noidentity/client.cert", "../../test/data/noidentity/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without TLS mutual auth setup should get certificate error
		resp, _ := resty.R().Get(secureBaseURL + "/v2/_catalog")
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestTLSMutualAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, should get conn error
		_, err = resty.R().Get(secureBaseURL)
		So(err, ShouldNotBeNil)

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		// with creds but without certs, should get conn error
		_, err = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(err, ShouldNotBeNil)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should succeed
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTSLFailedReadingOfCACert(t *testing.T) {
	Convey("no permissions", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		err := os.Chmod(CACert, 0o000)
		defer func() {
			err := os.Chmod(CACert, 0o644)
			So(err, ShouldBeNil)
		}()
		So(err, ShouldBeNil)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctlr := makeController(conf, t.TempDir())

		err = ctlr.Init()
		So(err, ShouldBeNil)

		errChan := make(chan error, 1)
		go func() {
			err = ctlr.Run()
			errChan <- err
		}()

		testTimeout := false

		select {
		case err := <-errChan:
			So(err, ShouldNotBeNil)
		case <-ctx.Done():
			testTimeout = true
			cancel()
		}

		So(testTimeout, ShouldBeFalse)
	})

	Convey("empty CACert", t, func() {
		badCACert := filepath.Join(t.TempDir(), "badCACert")
		err := os.WriteFile(badCACert, []byte(""), 0o600)
		So(err, ShouldBeNil)

		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: badCACert,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ctlr := makeController(conf, t.TempDir())

		err = ctlr.Init()
		So(err, ShouldBeNil)

		errChan := make(chan error, 1)
		go func() {
			err = ctlr.Run()
			errChan <- err
		}()

		testTimeout := false

		select {
		case err := <-errChan:
			So(err, ShouldNotBeNil)
		case <-ctx.Done():
			testTimeout = true
			cancel()
		}

		So(testTimeout, ShouldBeFalse)
	})
}

func TestTLSMutualAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, reads are allowed
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		// with creds but without certs, reads are allowed
		resp, err = resty.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// without creds, writes should fail
		resp, err = resty.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should succeed
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSMutualAndBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		ctlr := makeController(conf, t.TempDir())
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, should fail
		_, err = resty.R().Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should get access error
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSMutualAndBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		secureBaseURL := test.GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := makeController(conf, t.TempDir())
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, should fail
		_, err = resty.R().Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, reads should succeed
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with only client certs, writes should fail
		resp, err = resty.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

type testLDAPServer struct {
	server *vldap.Server
	quitCh chan bool
}

func newTestLDAPServer() *testLDAPServer {
	ldaps := &testLDAPServer{}
	quitCh := make(chan bool)
	server := vldap.NewServer()
	server.QuitChannel(quitCh)
	server.BindFunc("", ldaps)
	server.SearchFunc("", ldaps)
	ldaps.server = server
	ldaps.quitCh = quitCh

	return ldaps
}

func (l *testLDAPServer) Start(port int) {
	addr := fmt.Sprintf("%s:%d", LDAPAddress, port)

	go func() {
		if err := l.server.ListenAndServe(addr); err != nil {
			panic(err)
		}
	}()

	for {
		_, err := net.Dial("tcp", addr)
		if err == nil {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (l *testLDAPServer) Stop() {
	l.quitCh <- true
}

func (l *testLDAPServer) Bind(bindDN, bindSimplePw string, conn net.Conn) (vldap.LDAPResultCode, error) {
	if bindSimplePw == "" {
		switch bindDN {
		case "bad-user", "cn=fail-user-bind,ou=test":
			return vldap.LDAPResultInvalidCredentials, errors.ErrInvalidCred
		default:
			return vldap.LDAPResultSuccess, nil
		}
	}

	if (bindDN == LDAPBindDN && bindSimplePw == LDAPBindPassword) ||
		(bindDN == fmt.Sprintf("cn=%s,%s", username, LDAPBaseDN) && bindSimplePw == password) {
		return vldap.LDAPResultSuccess, nil
	}

	return vldap.LDAPResultInvalidCredentials, errors.ErrInvalidCred
}

func (l *testLDAPServer) Search(boundDN string, req vldap.SearchRequest,
	conn net.Conn,
) (vldap.ServerSearchResult, error) {
	if req.Filter == "(uid=fail-user-bind)" {
		return vldap.ServerSearchResult{
			Entries: []*vldap.Entry{
				{
					DN: fmt.Sprintf("cn=%s,%s", "fail-user-bind", LDAPBaseDN),
					Attributes: []*vldap.EntryAttribute{
						{
							Name:   "memberOf",
							Values: []string{group},
						},
					},
				},
			},
			ResultCode: vldap.LDAPResultSuccess,
		}, nil
	}

	check := fmt.Sprintf("(uid=%s)", username)

	if check == req.Filter {
		return vldap.ServerSearchResult{
			Entries: []*vldap.Entry{
				{
					DN: fmt.Sprintf("cn=%s,%s", username, LDAPBaseDN),
					Attributes: []*vldap.EntryAttribute{
						{
							Name:   "memberOf",
							Values: []string{group},
						},
					},
				},
			},
			ResultCode: vldap.LDAPResultSuccess,
		}, nil
	}

	return vldap.ServerSearchResult{}, nil
}

func TestBasicAuthWithLDAP(t *testing.T) {
	Convey("Make a new controller", t, func() {
		l := newTestLDAPServer()
		port := test.GetFreePort()
		ldapPort, err := strconv.Atoi(port)
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		port = test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			LDAP: (&config.LDAPConfig{
				Insecure:      true,
				Address:       LDAPAddress,
				Port:          ldapPort,
				BaseDN:        LDAPBaseDN,
				UserAttribute: "uid",
			}).SetBindDN(LDAPBindDN).SetBindPassword(LDAPBindPassword),
		}
		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e apiErr.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// missing password
		resp, _ = resty.R().SetBasicAuth(username, "").Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestBasicAuthWithReloadedCredentials(t *testing.T) {
	Convey("Start server with bad credentials", t, func() {
		l := newTestLDAPServer()
		ldapPort, err := strconv.Atoi(test.GetFreePort())
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		tempDir := t.TempDir()
		ldapConfigContent := fmt.Sprintf(`{"BindDN": "%s", "BindPassword": "%s"}`, LDAPBindDN, LDAPBindPassword)
		ldapConfigPath := filepath.Join(tempDir, "ldap.json")

		err = os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		configTemplate := `
		{
			"Storage": {
				"rootDirectory": "%s"
			},
			"HTTP": {
				"Address": "%s",
				"Port": "%s",
				"Auth": {
					"LDAP": {
						"CredentialsFile":    "%s",
						"UserAttribute":      "uid",
						"BaseDN": 			  "LDAPBaseDN",
						"UserGroupAttribute": "memberOf",
						"Insecure":           true,
						"Address":            "%v",
						"Port":               %v
					}
				}
			}
		}
		`

		configStr := fmt.Sprintf(configTemplate,
			tempDir, "127.0.0.1", port, ldapConfigPath, LDAPAddress, ldapPort)

		configPath := filepath.Join(tempDir, "config.json")
		err = os.WriteFile(configPath, []byte(configStr), 0o600)
		So(err, ShouldBeNil)

		conf := config.New()
		err = server.LoadConfiguration(conf, configPath)
		So(err, ShouldBeNil)

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		hotReloader, err := server.NewHotReloader(ctlr, configPath, ldapConfigPath)
		So(err, ShouldBeNil)

		hotReloader.Start()

		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()
		time.Sleep(time.Second * 2)

		// test if the credentials work
		resp, _ := resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		newLdapConfigContent := `{"BindDN": "NewBindDB", "BindPassword": "NewBindPassword"}`

		err = os.WriteFile(ldapConfigPath, []byte(newLdapConfigContent), 0o600)
		So(err, ShouldBeNil)

		for i := 0; i < 10; i++ {
			// test if the credentials don't work
			resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)

			if resp.StatusCode() != http.StatusOK {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		So(resp.StatusCode(), ShouldNotEqual, http.StatusOK)

		err = os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		for i := 0; i < 10; i++ {
			// test if the credentials don't work
			resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)
			if resp.StatusCode() == http.StatusOK {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// change the file
		changedDir := t.TempDir()
		changedLdapConfigPath := filepath.Join(changedDir, "ldap.json")

		err = os.WriteFile(changedLdapConfigPath, []byte(newLdapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr = fmt.Sprintf(configTemplate,
			tempDir, "127.0.0.1", port, changedLdapConfigPath, LDAPAddress, ldapPort)

		err = os.WriteFile(configPath, []byte(configStr), 0o600)
		So(err, ShouldBeNil)

		for i := 0; i < 10; i++ {
			// test if the credentials don't work
			resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)

			if resp.StatusCode() != http.StatusOK {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		So(resp.StatusCode(), ShouldNotEqual, http.StatusOK)

		err = os.WriteFile(changedLdapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		for i := 0; i < 10; i++ {
			// test if the credentials don't work
			resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)
			if resp.StatusCode() == http.StatusOK {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// make it panic
		badLDAPFilePath := filepath.Join(changedDir, "ldap222.json")

		err = os.WriteFile(badLDAPFilePath, []byte(newLdapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr = fmt.Sprintf(configTemplate,
			tempDir, "127.0.0.1", port, changedLdapConfigPath, LDAPAddress, ldapPort)

		err = os.WriteFile(configPath, []byte(configStr), 0o600)
		So(err, ShouldBeNil)

		// Loading the config should fail because the file doesn't exist so the old credentials
		// are still up and working fine.

		for i := 0; i < 10; i++ {
			// test if the credentials don't work
			resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)
			if resp.StatusCode() == http.StatusOK {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestLDAPWithoutCreds(t *testing.T) {
	Convey("Make a new LDAP server", t, func() {
		l := newTestLDAPServer()
		port := test.GetFreePort()
		ldapPort, err := strconv.Atoi(port)
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		Convey("Server credentials succed ldap auth", func() {
			port = test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf := config.New()
			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				LDAP: (&config.LDAPConfig{
					Insecure:      true,
					Address:       LDAPAddress,
					Port:          ldapPort,
					BaseDN:        LDAPBaseDN,
					UserAttribute: "uid",
				}).SetBindDN("anonym"),
			}
			ctlr := makeController(conf, t.TempDir())

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			// without creds, should get access error
			resp, err := resty.R().Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			var e apiErr.Error
			err = json.Unmarshal(resp.Body(), &e)
			So(err, ShouldBeNil)

			resp, _ = resty.R().SetBasicAuth(username, "").Get(baseURL)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, _ = resty.R().SetBasicAuth(username, "").Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Server credentials fail ldap auth", func() {
			port = test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf := config.New()
			conf.HTTP.Port = port
			conf.HTTP.Auth = &config.AuthConfig{
				LDAP: (&config.LDAPConfig{
					Insecure:      true,
					Address:       LDAPAddress,
					Port:          ldapPort,
					BaseDN:        LDAPBaseDN,
					UserAttribute: "uid",
				}).SetBindDN("bad-user"),
			}
			ctlr := makeController(conf, t.TempDir())

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			resp, _ := resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})
	})
}

func TestBasicAuthWithLDAPFromFile(t *testing.T) {
	Convey("Make a new controller", t, func() {
		l := newTestLDAPServer()
		port := test.GetFreePort()
		ldapPort, err := strconv.Atoi(port)
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		port = test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		tempDir := t.TempDir()

		ldapConfigContent := fmt.Sprintf(`
		{
			"BindDN":             "%v",
			"BindPassword":       "%v"
		}`, LDAPBindDN, LDAPBindPassword)

		ldapConfigPath := filepath.Join(tempDir, "ldap.json")

		err = os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr := fmt.Sprintf(`
		{
			"Storage": {
				"RootDirectory": "%s"
			},
			"HTTP": {
				"Address": "%s",
				"Port": "%s",
				"Auth": {
					"LDAP": {
						"CredentialsFile":     "%s",
						"BaseDN":             "%v",
						"UserAttribute":      "uid",
						"UserGroupAttribute": "memberOf",
						"Insecure":           true,
						"Address":            "%v",
						"Port":               %v
					}
				}
			}
		}`, tempDir, "127.0.0.1", port, ldapConfigPath, LDAPBaseDN, LDAPAddress, ldapPort)

		configPath := filepath.Join(tempDir, "config.json")

		err = os.WriteFile(configPath, []byte(configStr), 0o0600)
		So(err, ShouldBeNil)

		server := server.NewServerRootCmd()
		server.SetArgs([]string{"serve", configPath})
		go func() {
			err := server.Execute()
			if err != nil {
				panic(err)
			}
		}()

		test.WaitTillServerReady(baseURL)

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e apiErr.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// missing password
		resp, _ = resty.R().SetBasicAuth(username, "").Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestLDAPConfigErrors(t *testing.T) {
	const configTemplate = `
	{
		"Storage": {
			"RootDirectory": "%s"
		},
		"HTTP": {
			"Address": "%s",
			"Port": "%s",
			"Auth": {
				"LDAP": {
					"CredentialsFile":    "%s",
					"BaseDN":             "%v",
					"UserAttribute":      "%v",
					"UserGroupAttribute": "memberOf",
					"Insecure":           true,
					"Address":            "%v",
					"Port":               %v
				}
			}
		}
	}`

	Convey("bad credentials file", t, func() {
		conf := config.New()
		tempDir := t.TempDir()
		ldapPort := 9000
		userAttribute := ""

		ldapConfigContent := `bad-json`
		ldapConfigPath := filepath.Join(tempDir, "ldap.json")
		err := os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr := fmt.Sprintf(configTemplate,
			tempDir, "127.0.0.1", "8000", ldapConfigPath, LDAPBaseDN, userAttribute, LDAPAddress, ldapPort)
		configPath := filepath.Join(tempDir, "config.json")
		err = os.WriteFile(configPath, []byte(configStr), 0o0600)
		So(err, ShouldBeNil)

		err = server.LoadConfiguration(conf, configPath)
		So(err, ShouldNotBeNil)
	})

	Convey("UserAttribute  is empty", t, func() {
		conf := config.New()
		tempDir := t.TempDir()
		ldapPort := 9000
		userAttribute := ""

		ldapConfigContent := fmt.Sprintf(`
		{
			"BindDN":             "%v",
			"BindPassword":       "%v"
		}`, LDAPBindDN, LDAPBindPassword)
		ldapConfigPath := filepath.Join(tempDir, "ldap.json")
		err := os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr := fmt.Sprintf(configTemplate,
			tempDir, "127.0.0.1", "8000", ldapConfigPath, LDAPBaseDN, userAttribute, LDAPAddress, ldapPort)
		configPath := filepath.Join(tempDir, "config.json")
		err = os.WriteFile(configPath, []byte(configStr), 0o0600)
		So(err, ShouldBeNil)

		err = server.LoadConfiguration(conf, configPath)
		So(err, ShouldNotBeNil)
	})

	Convey("address is empty", t, func() {
		conf := config.New()
		tempDir := t.TempDir()
		ldapPort := 9000
		userAttribute := "uid"

		ldapConfigContent := fmt.Sprintf(`
		{
			"BindDN":             "%v",
			"BindPassword":       "%v"
		}`, LDAPBindDN, LDAPBindPassword)
		ldapConfigPath := filepath.Join(tempDir, "ldap.json")
		err := os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr := fmt.Sprintf(configTemplate,
			tempDir, "127.0.0.1", "8000", ldapConfigPath, LDAPBaseDN, userAttribute, "", ldapPort)
		configPath := filepath.Join(tempDir, "config.json")
		err = os.WriteFile(configPath, []byte(configStr), 0o0600)
		So(err, ShouldBeNil)

		err = server.LoadConfiguration(conf, configPath)
		So(err, ShouldNotBeNil)
	})

	Convey("BaseDN is empty", t, func() {
		conf := config.New()
		tempDir := t.TempDir()
		ldapPort := 9000
		userAttribute := "uid"

		ldapConfigContent := fmt.Sprintf(`
		{
			"BindDN":             "%v",
			"BindPassword":       "%v"
		}`, LDAPBindDN, LDAPBindPassword)
		ldapConfigPath := filepath.Join(tempDir, "ldap.json")
		err := os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr := fmt.Sprintf(configTemplate,
			tempDir, "127.0.0.1", "8000", ldapConfigPath, "", userAttribute, LDAPAddress, ldapPort)
		configPath := filepath.Join(tempDir, "config.json")
		err = os.WriteFile(configPath, []byte(configStr), 0o0600)
		So(err, ShouldBeNil)

		err = server.LoadConfiguration(conf, configPath)
		So(err, ShouldNotBeNil)
	})
}

func TestGroupsPermissionsForLDAP(t *testing.T) {
	Convey("Make a new controller", t, func() {
		l := newTestLDAPServer()
		port := test.GetFreePort()
		ldapPort, err := strconv.Atoi(port)
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		port = test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		tempDir := t.TempDir()

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			LDAP: (&config.LDAPConfig{
				Insecure:           true,
				Address:            LDAPAddress,
				Port:               ldapPort,
				BaseDN:             LDAPBaseDN,
				UserAttribute:      "uid",
				UserGroupAttribute: "memberOf",
			}).SetBindDN(LDAPBindDN).SetBindPassword(LDAPBindPassword),
		}

		repoName, seed := test.GenerateRandomName()
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Groups: config.Groups{
				group: {
					Users: []string{username},
				},
			},
			Repositories: config.Repositories{
				repoName: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Groups:  []string{group},
							Actions: []string{"read", "create"},
						},
					},
					DefaultPolicy: []string{},
				},
			},
			AdminPolicy: config.Policy{
				Users:   []string{},
				Actions: []string{},
			},
		}

		ctlr := makeController(conf, tempDir)
		ctlr.Log.Info().Int64("seed", seed).Msg("random seed for repoName")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		img := CreateDefaultImage()

		err = UploadImageWithBasicAuth(
			img, baseURL, repoName, img.DigestStr(),
			username, password)
		So(err, ShouldBeNil)
	})
}

func TestLDAPConfigFromFile(t *testing.T) {
	Convey("Make a new controller", t, func() {
		l := newTestLDAPServer()
		port := test.GetFreePort()
		ldapPort, err := strconv.Atoi(port)
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		port = test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		tempDir := t.TempDir()

		ldapConfigContent := fmt.Sprintf(`
		{
			"bindDN":             "%v",
			"bindPassword":       "%v"
		}`, LDAPBindDN, LDAPBindPassword)

		ldapConfigPath := filepath.Join(tempDir, "ldap.json")

		err = os.WriteFile(ldapConfigPath, []byte(ldapConfigContent), 0o600)
		So(err, ShouldBeNil)

		configStr := fmt.Sprintf(`
		{
			"Storage": {
				"RootDirectory": "%s"
			},
			"HTTP": {
				"Address": "%s",
				"Port": "%s",
				"Auth": {
					"LDAP": {
						"CredentialsFile": "%s",
						"BaseDN":             "%v",
						"UserAttribute":      "uid",
						"UserGroupAttribute": "memberOf",
						"Insecure":           true,
						"Address":            "%v",
						"Port":               %v
					}
				},
				"AccessControl": {
					"repositories": {
						"test-ldap": {
							"Policies": [
								{
									"Users": null,
									"Actions": [
										"read",
										"create"
									],
									"Groups": [
										"test"
									]
								}
							]
						}
					},
					"Groups": {
						"test": {
							"Users": [
								"test"
							]
						}
					}
				}
			}
		}`, tempDir, "127.0.0.1", port, ldapConfigPath, LDAPBaseDN, LDAPAddress, ldapPort)

		configPath := filepath.Join(tempDir, "config.json")

		err = os.WriteFile(configPath, []byte(configStr), 0o0600)
		So(err, ShouldBeNil)

		server := server.NewServerRootCmd()
		server.SetArgs([]string{"serve", configPath})
		go func() {
			err := server.Execute()
			if err != nil {
				panic(err)
			}
		}()

		test.WaitTillServerReady(baseURL)

		repo := "test-ldap"
		img := CreateDefaultImage()

		err = UploadImageWithBasicAuth(img, baseURL, repo, img.DigestStr(), username, password)
		So(err, ShouldBeNil)
	})
}

func TestLDAPFailures(t *testing.T) {
	Convey("Make a LDAP conn", t, func() {
		l := newTestLDAPServer()
		port := test.GetFreePort()
		ldapPort, err := strconv.Atoi(port)
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		Convey("Empty config", func() {
			lc := &api.LDAPClient{}
			err := lc.Connect()
			So(err, ShouldNotBeNil)
		})

		Convey("Basic connectivity config", func() {
			lc := &api.LDAPClient{
				Host: LDAPAddress,
				Port: ldapPort,
			}
			err := lc.Connect()
			So(err, ShouldNotBeNil)
		})

		Convey("Basic TLS connectivity config", func() {
			lc := &api.LDAPClient{
				Host:   LDAPAddress,
				Port:   ldapPort,
				UseSSL: true,
			}
			err := lc.Connect()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestLDAPClient(t *testing.T) {
	Convey("LDAP Client", t, func() {
		l := newTestLDAPServer()
		port := test.GetFreePort()
		ldapPort, err := strconv.Atoi(port)
		So(err, ShouldBeNil)
		l.Start(ldapPort)
		defer l.Stop()

		// bad server credentials
		lClient := &api.LDAPClient{
			Host:         LDAPAddress,
			Port:         ldapPort,
			BindDN:       "bad-user",
			BindPassword: "bad-pass",
			SkipTLS:      true,
		}

		_, _, _, err = lClient.Authenticate("bad-user", "bad-pass")
		So(err, ShouldNotBeNil)

		// bad credentials with anonymous authentication
		lClient = &api.LDAPClient{
			Host:         LDAPAddress,
			Port:         ldapPort,
			BindDN:       "bad-user",
			BindPassword: "",
			SkipTLS:      true,
		}

		_, _, _, err = lClient.Authenticate("user", "")
		So(err, ShouldNotBeNil)

		// bad user credentials with anonymous authentication
		lClient = &api.LDAPClient{
			Host:         LDAPAddress,
			Port:         ldapPort,
			BindDN:       LDAPBindDN,
			BindPassword: LDAPBindPassword,
			Base:         LDAPBaseDN,
			UserFilter:   "(uid=%s)",
			SkipTLS:      true,
		}

		_, _, _, err = lClient.Authenticate("fail-user-bind", "")
		So(err, ShouldNotBeNil)

		// bad user credentials with anonymous authentication
		lClient = &api.LDAPClient{
			Host:         LDAPAddress,
			Port:         ldapPort,
			BindDN:       LDAPBindDN,
			BindPassword: LDAPBindPassword,
			Base:         LDAPBaseDN,
			UserFilter:   "(uid=%s)",
			SkipTLS:      true,
		}

		_, _, _, err = lClient.Authenticate("fail-user-bind", "pass")
		So(err, ShouldNotBeNil)
	})
}

func TestBearerAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authTestServer := authutils.MakeAuthTestServer(ServerKey, UnauthorizedNamespace)
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
		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader := authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
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

		// trigger decode error
		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", "invalidToken")).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		resp, err = resty.R().SetHeader("Authorization",
			fmt.Sprintf("Bearer %s", goodToken.AccessToken)).Options(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		s1, seed1 := test.GenerateRandomName()
		s2, seed2 := test.GenerateRandomName()
		repoName := s1 + "/" + s2
		ctlr.Log.Info().Int64("seed1", seed1).Int64("seed2", seed2).Msg("random seeds for repoName")
		resp, err = resty.R().Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
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
			Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := resp.Header().Get("Location")

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
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
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(baseURL + "/v2/" + repoName + "/tags/list")
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
			Get(baseURL + "/v2/" + repoName + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().
			Post(baseURL + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
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
			Post(baseURL + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestBearerAuthWrongAuthorizer(t *testing.T) {
	Convey("Make a new authorizer", t, func() {
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    "bla",
				Realm:   "blabla",
				Service: "blablabla",
			},
		}
		ctlr := makeController(conf, t.TempDir())

		So(func() {
			api.AuthHandler(ctlr)
		}, ShouldPanic)
	})
}

func TestBearerAuthWithAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authTestServer := authutils.MakeAuthTestServer(ServerKey, UnauthorizedNamespace)
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
		ctlr := makeController(conf, t.TempDir())

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

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

		s1, seed1 := test.GenerateRandomName()
		s2, seed2 := test.GenerateRandomName()
		repoName := s1 + "/" + s2
		ctlr.Log.Info().Int64("seed1", seed1).Int64("seed2", seed2).Msg("random seeds for repoName")
		resp, err = resty.R().Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
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
			Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := resp.Header().Get("Location")

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
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
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(baseURL + "/v2/" + repoName + "/tags/list")
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
			Get(baseURL + "/v2/" + repoName + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().
			Post(baseURL + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
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
			Post(baseURL + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestNewRelyingPartyOIDC(t *testing.T) {
	Convey("Test NewRelyingPartyOIDC", t, func() {
		conf := config.New()

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

		conf.HTTP.Auth = &config.AuthConfig{
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email"},
					},
				},
			},
		}

		Convey("provider not found in config", func() {
			So(func() { _ = api.NewRelyingPartyOIDC(conf, "notDex", log.NewLogger("debug", "")) }, ShouldPanic)
		})

		Convey("key path not found on disk", func() {
			oidcProviderCfg := conf.HTTP.Auth.OpenID.Providers["oidc"]
			oidcProviderCfg.KeyPath = "path/to/file"
			conf.HTTP.Auth.OpenID.Providers["oidc"] = oidcProviderCfg

			So(func() { _ = api.NewRelyingPartyOIDC(conf, "oidc", log.NewLogger("debug", "")) }, ShouldPanic)
		})

		Convey("https callback", func() {
			conf.HTTP.TLS = &config.TLSConfig{
				Cert: ServerCert,
				Key:  ServerKey,
			}

			rp := api.NewRelyingPartyOIDC(conf, "oidc", log.NewLogger("debug", ""))
			So(rp, ShouldNotBeNil)
		})

		Convey("no client secret in config", func() {
			oidcProvider := conf.HTTP.Auth.OpenID.Providers["oidc"]
			oidcProvider.ClientSecret = ""
			conf.HTTP.Auth.OpenID.Providers["oidc"] = oidcProvider

			rp := api.NewRelyingPartyOIDC(conf, "oidc", log.NewLogger("debug", ""))
			So(rp, ShouldNotBeNil)
		})

		Convey("provider issuer unreachable", func() {
			oidcProvider := conf.HTTP.Auth.OpenID.Providers["oidc"]
			oidcProvider.Issuer = ""
			conf.HTTP.Auth.OpenID.Providers["oidc"] = oidcProvider

			So(func() { _ = api.NewRelyingPartyOIDC(conf, "oidc", log.NewLogger("debug", "")) }, ShouldPanic)
		})
	})
}

func TestOpenIDMiddleware(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	defaultVal := true

	conf := config.New()
	conf.HTTP.Port = port

	testCases := []struct {
		testCaseName string
		address      string
		externalURL  string
	}{
		{
			address:      "0.0.0.0",
			externalURL:  fmt.Sprintf("http://%s", net.JoinHostPort(conf.HTTP.Address, conf.HTTP.Port)),
			testCaseName: "with ExternalURL provided in config",
		},
		{
			address:      "127.0.0.1",
			externalURL:  "",
			testCaseName: "without ExternalURL provided in config",
		},
	}

	// need a username different than ldap one, to test both logic
	htpasswdUsername, seedUser := test.GenerateRandomString()
	htpasswdPassword, seedPass := test.GenerateRandomString()
	htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(htpasswdUsername, htpasswdPassword))

	defer os.Remove(htpasswdPath)

	ldapServer := newTestLDAPServer()
	port = test.GetFreePort()

	ldapPort, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}

	ldapServer.Start(ldapPort)
	defer ldapServer.Stop()

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
	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd: config.AuthHTPasswd{
			Path: htpasswdPath,
		},
		LDAP: (&config.LDAPConfig{
			Insecure:      true,
			Address:       LDAPAddress,
			Port:          ldapPort,
			BaseDN:        LDAPBaseDN,
			UserAttribute: "uid",
		}).SetBindDN(LDAPBindDN).SetBindPassword(LDAPBindPassword),
		OpenID: &config.OpenIDConfig{
			Providers: map[string]config.OpenIDProviderConfig{
				"oidc": {
					ClientID:     mockOIDCConfig.ClientID,
					ClientSecret: mockOIDCConfig.ClientSecret,
					KeyPath:      "",
					Issuer:       mockOIDCConfig.Issuer,
					Scopes:       []string{"openid", "email"},
				},
				// just for the constructor coverage
				"github": {
					ClientID:     mockOIDCConfig.ClientID,
					ClientSecret: mockOIDCConfig.ClientSecret,
					KeyPath:      "",
					Issuer:       mockOIDCConfig.Issuer,
					Scopes:       []string{"openid", "email"},
				},
			},
		},
	}

	searchConfig := &extconf.SearchConfig{
		BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
	}

	// UI is enabled because we also want to test access on the mgmt route
	uiConfig := &extconf.UIConfig{
		BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
	}

	conf.Extensions = &extconf.ExtensionConfig{
		Search: searchConfig,
		UI:     uiConfig,
	}

	ctlr := api.NewController(conf)
	ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

	for _, testcase := range testCases {
		t.Run(testcase.testCaseName, func(t *testing.T) {
			Convey("make controller", t, func() {
				dir := t.TempDir()

				ctlr.Config.Storage.RootDirectory = dir
				ctlr.Config.HTTP.ExternalURL = testcase.externalURL
				ctlr.Config.HTTP.Address = testcase.address
				cm := test.NewControllerManager(ctlr)

				cm.StartServer()
				defer cm.StopServer()
				test.WaitTillServerReady(baseURL)

				Convey("browser client requests", func() {
					Convey("login with no provider supplied", func() {
						client := resty.New()
						client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
						// first login user
						resp, err := client.R().
							SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
							SetQueryParam("provider", "unknown").
							Get(baseURL + constants.LoginPath)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
					})

					//nolint: dupl
					Convey("make sure sessions are not used without UI header value", func() {
						sessionsNo, err := getNumberOfSessions(conf.Storage.RootDirectory)
						So(err, ShouldBeNil)
						So(sessionsNo, ShouldEqual, 0)

						client := resty.New()

						// without header should not create session
						resp, err := client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						sessionsNo, err = getNumberOfSessions(conf.Storage.RootDirectory)
						So(err, ShouldBeNil)
						So(sessionsNo, ShouldEqual, 0)

						client.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

						resp, err = client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						sessionsNo, err = getNumberOfSessions(conf.Storage.RootDirectory)
						So(err, ShouldBeNil)
						So(sessionsNo, ShouldEqual, 1)

						// set cookies
						client.SetCookies(resp.Cookies())

						// should get same cookie
						resp, err = client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						sessionsNo, err = getNumberOfSessions(conf.Storage.RootDirectory)
						So(err, ShouldBeNil)
						So(sessionsNo, ShouldEqual, 1)

						resp, err = client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).
							Get(baseURL + constants.FullMgmt)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						client.SetCookies(resp.Cookies())

						// call endpoint with session, without credentials, (added to client after previous request)
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						resp, err = client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						sessionsNo, err = getNumberOfSessions(conf.Storage.RootDirectory)
						So(err, ShouldBeNil)
						So(sessionsNo, ShouldEqual, 1)
					})

					Convey("login with openid and get catalog with session", func() {
						client := resty.New()
						client.SetRedirectPolicy(test.CustomRedirectPolicy(20))
						client.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

						Convey("with callback_ui value provided", func() {
							// first login user
							resp, err := client.R().
								SetQueryParam("provider", "oidc").
								SetQueryParam("callback_ui", baseURL+"/v2/").
								Get(baseURL + constants.LoginPath)
							So(err, ShouldBeNil)
							So(resp, ShouldNotBeNil)
							So(resp.StatusCode(), ShouldEqual, http.StatusOK)
						})

						// first login user
						resp, err := client.R().
							SetQueryParam("provider", "oidc").
							Get(baseURL + constants.LoginPath)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

						client.SetCookies(resp.Cookies())

						// call endpoint with session (added to client after previous request)
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						// logout with options method for coverage
						resp, err = client.R().
							Options(baseURL + constants.LogoutPath)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)

						// logout user
						resp, err = client.R().
							Post(baseURL + constants.LogoutPath)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						// calling endpoint should fail with unauthorized access
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
					})

					//nolint: dupl
					Convey("login with basic auth(htpasswd) and get catalog with session", func() {
						client := resty.New()
						client.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

						// without creds, should get access error
						resp, err := client.R().Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
						var e apiErr.Error
						err = json.Unmarshal(resp.Body(), &e)
						So(err, ShouldBeNil)

						// first login user
						// with creds, should get expected status code
						resp, err = client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).Get(baseURL)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						resp, err = client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						resp, err = client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).
							Get(baseURL + constants.FullMgmt)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						client.SetCookies(resp.Cookies())

						// call endpoint with session, without credentials, (added to client after previous request)
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						resp, err = client.R().
							Get(baseURL + constants.FullMgmt)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						// logout user
						resp, err = client.R().
							Post(baseURL + constants.LogoutPath)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						// calling endpoint should fail with unauthorized access
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
					})

					//nolint: dupl
					Convey("login with ldap and get catalog", func() {
						client := resty.New()
						client.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

						// without creds, should get access error
						resp, err := client.R().Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
						var e apiErr.Error
						err = json.Unmarshal(resp.Body(), &e)
						So(err, ShouldBeNil)

						// first login user
						// with creds, should get expected status code
						resp, err = client.R().SetBasicAuth(username, password).Get(baseURL)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						resp, err = client.R().SetBasicAuth(username, password).Get(baseURL + "/v2/")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						resp, err = client.R().SetBasicAuth(username, password).
							Get(baseURL + constants.FullMgmt)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						client.SetCookies(resp.Cookies())

						// call endpoint with session, without credentials, (added to client after previous request)
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						resp, err = client.R().
							Get(baseURL + constants.FullMgmt)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						// logout user
						resp, err = client.R().
							Post(baseURL + constants.LogoutPath)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						// calling endpoint should fail with unauthorized access
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
					})

					Convey("unauthenticated catalog request", func() {
						client := resty.New()

						// mgmt should work both unauthenticated and authenticated
						resp, err := client.R().
							Get(baseURL + constants.FullMgmt)
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusOK)

						// call endpoint without session
						resp, err = client.R().
							Get(baseURL + "/v2/_catalog")
						So(err, ShouldBeNil)
						So(resp, ShouldNotBeNil)
						So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
					})
				})
			})
		})
	}
}

func TestIsOpenIDEnabled(t *testing.T) {
	Convey("make oidc server", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

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

		rootDir := t.TempDir()

		Convey("Only OAuth2 provided", func() {
			mockOIDCConfig := mockOIDCServer.Config()
			conf.HTTP.Auth = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"github": {
							ClientID:     mockOIDCConfig.ClientID,
							ClientSecret: mockOIDCConfig.ClientSecret,
							KeyPath:      "",
							Issuer:       mockOIDCConfig.Issuer,
							Scopes:       []string{"email", "groups"},
						},
					},
				},
			}

			ctlr := api.NewController(conf)

			ctlr.Config.Storage.RootDirectory = rootDir

			cm := test.NewControllerManager(ctlr)

			cm.StartServer()
			defer cm.StopServer()
			test.WaitTillServerReady(baseURL)

			resp, err := resty.R().
				Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})

		Convey("Unsupported provider", func() {
			mockOIDCConfig := mockOIDCServer.Config()
			conf.HTTP.Auth = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"invalidProvider": {
							ClientID:     mockOIDCConfig.ClientID,
							ClientSecret: mockOIDCConfig.ClientSecret,
							KeyPath:      "",
							Issuer:       mockOIDCConfig.Issuer,
							Scopes:       []string{"email", "groups"},
						},
					},
				},
			}

			ctlr := api.NewController(conf)

			ctlr.Config.Storage.RootDirectory = rootDir

			cm := test.NewControllerManager(ctlr)

			cm.StartServer()
			defer cm.StopServer()
			test.WaitTillServerReady(baseURL)

			// it will work because we have an invalid provider, and no other authn enabled, so no authn enabled
			// normally an invalid provider will exit with error in cli validations
			resp, err := resty.R().
				Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})
	})
}

func TestAuthnSessionErrors(t *testing.T) {
	Convey("make controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		defaultVal := true

		conf := config.New()
		conf.HTTP.Port = port
		invalidSessionID := "sessionID"

		// need a username different than ldap one, to test both logic
		htpasswdUsername, seedUser := test.GenerateRandomString()
		htpasswdPassword, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(htpasswdUsername, htpasswdPassword))
		defer os.Remove(htpasswdPath)

		ldapServer := newTestLDAPServer()
		port = test.GetFreePort()

		ldapPort, err := strconv.Atoi(port)
		if err != nil {
			panic(err)
		}

		ldapServer.Start(ldapPort)
		defer ldapServer.Stop()

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

		rootDir := t.TempDir()

		mockOIDCConfig := mockOIDCServer.Config()
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
			LDAP: (&config.LDAPConfig{
				Insecure:      true,
				Address:       LDAPAddress,
				Port:          ldapPort,
				BaseDN:        LDAPBaseDN,
				UserAttribute: "uid",
			}).SetBindDN(LDAPBindDN).SetBindPassword(LDAPBindPassword),
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"email", "groups"},
					},
				},
			},
		}

		uiConfig := &extconf.UIConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}

		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}

		conf.Extensions = &extconf.ExtensionConfig{
			UI:     uiConfig,
			Search: searchConfig,
		}

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		ctlr.Config.Storage.RootDirectory = rootDir

		cm := test.NewControllerManager(ctlr)

		cm.StartServer()
		defer cm.StopServer()
		test.WaitTillServerReady(baseURL)

		Convey("trigger basic authn middle(htpasswd) error", func() {
			client := resty.New()

			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					return ErrUnexpectedError
				},
			}

			resp, err := client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("trigger basic authn middle(ldap) error", func() {
			client := resty.New()

			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					return ErrUnexpectedError
				},
			}

			resp, err := client.R().SetBasicAuth(username, password).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("trigger updateUserData error", func() {
			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					return ErrUnexpectedError
				},
			}

			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("trigger session middle metaDB errors", func() {
			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			user := mockoidc.DefaultUser()
			user.Groups = []string{"group1", "group2"}

			mockOIDCServer.QueueUser(user)

			ctlr.MetaDB = mocks.MetaDBMock{}

			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			Convey("trigger session middle error internal server error", func() {
				cookies := resp.Cookies()

				client.SetCookies(cookies)

				ctlr.MetaDB = mocks.MetaDBMock{
					GetUserGroupsFn: func(ctx context.Context) ([]string, error) {
						return []string{}, ErrUnexpectedError
					},
				}

				// call endpoint with session (added to client after previous request)
				resp, err = client.R().
					SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
					Get(baseURL + "/v2/_catalog")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})

			Convey("trigger session middle error GetUserGroups not found", func() {
				cookies := resp.Cookies()

				client.SetCookies(cookies)

				ctlr.MetaDB = mocks.MetaDBMock{
					GetUserGroupsFn: func(ctx context.Context) ([]string, error) {
						return []string{}, errors.ErrUserDataNotFound
					},
				}

				// call endpoint with session (added to client after previous request)
				resp, err = client.R().
					SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
					Get(baseURL + "/v2/_catalog")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			})
		})

		Convey("trigger no email error in routes(callback)", func() {
			user := mockoidc.DefaultUser()
			user.Email = ""

			mockOIDCServer.QueueUser(user)

			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			client.SetCookie(&http.Cookie{Name: "session"})

			// call endpoint with session (added to client after previous request)
			resp, err := client.R().
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		})

		Convey("trigger session save error in routes(callback)", func() {
			err := os.Chmod(rootDir, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(rootDir, storageConstants.DefaultDirPerms)
				So(err, ShouldBeNil)
			}()

			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("trigger session save error in basicAuthn", func() {
			err := os.Chmod(rootDir, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(rootDir, storageConstants.DefaultDirPerms)
				So(err, ShouldBeNil)
			}()

			client := resty.New()
			client.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

			// first htpasswd saveSessionLoggedUser() error
			resp, err := client.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).
				Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

			// second ldap saveSessionLoggedUser() error
			resp, err = client.R().SetBasicAuth(username, password).
				Get(baseURL + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("trigger session middle errors", func() {
			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			user := mockoidc.DefaultUser()
			user.Groups = []string{"group1", "group2"}

			mockOIDCServer.QueueUser(user)

			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			Convey("trigger bad session encoding error in authn", func() {
				cookies := resp.Cookies()
				for _, cookie := range cookies {
					if cookie.Name == "session" {
						cookie.Value = "badSessionValue"
					}
				}

				client.SetCookies(cookies)

				// call endpoint with session (added to client after previous request)
				resp, err = client.R().
					SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
					Get(baseURL + "/v2/_catalog")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			})

			Convey("web request without cookies", func() {
				client.SetCookie(&http.Cookie{})

				// call endpoint with session (added to client after previous request)
				resp, err = client.R().
					SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
					Get(baseURL + "/v2/_catalog")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			})

			Convey("web request with userless cookie", func() {
				// first get session
				session, err := ctlr.CookieStore.Get(resp.RawResponse.Request, "session")
				So(err, ShouldBeNil)

				session.ID = invalidSessionID
				session.IsNew = false
				session.Values["authStatus"] = true

				cookieStore, ok := ctlr.CookieStore.Store.(*sessions.FilesystemStore)
				So(ok, ShouldBeTrue)

				// first encode sessionID
				encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
					cookieStore.Codecs...)
				So(err, ShouldBeNil)

				// save cookie
				cookie := sessions.NewCookie(session.Name(), encoded, session.Options)
				client.SetCookie(cookie)

				// encode session values and save on disk
				encoded, err = securecookie.EncodeMulti(session.Name(), session.Values,
					cookieStore.Codecs...)
				So(err, ShouldBeNil)

				filename := filepath.Join(rootDir, "_sessions", "session_"+session.ID)

				err = os.WriteFile(filename, []byte(encoded), 0o600)
				So(err, ShouldBeNil)

				// call endpoint with session (added to client after previous request)
				resp, err = client.R().
					SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
					Get(baseURL + "/v2/_catalog")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			})

			Convey("web request with authStatus false cookie", func() {
				// first get session
				session, err := ctlr.CookieStore.Get(resp.RawResponse.Request, "session")
				So(err, ShouldBeNil)

				session.ID = invalidSessionID
				session.IsNew = false
				session.Values["authStatus"] = false
				session.Values["test.Username"] = username

				cookieStore, ok := ctlr.CookieStore.Store.(*sessions.FilesystemStore)
				So(ok, ShouldBeTrue)

				// first encode sessionID
				encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
					cookieStore.Codecs...)
				So(err, ShouldBeNil)

				// save cookie
				cookie := sessions.NewCookie(session.Name(), encoded, session.Options)
				client.SetCookie(cookie)

				// encode session values and save on disk
				encoded, err = securecookie.EncodeMulti(session.Name(), session.Values,
					cookieStore.Codecs...)
				So(err, ShouldBeNil)

				filename := filepath.Join(rootDir, "_sessions", "session_"+session.ID)

				err = os.WriteFile(filename, []byte(encoded), 0o600)
				So(err, ShouldBeNil)

				// call endpoint with session (added to client after previous request)
				resp, err = client.R().
					SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
					Get(baseURL + "/v2/_catalog")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			})
		})
	})
}

func TestAuthnMetaDBErrors(t *testing.T) {
	Convey("make controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

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

		rootDir := t.TempDir()

		mockOIDCConfig := mockOIDCServer.Config()
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
			OpenID: &config.OpenIDConfig{
				Providers: map[string]config.OpenIDProviderConfig{
					"oidc": {
						ClientID:     mockOIDCConfig.ClientID,
						ClientSecret: mockOIDCConfig.ClientSecret,
						KeyPath:      "",
						Issuer:       mockOIDCConfig.Issuer,
						Scopes:       []string{"openid", "email"},
					},
				},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		ctlr.Config.Storage.RootDirectory = rootDir

		cm := test.NewControllerManager(ctlr)

		cm.StartServer()
		defer cm.StopServer()
		test.WaitTillServerReady(baseURL)

		Convey("trigger basic authn middle(htpasswd) error", func() {
			client := resty.New()

			ctlr.MetaDB = mocks.MetaDBMock{
				SetUserGroupsFn: func(ctx context.Context, groups []string) error {
					return ErrUnexpectedError
				},
			}

			resp, err := client.R().SetBasicAuth(username, password).
				Get(baseURL + "/v2/_catalog")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})

		Convey("trigger session middle metaDB errors", func() {
			client := resty.New()
			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			user := mockoidc.DefaultUser()
			user.Groups = []string{"group1", "group2"}

			mockOIDCServer.QueueUser(user)

			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			Convey("trigger session middle error", func() {
				cookies := resp.Cookies()

				client.SetCookies(cookies)

				ctlr.MetaDB = mocks.MetaDBMock{
					GetUserGroupsFn: func(ctx context.Context) ([]string, error) {
						return []string{}, ErrUnexpectedError
					},
				}

				// call endpoint with session (added to client after previous request)
				resp, err = client.R().
					SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
					Get(baseURL + "/v2/_catalog")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
			})
		})
	})
}

func TestAuthorization(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{},
							Actions: []string{},
						},
					},
					DefaultPolicy: []string{},
				},
			},
			AdminPolicy: config.Policy{
				Users:   []string{},
				Actions: []string{},
			},
		}

		Convey("with openid", func() {
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
			conf.HTTP.Auth = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {
							ClientID:     mockOIDCConfig.ClientID,
							ClientSecret: mockOIDCConfig.ClientSecret,
							KeyPath:      "",
							Issuer:       mockOIDCConfig.Issuer,
							Scopes:       []string{"openid", "email"},
						},
					},
				},
			}

			ctlr := api.NewController(conf)
			ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			err = WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1",
				ociutils.GetDefaultStoreController(ctlr.Config.Storage.RootDirectory, ctlr.Log))
			So(err, ShouldBeNil)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			client := resty.New()

			client.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			mockOIDCServer.QueueUser(&mockoidc.MockUser{
				Email:   username,
				Subject: "1234567890",
			})

			// first login user
			resp, err := client.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			client.SetCookies(resp.Cookies())
			client.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

			RunAuthorizationTests(t, client, baseURL, username, conf)
		})

		Convey("with basic auth", func() {
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1",
				ociutils.GetDefaultStoreController(ctlr.Config.Storage.RootDirectory, ctlr.Log))
			So(err, ShouldBeNil)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			client := resty.New()
			client.SetBasicAuth(username, password)

			RunAuthorizationTests(t, client, baseURL, username, conf)
		})
	})
}

func TestGetUsername(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// test base64 encode
		resp, err = resty.R().SetHeader("Authorization", "Basic should fail").Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// test "username:password" encoding
		resp, err = resty.R().SetHeader("Authorization", "Basic dGVzdA==").Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// failed parsing authorization header
		resp, err = resty.R().SetHeader("Authorization", "Basic ").Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		var e apiErr.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetBasicAuth(username, password).Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestAuthorizationWithOnlyAnonymousPolicy(t *testing.T) {
	Convey("Make a new controller", t, func() {
		const TestRepo = "my-repos/repo"
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				TestRepo: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var e apiErr.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// should get 401 without create
		resp, err = resty.R().Post(baseURL + "/v2/" + TestRepo + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		if entry, ok := conf.HTTP.AccessControl.Repositories[TestRepo]; ok {
			entry.AnonymousPolicy = []string{"create", "read"}
			conf.HTTP.AccessControl.Repositories[TestRepo] = entry
		}

		// now it should get 202
		resp, err = resty.R().Post(baseURL + "/v2/" + TestRepo + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := resp.Header().Get("Location")

		// uploading blob should get 201
		resp, err = resty.R().SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		cblob, cdigest := GetRandomImageConfig()

		resp, err = resty.R().Post(baseURL + "/v2/" + TestRepo + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)

		// uploading blob should get 201
		resp, err = resty.R().SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", cdigest.String()).
			SetBody(cblob).
			Put(loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(blob),
					Size:      int64(len(blob)),
				},
			},
		}
		manifest.SchemaVersion = 2
		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/" + TestRepo + "/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		updateBlob := []byte("Hello, blob update!")

		resp, err = resty.R().
			Post(baseURL + "/v2/" + TestRepo + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)
		// uploading blob should get 201
		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(updateBlob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", string(godigest.FromBytes(updateBlob))).
			SetBody(updateBlob).
			Put(loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		updatedManifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(updateBlob),
					Size:      int64(len(updateBlob)),
				},
			},
		}
		updatedManifest.SchemaVersion = 2
		updatedManifestBlob, err := json.Marshal(updatedManifest)
		So(err, ShouldBeNil)

		// update manifest should get 401 without update perm
		resp, err = resty.R().SetBody(updatedManifestBlob).
			Put(baseURL + "/v2/" + TestRepo + "/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// get the manifest and check if it's the old one
		resp, err = resty.R().
			Get(baseURL + "/v2/" + TestRepo + "/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldResemble, manifestBlob)

		// add update perm on repo
		if entry, ok := conf.HTTP.AccessControl.Repositories[TestRepo]; ok {
			entry.AnonymousPolicy = []string{"create", "read", "update"}
			conf.HTTP.AccessControl.Repositories[TestRepo] = entry
		}

		// update manifest should get 201 with update perm
		resp, err = resty.R().
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(updatedManifestBlob).
			Put(baseURL + "/v2/" + TestRepo + "/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// get the manifest and check if it's the new updated one
		resp, err = resty.R().
			Get(baseURL + "/v2/" + TestRepo + "/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldResemble, updatedManifestBlob)

		resp, err = resty.R().Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// make sure anonymous is correctly handled when using acCtx (requestcontext package)
		catalog := struct {
			Repositories []string `json:"repositories"`
		}{}

		err = json.Unmarshal(resp.Body(), &catalog)
		So(err, ShouldBeNil)
		So(len(catalog.Repositories), ShouldEqual, 1)
		So(catalog.Repositories, ShouldContain, TestRepo)

		err = os.Mkdir(path.Join(dir, "zot-test"), storageConstants.DefaultDirPerms)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "tag", ctlr.StoreController)
		So(err, ShouldBeNil)

		// should not have read rights on zot-test
		resp, err = resty.R().Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &catalog)
		So(err, ShouldBeNil)
		So(len(catalog.Repositories), ShouldEqual, 1)
		So(catalog.Repositories, ShouldContain, TestRepo)

		// add rights
		conf.HTTP.AccessControl.Repositories["zot-test"] = config.PolicyGroup{
			AnonymousPolicy: []string{"read"},
		}

		resp, err = resty.R().Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &catalog)
		So(err, ShouldBeNil)
		So(len(catalog.Repositories), ShouldEqual, 2)
		So(catalog.Repositories, ShouldContain, TestRepo)
		So(catalog.Repositories, ShouldContain, "zot-test")
	})
}

func TestAuthorizationWithAnonymousPolicyBasicAuthAndSessionHeader(t *testing.T) {
	Convey("Make a new controller", t, func() {
		const TestRepo = "my-repos/repo"
		const AllRepos = "**"
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		badpassphrase := "bad"
		htpasswdUsername, seedUser := test.GenerateRandomString()
		htpasswdPassword, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(htpasswdUsername, htpasswdPassword))
		defer os.Remove(htpasswdPath)

		img := CreateRandomImage()
		tagAnonymous := "1.0-anon"
		tagAuth := "1.0-auth"
		tagUnauth := "1.0-unauth"

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AllRepos: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{htpasswdUsername},
							Actions: []string{"read"},
						},
					},
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// /v2 access
		// Can access /v2 without credentials
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// Can access /v2 without credentials and with X-Zot-Api-Client=zot-ui
		resp, err = resty.R().
			SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// Can access /v2 with correct credentials
		resp, err = resty.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// Fail to access /v2 with incorrect credentials
		resp, err = resty.R().SetBasicAuth(htpasswdUsername, badpassphrase).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		// Catalog access
		resp, err = resty.R().Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var apiError apiErr.Error
		err = json.Unmarshal(resp.Body(), &apiError)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
			Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		apiError = apiErr.Error{}
		err = json.Unmarshal(resp.Body(), &apiError)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).
			Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		apiError = apiErr.Error{}
		err = json.Unmarshal(resp.Body(), &apiError)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetBasicAuth(htpasswdUsername, badpassphrase).
			Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		apiError = apiErr.Error{}
		err = json.Unmarshal(resp.Body(), &apiError)
		So(err, ShouldBeNil)

		// upload capability
		// should get 403 without create
		err = UploadImage(img, baseURL, TestRepo, tagAnonymous)
		So(err, ShouldNotBeNil)

		err = UploadImageWithBasicAuth(img, baseURL,
			TestRepo, tagAuth, htpasswdUsername, htpasswdPassword)
		So(err, ShouldNotBeNil)

		err = UploadImageWithBasicAuth(img, baseURL,
			TestRepo, tagUnauth, htpasswdUsername, badpassphrase)
		So(err, ShouldNotBeNil)

		if entry, ok := conf.HTTP.AccessControl.Repositories[AllRepos]; ok {
			entry.AnonymousPolicy = []string{"create", "read"}
			entry.Policies[0] = config.Policy{
				Users:   []string{htpasswdUsername},
				Actions: []string{"create", "read"},
			}
			conf.HTTP.AccessControl.Repositories[AllRepos] = entry
		}

		// now it should succeed for valid users
		err = UploadImage(img, baseURL, TestRepo, tagAnonymous)
		So(err, ShouldBeNil)

		err = UploadImageWithBasicAuth(img, baseURL,
			TestRepo, tagAuth, htpasswdUsername, htpasswdPassword)
		So(err, ShouldBeNil)

		err = UploadImageWithBasicAuth(img, baseURL,
			TestRepo, tagUnauth, htpasswdUsername, badpassphrase)
		So(err, ShouldNotBeNil)

		// read capability
		catalog := struct {
			Repositories []string `json:"repositories"`
		}{}

		resp, err = resty.R().Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &catalog)
		So(err, ShouldBeNil)
		So(len(catalog.Repositories), ShouldEqual, 1)
		So(catalog.Repositories, ShouldContain, TestRepo)

		catalog = struct {
			Repositories []string `json:"repositories"`
		}{}

		resp, err = resty.R().
			SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
			Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &catalog)
		So(err, ShouldBeNil)
		So(len(catalog.Repositories), ShouldEqual, 1)
		So(catalog.Repositories, ShouldContain, TestRepo)

		catalog = struct {
			Repositories []string `json:"repositories"`
		}{}

		resp, err = resty.R().SetBasicAuth(htpasswdUsername, htpasswdPassword).
			Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &catalog)
		So(err, ShouldBeNil)
		So(len(catalog.Repositories), ShouldEqual, 1)
		So(catalog.Repositories, ShouldContain, TestRepo)

		resp, err = resty.R().SetBasicAuth(htpasswdUsername, badpassphrase).
			Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestAuthorizationWithMultiplePolicies(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		// have two users: one for  user Policy, and another for default policy
		username1, seedUser1 := test.GenerateRandomString()
		password1, seedPass1 := test.GenerateRandomString()
		username2, seedUser2 := test.GenerateRandomString()
		password2, seedPass2 := test.GenerateRandomString()
		content := test.GetCredString(username1, password1) + test.GetCredString(username2, password2)
		htpasswdPath := test.MakeHtpasswdFileFromString(content)
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		// config with all policy types, to test that the correct one is applied in each case
		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{},
							Actions: []string{},
						},
					},
					DefaultPolicy:   []string{},
					AnonymousPolicy: []string{},
				},
			},
			AdminPolicy: config.Policy{
				Users:   []string{},
				Actions: []string{},
			},
		}

		Convey("with openid", func() {
			dir := t.TempDir()

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
			conf.HTTP.Auth = &config.AuthConfig{
				OpenID: &config.OpenIDConfig{
					Providers: map[string]config.OpenIDProviderConfig{
						"oidc": {
							ClientID:     mockOIDCConfig.ClientID,
							ClientSecret: mockOIDCConfig.ClientSecret,
							KeyPath:      "",
							Issuer:       mockOIDCConfig.Issuer,
							Scopes:       []string{"openid", "email"},
						},
					},
				},
			}

			ctlr := api.NewController(conf)
			ctlr.Log.Info().Int64("seedUser1", seedUser1).Int64("seedPass1", seedPass1).
				Msg("random seed for username & password")
			ctlr.Log.Info().Int64("seedUser2", seedUser2).Int64("seedPass2", seedPass2).
				Msg("random seed for username & password")
			ctlr.Config.Storage.RootDirectory = dir

			err = WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1",
				ociutils.GetDefaultStoreController(ctlr.Config.Storage.RootDirectory, ctlr.Log))
			So(err, ShouldBeNil)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			testUserClient := resty.New()

			testUserClient.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			mockOIDCServer.QueueUser(&mockoidc.MockUser{
				Email:   username1,
				Subject: "1234567890",
			})

			// first login user
			resp, err := testUserClient.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			testUserClient.SetCookies(resp.Cookies())
			testUserClient.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

			bobUserClient := resty.New()

			bobUserClient.SetRedirectPolicy(test.CustomRedirectPolicy(20))

			mockOIDCServer.QueueUser(&mockoidc.MockUser{
				Email:   username2,
				Subject: "1234567890",
			})

			// first login user
			resp, err = bobUserClient.R().
				SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue).
				SetQueryParam("provider", "oidc").
				Get(baseURL + constants.LoginPath)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			bobUserClient.SetCookies(resp.Cookies())
			bobUserClient.SetHeader(constants.SessionClientHeaderName, constants.SessionClientHeaderValue)

			RunAuthorizationWithMultiplePoliciesTests(t, testUserClient, bobUserClient, baseURL, username1, username2, conf)
		})

		Convey("with basic auth", func() {
			dir := t.TempDir()

			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = dir

			err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1",
				ociutils.GetDefaultStoreController(ctlr.Config.Storage.RootDirectory, ctlr.Log))
			So(err, ShouldBeNil)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			userClient1 := resty.New()
			userClient1.SetBasicAuth(username1, password1)

			userClient2 := resty.New()
			userClient2.SetBasicAuth(username2, password2)

			RunAuthorizationWithMultiplePoliciesTests(t, userClient1, userClient2, baseURL, username1, username2, conf)
		})
	})
}

func TestInvalidCases(t *testing.T) {
	Convey("Invalid repo dir", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer func(ctrl *api.Controller) {
			err := os.Chmod(dir, 0o755)
			if err != nil {
				panic(err)
			}

			err = ctrl.Server.Shutdown(context.Background())
			if err != nil {
				panic(err)
			}

			err = os.RemoveAll(ctrl.Config.Storage.RootDirectory)
			if err != nil {
				panic(err)
			}
		}(ctlr)

		err := os.Chmod(dir, 0o000)
		if err != nil {
			panic(err)
		}

		digest := godigest.FromString("dummy").String()
		name := "zot-c-test"

		client := resty.New()

		params := make(map[string]string)
		params["from"] = "zot-cveid-test"
		params["mount"] = digest

		postResponse, err := client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", baseURL, name))
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusInternalServerError)
	})
}

func TestHTTPReadOnly(t *testing.T) {
	Convey("Single cred", t, func() {
		singleCredtests := []string{}
		user, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		singleCredtests = append(singleCredtests, test.GetCredString(user, password))
		singleCredtests = append(singleCredtests, test.GetCredString(user, password)+"\n")

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		for _, testString := range singleCredtests {
			func() {
				conf := config.New()
				conf.HTTP.Port = port
				// enable read-only mode
				conf.HTTP.AccessControl = &config.AccessControlConfig{
					Repositories: config.Repositories{
						test.AuthorizationAllRepos: config.PolicyGroup{
							DefaultPolicy: []string{"read"},
						},
					},
				}

				htpasswdPath := test.MakeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				conf.HTTP.Auth = &config.AuthConfig{
					HTPasswd: config.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				ctlr := makeController(conf, t.TempDir())
				ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

				cm := test.NewControllerManager(ctlr)
				cm.StartAndWait(port)
				defer cm.StopServer()

				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				s1, seed1 := test.GenerateRandomName()
				s2, seed2 := test.GenerateRandomName()
				repoName := s1 + "/" + s2
				ctlr.Log.Info().Int64("seed1", seed1).Int64("seed2", seed2).Msg("random seeds for repoName")
				// with creds, any modifications should still fail on read-only mode
				resp, err := resty.R().SetBasicAuth(user, password).
					Post(baseURL + "/v2/" + repoName + "/blobs/uploads/")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

				// with invalid creds, it should fail
				resp, _ = resty.R().SetBasicAuth("chuck", "chuck").Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
			}()
		}
	})
}

func TestCrossRepoMount(t *testing.T) {
	Convey("Cross Repo Mount", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		dir := t.TempDir()
		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")

		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.RemoteCache = false
		ctlr.Config.Storage.Dedupe = false

		image := CreateDefaultImage()
		err := WriteImageToFileSystem(image, "zot-cve-test", "test", storage.StoreController{
			DefaultStore: ociutils.GetDefaultImageStore(dir, ctlr.Log),
		})
		So(err, ShouldBeNil)

		cm := test.NewControllerManager(ctlr) //nolint: varnamelen
		cm.StartAndWait(port)

		params := make(map[string]string)

		manifestDigest := image.ManifestDescriptor.Digest

		dgst := manifestDigest
		name := "zot-cve-test"
		params["mount"] = string(manifestDigest)
		params["from"] = name

		client := resty.New()
		headResponse, err := client.R().SetBasicAuth(username, password).
			Head(fmt.Sprintf("%s/v2/%s/blobs/%s", baseURL, name, manifestDigest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusOK)

		// All invalid request of mount should return 202.
		params["mount"] = "sha:"

		postResponse, err := client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)
		location, err := postResponse.RawResponse.Location()
		So(err, ShouldBeNil)
		So(location.String(), ShouldStartWith, fmt.Sprintf("%s%s/zot-c-test/%s/%s",
			baseURL, constants.RoutePrefix, constants.Blobs, constants.Uploads))

		incorrectParams := make(map[string]string)
		incorrectParams["mount"] = godigest.FromString("dummy").String()
		incorrectParams["from"] = "zot-x-test"

		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(incorrectParams).
			Post(baseURL + "/v2/zot-y-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)
		So(test.Location(baseURL, postResponse), ShouldStartWith, fmt.Sprintf("%s%s/zot-y-test/%s/%s",
			baseURL, constants.RoutePrefix, constants.Blobs, constants.Uploads))

		// Use correct request
		// This is correct request but it will return 202 because blob is not present in cache.
		params["mount"] = string(manifestDigest)
		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)
		So(test.Location(baseURL, postResponse), ShouldStartWith, fmt.Sprintf("%s%s/zot-c-test/%s/%s",
			baseURL, constants.RoutePrefix, constants.Blobs, constants.Uploads))

		// Send same request again
		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		// Valid requests
		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-d-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		headResponse, err = client.R().SetBasicAuth(username, password).
			Head(fmt.Sprintf("%s/v2/zot-cv-test/blobs/%s", baseURL, manifestDigest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusNotFound)

		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/ /blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusNotFound)

		blob := manifestDigest.Encoded()

		buf, err := os.ReadFile(path.Join(ctlr.Config.Storage.RootDirectory, "zot-cve-test/blobs/sha256/"+blob))
		if err != nil {
			panic(err)
		}

		postResponse, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBasicAuth(username, password).SetQueryParam("digest", "sha256:"+blob).
			SetBody(buf).Post(baseURL + "/v2/zot-d-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)

		// We have uploaded a blob and since we have provided digest it should be full blob upload and there should be entry
		// in cache, now try mount blob request status and it should be 201 because now blob is present in cache
		// and it should do hard link.

		// make a new server with dedupe on and same rootDir (can't restart because of metadb - boltdb being open)
		newDir := t.TempDir()
		err = test.CopyFiles(dir, newDir)
		So(err, ShouldBeNil)

		cm.StopServer()

		ctlr.Config.Storage.Dedupe = true
		ctlr.Config.Storage.GC = false
		ctlr.Config.Storage.RootDirectory = newDir
		cm = test.NewControllerManager(ctlr) //nolint: varnamelen
		cm.StartAndWait(port)
		defer cm.StopServer()

		// wait for dedupe task to run
		time.Sleep(10 * time.Second)

		params["mount"] = string(manifestDigest)
		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)
		So(test.Location(baseURL, postResponse), ShouldEqual, fmt.Sprintf("%s%s/zot-mount-test/%s/%s:%s",
			baseURL, constants.RoutePrefix, constants.Blobs, godigest.SHA256, blob))

		// Check os.SameFile here
		cachePath := path.Join(ctlr.Config.Storage.RootDirectory, "zot-d-test", "blobs/sha256", dgst.Encoded())

		cacheFi, err := os.Stat(cachePath)
		So(err, ShouldBeNil)

		linkPath := path.Join(ctlr.Config.Storage.RootDirectory, "zot-mount-test", "blobs/sha256", dgst.Encoded())

		linkFi, err := os.Stat(linkPath)
		So(err, ShouldBeNil)

		So(os.SameFile(cacheFi, linkFi), ShouldEqual, true)

		// Now try another mount request and this time it should be from above uploaded repo i.e zot-mount-test
		// mount request should pass and should return 201.
		params["mount"] = string(manifestDigest)
		params["from"] = "zot-mount-test"
		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount1-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)
		So(test.Location(baseURL, postResponse), ShouldEqual, fmt.Sprintf("%s%s/zot-mount1-test/%s/%s:%s",
			baseURL, constants.RoutePrefix, constants.Blobs, godigest.SHA256, blob))

		linkPath = path.Join(ctlr.Config.Storage.RootDirectory, "zot-mount1-test", "blobs/sha256", dgst.Encoded())

		linkFi, err = os.Stat(linkPath)
		So(err, ShouldBeNil)

		So(os.SameFile(cacheFi, linkFi), ShouldEqual, true)

		headResponse, err = client.R().SetBasicAuth(username, password).
			Head(fmt.Sprintf("%s/v2/zot-cv-test/blobs/%s", baseURL, manifestDigest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusOK)

		// Invalid request
		params = make(map[string]string)
		params["mount"] = "sha256:"
		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		params = make(map[string]string)
		params["from"] = "zot-cve-test"
		postResponse, err = client.R().
			SetBasicAuth(username, password).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
	})

	Convey("Disable dedupe and cache", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))

		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		dir := t.TempDir()

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.Dedupe = false
		ctlr.Config.Storage.GC = false

		image := CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

		err := WriteImageToFileSystem(image, "zot-cve-test", "0.0.1",
			ociutils.GetDefaultStoreController(dir, ctlr.Log))
		So(err, ShouldBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// digest := test.GetTestBlobDigest("zot-cve-test", "layer").String()
		digest := godigest.FromBytes(image.Layers[0])
		name := "zot-c-test"
		client := resty.New()
		headResponse, err := client.R().SetBasicAuth(username, password).
			Head(fmt.Sprintf("%s/v2/%s/blobs/%s", baseURL, name, digest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestParallelRequests(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		srcImageName  string
		srcImageTag   string
		destImageName string
		destImageTag  string
		testCaseName  string
	}{
		{
			srcImageName:  "zot-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-1-test",
			destImageTag:  "0.0.1",
			testCaseName:  "Request-1",
		},
		{
			srcImageName:  "zot-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-2-test",
			testCaseName:  "Request-2",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "a/zot-3-test",
			testCaseName:  "Request-3",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "b/zot-4-test",
			testCaseName:  "Request-4",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-5-test",
			testCaseName:  "Request-5",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-1-test",
			testCaseName:  "Request-6",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-2-test",
			testCaseName:  "Request-7",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-3-test",
			testCaseName:  "Request-8",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-4-test",
			testCaseName:  "Request-9",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-5-test",
			testCaseName:  "Request-10",
		},
		{
			srcImageName:  "zot-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-1-test",
			destImageTag:  "0.0.1",
			testCaseName:  "Request-11",
		},
		{
			srcImageName:  "zot-test",
			srcImageTag:   "0.0.1",
			destImageName: "zot-2-test",
			testCaseName:  "Request-12",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "a/zot-3-test",
			testCaseName:  "Request-13",
		},
		{
			srcImageName:  "zot-cve-test",
			srcImageTag:   "0.0.1",
			destImageName: "b/zot-4-test",
			testCaseName:  "Request-14",
		},
	}

	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)

	conf := config.New()
	conf.HTTP.Port = port
	username, seedUser := test.GenerateRandomString()
	password, seedPass := test.GenerateRandomString()
	htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(username, password))

	t.Cleanup(func() {
		os.Remove(htpasswdPath)
	})

	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd: config.AuthHTPasswd{
			Path: htpasswdPath,
		},
	}

	dir := t.TempDir()
	firstSubDir := t.TempDir()
	secondSubDir := t.TempDir()

	subPaths := make(map[string]config.StorageConfig)

	subPaths["/a"] = config.StorageConfig{RootDirectory: firstSubDir}
	subPaths["/b"] = config.StorageConfig{RootDirectory: secondSubDir}

	ctlr := makeController(conf, dir)
	ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
	ctlr.Config.Storage.SubPaths = subPaths

	testImagesDir := t.TempDir()
	testImagesController := ociutils.GetDefaultStoreController(testImagesDir, ctlr.Log)

	err := WriteImageToFileSystem(CreateRandomImage(), "zot-test", "0.0.1", testImagesController)
	assert.Equal(t, err, nil, "Error should be nil")

	err = WriteImageToFileSystem(CreateRandomImage(), "zot-cve-test", "0.0.1", testImagesController)
	assert.Equal(t, err, nil, "Error should be nil")

	cm := test.NewControllerManager(ctlr)
	cm.StartAndWait(port)

	// without creds, should get access error
	for i, testcase := range testCases {
		testcase := testcase
		run := i

		t.Run(testcase.testCaseName, func(t *testing.T) {
			t.Parallel()
			client := resty.New()

			tagResponse, err := client.R().SetBasicAuth(username, password).
				Get(baseURL + "/v2/" + testcase.destImageName + "/tags/list")
			assert.Equal(t, err, nil, "Error should be nil")
			assert.NotEqual(t, tagResponse.StatusCode(), http.StatusBadRequest, "bad request")

			manifestList := getAllManifests(path.Join(testImagesDir, testcase.srcImageName))

			for _, manifest := range manifestList {
				headResponse, err := client.R().SetBasicAuth(username, password).
					Head(baseURL + "/v2/" + testcase.destImageName + "/manifests/" + manifest)
				assert.Equal(t, err, nil, "Error should be nil")
				assert.Equal(t, headResponse.StatusCode(), http.StatusNotFound, "response status code should return 404")

				getResponse, err := client.R().SetBasicAuth(username, password).
					Get(baseURL + "/v2/" + testcase.destImageName + "/manifests/" + manifest)
				assert.Equal(t, err, nil, "Error should be nil")
				assert.Equal(t, getResponse.StatusCode(), http.StatusNotFound, "response status code should return 404")
			}

			blobList := getAllBlobs(path.Join(testImagesDir, testcase.srcImageName))

			for _, blob := range blobList {
				// Get request of blob
				headResponse, err := client.R().SetBasicAuth(username, password).
					Head(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, headResponse.StatusCode(), http.StatusInternalServerError,
					"internal server error should not occurred")

				getResponse, err := client.R().SetBasicAuth(username, password).
					Get(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, getResponse.StatusCode(), http.StatusInternalServerError,
					"internal server error should not occurred")

				blobPath := path.Join(testImagesDir, testcase.srcImageName, "blobs/sha256", blob)

				buf, err := os.ReadFile(blobPath)
				if err != nil {
					panic(err)
				}

				// Post request of blob
				postResponse, err := client.R().
					SetHeader("Content-type", "application/octet-stream").
					SetBasicAuth(username, password).
					SetBody(buf).Post(baseURL + "/v2/" + testcase.destImageName + "/blobs/uploads/")

				assert.Equal(t, err, nil, "Error should be nil")
				assert.NotEqual(t, postResponse.StatusCode(), http.StatusInternalServerError,
					"response status code should not return 500")

				// Post request with query parameter
				if run%2 == 0 {
					postResponse, err = client.R().
						SetHeader("Content-type", "application/octet-stream").
						SetBasicAuth(username, password).
						SetBody(buf).
						Post(baseURL + "/v2/" + testcase.destImageName + "/blobs/uploads/")

					assert.Equal(t, err, nil, "Error should be nil")
					assert.NotEqual(t, postResponse.StatusCode(), http.StatusInternalServerError,
						"response status code should not return 500")

					var sessionID string
					sessionIDList := postResponse.Header().Values("Blob-Upload-UUID")
					if len(sessionIDList) == 0 {
						location := postResponse.Header().Values("Location")
						firstLocation := location[0]
						splitLocation := strings.Split(firstLocation, "/")
						sessionID = splitLocation[len(splitLocation)-1]
					} else {
						sessionID = sessionIDList[0]
					}

					file, err := os.Open(blobPath)
					if err != nil {
						panic(err)
					}

					defer file.Close()

					reader := bufio.NewReader(file)

					buf := make([]byte, 5*1024*1024)

					if run%4 == 0 {
						readContent := 0
						for {
							nbytes, err := reader.Read(buf)
							if err != nil {
								if goerrors.Is(err, io.EOF) {
									break
								}
								panic(err)
							}
							// Patch request of blob

							patchResponse, err := client.R().
								SetBody(buf[0:nbytes]).
								SetHeader("Content-Type", "application/octet-stream").
								SetHeader("Content-Length", fmt.Sprintf("%d", nbytes)).
								SetHeader("Content-Range", fmt.Sprintf("%d", readContent)+"-"+fmt.Sprintf("%d", readContent+nbytes-1)).
								SetBasicAuth(username, password).
								Patch(baseURL + "/v2/" + testcase.destImageName + "/blobs/uploads/" + sessionID)

							assert.Equal(t, err, nil, "Error should be nil")
							assert.NotEqual(t, patchResponse.StatusCode(), http.StatusInternalServerError,
								"response status code should not return 500")

							readContent += nbytes
						}
					} else {
						for {
							nbytes, err := reader.Read(buf)
							if err != nil {
								if goerrors.Is(err, io.EOF) {
									break
								}
								panic(err)
							}
							// Patch request of blob

							patchResponse, err := client.R().SetBody(buf[0:nbytes]).SetHeader("Content-type", "application/octet-stream").
								SetBasicAuth(username, password).
								Patch(baseURL + "/v2/" + testcase.destImageName + "/blobs/uploads/" + sessionID)
							if err != nil {
								panic(err)
							}

							assert.Equal(t, err, nil, "Error should be nil")
							assert.NotEqual(t, patchResponse.StatusCode(), http.StatusInternalServerError,
								"response status code should not return 500")
						}
					}
				} else {
					postResponse, err = client.R().
						SetHeader("Content-type", "application/octet-stream").
						SetBasicAuth(username, password).
						SetBody(buf).SetQueryParam("digest", "sha256:"+blob).
						Post(baseURL + "/v2/" + testcase.destImageName + "/blobs/uploads/")

					assert.Equal(t, err, nil, "Error should be nil")
					assert.NotEqual(t, postResponse.StatusCode(), http.StatusInternalServerError,
						"response status code should not return 500")
				}

				headResponse, err = client.R().
					SetBasicAuth(username, password).
					Head(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, headResponse.StatusCode(), http.StatusInternalServerError, "response should return success code")

				getResponse, err = client.R().
					SetBasicAuth(username, password).
					Get(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, getResponse.StatusCode(), http.StatusInternalServerError, "response should return success code")
			}

			tagResponse, err = client.R().SetBasicAuth(username, password).
				Get(baseURL + "/v2/" + testcase.destImageName + "/tags/list")
			assert.Equal(t, err, nil, "Error should be nil")
			assert.Equal(t, tagResponse.StatusCode(), http.StatusOK, "response status code should return success code")

			repoResponse, err := client.R().SetBasicAuth(username, password).
				Get(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
			assert.Equal(t, err, nil, "Error should be nil")
			assert.Equal(t, repoResponse.StatusCode(), http.StatusOK, "response status code should return success code")
		})
	}
}

func TestHardLink(t *testing.T) {
	Convey("Validate hard link", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false

		dir := t.TempDir()

		err := os.Chmod(dir, 0o400)
		if err != nil {
			panic(err)
		}

		subDir := t.TempDir()

		err = os.Chmod(subDir, 0o400)
		if err != nil {
			panic(err)
		}

		ctlr := makeController(conf, dir)
		subPaths := make(map[string]config.StorageConfig)

		subPaths["/a"] = config.StorageConfig{RootDirectory: subDir, Dedupe: true}
		ctlr.Config.Storage.SubPaths = subPaths

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		err = os.Chmod(dir, 0o644)
		if err != nil {
			panic(err)
		}

		err = os.Chmod(subDir, 0o644)
		if err != nil {
			panic(err)
		}

		So(ctlr.Config.Storage.Dedupe, ShouldEqual, false)
	})
}

func TestImageSignatures(t *testing.T) {
	Convey("Validate signatures", t, func() {
		// start a new server
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		cm := test.NewControllerManager(ctlr)
		// this blocks
		cm.StartAndWait(port)
		defer cm.StopServer()

		repoName := "signed-repo"
		img := CreateRandomImage()
		content := img.ManifestDescriptor.Data
		digest := img.ManifestDescriptor.Digest

		err := UploadImage(img, baseURL, repoName, "1.0")
		So(err, ShouldBeNil)

		Convey("Validate cosign signatures", func() {
			cwd, err := os.Getwd()
			So(err, ShouldBeNil)
			defer func() { _ = os.Chdir(cwd) }()
			tdir := t.TempDir()
			_ = os.Chdir(tdir)

			// generate a keypair
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
			So(err, ShouldBeNil)

			annotations := []string{"tag=1.0"}

			// sign the image
			err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
				options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
				options.SignOptions{
					Registry:          options.RegistryOptions{AllowInsecure: true},
					AnnotationOptions: options.AnnotationOptions{Annotations: annotations},
					Upload:            true,
				},
				[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())})
			So(err, ShouldBeNil)

			// verify the image
			aopts := &options.AnnotationOptions{Annotations: annotations}
			amap, err := aopts.AnnotationsMap()
			So(err, ShouldBeNil)
			vrfy := verify.VerifyCommand{
				RegistryOptions: options.RegistryOptions{AllowInsecure: true},
				CheckClaims:     true,
				KeyRef:          path.Join(tdir, "cosign.pub"),
				Annotations:     amap,
				IgnoreTlog:      true,
			}
			err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")})
			So(err, ShouldBeNil)

			// verify the image with incorrect tag
			aopts = &options.AnnotationOptions{Annotations: []string{"tag=2.0"}}
			amap, err = aopts.AnnotationsMap()
			So(err, ShouldBeNil)
			vrfy = verify.VerifyCommand{
				RegistryOptions: options.RegistryOptions{AllowInsecure: true},
				CheckClaims:     true,
				KeyRef:          path.Join(tdir, "cosign.pub"),
				Annotations:     amap,
				IgnoreTlog:      true,
			}
			err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")})
			So(err, ShouldNotBeNil)

			// verify the image with incorrect key
			aopts = &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}
			amap, err = aopts.AnnotationsMap()
			So(err, ShouldBeNil)
			vrfy = verify.VerifyCommand{
				CheckClaims:     true,
				RegistryOptions: options.RegistryOptions{AllowInsecure: true},
				KeyRef:          path.Join(tdir, "cosign.key"),
				Annotations:     amap,
				IgnoreTlog:      true,
			}
			err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")})
			So(err, ShouldNotBeNil)

			// generate another keypair
			err = os.Remove(path.Join(tdir, "cosign.pub"))
			So(err, ShouldBeNil)
			err = os.Remove(path.Join(tdir, "cosign.key"))
			So(err, ShouldBeNil)

			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
			So(err, ShouldBeNil)

			// verify the image with incorrect key
			aopts = &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}
			amap, err = aopts.AnnotationsMap()
			So(err, ShouldBeNil)
			vrfy = verify.VerifyCommand{
				CheckClaims:     true,
				RegistryOptions: options.RegistryOptions{AllowInsecure: true},
				KeyRef:          path.Join(tdir, "cosign.pub"),
				Annotations:     amap,
				IgnoreTlog:      true,
			}
			err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")})
			So(err, ShouldNotBeNil)
		})

		Convey("Validate notation signatures", func() {
			cwd, err := os.Getwd()
			So(err, ShouldBeNil)
			defer func() { _ = os.Chdir(cwd) }()
			tdir := t.TempDir()
			_ = os.Chdir(tdir)

			signature.NotationPathLock.Lock()
			defer signature.NotationPathLock.Unlock()

			signature.LoadNotationPath(tdir)

			err = signature.GenerateNotationCerts(tdir, "good")
			So(err, ShouldBeNil)

			err = signature.GenerateNotationCerts(tdir, "bad")
			So(err, ShouldBeNil)

			image := fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")
			err = signature.SignWithNotation("good", image, tdir, true)
			So(err, ShouldBeNil)

			err = signature.VerifyWithNotation(image, tdir)
			So(err, ShouldBeNil)

			// check list
			sigs, err := signature.ListNotarySignatures(image, tdir)
			So(len(sigs), ShouldEqual, 1)
			So(err, ShouldBeNil)

			// check unsupported manifest media type
			resp, err := resty.R().SetHeader("Content-Type", "application/vnd.unsupported.image.manifest.v1+json").
				SetBody(content).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnsupportedMediaType)

			// check invalid content with artifact media type
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
				SetBody([]byte("bogus")).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			Convey("Validate corrupted signature", func() {
				// verify with corrupted signature
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/v2/%s/referrers/%s", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				var refs ispec.Index
				err = json.Unmarshal(resp.Body(), &refs)
				So(err, ShouldBeNil)
				So(len(refs.Manifests), ShouldEqual, 1)
				err = os.WriteFile(path.Join(dir, repoName, "blobs",
					strings.ReplaceAll(refs.Manifests[0].Digest.String(), ":", "/")), []byte("corrupt"), 0o600)
				So(err, ShouldBeNil)
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/v2/%s/referrers/%s", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

				err = signature.VerifyWithNotation(image, tdir)
				So(err, ShouldNotBeNil)
			})

			Convey("Validate deleted signature", func() {
				// verify with corrupted signature
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/v2/%s/referrers/%s", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				var refs ispec.Index
				err = json.Unmarshal(resp.Body(), &refs)
				So(err, ShouldBeNil)
				So(len(refs.Manifests), ShouldEqual, 1)
				err = os.Remove(path.Join(dir, repoName, "blobs",
					strings.ReplaceAll(refs.Manifests[0].Digest.String(), ":", "/")))
				So(err, ShouldBeNil)
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/v2/%s/referrers/%s", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

				err = signature.VerifyWithNotation(image, tdir)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestManifestValidation(t *testing.T) {
	Convey("Validate manifest", t, func() {
		// start a new server
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		cm := test.NewControllerManager(ctlr)
		// this blocks
		cm.StartServer()
		time.Sleep(1000 * time.Millisecond)
		defer cm.StopServer()

		repoName := "validation"
		blobContent := []byte("this is a blob")
		blobDigest := godigest.FromBytes(blobContent)
		So(blobDigest, ShouldNotBeNil)

		img := CreateRandomImage()
		content := img.ManifestDescriptor.Data
		digest := img.ManifestDescriptor.Digest
		configDigest := img.ConfigDescriptor.Digest
		configBlob := img.ConfigDescriptor.Data

		err := UploadImage(img, baseURL, repoName, "1.0")
		So(err, ShouldBeNil)

		Convey("empty layers should pass validation", func() {
			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Size:      int64(len(configBlob)),
					Digest:    configDigest,
				},
				Layers: []ispec.Descriptor{},
				Annotations: map[string]string{
					"key": "val",
				},
			}
			manifest.SchemaVersion = 2

			mcontent, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
				SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
		})

		Convey("empty layers and schemaVersion missing should fail validation", func() {
			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Size:      int64(len(configBlob)),
					Digest:    configDigest,
				},
				Layers: []ispec.Descriptor{},
				Annotations: map[string]string{
					"key": "val",
				},
			}

			mcontent, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
				SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})

		Convey("missing layer should fail validation", func() {
			missingLayer := []byte("missing layer")
			missingLayerDigest := godigest.FromBytes(missingLayer)
			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Size:      int64(len(configBlob)),
					Digest:    configDigest,
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(len(content)),
					},
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    missingLayerDigest,
						Size:      int64(len(missingLayer)),
					},
				},
				Annotations: map[string]string{
					"key": "val",
				},
			}
			manifest.SchemaVersion = 2

			mcontent, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
				SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})

		Convey("wrong mediatype should fail validation", func() {
			// create a manifest
			manifest := ispec.Manifest{
				MediaType: "bad.mediatype",
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Size:      int64(len(configBlob)),
					Digest:    configDigest,
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
				Annotations: map[string]string{
					"key": "val",
				},
			}
			manifest.SchemaVersion = 2

			mcontent, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
				SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})

		Convey("multiarch image should pass validation", func() {
			index := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
						Size:      int64(len((content))),
					},
				},
			}

			index.SchemaVersion = 2

			indexContent, err := json.Marshal(index)
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				SetBody(indexContent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/index", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
		})

		Convey("multiarch image without schemaVersion should fail validation", func() {
			index := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
						Size:      int64(len((content))),
					},
				},
			}

			indexContent, err := json.Marshal(index)
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				SetBody(indexContent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/index", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})

		Convey("multiarch image with missing manifest should fail validation", func() {
			index := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
						Size:      int64(len((content))),
					},
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromString("missing layer"),
						Size:      10,
					},
				},
			}

			index.SchemaVersion = 2

			indexContent, err := json.Marshal(index)
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				SetBody(indexContent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/index", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
		})
	})
}

func TestArtifactReferences(t *testing.T) {
	Convey("Validate Artifact References", t, func() {
		// start a new server
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		cm := test.NewControllerManager(ctlr)
		// this blocks
		cm.StartServer()
		time.Sleep(1000 * time.Millisecond)
		defer cm.StopServer()

		repoName := "artifact-repo"

		image := CreateImageWith().RandomLayers(1, 2).DefaultConfig().Build()
		digest := image.ManifestDescriptor.Digest

		err := UploadImage(image, baseURL, repoName, "1.0")
		So(err, ShouldBeNil)

		artifactType := "application/vnd.example.icecream.v1"

		Convey("Validate Image Manifest Reference", func() {
			resp, err := resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName, digest.String()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var referrers ispec.Index
			err = json.Unmarshal(resp.Body(), &referrers)
			So(err, ShouldBeNil)
			So(referrers.Manifests, ShouldBeEmpty)

			// now upload a reference

			// upload image config blob
			resp, err = resty.R().Post(baseURL + fmt.Sprintf("/v2/%s/blobs/uploads/", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			cblob, cdigest := getEmptyImageConfig()

			resp, err = resty.R().
				SetContentLength(true).
				SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
				SetHeader("Content-Type", "application/octet-stream").
				SetQueryParam("digest", cdigest.String()).
				SetBody(cblob).
				Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: artifactType,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      image.ManifestDescriptor.Size,
					},
				},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    digest,
					Size:      image.ManifestDescriptor.Size,
				},
				Annotations: map[string]string{
					"key": "val",
				},
			}
			manifest.SchemaVersion = 2

			Convey("Using invalid content", func() {
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody([]byte("invalid data")).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

				// unknown repo will return status not found
				resp, err = resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", "unknown", digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

				resp, err = resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				resp, err = resty.R().SetQueryParams(map[string]string{"artifactType": artifactType}).
					Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				// create a bad manifest (constructed manually)
				content := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","subject":{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:71dbae9d7e6445fb5e0b11328e941b8e8937fdd52465079f536ce44bb78796ed","size":406}}` //nolint: lll
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(content).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

				// missing layers
				mcontent := []byte("this is a missing blob")
				digest = godigest.FromBytes(mcontent)
				So(digest, ShouldNotBeNil)

				manifest.Layers = append(manifest.Layers, ispec.Descriptor{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(len(mcontent)),
				})

				mcontent, err = json.Marshal(manifest)
				So(err, ShouldBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

				// invalid schema version
				manifest.SchemaVersion = 1

				mcontent, err = json.Marshal(manifest)
				So(err, ShouldBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

				// upload image config blob
				resp, err = resty.R().Post(baseURL + fmt.Sprintf("/v2/%s/blobs/uploads/", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				loc := test.Location(baseURL, resp)
				cblob = []byte("{}")
				cdigest = godigest.FromBytes(cblob)
				So(cdigest, ShouldNotBeNil)

				resp, err = resty.R().
					SetContentLength(true).
					SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
					SetHeader("Content-Type", "application/octet-stream").
					SetQueryParam("digest", cdigest.String()).
					SetBody(cblob).
					Put(loc)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

				manifest := ispec.Manifest{
					Config: ispec.Descriptor{
						MediaType: "application/vnd.oci.image.config.v1+json",
						Digest:    cdigest,
						Size:      int64(len(cblob)),
					},
				}

				manifest.SchemaVersion = 2
				mcontent, err = json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(mcontent)
				So(digest, ShouldNotBeNil)

				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

				// missing layers
				mcontent = []byte("this is a missing blob")
				digest = godigest.FromBytes(mcontent)
				So(digest, ShouldNotBeNil)

				manifest.Layers = append(manifest.Layers, ispec.Descriptor{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(len(mcontent)),
				})

				mcontent, err = json.Marshal(manifest)
				So(err, ShouldBeNil)

				// should fail because config is of type image and blob is not uploaded
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

				// no layers at all
				manifest.Layers = []ispec.Descriptor{}

				mcontent, err = json.Marshal(manifest)
				So(err, ShouldBeNil)

				// should not fail
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(mcontent).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			})

			Convey("Using valid content", func() {
				content, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(content).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

				resp, err = resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				resp, err = resty.R().SetQueryParams(map[string]string{"artifact": "invalid"}).
					Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				resp, err = resty.R().SetQueryParams(map[string]string{"artifactType": "invalid"}).
					Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				resp, err = resty.R().SetQueryParams(map[string]string{"artifactType": artifactType}).
					Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Header().Get("Content-Type"), ShouldEqual, ispec.MediaTypeImageIndex)
				So(resp.Header().Get("OCI-Filters-Applied"), ShouldEqual, "artifactType")

				resp, err = resty.R().SetQueryParams(map[string]string{"artifactType": artifactType +
					",otherArtType"}).Get(baseURL + fmt.Sprintf("/v2/%s/referrers/%s", repoName,
					digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Header().Get("Content-Type"), ShouldEqual, ispec.MediaTypeImageIndex)
				So(resp.Header().Get("OCI-Filters-Applied"), ShouldEqual, "artifactType")
			})
		})
	})
}

//nolint:dupl // duplicated test code
func TestRouteFailures(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := makeController(conf, t.TempDir())
		ctlr.Config.Storage.Commit = true

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		rthdlr := api.NewRouteHandler(ctlr)

		// NOTE: the url or method itself doesn't matter below since we are calling the handlers directly,
		// so path routing is bypassed

		Convey("List tags", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm := request.URL.Query()
			qparm.Add("n", "a")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("n", "-1")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("n", "abc")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("n", "a")
			qparm.Add("n", "abc")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("n", "0")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("n", "1")
			qparm.Add("last", "")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("n", "1")
			qparm.Add("last", "a")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("last", "a")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("n", "1")
			qparm.Add("last", "a")
			qparm.Add("last", "abc")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("Check manifest", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodHead, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.CheckManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodHead, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.CheckManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodHead, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.CheckManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Get manifest", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Update manifest", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Delete manifest", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.DeleteManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.DeleteManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.DeleteManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Check blob", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodHead, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.CheckBlob(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodHead, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.CheckBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodHead, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "digest": ""})
			response = httptest.NewRecorder()

			rthdlr.CheckBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Get blob", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.GetBlob(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.GetBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "digest": ""})
			response = httptest.NewRecorder()

			rthdlr.GetBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Delete blob", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.DeleteBlob(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.DeleteBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "digest": ""})
			response = httptest.NewRecorder()

			rthdlr.DeleteBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Create blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPost, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.CreateBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodPost, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm := request.URL.Query()
			qparm.Add("mount", "a")
			qparm.Add("mount", "abc")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.CreateBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodPost, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			qparm = request.URL.Query()
			qparm.Add("mount", "a")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.CreateBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusAccepted)
		})

		Convey("Get blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.GetBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.GetBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Patch blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPatch, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.PatchBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.PatchBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Update blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "session_id": "bar"})
			response = httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "session_id": "bar"})
			qparm := request.URL.Query()
			qparm.Add("digest", "a")
			qparm.Add("digest", "abc")
			request.URL.RawQuery = qparm.Encode()
			response = httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)
		})

		Convey("Delete blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.DeleteBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), http.MethodDelete, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.DeleteBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})
	})
}

func TestListingTags(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	ctlr := makeController(conf, t.TempDir())
	ctlr.Config.Storage.Commit = true

	cm := test.NewControllerManager(ctlr)
	cm.StartAndWait(port)

	defer cm.StopServer()

	rthdlr := api.NewRouteHandler(ctlr)

	img := CreateRandomImage()
	sigTag := fmt.Sprintf("sha256-%s.sig", img.Digest().Encoded())

	repoName := "test-tags"
	tagsList := []string{
		"1", "2", "1.0.0", "new", "2.0.0", sigTag,
		"2-test", "New", "2.0.0-test", "latest",
	}

	for _, tag := range tagsList {
		err := UploadImage(img, baseURL, repoName, tag)
		if err != nil {
			panic(err)
		}
	}

	// Note empty strings signify the query parameter is not set
	// There are separate tests for passing the empty string as query parameter
	testCases := []struct {
		testCaseName string
		pageSize     string
		last         string
		expectedTags []string
	}{
		{
			testCaseName: "Test tag soting order with no parameters",
			pageSize:     "",
			last:         "",
			expectedTags: []string{
				"1", "1.0.0", "2", "2-test", "2.0.0", "2.0.0-test",
				"New", "latest", "new", sigTag,
			},
		},
		{
			testCaseName: "Test with the parameter 'n' lower than total number of results",
			pageSize:     "5",
			last:         "",
			expectedTags: []string{
				"1", "1.0.0", "2", "2-test", "2.0.0",
			},
		},
		{
			testCaseName: "Test with the parameter 'n' larger than total number of results",
			pageSize:     "50",
			last:         "",
			expectedTags: []string{
				"1", "1.0.0", "2", "2-test", "2.0.0", "2.0.0-test",
				"New", "latest", "new", sigTag,
			},
		},
		{
			testCaseName: "Test the parameter 'n' is 0",
			pageSize:     "0",
			last:         "",
			expectedTags: []string{},
		},
		{
			testCaseName: "Test the parameters 'n' and 'last'",
			pageSize:     "5",
			last:         "2-test",
			expectedTags: []string{"2.0.0", "2.0.0-test", "New", "latest", "new"},
		},
		{
			testCaseName: "Test the parameters 'n' and 'last' with `n` exceeding total number of results",
			pageSize:     "5",
			last:         "latest",
			expectedTags: []string{"new", sigTag},
		},
		{
			testCaseName: "Test the parameter 'n' and 'last' being second to last tag as value",
			pageSize:     "2",
			last:         "new",
			expectedTags: []string{sigTag},
		},
		{
			testCaseName: "Test the parameter 'last' without parameter 'n'",
			pageSize:     "",
			last:         "2",
			expectedTags: []string{
				"2-test", "2.0.0", "2.0.0-test",
				"New", "latest", "new", sigTag,
			},
		},
		{
			testCaseName: "Test the parameter 'last' with the final tag as value",
			pageSize:     "",
			last:         sigTag,
			expectedTags: []string{},
		},
		{
			testCaseName: "Test the parameter 'last' with the second to last tag as value",
			pageSize:     "",
			last:         "new",
			expectedTags: []string{sigTag},
		},
	}

	for _, testCase := range testCases {
		Convey(testCase.testCaseName, t, func() {
			t.Log("Running " + testCase.testCaseName)

			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": repoName})

			if testCase.pageSize != "" || testCase.last != "" {
				qparm := request.URL.Query()

				if testCase.pageSize != "" {
					qparm.Add("n", testCase.pageSize)
				}

				if testCase.last != "" {
					qparm.Add("last", testCase.last)
				}

				request.URL.RawQuery = qparm.Encode()
			}

			response := httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusOK)

			var tags common.ImageTags
			err := json.NewDecoder(resp.Body).Decode(&tags)
			So(err, ShouldBeNil)
			So(tags.Tags, ShouldEqual, testCase.expectedTags)

			alltags := tagsList
			sort.Strings(alltags)

			actualLinkValue := resp.Header.Get("Link")
			if testCase.pageSize == "0" || testCase.pageSize == "" { //nolint:gocritic
				So(actualLinkValue, ShouldEqual, "")
			} else if testCase.expectedTags[len(testCase.expectedTags)-1] == alltags[len(alltags)-1] {
				So(actualLinkValue, ShouldEqual, "")
			} else {
				expectedLinkValue := fmt.Sprintf("</v2/%s/tags/list?n=%s&last=%s>; rel=\"next\"",
					repoName, testCase.pageSize, tags.Tags[len(tags.Tags)-1],
				)
				So(actualLinkValue, ShouldEqual, expectedLinkValue)
			}

			t.Log("Finished " + testCase.testCaseName)
		})
	}
}

func TestStorageCommit(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		ctlr.Config.Storage.Commit = true

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		Convey("Manifests", func() {
			_, _ = Print("\nManifests")

			// check a non-existent manifest
			resp, err := resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				Head(baseURL + "/v2/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			image := CreateImageWith().RandomLayers(1, 2).DefaultConfig().Build()

			repoName := "repo7"
			err = UploadImage(image, baseURL, repoName, "test:1.0")
			So(err, ShouldBeNil)

			_, err = os.Stat(path.Join(dir, "repo7"))
			So(err, ShouldBeNil)

			content := image.ManifestDescriptor.Data
			digest := image.ManifestDescriptor.Digest
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr := resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repo7/manifests/test:1.0.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr = resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())

			err = UploadImage(image, baseURL, repoName, "test:1.0.1")
			So(err, ShouldBeNil)

			image = CreateImageWith().RandomLayers(1, 1).DefaultConfig().Build()

			err = UploadImage(image, baseURL, repoName, "test:2.0")
			So(err, ShouldBeNil)

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr = resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)

			// delete manifest by tag should pass
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			// delete manifest by digest (1.0 deleted but 1.0.1 has same reference)
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			// delete manifest by digest
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			// delete again should fail
			resp, err = resty.R().Delete(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			// check/get by tag
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/test:2.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)
			// check/get by reference
			resp, err = resty.R().Head(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			resp, err = resty.R().Get(baseURL + "/v2/repo7/manifests/" + digest.String())
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			So(resp.Body(), ShouldNotBeEmpty)
		})
	})
}

func TestManifestImageIndex(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		rthdlr := api.NewRouteHandler(ctlr)

		img := CreateImageWith().RandomLayers(1, 2).DefaultConfig().Build()

		// check a non-existent manifest
		resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
			Head(baseURL + "/v2/unknown/manifests/test:1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		repoName := "index"
		err = UploadImage(img, baseURL, repoName, "test:1.0")
		So(err, ShouldBeNil)

		_, err = os.Stat(path.Join(dir, "index"))
		So(err, ShouldBeNil)

		content := img.ManifestDescriptor.Data
		digest := img.ManifestDescriptor.Digest
		So(digest, ShouldNotBeNil)
		m1content := content
		resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
			SetBody(content).Put(baseURL + "/v2/index/manifests/test:1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
		digestHdr := resp.Header().Get(constants.DistContentDigestKey)
		So(digestHdr, ShouldNotBeEmpty)
		So(digestHdr, ShouldEqual, digest.String())

		// create another manifest but upload using its sha256 reference

		// upload image config blob
		resp, err = resty.R().Post(baseURL + "/v2/index/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		img = CreateRandomImage()

		err = UploadImage(img, baseURL, repoName, img.DigestStr())
		So(err, ShouldBeNil)

		content = img.ManifestDescriptor.Data
		digest = img.ManifestDescriptor.Digest

		m2dgst := digest
		m2size := len(content)
		resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
			SetBody(content).Put(baseURL + fmt.Sprintf("/v2/index/manifests/%s", digest))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
		digestHdr = resp.Header().Get(constants.DistContentDigestKey)
		So(digestHdr, ShouldNotBeEmpty)
		So(digestHdr, ShouldEqual, digest.String())

		Convey("Image index", func() {
			img := CreateRandomImage()

			err = UploadImage(img, baseURL, repoName, img.DigestStr())
			So(err, ShouldBeNil)

			content := img.ManifestDescriptor.Data
			digest = img.ManifestDescriptor.Digest

			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
				SetBody(content).Put(baseURL + fmt.Sprintf("/v2/index/manifests/%s", digest.String()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr := resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())

			var index ispec.Index
			index.SchemaVersion = 2
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    digest,
					Size:      int64(len(content)),
				},
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    m2dgst,
					Size:      int64(m2size),
				},
			}

			content, err = json.Marshal(index)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			index1dgst := digest
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				SetBody(content).Put(baseURL + "/v2/index/manifests/test:index1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr = resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(baseURL + "/v2/index/manifests/test:index1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			img = CreateRandomImage()

			err = UploadImage(img, baseURL, repoName, img.DigestStr())
			So(err, ShouldBeNil)

			content = img.ManifestDescriptor.Data
			digest = img.ManifestDescriptor.Digest

			m4dgst := digest
			m4size := len(content)
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
				SetBody(content).Put(baseURL + fmt.Sprintf("/v2/index/manifests/%s", digest.String()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr = resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())

			index.SchemaVersion = 2
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    digest,
					Size:      int64(len(content)),
				},
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    m2dgst,
					Size:      int64(m2size),
				},
			}

			content, err = json.Marshal(index)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				SetBody(content).Put(baseURL + "/v2/index/manifests/test:index2")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr = resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(baseURL + "/v2/index/manifests/test:index2")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			Convey("List tags", func() {
				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodGet, baseURL, nil)
				request = mux.SetURLVars(request, map[string]string{"name": "index"})
				response := httptest.NewRecorder()

				rthdlr.ListTags(response, request)

				resp := response.Result()
				defer resp.Body.Close()
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode, ShouldEqual, http.StatusOK)

				var tags common.ImageTags
				err = json.NewDecoder(resp.Body).Decode(&tags)
				So(err, ShouldBeNil)
				So(len(tags.Tags), ShouldEqual, 3)
				So(tags.Tags, ShouldContain, "test:1.0")
				So(tags.Tags, ShouldContain, "test:index1")
				So(tags.Tags, ShouldContain, "test:index2")
			})

			Convey("Another index with same manifest", func() {
				var index ispec.Index
				index.SchemaVersion = 2
				index.Manifests = []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    m4dgst,
						Size:      int64(m4size),
					},
				}

				content, err = json.Marshal(index)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					SetBody(content).Put(baseURL + "/v2/index/manifests/test:index3")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
				digestHdr = resp.Header().Get(constants.DistContentDigestKey)
				So(digestHdr, ShouldNotBeEmpty)
				So(digestHdr, ShouldEqual, digest.String())
			})

			Convey("Another index using digest with same manifest", func() {
				var index ispec.Index
				index.SchemaVersion = 2
				index.Manifests = []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    m4dgst,
						Size:      int64(m4size),
					},
				}

				content, err = json.Marshal(index)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					SetBody(content).Put(baseURL + fmt.Sprintf("/v2/index/manifests/%s", digest))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
				digestHdr = resp.Header().Get(constants.DistContentDigestKey)
				So(digestHdr, ShouldNotBeEmpty)
				So(digestHdr, ShouldEqual, digest.String())
			})

			Convey("Deleting manifest contained by a multiarch image should not be allowed", func() {
				resp, err = resty.R().Delete(baseURL + fmt.Sprintf("/v2/index/manifests/%s", m2dgst.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
			})

			Convey("Deleting an image index", func() {
				// delete manifest by tag should pass
				resp, err = resty.R().Delete(baseURL + "/v2/index/manifests/test:index3")
				So(err, ShouldBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index3")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
				So(resp.Body(), ShouldNotBeEmpty)
				resp, err = resty.R().Delete(baseURL + "/v2/index/manifests/test:index1")
				So(err, ShouldBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
				So(resp.Body(), ShouldNotBeEmpty)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index2")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			})

			Convey("Deleting an image index by digest", func() {
				// delete manifest by tag should pass
				resp, err = resty.R().Delete(baseURL + "/v2/index/manifests/test:index3")
				So(err, ShouldBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index3")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
				So(resp.Body(), ShouldNotBeEmpty)
				resp, err = resty.R().Delete(baseURL + fmt.Sprintf("/v2/index/manifests/%s", index1dgst))
				So(err, ShouldBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
				So(resp.Body(), ShouldNotBeEmpty)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index2")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)
			})

			Convey("Update an index tag with different manifest", func() {
				img := CreateRandomImage()

				err = UploadImage(img, baseURL, repoName, img.DigestStr())
				So(err, ShouldBeNil)

				content = img.ManifestDescriptor.Data
				digest = img.ManifestDescriptor.Digest

				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
					SetBody(content).Put(baseURL + fmt.Sprintf("/v2/index/manifests/%s", digest))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
				digestHdr = resp.Header().Get(constants.DistContentDigestKey)
				So(digestHdr, ShouldNotBeEmpty)
				So(digestHdr, ShouldEqual, digest.String())

				index.SchemaVersion = 2
				index.Manifests = []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
						Size:      int64(len(content)),
					},
				}

				content, err = json.Marshal(index)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					SetBody(content).Put(baseURL + "/v2/index/manifests/test:index1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
				digestHdr = resp.Header().Get(constants.DistContentDigestKey)
				So(digestHdr, ShouldNotBeEmpty)
				So(digestHdr, ShouldEqual, digest.String())
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

				// delete manifest by tag should pass
				resp, err = resty.R().Delete(baseURL + "/v2/index/manifests/test:index1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(baseURL + "/v2/index/manifests/test:index1")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
				So(resp.Body(), ShouldNotBeEmpty)
			})

			Convey("Negative test cases", func() {
				Convey("Delete index", func() {
					err = os.Remove(path.Join(dir, "index", "blobs", index1dgst.Algorithm().String(), index1dgst.Encoded()))
					So(err, ShouldBeNil)
					resp, err = resty.R().Delete(baseURL + fmt.Sprintf("/v2/index/manifests/%s", index1dgst))
					So(err, ShouldBeNil)
					resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
						Get(baseURL + "/v2/index/manifests/test:index1")
					So(err, ShouldBeNil)
					So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
					So(resp.Body(), ShouldNotBeEmpty)
				})

				Convey("Corrupt index", func() {
					err = os.WriteFile(path.Join(dir, "index", "blobs", index1dgst.Algorithm().String(), index1dgst.Encoded()),
						[]byte("deadbeef"), storageConstants.DefaultFilePerms)
					So(err, ShouldBeNil)
					resp, err = resty.R().Delete(baseURL + fmt.Sprintf("/v2/index/manifests/%s", index1dgst))
					So(err, ShouldBeNil)
					resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
						Get(baseURL + "/v2/index/manifests/test:index1")
					So(err, ShouldBeNil)
					So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
					So(resp.Body(), ShouldBeEmpty)
				})

				Convey("Change media-type", func() {
					// previously a manifest, try writing an image index
					var index ispec.Index
					index.SchemaVersion = 2
					index.Manifests = []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageIndex,
							Digest:    m4dgst,
							Size:      int64(m4size),
						},
					}

					content, err = json.Marshal(index)
					So(err, ShouldBeNil)
					digest = godigest.FromBytes(content)
					So(digest, ShouldNotBeNil)
					resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
						SetBody(content).Put(baseURL + "/v2/index/manifests/test:1.0")
					So(err, ShouldBeNil)
					So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

					// previously an image index, try writing a manifest
					resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
						SetBody(m1content).Put(baseURL + "/v2/index/manifests/test:index1")
					So(err, ShouldBeNil)
					So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
				})
			})
		})
	})
}

func TestManifestCollision(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				test.AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{
						constants.ReadPermission,
						constants.CreatePermission,
						constants.DeletePermission,
						constants.DetectManifestCollisionPermission,
					},
				},
			},
		}

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		img := CreateImageWith().RandomLayers(1, 2).DefaultConfig().Build()

		err := UploadImage(img, baseURL, "index", "test:1.0")
		So(err, ShouldBeNil)

		_, err = os.Stat(path.Join(dir, "index"))
		So(err, ShouldBeNil)

		// check a non-existent manifest
		resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
			Head(baseURL + "/v2/unknown/manifests/test:1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		digest := img.ManifestDescriptor.Digest
		So(digest, ShouldNotBeNil)

		err = UploadImage(img, baseURL, "index", "test:2.0")
		So(err, ShouldBeNil)

		// Deletion should fail if using digest
		resp, err = resty.R().Delete(baseURL + "/v2/index/manifests/" + digest.String())
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusConflict)

		// remove detectManifestCollision action from ** (all repos)
		repoPolicy := conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos]
		repoPolicy.AnonymousPolicy = []string{"read", "delete"}
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos] = repoPolicy

		resp, err = resty.R().Delete(baseURL + "/v2/index/manifests/" + digest.String())
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		resp, err = resty.R().Get(baseURL + "/v2/index/manifests/test:1.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, err = resty.R().Get(baseURL + "/v2/index/manifests/test:2.0")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestPullRange(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// create a blob/layer
		resp, err := resty.R().Post(baseURL + "/v2/index/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := test.Location(baseURL, resp)
		So(loc, ShouldNotBeEmpty)

		// since we are not specifying any prefix i.e provided in config while starting server,
		// so it should store index1 to global root dir
		_, err = os.Stat(path.Join(dir, "index"))
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(loc)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
		content := []byte("0123456789")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)
		// monolithic blob upload: success
		resp, err = resty.R().SetQueryParam("digest", digest.String()).
			SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
		blobLoc := resp.Header().Get("Location")
		So(blobLoc, ShouldNotBeEmpty)
		So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
		So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)
		blobLoc = baseURL + blobLoc

		Convey("Range is supported using 'bytes'", func() {
			resp, err = resty.R().Head(blobLoc)
			So(err, ShouldBeNil)
			So(resp.Header().Get("Accept-Ranges"), ShouldEqual, "bytes")
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Get a range of bytes", func() {
			resp, err = resty.R().SetHeader("Range", "bytes=0-").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusPartialContent)
			So(resp.Header().Get("Content-Length"), ShouldEqual, fmt.Sprintf("%d", len(content)))
			So(resp.Body(), ShouldResemble, content)

			resp, err = resty.R().SetHeader("Range", "bytes=0-100").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusPartialContent)
			So(resp.Header().Get("Content-Length"), ShouldEqual, fmt.Sprintf("%d", len(content)))
			So(resp.Body(), ShouldResemble, content)

			resp, err = resty.R().SetHeader("Range", "bytes=0-10").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusPartialContent)
			So(resp.Header().Get("Content-Length"), ShouldEqual, fmt.Sprintf("%d", len(content)))
			So(resp.Body(), ShouldResemble, content)

			resp, err = resty.R().SetHeader("Range", "bytes=0-0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusPartialContent)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "1")
			So(resp.Body(), ShouldResemble, content[0:1])

			resp, err = resty.R().SetHeader("Range", "bytes=0-1").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusPartialContent)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "2")
			So(resp.Body(), ShouldResemble, content[0:2])

			resp, err = resty.R().SetHeader("Range", "bytes=2-3").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusPartialContent)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "2")
			So(resp.Body(), ShouldResemble, content[2:4])
		})

		Convey("Negative cases", func() {
			resp, err = resty.R().SetHeader("Range", "=0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "=a").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "=").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "byte=").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "byte=-0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "byte=0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "octet=-0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=-0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=1-0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=-1-0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=-1--0").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=1--2").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=0-a").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=a-10").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)

			resp, err = resty.R().SetHeader("Range", "bytes=a-b").Get(blobLoc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusRequestedRangeNotSatisfiable)
		})
	})
}

func TestInjectInterruptedImageManifest(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		rthdlr := api.NewRouteHandler(ctlr)

		Convey("Upload a blob & a config blob; Create an image manifest", func() {
			// create a blob/layer
			resp, err := resty.R().Post(baseURL + "/v2/repotest/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			// since we are not specifying any prefix i.e provided in config while starting server,
			// so it should store repotest to global root dir
			_, err = os.Stat(path.Join(dir, "repotest"))
			So(err, ShouldBeNil)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
			content := []byte("this is a dummy blob")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			// monolithic blob upload: success
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)

			// upload image config blob
			resp, err = resty.R().Post(baseURL + "/v2/repotest/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc = test.Location(baseURL, resp)
			cblob, cdigest := GetRandomImageConfig()

			resp, err = resty.R().
				SetContentLength(true).
				SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
				SetHeader("Content-Type", "application/octet-stream").
				SetQueryParam("digest", cdigest.String()).
				SetBody(cblob).
				Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: "application/vnd.oci.image.config.v1+json",
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/vnd.oci.image.layer.v1.tar",
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			// Testing router path:  @Router /v2/{name}/manifests/{reference} [put]
			Convey("Uploading an image manifest blob (when injected simulates an interrupted image manifest upload)", func() {
				injected := inject.InjectFailure(0)

				request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, bytes.NewReader(content))
				request = mux.SetURLVars(request, map[string]string{"name": "repotest", "reference": "1.0"})
				request.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
				response := httptest.NewRecorder()

				rthdlr.UpdateManifest(response, request)

				resp := response.Result()
				defer resp.Body.Close()

				So(resp, ShouldNotBeNil)

				if injected {
					So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
				} else {
					So(resp.StatusCode, ShouldEqual, http.StatusCreated)
				}
			})
		})
	})
}

func TestInjectTooManyOpenFiles(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		conf.Storage.RemoteCache = false

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		rthdlr := api.NewRouteHandler(ctlr)

		// create a blob/layer
		resp, err := resty.R().Post(baseURL + "/v2/repotest/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := test.Location(baseURL, resp)
		So(loc, ShouldNotBeEmpty)

		// since we are not specifying any prefix i.e provided in config while starting server,
		// so it should store repotest to global root dir
		_, err = os.Stat(path.Join(dir, "repotest"))
		So(err, ShouldBeNil)

		resp, err = resty.R().Get(loc)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
		content := []byte("this is a dummy blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		// monolithic blob upload
		injected := inject.InjectFailure(2)
		if injected {
			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, loc, bytes.NewReader(content))
			tokens := strings.Split(loc, "/")
			request = mux.SetURLVars(request, map[string]string{"name": "repotest", "session_id": tokens[len(tokens)-1]})
			q := request.URL.Query()
			q.Add("digest", digest.String())
			request.URL.RawQuery = q.Encode()
			request.Header.Set("Content-Type", "application/octet-stream")
			request.Header.Set("Content-Length", fmt.Sprintf("%d", len(content)))
			response := httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()

			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
		} else {
			resp, err = resty.R().SetQueryParam("digest", digest.String()).
				SetHeader("Content-Type", "application/octet-stream").
				SetBody(content).Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			blobLoc := resp.Header().Get("Location")
			So(blobLoc, ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Length"), ShouldEqual, "0")
			So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)
		}

		// upload image config blob
		resp, err = resty.R().Post(baseURL + "/v2/repotest/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)
		cblob, cdigest := GetRandomImageConfig()

		resp, err = resty.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", cdigest.String()).
			SetBody(cblob).
			Put(loc)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// create a manifest
		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(len(content)),
				},
			},
		}
		manifest.SchemaVersion = 2
		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest = godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		// Testing router path:  @Router /v2/{name}/manifests/{reference} [put]
		//nolint:lll // gofumpt conflicts with lll
		Convey("Uploading an image manifest blob (when injected simulates that PutImageManifest failed due to 'too many open files' error)", func() {
			injected := inject.InjectFailure(2)

			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, bytes.NewReader(content))
			request = mux.SetURLVars(request, map[string]string{"name": "repotest", "reference": "1.0"})
			request.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			response := httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp := response.Result()
			So(resp, ShouldNotBeNil)
			defer resp.Body.Close()

			if injected {
				So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusCreated)
			}
		})
		Convey("when injected simulates a `too many open files` error inside PutImageManifest method of img store", func() {
			injected := inject.InjectFailure(2)

			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, bytes.NewReader(content))
			request = mux.SetURLVars(request, map[string]string{"name": "repotest", "reference": "1.0"})
			request.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			response := httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()

			So(resp, ShouldNotBeNil)

			if injected {
				So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusCreated)
			}
		})
		Convey("code coverage: error inside PutImageManifest method of img store (unable to marshal JSON)", func() {
			injected := inject.InjectFailure(1)

			request, _ := http.NewRequestWithContext(context.TODO(), http.MethodPut, baseURL, bytes.NewReader(content))
			request = mux.SetURLVars(request, map[string]string{"name": "repotest", "reference": "1.0"})
			request.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			response := httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()

			So(resp, ShouldNotBeNil)

			if injected {
				So(resp.StatusCode, ShouldEqual, http.StatusInternalServerError)
			} else {
				So(resp.StatusCode, ShouldEqual, http.StatusCreated)
			}
		})

		Convey("when index.json is not in json format", func() {
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repotest/manifests/v1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
			digestHdr := resp.Header().Get(constants.DistContentDigestKey)
			So(digestHdr, ShouldNotBeEmpty)
			So(digestHdr, ShouldEqual, digest.String())

			indexFile := path.Join(dir, "repotest", "index.json")
			_, err = os.Stat(indexFile)
			So(err, ShouldBeNil)
			indexContent := []byte(`not a JSON content`)
			err = os.WriteFile(indexFile, indexContent, 0o600)
			So(err, ShouldBeNil)

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repotest/manifests/v1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})
	})
}

func TestGCSignaturesAndUntaggedManifestsWithMetaDB(t *testing.T) {
	ctx := context.Background()

	Convey("Make controller", t, func() {
		trueVal := true

		Convey("Garbage collect signatures without subject and manifests without tags", func(c C) {
			repoName := "testrepo" //nolint:goconst
			tag := "0.0.1"

			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port

			logFile, err := os.CreateTemp("", "zot-log*.txt")
			So(err, ShouldBeNil)

			conf.Log.Audit = logFile.Name()

			value := true
			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &value},
			}

			// added search extensions so that metaDB is initialized and its tested in GC logic
			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}

			ctlr := makeController(conf, t.TempDir())

			dir := t.TempDir()
			ctlr.Config.Storage.RootDirectory = dir
			ctlr.Config.Storage.GC = true
			ctlr.Config.Storage.GCDelay = 1 * time.Millisecond
			ctlr.Config.Storage.Retention = config.ImageRetention{
				Delay: 1 * time.Millisecond,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
						DeleteUntagged:  &trueVal,
						KeepTags: []config.KeepTagsPolicy{
							{
								Patterns: []string{".*"}, // just for coverage
							},
						},
					},
				},
			}

			ctlr.Config.Storage.Dedupe = false

			cm := test.NewControllerManager(ctlr)
			cm.StartServer() //nolint: contextcheck
			cm.WaitServerToBeReady(port)
			defer cm.StopServer()

			img := CreateDefaultImage()

			err = UploadImage(img, baseURL, repoName, tag)
			So(err, ShouldBeNil)

			gc := gc.NewGarbageCollect(ctlr.StoreController.DefaultStore, ctlr.MetaDB,
				gc.Options{
					Delay:          ctlr.Config.Storage.GCDelay,
					ImageRetention: ctlr.Config.Storage.Retention,
				}, ctlr.Audit, ctlr.Log)

			resp, err := resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, tag))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			digest := godigest.FromBytes(resp.Body())
			So(digest, ShouldNotBeEmpty)

			cwd, err := os.Getwd()
			So(err, ShouldBeNil)
			defer func() { _ = os.Chdir(cwd) }()
			tdir := t.TempDir()
			_ = os.Chdir(tdir)

			// generate a keypair
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(ctx, "", "cosign", nil)
			So(err, ShouldBeNil)

			image := fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())

			annotations := []string{fmt.Sprintf("tag=%s", tag)}

			// sign the image
			err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
				options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
				options.SignOptions{
					Registry:          options.RegistryOptions{AllowInsecure: true},
					AnnotationOptions: options.AnnotationOptions{Annotations: annotations},
					Upload:            true,
				},
				[]string{image})

			So(err, ShouldBeNil)

			signature.NotationPathLock.Lock()
			defer signature.NotationPathLock.Unlock()

			signature.LoadNotationPath(tdir)

			// generate a keypair
			err = signature.GenerateNotationCerts(tdir, "good")
			So(err, ShouldBeNil)

			// sign the image
			err = signature.SignWithNotation("good", image, tdir, true) //nolint: contextcheck
			So(err, ShouldBeNil)

			// get cosign signature manifest
			cosignTag := strings.Replace(digest.String(), ":", "-", 1) + "." + remote.SignatureTagSuffix

			resp, err = resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, cosignTag))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			cosignDigest := resp.Header().Get(constants.DistContentDigestKey)
			So(cosignDigest, ShouldNotBeEmpty)

			// get notation signature manifest
			resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
				fmt.Sprintf("%s/v2/%s/referrers/%s", baseURL, repoName, digest.String()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var index ispec.Index

			err = json.Unmarshal(resp.Body(), &index)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 1)

			// shouldn't do anything
			err = gc.CleanRepo(ctx, repoName) //nolint: contextcheck
			So(err, ShouldBeNil)

			// make sure both signatures are stored in repodb
			repoMeta, err := ctlr.MetaDB.GetRepoMeta(ctx, repoName)
			So(err, ShouldBeNil)

			sigMeta := repoMeta.Signatures[digest.String()]
			So(len(sigMeta[storage.CosignType]), ShouldEqual, 1)
			So(len(sigMeta[storage.NotationType]), ShouldEqual, 1)
			So(sigMeta[storage.CosignType][0].SignatureManifestDigest, ShouldEqual, cosignDigest)
			So(sigMeta[storage.NotationType][0].SignatureManifestDigest, ShouldEqual, index.Manifests[0].Digest.String())

			Convey("Trigger gcNotationSignatures() error", func() {
				var refs ispec.Index
				err = json.Unmarshal(resp.Body(), &refs)

				err := os.Chmod(path.Join(dir, repoName, "blobs", "sha256", refs.Manifests[0].Digest.Encoded()), 0o000)
				So(err, ShouldBeNil)

				// trigger gc
				img := CreateRandomImage()

				err = UploadImage(img, baseURL, repoName, img.DigestStr())
				So(err, ShouldBeNil)

				err = gc.CleanRepo(ctx, repoName)
				So(err, ShouldNotBeNil)

				err = os.Chmod(path.Join(dir, repoName, "blobs", "sha256", refs.Manifests[0].Digest.Encoded()), 0o755)
				So(err, ShouldBeNil)

				content, err := os.ReadFile(path.Join(dir, repoName, "blobs", "sha256", refs.Manifests[0].Digest.Encoded()))
				So(err, ShouldBeNil)
				err = os.WriteFile(path.Join(dir, repoName, "blobs", "sha256", refs.Manifests[0].Digest.Encoded()), []byte("corrupt"), 0o600) //nolint:lll
				So(err, ShouldBeNil)

				err = UploadImage(img, baseURL, repoName, tag)
				So(err, ShouldBeNil)

				err = gc.CleanRepo(ctx, repoName)
				So(err, ShouldNotBeNil)

				err = os.WriteFile(path.Join(dir, repoName, "blobs", "sha256", refs.Manifests[0].Digest.Encoded()), content, 0o600)
				So(err, ShouldBeNil)
			})

			Convey("Overwrite original image, signatures should be garbage-collected", func() {
				// push an image without tag
				img := CreateImageWith().RandomLayers(1, 2).DefaultConfig().Build()

				untaggedManifestDigest := img.ManifestDescriptor.Digest

				err = UploadImage(img, baseURL, repoName, untaggedManifestDigest.String())
				So(err, ShouldBeNil)

				// make sure repoDB reference was added
				repoMeta, err := ctlr.MetaDB.GetRepoMeta(ctx, repoName)
				So(err, ShouldBeNil)

				_, ok := repoMeta.Referrers[untaggedManifestDigest.String()]
				So(ok, ShouldBeTrue)
				_, ok = repoMeta.Signatures[untaggedManifestDigest.String()]
				So(ok, ShouldBeTrue)
				_, ok = repoMeta.Statistics[untaggedManifestDigest.String()]
				So(ok, ShouldBeTrue)

				// overwrite image so that signatures will get invalidated and gc'ed
				img = CreateImageWith().RandomLayers(1, 3).DefaultConfig().Build()

				err = UploadImage(img, baseURL, repoName, tag)
				So(err, ShouldBeNil)

				newManifestDigest := img.ManifestDescriptor.Digest

				err = gc.CleanRepo(ctx, repoName) //nolint: contextcheck
				So(err, ShouldBeNil)

				// make sure both signatures are removed from metaDB and repo reference for untagged is removed
				repoMeta, err = ctlr.MetaDB.GetRepoMeta(ctx, repoName)
				So(err, ShouldBeNil)

				sigMeta := repoMeta.Signatures[digest.String()]
				So(len(sigMeta[storage.CosignType]), ShouldEqual, 0)
				So(len(sigMeta[storage.NotationType]), ShouldEqual, 0)

				_, ok = repoMeta.Referrers[untaggedManifestDigest.String()]
				So(ok, ShouldBeFalse)
				_, ok = repoMeta.Signatures[untaggedManifestDigest.String()]
				So(ok, ShouldBeFalse)
				_, ok = repoMeta.Statistics[untaggedManifestDigest.String()]
				So(ok, ShouldBeFalse)

				// both signatures should be gc'ed
				resp, err = resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, cosignTag))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/v2/%s/referrers/%s", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				err = json.Unmarshal(resp.Body(), &index)
				So(err, ShouldBeNil)
				So(len(index.Manifests), ShouldEqual, 0)

				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/v2/%s/referrers/%s", baseURL, repoName, newManifestDigest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				err = json.Unmarshal(resp.Body(), &index)
				So(err, ShouldBeNil)
				So(len(index.Manifests), ShouldEqual, 0)

				// untagged image should also be gc'ed
				resp, err = resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, untaggedManifestDigest))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			})
		})

		Convey("Do not gc manifests which are part of a multiarch image", func(c C) {
			repoName := "testrepo" //nolint:goconst
			tag := "0.0.1"

			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port

			ctlr := makeController(conf, t.TempDir())

			dir := t.TempDir()
			ctlr.Config.Storage.RootDirectory = dir
			ctlr.Config.Storage.GC = true
			ctlr.Config.Storage.GCDelay = 1 * time.Second
			ctlr.Config.Storage.Retention = config.ImageRetention{
				Delay: 1 * time.Second,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
						DeleteUntagged:  &trueVal,
					},
				},
			}

			err := WriteImageToFileSystem(CreateDefaultImage(), repoName, tag,
				ociutils.GetDefaultStoreController(dir, ctlr.Log))
			So(err, ShouldBeNil)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port) //nolint: contextcheck
			defer cm.StopServer()

			gc := gc.NewGarbageCollect(ctlr.StoreController.DefaultStore, ctlr.MetaDB,
				gc.Options{
					Delay:          ctlr.Config.Storage.GCDelay,
					ImageRetention: ctlr.Config.Storage.Retention,
				}, ctlr.Audit, ctlr.Log)

			resp, err := resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, tag))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			digest := godigest.FromBytes(resp.Body())
			So(digest, ShouldNotBeEmpty)

			// push an image index and make sure manifests contained by it are not gc'ed
			// create an image index on upstream
			var index ispec.Index
			index.SchemaVersion = 2
			index.MediaType = ispec.MediaTypeImageIndex

			// upload multiple manifests
			for i := 0; i < 4; i++ {
				img := CreateImageWith().RandomLayers(1, 1000+i).DefaultConfig().Build()

				manifestDigest := img.ManifestDescriptor.Digest

				err = UploadImage(img, baseURL, repoName, manifestDigest.String())
				So(err, ShouldBeNil)

				index.Manifests = append(index.Manifests, ispec.Descriptor{
					Digest:    manifestDigest,
					MediaType: ispec.MediaTypeImageManifest,
					Size:      img.ManifestDescriptor.Size,
				})
			}

			content, err := json.Marshal(index)
			So(err, ShouldBeNil)
			indexDigest := godigest.FromBytes(content)
			So(indexDigest, ShouldNotBeNil)

			time.Sleep(1 * time.Second)
			// upload image index
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				SetBody(content).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/latest", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(baseURL + fmt.Sprintf("/v2/%s/manifests/latest", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			// make sure manifests which are part of image index are not gc'ed
			for _, manifest := range index.Manifests {
				resp, err = resty.R().Get(baseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, manifest.Digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			}
		})
	})
}

func TestPeriodicGC(t *testing.T) {
	Convey("Periodic gc enabled for default store", t, func() {
		repoName := "testrepo" //nolint:goconst

		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RemoteCache = false

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.Dedupe = false
		ctlr.Config.Storage.GC = true
		ctlr.Config.Storage.GCInterval = 1 * time.Hour
		ctlr.Config.Storage.GCDelay = 1 * time.Second

		err = WriteImageToFileSystem(CreateDefaultImage(), repoName, "0.0.1",
			ociutils.GetDefaultStoreController(dir, ctlr.Log))
		So(err, ShouldBeNil)

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		time.Sleep(5000 * time.Millisecond)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"\"GC\":true,\"Commit\":false,\"GCDelay\":1000000000,\"GCInterval\":3600000000000")
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("executing GC of orphaned blobs for %s", path.Join(ctlr.StoreController.DefaultStore.RootDir(), repoName))) //nolint:lll
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("GC successfully completed for %s", path.Join(ctlr.StoreController.DefaultStore.RootDir(), repoName))) //nolint:lll
	})

	Convey("Periodic GC enabled for substore", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		dir := t.TempDir()
		ctlr := makeController(conf, dir)
		subDir := t.TempDir()

		subPaths := make(map[string]config.StorageConfig)

		subPaths["/a"] = config.StorageConfig{
			RootDirectory: subDir,
			GC:            true,
			GCDelay:       1 * time.Second,
			GCInterval:    24 * time.Hour,
			RemoteCache:   false,
			Dedupe:        false,
		} //nolint:lll // gofumpt conflicts with lll
		ctlr.Config.Storage.Dedupe = false
		ctlr.Config.Storage.SubPaths = subPaths

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		// periodic GC is enabled by default for default store with a default interval
		So(string(data), ShouldContainSubstring,
			"\"GCDelay\":3600000000000,\"GCInterval\":3600000000000,\"")
		// periodic GC is enabled for sub store
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("\"SubPaths\":{\"/a\":{\"RootDirectory\":\"%s\",\"Dedupe\":false,\"RemoteCache\":false,\"GC\":true,\"Commit\":false,\"GCDelay\":1000000000,\"GCInterval\":86400000000000", subDir)) //nolint:lll // gofumpt conflicts with lll
	})

	Convey("Periodic gc error", t, func() {
		repoName := "testrepo" //nolint:goconst

		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RemoteCache = false

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.Dedupe = false

		ctlr.Config.Storage.GC = true
		ctlr.Config.Storage.GCInterval = 1 * time.Hour
		ctlr.Config.Storage.GCDelay = 1 * time.Second

		err = WriteImageToFileSystem(CreateDefaultImage(), repoName, "0.0.1",
			ociutils.GetDefaultStoreController(dir, ctlr.Log))
		So(err, ShouldBeNil)

		So(os.Chmod(dir, 0o000), ShouldBeNil)

		defer func() {
			So(os.Chmod(dir, 0o755), ShouldBeNil)
		}()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		time.Sleep(5000 * time.Millisecond)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"\"GC\":true,\"Commit\":false,\"GCDelay\":1000000000,\"GCInterval\":3600000000000")
		So(string(data), ShouldContainSubstring, "failed to walk storage root-dir") //nolint:lll
	})
}

func TestSearchRoutes(t *testing.T) {
	Convey("Upload image for test", t, func(c C) {
		tempDir := t.TempDir()
		repoName := "testrepo" //nolint:goconst
		inaccessibleRepo := "inaccessible"

		Convey("GlobalSearch with authz enabled", func(c C) {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			user1 := "test"
			password1 := "test"
			testString1 := test.GetCredString(user1, password1)
			htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}

			conf.HTTP.Port = port

			defaultVal := true

			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			}

			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}

			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Repositories: config.Repositories{
					repoName: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{user1},
								Actions: []string{"read", "create"},
							},
						},
						DefaultPolicy: []string{},
					},
					inaccessibleRepo: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{user1},
								Actions: []string{"create"},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{},
					Actions: []string{},
				},
			}

			ctlr := makeController(conf, tempDir)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			img := CreateImageWith().RandomLayers(1, 10000).DefaultConfig().Build()

			err := UploadImageWithBasicAuth(
				img, baseURL, repoName, "latest",
				user1, password1)
			So(err, ShouldBeNil)

			// data for the inaccessible repo
			img = CreateImageWith().RandomLayers(1, 10000).DefaultConfig().Build()

			err = UploadImageWithBasicAuth(
				img, baseURL, inaccessibleRepo, "latest",
				user1, password1)
			So(err, ShouldBeNil)

			query := `
				{
					GlobalSearch(query:"testrepo"){
						Repos {
							Name
							NewestImage {
								RepoName
								Tag
							}
						}
					}
				}`
			resp, err := resty.R().SetBasicAuth(user1, password1).Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(query))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
			So(string(resp.Body()), ShouldContainSubstring, repoName)
			So(string(resp.Body()), ShouldNotContainSubstring, inaccessibleRepo)

			resp, err = resty.R().Get(baseURL + constants.FullSearchPrefix + "?query=" + url.QueryEscape(query))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Repositories: config.Repositories{
					repoName: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{user1},
								Actions: []string{},
							},
						},
						DefaultPolicy: []string{},
					},
					inaccessibleRepo: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Users:   []string{},
								Actions: []string{},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{},
					Actions: []string{},
				},
			}

			// authenticated, but no access to resource
			resp, err = resty.R().SetBasicAuth(user1, password1).Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(query))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(string(resp.Body()), ShouldNotContainSubstring, repoName)
			So(string(resp.Body()), ShouldNotContainSubstring, inaccessibleRepo)
		})

		Convey("Testing group permissions", func(c C) {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			user1 := "test1"
			password1 := "test1"
			group1 := "testgroup3"
			testString1 := test.GetCredString(user1, password1)
			htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}

			conf.HTTP.Port = port

			defaultVal := true

			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			}

			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}

			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Groups: config.Groups{
					group1: {
						Users: []string{user1},
					},
				},
				Repositories: config.Repositories{
					repoName: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Groups:  []string{group1},
								Actions: []string{"read", "create"},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{},
					Actions: []string{},
				},
			}

			ctlr := makeController(conf, tempDir)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			img := CreateRandomImage()

			err := UploadImageWithBasicAuth(img, baseURL, repoName, img.DigestStr(), user1, password1)
			So(err, ShouldBeNil)

			query := `
						{
							GlobalSearch(query:"testrepo"){
								Repos {
									Name
									NewestImage {
										RepoName
										Tag
									}
								}
							}
						}`
			resp, err := resty.R().SetBasicAuth(user1, password1).Get(baseURL + constants.FullSearchPrefix +
				"?query=" + url.QueryEscape(query))
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 200)
		})

		Convey("Testing group permissions when the user is part of more groups with different permissions", func(c C) {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			user1 := "test2"
			password1 := "test2"
			group1 := "testgroup1"
			group2 := "secondtestgroup"
			testString1 := test.GetCredString(user1, password1)
			htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}

			conf.HTTP.Port = port

			defaultVal := true

			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			}

			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}

			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Groups: config.Groups{
					group1: {
						Users: []string{user1},
					},
				},
				Repositories: config.Repositories{
					repoName: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Groups:  []string{group1},
								Actions: []string{"delete"},
							},
							{
								Groups:  []string{group2},
								Actions: []string{"read", "create"},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{},
					Actions: []string{},
				},
			}

			ctlr := makeController(conf, tempDir)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			img := CreateRandomImage()

			err := UploadImageWithBasicAuth(img, baseURL, repoName, img.DigestStr(), user1, password1)
			So(err, ShouldNotBeNil)
		})

		Convey("Testing group permissions when group has less permissions than user", func(c C) {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			user1 := "test3"
			password1 := "test3"
			group1 := "testgroup"
			testString1 := test.GetCredString(user1, password1)
			htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}

			conf.HTTP.Port = port

			defaultVal := true

			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			}

			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}

			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Groups: config.Groups{
					group1: {
						Users: []string{user1},
					},
				},
				Repositories: config.Repositories{
					repoName: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Groups:  []string{group1},
								Actions: []string{"delete"},
							},
							{
								Users:   []string{user1},
								Actions: []string{"read", "create", "delete"},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{},
					Actions: []string{},
				},
			}

			ctlr := makeController(conf, tempDir)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			img := CreateRandomImage()

			err := UploadImageWithBasicAuth(img, baseURL, repoName, img.DigestStr(), user1, password1)
			So(err, ShouldBeNil)
		})

		Convey("Testing group permissions when user has less permissions than group", func(c C) {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			user1 := "test4"
			password1 := "test4"
			group1 := "testgroup1"
			testString1 := test.GetCredString(user1, password1)
			htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}

			conf.HTTP.Port = port

			defaultVal := true

			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			}

			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}

			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Groups: config.Groups{
					group1: {
						Users: []string{user1},
					},
				},
				Repositories: config.Repositories{
					repoName: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Groups:  []string{group1},
								Actions: []string{"read", "create", "delete"},
							},
							{
								Users:   []string{user1},
								Actions: []string{"delete"},
							},
						},
						DefaultPolicy: []string{},
					},
				},
				AdminPolicy: config.Policy{
					Users:   []string{},
					Actions: []string{},
				},
			}

			ctlr := makeController(conf, tempDir)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			img := CreateRandomImage()

			err := UploadImageWithBasicAuth(img, baseURL, repoName, img.DigestStr(), user1, password1)
			So(err, ShouldBeNil)
		})

		Convey("Testing group permissions on admin policy", func(c C) {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			user1 := "test5"
			password1 := "test5"
			group1 := "testgroup2"
			testString1 := test.GetCredString(user1, password1)
			htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}

			conf.HTTP.Port = port

			defaultVal := true

			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			}

			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}

			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Groups: config.Groups{
					group1: {
						Users: []string{user1},
					},
				},
				Repositories: config.Repositories{},
				AdminPolicy: config.Policy{
					Groups:  []string{group1},
					Actions: []string{"read", "create"},
				},
			}

			ctlr := makeController(conf, tempDir)

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			img := CreateRandomImage()

			err := UploadImageWithBasicAuth(img, baseURL, repoName, img.DigestStr(), user1, password1)
			So(err, ShouldBeNil)
		})

		Convey("Testing group permissions on anonymous policy", func(c C) {
			conf := config.New()
			port := test.GetFreePort()
			baseURL := test.GetBaseURL(port)

			conf.HTTP.Port = port

			defaultVal := true
			group1, seedGroup1 := test.GenerateRandomString()
			user1, seedUser1 := test.GenerateRandomString()
			password1, seedPass1 := test.GenerateRandomString()
			htpasswdPath := test.MakeHtpasswdFileFromString(test.GetCredString(user1, password1))
			defer os.Remove(htpasswdPath)

			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}

			searchConfig := &extconf.SearchConfig{
				BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			}

			conf.Extensions = &extconf.ExtensionConfig{
				Search: searchConfig,
			}
			conf.HTTP.AccessControl = &config.AccessControlConfig{
				Groups: config.Groups{
					group1: {
						Users: []string{user1},
					},
				},
				Repositories: config.Repositories{
					repoName: config.PolicyGroup{
						Policies: []config.Policy{
							{
								Groups:  []string{group1},
								Actions: []string{"read", "create", "delete"},
							},
							{
								Users:   []string{user1},
								Actions: []string{"delete"},
							},
						},
						DefaultPolicy:   []string{},
						AnonymousPolicy: []string{"read", "create"},
					},
				},
			}

			ctlr := makeController(conf, tempDir)
			ctlr.Log.Info().Int64("seedUser1", seedUser1).Int64("seedPass1", seedPass1).
				Int64("seedGroup1", seedGroup1).Msg("random seed for username,password & group")

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(port)
			defer cm.StopServer()

			img := CreateRandomImage()

			err := UploadImageWithBasicAuth(img, baseURL, repoName, img.DigestStr(), "", "")
			So(err, ShouldBeNil)
		})
	})
}

func TestDistSpecExtensions(t *testing.T) {
	Convey("start zot server with search, ui and trust extensions", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf.HTTP.Port = port

		defaultVal := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultVal
		conf.Extensions.Search.CVE = nil
		conf.Extensions.UI = &extconf.UIConfig{}
		conf.Extensions.UI.Enable = &defaultVal
		conf.Extensions.Trust = &extconf.ImageTrustConfig{}
		conf.Extensions.Trust.Enable = &defaultVal
		conf.Extensions.Trust.Cosign = defaultVal
		conf.Extensions.Trust.Notation = defaultVal

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		var extensionList distext.ExtensionList

		resp, err := resty.R().Get(baseURL + constants.RoutePrefix + constants.ExtOciDiscoverPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &extensionList)
		So(err, ShouldBeNil)
		t.Log(extensionList.Extensions)
		So(len(extensionList.Extensions), ShouldEqual, 1)
		So(len(extensionList.Extensions[0].Endpoints), ShouldEqual, 5)
		So(extensionList.Extensions[0].Name, ShouldEqual, constants.BaseExtension)
		So(extensionList.Extensions[0].URL, ShouldContainSubstring, "_zot.md")
		So(extensionList.Extensions[0].Description, ShouldNotBeEmpty)
		// Verify the endpoints below are enabled by search
		So(extensionList.Extensions[0].Endpoints, ShouldContain, constants.FullSearchPrefix)
		// Verify the endpoints below are enabled by trust
		So(extensionList.Extensions[0].Endpoints, ShouldContain, constants.FullCosign)
		So(extensionList.Extensions[0].Endpoints, ShouldContain, constants.FullNotation)
		// Verify the endpint below are enabled by having both the UI and the Search enabled
		So(extensionList.Extensions[0].Endpoints, ShouldContain, constants.FullMgmt)
		So(extensionList.Extensions[0].Endpoints, ShouldContain, constants.FullUserPrefs)
	})

	Convey("start zot server with only the search extension enabled", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf.HTTP.Port = port

		defaultVal := true

		conf.Extensions = &extconf.ExtensionConfig{}
		conf.Extensions.Search = &extconf.SearchConfig{}
		conf.Extensions.Search.Enable = &defaultVal

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		var extensionList distext.ExtensionList

		resp, err := resty.R().Get(baseURL + constants.RoutePrefix + constants.ExtOciDiscoverPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &extensionList)
		So(err, ShouldBeNil)
		t.Log(extensionList.Extensions)
		So(len(extensionList.Extensions), ShouldEqual, 1)
		So(len(extensionList.Extensions[0].Endpoints), ShouldEqual, 2)
		So(extensionList.Extensions[0].Name, ShouldEqual, constants.BaseExtension)
		So(extensionList.Extensions[0].URL, ShouldContainSubstring, "_zot.md")
		So(extensionList.Extensions[0].Description, ShouldNotBeEmpty)
		// Verify the endpoints below are enabled by search
		So(extensionList.Extensions[0].Endpoints, ShouldContain, constants.FullSearchPrefix)
		So(extensionList.Extensions[0].Endpoints, ShouldContain, constants.FullMgmt)
		// Verify the endpoints below are not enabled since trust is not enabled
		So(extensionList.Extensions[0].Endpoints, ShouldNotContain, constants.FullCosign)
		So(extensionList.Extensions[0].Endpoints, ShouldNotContain, constants.FullNotation)
		// Verify the endpoints below are not enabled since the UI is not enabled
		So(extensionList.Extensions[0].Endpoints, ShouldNotContain, constants.FullUserPrefs)
	})

	Convey("start zot server with no enabled extensions", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf.HTTP.Port = port

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		var extensionList distext.ExtensionList

		resp, err := resty.R().Get(baseURL + constants.RoutePrefix + constants.ExtOciDiscoverPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &extensionList)
		So(err, ShouldBeNil)
		t.Log(extensionList.Extensions)
		// Verify all endpoints which are disabled (even signing urls depend on search being enabled)
		So(len(extensionList.Extensions), ShouldEqual, 0)
	})

	Convey("start minimal zot server", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf.HTTP.Port = port

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := makeController(conf, t.TempDir())

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		var extensionList distext.ExtensionList
		resp, err := resty.R().Get(baseURL + constants.RoutePrefix + constants.ExtOciDiscoverPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		err = json.Unmarshal(resp.Body(), &extensionList)
		So(err, ShouldBeNil)
		So(len(extensionList.Extensions), ShouldEqual, 0)
	})
}

func TestHTTPOptionsResponse(t *testing.T) {
	Convey("Test http options response", t, func() {
		conf := config.New()
		port := test.GetFreePort()
		conf.HTTP.Port = port
		baseURL := test.GetBaseURL(port)

		ctlr := api.NewController(conf)

		firstDir := t.TempDir()

		secondDir := t.TempDir()
		defer os.RemoveAll(firstDir)
		defer os.RemoveAll(secondDir)

		ctlr.Config.Storage.RootDirectory = firstDir
		subPaths := make(map[string]config.StorageConfig)
		subPaths["/a"] = config.StorageConfig{
			RootDirectory: secondDir,
		}

		ctlr.Config.Storage.SubPaths = subPaths
		ctrlManager := test.NewControllerManager(ctlr)

		ctrlManager.StartAndWait(port)

		resp, _ := resty.R().Options(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

		defer ctrlManager.StopServer()
	})
}

func TestGetGithubUserInfo(t *testing.T) {
	Convey("github api calls works", t, func() {
		mockedHTTPClient := mock.NewMockedHTTPClient(
			mock.WithRequestMatch(
				mock.GetUserEmails,
				[]github.UserEmail{
					{
						Email:   github.String("test@test"),
						Primary: github.Bool(true),
					},
				},
			),
			mock.WithRequestMatch(
				mock.GetUserOrgs,
				[]github.Organization{
					{
						Login: github.String("testOrg"),
					},
				},
			),
		)

		client := github.NewClient(mockedHTTPClient)

		_, _, err := api.GetGithubUserInfo(context.Background(), client, log.Logger{})
		So(err, ShouldBeNil)
	})

	Convey("github ListEmails error", t, func() {
		mockedHTTPClient := mock.NewMockedHTTPClient(
			mock.WithRequestMatchHandler(
				mock.GetUserEmails,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mock.WriteError(
						w,
						http.StatusInternalServerError,
						"github error",
					)
				}),
			),
		)

		client := github.NewClient(mockedHTTPClient)

		_, _, err := api.GetGithubUserInfo(context.Background(), client, log.Logger{})
		So(err, ShouldNotBeNil)
	})

	Convey("github ListEmails error", t, func() {
		mockedHTTPClient := mock.NewMockedHTTPClient(
			mock.WithRequestMatch(
				mock.GetUserEmails,
				[]github.UserEmail{
					{
						Email:   github.String("test@test"),
						Primary: github.Bool(true),
					},
				},
			),
			mock.WithRequestMatchHandler(
				mock.GetUserOrgs,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mock.WriteError(
						w,
						http.StatusInternalServerError,
						"github error",
					)
				}),
			),
		)

		client := github.NewClient(mockedHTTPClient)

		_, _, err := api.GetGithubUserInfo(context.Background(), client, log.Logger{})
		So(err, ShouldNotBeNil)
	})
}

func getAllBlobs(imagePath string) []string {
	blobList := make([]string, 0)

	if !common.DirExists(imagePath) {
		return []string{}
	}

	buf, err := os.ReadFile(path.Join(imagePath, "index.json"))
	if err != nil {
		panic(err)
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		panic(err)
	}

	var digest godigest.Digest

	for _, m := range index.Manifests {
		digest = m.Digest
		blobList = append(blobList, digest.Encoded())
		p := path.Join(imagePath, "blobs", digest.Algorithm().String(), digest.Encoded())

		buf, err = os.ReadFile(p)

		if err != nil {
			panic(err)
		}

		var manifest ispec.Manifest
		if err := json.Unmarshal(buf, &manifest); err != nil {
			panic(err)
		}

		blobList = append(blobList, manifest.Config.Digest.Encoded())

		for _, layer := range manifest.Layers {
			blobList = append(blobList, layer.Digest.Encoded())
		}
	}

	return blobList
}

func getAllManifests(imagePath string) []string {
	manifestList := make([]string, 0)

	if !common.DirExists(imagePath) {
		return []string{}
	}

	buf, err := os.ReadFile(path.Join(imagePath, "index.json"))
	if err != nil {
		panic(err)
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		panic(err)
	}

	var digest godigest.Digest

	for _, m := range index.Manifests {
		digest = m.Digest
		manifestList = append(manifestList, digest.Encoded())
	}

	return manifestList
}

func makeController(conf *config.Config, dir string) *api.Controller {
	ctlr := api.NewController(conf)

	ctlr.Config.Storage.RootDirectory = dir

	return ctlr
}

func RunAuthorizationWithMultiplePoliciesTests(t *testing.T, userClient *resty.Client, bobClient *resty.Client,
	baseURL, user1, user2 string, conf *config.Config,
) {
	t.Helper()

	blob := []byte("hello, blob!")
	digest := godigest.FromBytes(blob).String()

	// unauthenticated clients should not have access to /v2/, no policy is applied since none exists
	resp, err := resty.R().Get(baseURL + "/v2/")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, 401)

	repoPolicy := conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos]
	repoPolicy.AnonymousPolicy = append(repoPolicy.AnonymousPolicy, "read")
	conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos] = repoPolicy

	// should have access to /v2/, anonymous policy is applied, "read" allowed
	resp, err = resty.R().Get(baseURL + "/v2/")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	// with empty username:password
	resp, err = resty.R().SetHeader("Authorization", "Basic Og==").Get(baseURL + "/v2/")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	// add user1 to global policy with create permission
	repoPolicy.Policies[0].Users = append(repoPolicy.Policies[0].Users, user1)
	repoPolicy.Policies[0].Actions = append(repoPolicy.Policies[0].Actions, "create")

	// now it should get 202, user has the permission set on "create"
	resp, err = userClient.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
	loc := resp.Header().Get("Location")

	// uploading blob should get 201
	resp, err = userClient.R().
		SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", digest).
		SetBody(blob).
		Put(baseURL + loc)
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

	// head blob should get 403 without read perm
	resp, err = userClient.R().Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

	// get tags without read access should get 403
	resp, err = userClient.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

	repoPolicy.DefaultPolicy = append(repoPolicy.DefaultPolicy, "read")
	conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos] = repoPolicy

	// with read permission should get 200, because default policy allows reading now
	resp, err = userClient.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	// get tags with default read access should be ok, since the user is now "bob" and default policy is applied
	resp, err = bobClient.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	// get tags with anonymous read access should be ok
	resp, err = resty.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	// without create permission should get 403, since "bob" can only read(default policy applied)
	resp, err = bobClient.R().
		Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

	// add read permission to user2"
	conf.HTTP.AccessControl.AdminPolicy.Users = append(conf.HTTP.AccessControl.AdminPolicy.Users, user2)
	conf.HTTP.AccessControl.AdminPolicy.Actions = append(conf.HTTP.AccessControl.AdminPolicy.Actions, "create")

	// added create permission to user "bob", should be allowed now
	resp, err = bobClient.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

	resp, err = resty.R().Get(baseURL + "/v2/_catalog")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	// make sure anonymous is correctly handled when using acCtx (requestcontext package)
	catalog := struct {
		Repositories []string `json:"repositories"`
	}{}

	err = json.Unmarshal(resp.Body(), &catalog)
	So(err, ShouldBeNil)
	So(catalog.Repositories, ShouldContain, AuthorizationNamespace)

	resp, err = bobClient.R().Get(baseURL + "/v2/_catalog")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	err = json.Unmarshal(resp.Body(), &catalog)
	So(err, ShouldBeNil)
	So(catalog.Repositories, ShouldContain, AuthorizationNamespace)

	resp, err = userClient.R().Get(baseURL + "/v2/_catalog")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	err = json.Unmarshal(resp.Body(), &catalog)
	So(err, ShouldBeNil)
	So(catalog.Repositories, ShouldContain, AuthorizationNamespace)

	// no policy
	conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos] = config.PolicyGroup{}

	// no policies, so no anonymous allowed
	resp, err = resty.R().Get(baseURL + "/v2/_catalog")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

	// bob is admin so he can read
	resp, err = bobClient.R().Get(baseURL + "/v2/_catalog")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	err = json.Unmarshal(resp.Body(), &catalog)
	So(err, ShouldBeNil)
	So(catalog.Repositories, ShouldContain, AuthorizationNamespace)

	// test user has no permissions
	resp, err = userClient.R().Get(baseURL + "/v2/_catalog")
	So(err, ShouldBeNil)
	So(resp, ShouldNotBeNil)
	So(resp.StatusCode(), ShouldEqual, http.StatusOK)

	err = json.Unmarshal(resp.Body(), &catalog)
	So(err, ShouldBeNil)
	So(len(catalog.Repositories), ShouldEqual, 0)
}

func RunAuthorizationTests(t *testing.T, client *resty.Client, baseURL, user string, conf *config.Config) {
	t.Helper()

	Convey("run authorization tests", func() {
		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		// unauthenticated clients should not have access to /v2/
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// everybody should have access to /v2/
		resp, err = client.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// everybody should have access to /v2/_catalog
		resp, err = client.R().Get(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var apiErr apiErr.Error
		err = json.Unmarshal(resp.Body(), &apiErr)
		So(err, ShouldBeNil)

		// should get 403 without create
		resp, err = client.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// first let's use global based policies
		// add test user to global policy with create perm
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Users = append(conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Users, user)         //nolint:lll // gofumpt conflicts with lll
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Actions, "create") //nolint:lll // gofumpt conflicts with lll

		// now it should get 202
		resp, err = client.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := resp.Header().Get("Location")

		// uploading blob should get 201
		resp, err = client.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// head blob should get 403 without read perm
		resp, err = client.R().Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get tags without read access should get 403
		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get tags with read access should get 200
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Actions, "read") //nolint:lll // gofumpt conflicts with lll

		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// head blob should get 200 now
		resp, err = client.R().Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// get blob should get 200 now
		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// delete blob should get 403 without delete perm
		resp, err = client.R().Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add delete perm on repo
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos].Policies[0].Actions, "delete") //nolint:lll // gofumpt conflicts with lll

		// delete blob should get 202
		resp, err = client.R().Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// now let's use only repository based policies
		// add test user to repo's policy with create perm
		// longest path matching should match the repo and not **/*
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace] = config.PolicyGroup{
			Policies: []config.Policy{
				{
					Users:   []string{},
					Actions: []string{},
				},
			},
			DefaultPolicy: []string{},
		}

		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Users = append(conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Users, user)         //nolint:lll // gofumpt conflicts with lll
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "create") //nolint:lll // gofumpt conflicts with lll

		// now it should get 202
		resp, err = client.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = resp.Header().Get("Location")

		// uploading blob should get 201
		resp, err = client.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// head blob should get 403 without read perm
		resp, err = client.R().Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get tags without read access should get 403
		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get tags with read access should get 200
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "read") //nolint:lll // gofumpt conflicts with lll

		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// head blob should get 200 now
		resp, err = client.R().Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// get blob should get 200 now
		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// delete blob should get 403 without delete perm
		resp, err = client.R().Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add delete perm on repo
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "delete") //nolint:lll // gofumpt conflicts with lll

		// delete blob should get 202
		resp, err = client.R().Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// remove permissions on **/* so it will not interfere with zot-test namespace
		repoPolicy := conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos]
		repoPolicy.Policies = []config.Policy{}
		repoPolicy.DefaultPolicy = []string{}
		conf.HTTP.AccessControl.Repositories[test.AuthorizationAllRepos] = repoPolicy

		// get manifest should get 403, we don't have perm at all on this repo
		resp, err = client.R().Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add read perm on repo
		conf.HTTP.AccessControl.Repositories["zot-test"] = config.PolicyGroup{Policies: []config.Policy{
			{
				Users:   []string{user},
				Actions: []string{"read"},
			},
		}, DefaultPolicy: []string{}}

		/* we have 4 images(authz/image, golang, zot-test, zot-cve-test) in storage,
		but because at this point we only have read access
		in authz/image and zot-test, we should get only that when listing repositories*/
		resp, err = client.R().Get(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		err = json.Unmarshal(resp.Body(), &apiErr)
		So(err, ShouldBeNil)

		catalog := struct {
			Repositories []string `json:"repositories"`
		}{}

		err = json.Unmarshal(resp.Body(), &catalog)
		So(err, ShouldBeNil)
		So(len(catalog.Repositories), ShouldEqual, 2)
		So(catalog.Repositories, ShouldContain, "zot-test")
		So(catalog.Repositories, ShouldContain, AuthorizationNamespace)

		// get manifest should get 200 now
		resp, err = client.R().Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest

		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		// put manifest should get 403 without create perm
		resp, err = client.R().
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add create perm on repo
		conf.HTTP.AccessControl.Repositories["zot-test"].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories["zot-test"].Policies[0].Actions, "create") //nolint:lll // gofumpt conflicts with lll

		// should get 201 with create perm
		resp, err = client.R().
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// create update config and post it.
		cblob, cdigest := GetRandomImageConfig()

		resp, err = client.R().
			Post(baseURL + "/v2/zot-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)

		// uploading blob should get 201
		resp, err = client.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", cdigest.String()).
			SetBody(cblob).
			Put(loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// create updated layer and post it
		updateBlob := []byte("Hello, blob update!")

		resp, err = client.R().Post(baseURL + "/v2/zot-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)

		// uploading blob should get 201
		resp, err = client.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(updateBlob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", string(godigest.FromBytes(updateBlob))).
			SetBody(updateBlob).
			Put(loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		updatedManifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    godigest.FromBytes(updateBlob),
					Size:      int64(len(updateBlob)),
				},
			},
		}
		updatedManifest.SchemaVersion = 2
		updatedManifestBlob, err := json.Marshal(updatedManifest)
		So(err, ShouldBeNil)

		// update manifest should get 403 without update perm
		resp, err = client.R().
			SetBody(updatedManifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get the manifest and check if it's the old one
		resp, err = client.R().Get(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldResemble, manifestBlob)

		// add update perm on repo
		conf.HTTP.AccessControl.Repositories["zot-test"].Policies[0].Actions = append(conf.HTTP.AccessControl.Repositories["zot-test"].Policies[0].Actions, "update") //nolint:lll // gofumpt conflicts with lll

		// update manifest should get 201 with update perm
		resp, err = client.R().
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(updatedManifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// get the manifest and check if it's the new updated one
		resp, err = client.R().Get(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldResemble, updatedManifestBlob)

		// now use default repo policy
		conf.HTTP.AccessControl.Repositories["zot-test"].Policies[0].Actions = []string{}
		repoPolicy = conf.HTTP.AccessControl.Repositories["zot-test"]
		repoPolicy.DefaultPolicy = []string{"update"}
		conf.HTTP.AccessControl.Repositories["zot-test"] = repoPolicy

		// update manifest should get 201 with update perm on repo's default policy
		resp, err = client.R().
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// with default read on repo should still get 200
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = []string{}
		repoPolicy = conf.HTTP.AccessControl.Repositories[AuthorizationNamespace]
		repoPolicy.DefaultPolicy = []string{"read"}
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace] = repoPolicy

		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// upload blob without user create but with default create should get 200
		repoPolicy.DefaultPolicy = append(repoPolicy.DefaultPolicy, "create")
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace] = repoPolicy

		resp, err = client.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// remove per repo policy
		repoPolicy = conf.HTTP.AccessControl.Repositories[AuthorizationNamespace]
		repoPolicy.Policies = []config.Policy{}
		repoPolicy.DefaultPolicy = []string{}
		conf.HTTP.AccessControl.Repositories[AuthorizationNamespace] = repoPolicy

		repoPolicy = conf.HTTP.AccessControl.Repositories["zot-test"]
		repoPolicy.Policies = []config.Policy{}
		repoPolicy.DefaultPolicy = []string{}
		conf.HTTP.AccessControl.Repositories["zot-test"] = repoPolicy

		resp, err = client.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// whithout any perm should get 403
		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add read perm
		conf.HTTP.AccessControl.AdminPolicy.Users = append(conf.HTTP.AccessControl.AdminPolicy.Users, user)
		conf.HTTP.AccessControl.AdminPolicy.Actions = append(conf.HTTP.AccessControl.AdminPolicy.Actions, "read")

		// with read perm should get 200
		resp, err = client.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// without create perm should 403
		resp, err = client.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add create perm
		conf.HTTP.AccessControl.AdminPolicy.Actions = append(conf.HTTP.AccessControl.AdminPolicy.Actions, "create")

		// with create perm should get 202
		resp, err = client.R().Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = resp.Header().Get("Location")

		// uploading blob should get 201
		resp, err = client.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// without delete perm should 403
		resp, err = client.R().Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add delete perm
		conf.HTTP.AccessControl.AdminPolicy.Actions = append(conf.HTTP.AccessControl.AdminPolicy.Actions, "delete")

		// with delete perm should get http.StatusAccepted
		resp, err = client.R().Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// without update perm should 403
		resp, err = client.R().
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add update perm
		conf.HTTP.AccessControl.AdminPolicy.Actions = append(conf.HTTP.AccessControl.AdminPolicy.Actions, "update")

		// update manifest should get 201 with update perm
		resp, err = client.R().
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		conf.HTTP.AccessControl = &config.AccessControlConfig{}

		resp, err = client.R().
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)
	})
}

func getEmptyImageConfig() ([]byte, godigest.Digest) {
	config := ispec.Image{}

	configBlobContent, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		return nil, ""
	}

	configBlobDigestRaw := godigest.FromBytes(configBlobContent)

	return configBlobContent, configBlobDigestRaw
}

func getNumberOfSessions(rootDir string) (int, error) {
	rootDirContents, err := os.ReadDir(path.Join(rootDir, "_sessions"))
	if err != nil {
		return -1, err
	}

	sessionsNo := 0

	for _, file := range rootDirContents {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "session_") {
			sessionsNo += 1
		}
	}

	return sessionsNo, nil
}
