//go:build extended
// +build extended

package api_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chartmuseum/auth"
	"github.com/mitchellh/mapstructure"
	vldap "github.com/nmcclain/ldap"
	notreg "github.com/notaryproject/notation/pkg/registry"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/storage"
	. "zotregistry.io/zot/test"
)

const (
	username               = "test"
	passphrase             = "test"
	ServerCert             = "../../test/data/server.cert"
	ServerKey              = "../../test/data/server.key"
	CACert                 = "../../test/data/ca.crt"
	AuthorizedNamespace    = "everyone/isallowed"
	UnauthorizedNamespace  = "fortknox/notallowed"
	ALICE                  = "alice"
	AuthorizationNamespace = "authz/image"
)

type (
	accessTokenResponse struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // token format
	}

	authHeader struct {
		Realm   string
		Service string
		Scope   string
	}
)

func getCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
}

func skipIt(t *testing.T) {
	t.Helper()

	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS S3 mock server")
	}
}

func TestNew(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()
		So(conf, ShouldNotBeNil)
		So(api.NewController(conf), ShouldNotBeNil)
	})
}

func TestRunAlreadyRunningServer(t *testing.T) {
	Convey("Run server on unavailable port", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)

		globalDir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(globalDir)

		ctlr.Config.Storage.RootDirectory = globalDir

		go func() {
			if err := ctlr.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(baseURL)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		defer func() {
			ctx := context.Background()
			_ = ctlr.Server.Shutdown(ctx)
		}()

		err = ctlr.Run()
		So(err, ShouldNotBeNil)
	})
}

func TestObjectStorageController(t *testing.T) {
	skipIt(t)
	Convey("Negative make a new object storage controller", t, func() {
		port := GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		storageDriverParams := map[string]interface{}{
			"rootDir": "zot",
			"name":    storage.S3StorageDriverName,
		}
		conf.Storage.StorageDriver = storageDriverParams
		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		ctlr.Config.Storage.RootDirectory = "zot"

		err := ctlr.Run()
		So(err, ShouldNotBeNil)
	})

	Convey("Make a new object storage controller", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		bucket := "zot-storage-test"
		endpoint := os.Getenv("S3MOCK_ENDPOINT")

		storageDriverParams := map[string]interface{}{
			"rootDir":        "zot",
			"name":           storage.S3StorageDriverName,
			"region":         "us-east-2",
			"bucket":         bucket,
			"regionendpoint": endpoint,
			"secure":         false,
			"skipverify":     false,
		}
		conf.Storage.StorageDriver = storageDriverParams
		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		ctlr.Config.Storage.RootDirectory = "/"

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)
	})
}

func TestObjectStorageControllerSubPaths(t *testing.T) {
	skipIt(t)
	Convey("Make a new object storage controller", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		bucket := "zot-storage-test"
		endpoint := os.Getenv("S3MOCK_ENDPOINT")

		storageDriverParams := map[string]interface{}{
			"rootDir":        "zot",
			"name":           storage.S3StorageDriverName,
			"region":         "us-east-2",
			"bucket":         bucket,
			"regionendpoint": endpoint,
			"secure":         false,
			"skipverify":     false,
		}
		conf.Storage.StorageDriver = storageDriverParams
		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		ctlr.Config.Storage.RootDirectory = "zot"
		subPathMap := make(map[string]config.StorageConfig)
		subPathMap["/a"] = config.StorageConfig{
			RootDirectory: "/a",
			StorageDriver: storageDriverParams,
		}
		ctlr.Config.Storage.SubPaths = subPathMap

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)
	})
}

func TestHtpasswdSingleCred(t *testing.T) {
	Convey("Single cred", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		singleCredtests := []string{}
		user := ALICE
		password := ALICE
		singleCredtests = append(singleCredtests, getCredString(user, password))
		singleCredtests = append(singleCredtests, getCredString(user, password)+"\n")

		for _, testString := range singleCredtests {
			func() {
				conf := config.New()
				conf.HTTP.Port = port

				htpasswdPath := MakeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				conf.HTTP.Auth = &config.AuthConfig{
					HTPasswd: config.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				ctlr := api.NewController(conf)
				dir, err := ioutil.TempDir("", "oci-repo-test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(dir)
				ctlr.Config.Storage.RootDirectory = dir

				go startServer(ctlr)
				defer stopServer(ctlr)
				WaitTillServerReady(baseURL)

				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(baseURL + "/v2/")
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

func TestHtpasswdTwoCreds(t *testing.T) {
	Convey("Two creds", t, func() {
		twoCredTests := []string{}
		user1 := "alicia"
		password1 := "aliciapassword"
		user2 := "bob"
		password2 := "robert"
		twoCredTests = append(twoCredTests, getCredString(user1, password1)+"\n"+
			getCredString(user2, password2))

		twoCredTests = append(twoCredTests, getCredString(user1, password1)+"\n"+
			getCredString(user2, password2)+"\n")

		twoCredTests = append(twoCredTests, getCredString(user1, password1)+"\n\n"+
			getCredString(user2, password2)+"\n\n")

		for _, testString := range twoCredTests {
			func() {
				port := GetFreePort()
				baseURL := GetBaseURL(port)
				conf := config.New()
				conf.HTTP.Port = port
				htpasswdPath := MakeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				conf.HTTP.Auth = &config.AuthConfig{
					HTPasswd: config.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				ctlr := api.NewController(conf)
				dir, err := ioutil.TempDir("", "oci-repo-test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(dir)
				ctlr.Config.Storage.RootDirectory = dir

				go startServer(ctlr)
				defer stopServer(ctlr)
				WaitTillServerReady(baseURL)

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
			credString.WriteString(getCredString(key, val) + "\n")
		}

		func() {
			port := GetFreePort()
			baseURL := GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port
			htpasswdPath := MakeHtpasswdFileFromString(credString.String())
			defer os.Remove(htpasswdPath)
			conf.HTTP.Auth = &config.AuthConfig{
				HTPasswd: config.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}
			ctlr := api.NewController(conf)
			dir, err := ioutil.TempDir("", "oci-repo-test")
			if err != nil {
				panic(err)
			}
			defer os.RemoveAll(dir)
			ctlr.Config.Storage.RootDirectory = dir

			go startServer(ctlr)
			defer stopServer(ctlr)
			WaitTillServerReady(baseURL)

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

func TestBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestInterruptedBlobUpload(t *testing.T) {
	Convey("Successfully cleaning interrupted blob uploads", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		client := resty.New()
		blob := make([]byte, 50*1024*1024)
		digest := godigest.FromBytes(blob).String()

		// nolint: dupl
		Convey("Test interrupt PATCH blob upload", func() {
			resp, err := client.R().Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
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
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(AuthorizedNamespace, sessionID)
				if n > 0 && err == nil {
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Test negative interrupt PATCH blob upload", func() {
			resp, err := client.R().Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
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
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(AuthorizedNamespace, sessionID)
				if n > 0 && err == nil {
					// cleaning blob uploads, so that zot fails to clean up, +code coverage
					err = ctlr.StoreController.DefaultStore.DeleteBlobUpload(AuthorizedNamespace, sessionID)
					So(err, ShouldBeNil)
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		// nolint: dupl
		Convey("Test interrupt PUT blob upload", func() {
			resp, err := client.R().Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
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
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(AuthorizedNamespace, sessionID)
				if n > 0 && err == nil {
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to try to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Test negative interrupt PUT blob upload", func() {
			resp, err := client.R().Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
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
				n, err := ctlr.StoreController.DefaultStore.GetBlobUpload(AuthorizedNamespace, sessionID)
				if n > 0 && err == nil {
					// cleaning blob uploads, so that zot fails to clean up, +code coverage
					err = ctlr.StoreController.DefaultStore.DeleteBlobUpload(AuthorizedNamespace, sessionID)
					So(err, ShouldBeNil)
					cancel()

					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			// wait for zot to try to remove blobUpload
			time.Sleep(1 * time.Second)

			resp, err = client.R().Get(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/" + sessionID)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})
	})
}

func TestMultipleInstance(t *testing.T) {
	Convey("Negative test zot multiple instance", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := api.NewController(conf)
		err := ctlr.Run()
		So(err, ShouldEqual, errors.ErrImgStoreNotFound)

		globalDir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(globalDir)

		subDir, err := ioutil.TempDir("", "oci-sub-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(subDir)

		ctlr.Config.Storage.RootDirectory = globalDir
		subPathMap := make(map[string]config.StorageConfig)

		subPathMap["/a"] = config.StorageConfig{RootDirectory: subDir}

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		client := resty.New()

		tagResponse, err := client.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/tags/list")
		So(err, ShouldBeNil)
		So(tagResponse.StatusCode(), ShouldEqual, http.StatusNotFound)
	})

	Convey("Test zot multiple instance", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := api.NewController(conf)
		globalDir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(globalDir)

		subDir, err := ioutil.TempDir("", "oci-sub-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(subDir)

		ctlr.Config.Storage.RootDirectory = globalDir
		subPathMap := make(map[string]config.StorageConfig)
		subPathMap["/a"] = config.StorageConfig{RootDirectory: subDir}

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSWithBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		secureBaseURL := GetSecureBaseURL(port)

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

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

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
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSWithBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		secureBaseURL := GetSecureBaseURL(port)

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
		conf.HTTP.AllowReadAccess = true

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

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
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// without creds, writes should fail
		resp, err = resty.R().Post(secureBaseURL + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
	})
}

func TestTLSMutualAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		secureBaseURL := GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, should get conn error
		_, err = resty.R().Get(secureBaseURL)
		So(err, ShouldNotBeNil)

		// with creds but without certs, should get conn error
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
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
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSMutualAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		secureBaseURL := GetSecureBaseURL(port)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}
		conf.HTTP.AllowReadAccess = true

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(baseURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

		// without client certs and creds, reads are allowed
		resp, err = resty.R().Get(secureBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// with creds but without certs, reads are allowed
		resp, err = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL + "/v2/")
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
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSMutualAndBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		secureBaseURL := GetSecureBaseURL(port)

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

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

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
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
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
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestTLSMutualAndBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		port := GetFreePort()
		baseURL := GetBaseURL(port)
		secureBaseURL := GetSecureBaseURL(port)

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
		conf.HTTP.AllowReadAccess = true

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

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
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
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
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(secureBaseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

const (
	LDAPAddress      = "127.0.0.1"
	LDAPPort         = 9636
	LDAPBaseDN       = "ou=test"
	LDAPBindDN       = "cn=reader," + LDAPBaseDN
	LDAPBindPassword = "bindPassword"
)

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

func (l *testLDAPServer) Start() {
	addr := fmt.Sprintf("%s:%d", LDAPAddress, LDAPPort)

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
	if bindDN == "" || bindSimplePw == "" {
		return vldap.LDAPResultInappropriateAuthentication, errors.ErrRequireCred
	}

	if (bindDN == LDAPBindDN && bindSimplePw == LDAPBindPassword) ||
		(bindDN == fmt.Sprintf("cn=%s,%s", username, LDAPBaseDN) && bindSimplePw == passphrase) {
		return vldap.LDAPResultSuccess, nil
	}

	return vldap.LDAPResultInvalidCredentials, errors.ErrInvalidCred
}

func (l *testLDAPServer) Search(boundDN string, req vldap.SearchRequest,
	conn net.Conn) (vldap.ServerSearchResult, error) {
	check := fmt.Sprintf("(uid=%s)", username)
	if check == req.Filter {
		return vldap.ServerSearchResult{
			Entries: []*vldap.Entry{
				{DN: fmt.Sprintf("cn=%s,%s", username, LDAPBaseDN)},
			},
			ResultCode: vldap.LDAPResultSuccess,
		}, nil
	}

	return vldap.ServerSearchResult{}, nil
}

func TestBasicAuthWithLDAP(t *testing.T) {
	Convey("Make a new controller", t, func() {
		l := newTestLDAPServer()
		l.Start()
		defer l.Stop()

		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			LDAP: &config.LDAPConfig{
				Insecure:      true,
				Address:       LDAPAddress,
				Port:          LDAPPort,
				BindDN:        LDAPBindDN,
				BindPassword:  LDAPBindPassword,
				BaseDN:        LDAPBaseDN,
				UserAttribute: "uid",
			},
		}
		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		// without creds, should get access error
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(baseURL + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestBearerAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authTestServer := makeAuthTestServer()
		defer authTestServer.Close()

		port := GetFreePort()
		baseURL := GetBaseURL(port)

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
		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader := parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var goodToken accessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
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
			Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
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

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
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
			Get(baseURL + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
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
			Get(baseURL + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().
			Post(baseURL + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var badToken accessTokenResponse
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

func TestBearerAuthWithAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authTestServer := makeAuthTestServer()
		defer authTestServer.Close()

		port := GetFreePort()
		baseURL := GetBaseURL(port)

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
		conf.HTTP.AllowReadAccess = true
		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader := parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var goodToken accessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
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
			Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
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

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
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
			Get(baseURL + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
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
			Get(baseURL + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = resty.R().
			Post(baseURL + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var badToken accessTokenResponse
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

func makeAuthTestServer() *httptest.Server {
	cmTokenGenerator, err := auth.NewTokenGenerator(&auth.TokenGeneratorOptions{
		PrivateKeyPath: ServerKey,
		Audience:       "Zot Registry",
		Issuer:         "Zot",
		AddKIDHeader:   true,
	})
	if err != nil {
		panic(err)
	}

	authTestServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		scope := request.URL.Query().Get("scope")
		parts := strings.Split(scope, ":")
		name := parts[1]
		actions := strings.Split(parts[2], ",")
		if name == UnauthorizedNamespace {
			actions = []string{}
		}
		access := []auth.AccessEntry{
			{
				Name:    name,
				Type:    "repository",
				Actions: actions,
			},
		}
		token, err := cmTokenGenerator.GenerateToken(access, time.Minute*1)
		if err != nil {
			panic(err)
		}
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(response, `{"access_token": "%s"}`, token)
	}))

	return authTestServer
}

func parseBearerAuthHeader(authHeaderRaw string) *authHeader {
	re := regexp.MustCompile(`([a-zA-z]+)="(.+?)"`)
	matches := re.FindAllStringSubmatch(authHeaderRaw, -1)
	matchmap := make(map[string]string)

	for i := 0; i < len(matches); i++ {
		matchmap[matches[i][1]] = matches[i][2]
	}

	var h authHeader
	if err := mapstructure.Decode(matchmap, &h); err != nil {
		panic(err)
	}

	return &h
}

func TestAuthorizationWithBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AuthorizationNamespace: config.PolicyGroup{
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

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		err = CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		// everybody should have access to /v2/
		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// everybody should have access to /v2/_catalog
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/_catalog")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// first let's use only repositories based policies
		// should get 403 without create
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add test user to repo's policy with create perm
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Users =
			append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Users, "test")
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions =
			append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "create")

		// now it should get 202
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := resp.Header().Get("Location")

		// uploading blob should get 201
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// head blob should get 403 with read perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get blob should get 403 without read perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get tags without read access should get 403
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get tags with read access should get 200
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions =
			append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "read")
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// head blob should get 200 now
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// get blob should get 200 now
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// delete blob should get 403 without delete perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add delete perm on repo
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions =
			append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "delete")

		// delete blob should get 202
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// get manifest should get 403, we don't have perm at all on this repo
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add read perm on repo
		conf.AccessControl.Repositories["zot-test"] = config.PolicyGroup{Policies: []config.Policy{
			{
				Users:   []string{"test"},
				Actions: []string{"read"},
			},
		}, DefaultPolicy: []string{}}

		// get manifest should get 200 now
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()

		// put manifest should get 403 without create perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add create perm on repo
		conf.AccessControl.Repositories["zot-test"].Policies[0].Actions =
			append(conf.AccessControl.Repositories["zot-test"].Policies[0].Actions, "create")

		// should get 201 with create perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// update manifest should get 403 without update perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add update perm on repo
		conf.AccessControl.Repositories["zot-test"].Policies[0].Actions =
			append(conf.AccessControl.Repositories["zot-test"].Policies[0].Actions, "update")

		// update manifest should get 201 with update perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// now use default repo policy
		conf.AccessControl.Repositories["zot-test"].Policies[0].Actions = []string{}
		repoPolicy := conf.AccessControl.Repositories["zot-test"]
		repoPolicy.DefaultPolicy = []string{"update"}
		conf.AccessControl.Repositories["zot-test"] = repoPolicy

		// update manifest should get 201 with update perm on repo's default policy
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// with default read on repo should still get 200
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = []string{}
		repoPolicy = conf.AccessControl.Repositories[AuthorizationNamespace]
		repoPolicy.DefaultPolicy = []string{"read"}
		conf.AccessControl.Repositories[AuthorizationNamespace] = repoPolicy

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// upload blob without user create but with default create should get 200
		repoPolicy.DefaultPolicy = append(repoPolicy.DefaultPolicy, "create")
		conf.AccessControl.Repositories[AuthorizationNamespace] = repoPolicy

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// remove per repo policy
		repoPolicy = conf.AccessControl.Repositories[AuthorizationNamespace]
		repoPolicy.Policies = []config.Policy{}
		repoPolicy.DefaultPolicy = []string{}
		conf.AccessControl.Repositories[AuthorizationNamespace] = repoPolicy

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// let's use admin policy
		// remove all repo based policy
		delete(conf.AccessControl.Repositories, AuthorizationNamespace)
		delete(conf.AccessControl.Repositories, "zot-test")

		// whithout any perm should get 403
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add read perm
		conf.AccessControl.AdminPolicy.Users = append(conf.AccessControl.AdminPolicy.Users, "test")
		conf.AccessControl.AdminPolicy.Actions = append(conf.AccessControl.AdminPolicy.Actions, "read")
		// with read perm should get 200
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// without create perm should 403
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add create perm
		conf.AccessControl.AdminPolicy.Actions = append(conf.AccessControl.AdminPolicy.Actions, "create")
		// with create perm should get 202
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = resp.Header().Get("Location")

		// uploading blob should get 201
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(baseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// without delete perm should 403
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add delete perm
		conf.AccessControl.AdminPolicy.Actions = append(conf.AccessControl.AdminPolicy.Actions, "delete")
		// with delete perm should get http.StatusAccepted
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// without update perm should 403
		resp, err = resty.R().SetBasicAuth(username, passphrase).SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add update perm
		conf.AccessControl.AdminPolicy.Actions = append(conf.AccessControl.AdminPolicy.Actions, "update")
		// update manifest should get 201 with update perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		conf.AccessControl = &config.AccessControlConfig{}

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)
	})
}

func TestInvalidCases(t *testing.T) {
	Convey("Invalid repo dir", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFileFromString(getCredString(username, passphrase))

		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		err := os.Mkdir("oci-repo-test", 0o000)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = "oci-repo-test"

		go startServer(ctlr)
		defer func(ctrl *api.Controller) {
			err := ctrl.Server.Shutdown(context.Background())
			if err != nil {
				panic(err)
			}

			err = os.RemoveAll(ctrl.Config.Storage.RootDirectory)
			if err != nil {
				panic(err)
			}
		}(ctlr)
		WaitTillServerReady(baseURL)

		digest := "sha256:8dd57e171a61368ffcfde38045ddb6ed74a32950c271c1da93eaddfb66a77e78"
		name := "zot-c-test"

		client := resty.New()

		params := make(map[string]string)
		params["from"] = "zot-cveid-test"
		params["mount"] = digest

		postResponse, err := client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", baseURL, name))
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusInternalServerError)
	})
}

func TestHTTPReadOnly(t *testing.T) {
	Convey("Single cred", t, func() {
		singleCredtests := []string{}
		user := ALICE
		password := ALICE
		singleCredtests = append(singleCredtests, getCredString(user, password))
		singleCredtests = append(singleCredtests, getCredString(user, password)+"\n")

		port := GetFreePort()
		baseURL := GetBaseURL(port)

		for _, testString := range singleCredtests {
			func() {
				conf := config.New()
				conf.HTTP.Port = port
				// enable read-only mode
				conf.HTTP.ReadOnly = true

				htpasswdPath := MakeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				conf.HTTP.Auth = &config.AuthConfig{
					HTPasswd: config.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				ctlr := api.NewController(conf)
				dir, err := ioutil.TempDir("", "oci-repo-test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(dir)
				ctlr.Config.Storage.RootDirectory = dir

				go startServer(ctlr)
				defer stopServer(ctlr)
				WaitTillServerReady(baseURL)

				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				// with creds, any modifications should still fail on read-only mode
				resp, err = resty.R().SetBasicAuth(user, password).
					Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

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
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFileFromString(getCredString(username, passphrase))

		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}

		err = CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		params := make(map[string]string)
		digest := "sha256:63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29"
		dgst := godigest.Digest(digest)
		name := "zot-cve-test"
		params["mount"] = digest
		params["from"] = name

		client := resty.New()
		headResponse, err := client.R().SetBasicAuth(username, passphrase).
			Head(fmt.Sprintf("%s/v2/%s/blobs/%s", baseURL, name, digest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusOK)

		// All invalid request of mount should return 202.
		params["mount"] = "sha:"

		postResponse, err := client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		incorrectParams := make(map[string]string)
		incorrectParams["mount"] = "sha256:63a795ca90aa6e7dda60941e826810a4cd0a2e73ea02bf458241df2a5c973e29"
		incorrectParams["from"] = "zot-x-test"

		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(incorrectParams).
			Post(baseURL + "/v2/zot-y-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		// Use correct request
		// This is correct request but it will return 202 because blob is not present in cache.
		params["mount"] = digest
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		// Send same request again
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		// Valid requests
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-d-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		headResponse, err = client.R().SetBasicAuth(username, passphrase).
			Head(fmt.Sprintf("%s/v2/zot-cv-test/blobs/%s", baseURL, digest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusNotFound)

		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/ /blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusNotFound)

		digest = "sha256:63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29"

		blob := "63a795ca90aa6e7cca60941e826810a4cd0a2e73ea02bf458241df2a5c973e29"

		buf, err := ioutil.ReadFile(path.Join(ctlr.Config.Storage.RootDirectory, "zot-cve-test/blobs/sha256/"+blob))
		if err != nil {
			panic(err)
		}

		postResponse, err = client.R().SetHeader("Content-type", "application/octet-stream").
			SetBasicAuth(username, passphrase).SetQueryParam("digest", "sha256:"+blob).
			SetBody(buf).Post(baseURL + "/v2/zot-d-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)

		// We have uploaded a blob and since we have provided digest it should be full blob upload and there should be entry
		// in cache, now try mount blob request status and it should be 201 because now blob is present in cache
		// and it should do hard link.

		params["mount"] = digest
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)

		// Check os.SameFile here
		cachePath := path.Join(ctlr.Config.Storage.RootDirectory, "zot-d-test", "blobs/sha256", dgst.Hex())

		cacheFi, err := os.Stat(cachePath)
		So(err, ShouldBeNil)

		linkPath := path.Join(ctlr.Config.Storage.RootDirectory, "zot-mount-test", "blobs/sha256", dgst.Hex())

		linkFi, err := os.Stat(linkPath)
		So(err, ShouldBeNil)

		So(os.SameFile(cacheFi, linkFi), ShouldEqual, true)

		// Now try another mount request and this time it should be from above uploaded repo i.e zot-mount-test
		// mount request should pass and should return 201.
		params["mount"] = digest
		params["from"] = "zot-mount-test"
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount1-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)

		linkPath = path.Join(ctlr.Config.Storage.RootDirectory, "zot-mount1-test", "blobs/sha256", dgst.Hex())

		linkFi, err = os.Stat(linkPath)
		So(err, ShouldBeNil)

		So(os.SameFile(cacheFi, linkFi), ShouldEqual, true)

		headResponse, err = client.R().SetBasicAuth(username, passphrase).
			Head(fmt.Sprintf("%s/v2/zot-cv-test/blobs/%s", baseURL, digest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusOK)

		// Invalid request
		params = make(map[string]string)
		params["mount"] = "sha256:"
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)

		params = make(map[string]string)
		params["from"] = "zot-cve-test"
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
	})

	Convey("Disable dedupe and cache", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFileFromString(getCredString(username, passphrase))

		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}

		err = CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.Dedupe = false
		ctlr.Config.Storage.GC = false

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

		digest := "sha256:7a0437f04f83f084b7ed68ad9c4a4947e12fc4e1b006b38129bac89114ec3621"
		name := "zot-c-test"
		client := resty.New()
		headResponse, err := client.R().SetBasicAuth(username, passphrase).
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

	port := GetFreePort()
	baseURL := GetBaseURL(port)

	conf := config.New()
	conf.HTTP.Port = port
	htpasswdPath := MakeHtpasswdFileFromString(getCredString(username, passphrase))

	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd: config.AuthHTPasswd{
			Path: htpasswdPath,
		},
	}

	ctlr := api.NewController(conf)

	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	firstSubDir, err := ioutil.TempDir("", "oci-sub-dir")
	if err != nil {
		panic(err)
	}

	secondSubDir, err := ioutil.TempDir("", "oci-sub-dir")
	if err != nil {
		panic(err)
	}

	subPaths := make(map[string]config.StorageConfig)

	subPaths["/a"] = config.StorageConfig{RootDirectory: firstSubDir}
	subPaths["/b"] = config.StorageConfig{RootDirectory: secondSubDir}

	ctlr.Config.Storage.SubPaths = subPaths
	ctlr.Config.Storage.RootDirectory = dir

	go startServer(ctlr)
	WaitTillServerReady(baseURL)

	// without creds, should get access error
	for i, testcase := range testCases {
		testcase := testcase
		run := i

		t.Run(testcase.testCaseName, func(t *testing.T) {
			t.Parallel()
			client := resty.New()

			tagResponse, err := client.R().SetBasicAuth(username, passphrase).
				Get(baseURL + "/v2/" + testcase.destImageName + "/tags/list")
			assert.Equal(t, err, nil, "Error should be nil")
			assert.NotEqual(t, tagResponse.StatusCode(), http.StatusBadRequest, "bad request")

			manifestList := getAllManifests(path.Join("../../test/data", testcase.srcImageName))

			for _, manifest := range manifestList {
				headResponse, err := client.R().SetBasicAuth(username, passphrase).
					Head(baseURL + "/v2/" + testcase.destImageName + "/manifests/" + manifest)
				assert.Equal(t, err, nil, "Error should be nil")
				assert.Equal(t, headResponse.StatusCode(), http.StatusNotFound, "response status code should return 404")

				getResponse, err := client.R().SetBasicAuth(username, passphrase).
					Get(baseURL + "/v2/" + testcase.destImageName + "/manifests/" + manifest)
				assert.Equal(t, err, nil, "Error should be nil")
				assert.Equal(t, getResponse.StatusCode(), http.StatusNotFound, "response status code should return 404")
			}

			blobList := getAllBlobs(path.Join("../../test/data", testcase.srcImageName))

			for _, blob := range blobList {
				// Get request of blob
				headResponse, err := client.R().
					SetBasicAuth(username, passphrase).
					Head(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, headResponse.StatusCode(), http.StatusInternalServerError,
					"internal server error should not occurred")

				getResponse, err := client.R().
					SetBasicAuth(username, passphrase).
					Get(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, getResponse.StatusCode(), http.StatusInternalServerError,
					"internal server error should not occurred")

				blobPath := path.Join("../../test/data", testcase.srcImageName, "blobs/sha256", blob)

				buf, err := ioutil.ReadFile(blobPath)
				if err != nil {
					panic(err)
				}

				// Post request of blob
				postResponse, err := client.R().
					SetHeader("Content-type", "application/octet-stream").
					SetBasicAuth(username, passphrase).
					SetBody(buf).Post(baseURL + "/v2/" + testcase.destImageName + "/blobs/uploads/")

				assert.Equal(t, err, nil, "Error should be nil")
				assert.NotEqual(t, postResponse.StatusCode(), http.StatusInternalServerError,
					"response status code should not return 500")

				// Post request with query parameter
				if run%2 == 0 {
					postResponse, err = client.R().
						SetHeader("Content-type", "application/octet-stream").
						SetBasicAuth(username, passphrase).
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
								if err == io.EOF {
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
								SetBasicAuth(username, passphrase).
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
								if err == io.EOF {
									break
								}
								panic(err)
							}
							// Patch request of blob

							patchResponse, err := client.R().SetBody(buf[0:nbytes]).SetHeader("Content-type", "application/octet-stream").
								SetBasicAuth(username, passphrase).
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
						SetBasicAuth(username, passphrase).
						SetBody(buf).SetQueryParam("digest", "sha256:"+blob).
						Post(baseURL + "/v2/" + testcase.destImageName + "/blobs/uploads/")

					assert.Equal(t, err, nil, "Error should be nil")
					assert.NotEqual(t, postResponse.StatusCode(), http.StatusInternalServerError,
						"response status code should not return 500")
				}

				headResponse, err = client.R().
					SetBasicAuth(username, passphrase).
					Head(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, headResponse.StatusCode(), http.StatusInternalServerError, "response should return success code")

				getResponse, err = client.R().
					SetBasicAuth(username, passphrase).
					Get(baseURL + "/v2/" + testcase.destImageName + "/blobs/sha256:" + blob)

				assert.Equal(t, err, nil, "Should not be nil")
				assert.NotEqual(t, getResponse.StatusCode(), http.StatusInternalServerError, "response should return success code")
			}

			tagResponse, err = client.R().SetBasicAuth(username, passphrase).
				Get(baseURL + "/v2/" + testcase.destImageName + "/tags/list")
			assert.Equal(t, err, nil, "Error should be nil")
			assert.Equal(t, tagResponse.StatusCode(), http.StatusOK, "response status code should return success code")

			repoResponse, err := client.R().SetBasicAuth(username, passphrase).
				Get(baseURL + "/v2/_catalog")
			assert.Equal(t, err, nil, "Error should be nil")
			assert.Equal(t, repoResponse.StatusCode(), http.StatusOK, "response status code should return success code")
		})
	}
}

func TestHardLink(t *testing.T) {
	Convey("Validate hard link", t, func() {
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := MakeHtpasswdFileFromString(getCredString(username, passphrase))

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		dir, err := ioutil.TempDir("", "hard-link-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		err = os.Chmod(dir, 0o400)
		if err != nil {
			panic(err)
		}

		subDir, err := ioutil.TempDir("", "sub-hardlink-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(subDir)

		err = os.Chmod(subDir, 0o400)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir
		subPaths := make(map[string]config.StorageConfig)

		subPaths["/a"] = config.StorageConfig{RootDirectory: subDir, Dedupe: true}
		ctlr.Config.Storage.SubPaths = subPaths

		go startServer(ctlr)
		defer stopServer(ctlr)
		WaitTillServerReady(baseURL)

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
		port := GetFreePort()
		baseURL := GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		ctlr.Config.Storage.RootDirectory = dir
		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(); err != nil {
				return
			}
		}(ctlr)
		// wait till ready
		for {
			_, err := resty.R().Get(baseURL)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		repoName := "signed-repo"

		// create a blob/layer
		resp, err := resty.R().Post(baseURL + fmt.Sprintf("/v2/%s/blobs/uploads/", repoName))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc := Location(baseURL, resp)
		So(loc, ShouldNotBeEmpty)

		resp, err = resty.R().Get(loc)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 204)
		content := []byte("this is a blob")
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
		So(resp.Header().Get(api.DistContentDigestKey), ShouldNotBeEmpty)

		// create a manifest
		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				Digest: digest,
				Size:   int64(len(content)),
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
		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
		d := resp.Header().Get(api.DistContentDigestKey)
		So(d, ShouldNotBeEmpty)
		So(d, ShouldEqual, digest.String())

		Convey("Validate cosign signatures", func() {
			cwd, err := os.Getwd()
			So(err, ShouldBeNil)
			defer func() { _ = os.Chdir(cwd) }()
			tdir, err := ioutil.TempDir("", "cosign")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tdir)
			_ = os.Chdir(tdir)

			// generate a keypair
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", nil)
			So(err, ShouldBeNil)

			// sign the image
			err = sign.SignCmd(context.TODO(),
				sign.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
				options.RegistryOptions{AllowInsecure: true},
				map[string]interface{}{"tag": "1.0"},
				[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())},
				"", true, "", false, false, "")
			So(err, ShouldBeNil)

			// verify the image
			aopts := &options.AnnotationOptions{Annotations: []string{"tag=1.0"}}
			amap, err := aopts.AnnotationsMap()
			So(err, ShouldBeNil)
			vrfy := verify.VerifyCommand{
				RegistryOptions: options.RegistryOptions{AllowInsecure: true},
				CheckClaims:     true,
				KeyRef:          path.Join(tdir, "cosign.pub"),
				Annotations:     amap,
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
			}
			err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")})
			So(err, ShouldNotBeNil)

			// generate another keypair
			err = os.Remove(path.Join(tdir, "cosign.pub"))
			So(err, ShouldBeNil)
			err = os.Remove(path.Join(tdir, "cosign.key"))
			So(err, ShouldBeNil)

			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", nil)
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
			}
			err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")})
			So(err, ShouldNotBeNil)
		})

		Convey("Validate notation signatures", func() {
			cwd, err := os.Getwd()
			So(err, ShouldBeNil)
			defer func() { _ = os.Chdir(cwd) }()
			tdir, err := ioutil.TempDir("", "notation")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tdir)
			_ = os.Chdir(tdir)

			// "notation" (notaryv2) doesn't yet support exported apis, so use the binary instead
			notPath, err := exec.LookPath("notation")
			So(notPath, ShouldNotBeNil)
			So(err, ShouldBeNil)

			os.Setenv("XDG_CONFIG_HOME", tdir)

			// generate a keypair
			cmd := exec.Command("notation", "cert", "generate-test", "--trust", "good")
			err = cmd.Run()
			So(err, ShouldBeNil)

			// generate another keypair
			cmd = exec.Command("notation", "cert", "generate-test", "--trust", "bad")
			err = cmd.Run()
			So(err, ShouldBeNil)

			// sign the image
			image := fmt.Sprintf("localhost:%s/%s:%s", port, repoName, "1.0")
			cmd = exec.Command("notation", "sign", "--key", "good", "--plain-http", image)
			err = cmd.Run()
			So(err, ShouldBeNil)

			// verify the image
			cmd = exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
			out, err := cmd.CombinedOutput()
			So(err, ShouldBeNil)
			msg := string(out)
			So(msg, ShouldNotBeEmpty)
			So(strings.Contains(msg, "verification failure"), ShouldBeFalse)

			// verify the image with incorrect key
			cmd = exec.Command("notation", "verify", "--cert", "bad", "--plain-http", image)
			out, err = cmd.CombinedOutput()
			So(err, ShouldNotBeNil)
			msg = string(out)
			So(msg, ShouldNotBeEmpty)
			So(strings.Contains(msg, "verification failure"), ShouldBeTrue)

			// check unsupported manifest media type
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.unsupported.image.manifest.v1+json").
				SetBody(content).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusUnsupportedMediaType)

			// check invalid content with artifact media type
			resp, err = resty.R().SetHeader("Content-Type", artifactspec.MediaTypeArtifactManifest).
				SetBody([]byte("bogus")).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			Convey("Validate corrupted signature", func() {
				// verify with corrupted signature
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				var refs api.ReferenceList
				err = json.Unmarshal(resp.Body(), &refs)
				So(err, ShouldBeNil)
				So(len(refs.References), ShouldEqual, 1)
				err = ioutil.WriteFile(path.Join(dir, repoName, "blobs",
					strings.ReplaceAll(refs.References[0].Digest.String(), ":", "/")), []byte("corrupt"), 0o600)
				So(err, ShouldBeNil)
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
				cmd = exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
				out, err = cmd.CombinedOutput()
				So(err, ShouldNotBeNil)
				msg = string(out)
				So(msg, ShouldNotBeEmpty)
			})

			Convey("Validate deleted signature", func() {
				// verify with corrupted signature
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				var refs api.ReferenceList
				err = json.Unmarshal(resp.Body(), &refs)
				So(err, ShouldBeNil)
				So(len(refs.References), ShouldEqual, 1)
				err = os.Remove(path.Join(dir, repoName, "blobs",
					strings.ReplaceAll(refs.References[0].Digest.String(), ":", "/")))
				So(err, ShouldBeNil)
				resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
					fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, repoName, digest.String()))
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
				cmd = exec.Command("notation", "verify", "--cert", "good", "--plain-http", image)
				out, err = cmd.CombinedOutput()
				So(err, ShouldNotBeNil)
				msg = string(out)
				So(msg, ShouldNotBeEmpty)
			})
		})

		Convey("GetReferrers", func() {
			// cover error paths
			resp, err := resty.R().Get(
				fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, "badRepo", "badDigest"))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = resty.R().Get(
				fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, repoName, "badDigest"))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = resty.R().Get(
				fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, repoName, digest.String()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = resty.R().SetQueryParam("artifactType", "badArtifact").Get(
				fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, repoName, digest.String()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)

			resp, err = resty.R().SetQueryParam("artifactType", notreg.ArtifactTypeNotation).Get(
				fmt.Sprintf("%s/oras/artifacts/v1/%s/manifests/%s/referrers", baseURL, "badRepo", digest.String()))
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})
	})
}

func getAllBlobs(imagePath string) []string {
	blobList := make([]string, 0)

	if !storage.DirExists(imagePath) {
		return []string{}
	}

	buf, err := ioutil.ReadFile(path.Join(imagePath, "index.json"))
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

		buf, err = ioutil.ReadFile(p)

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

	if !storage.DirExists(imagePath) {
		return []string{}
	}

	buf, err := ioutil.ReadFile(path.Join(imagePath, "index.json"))
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

func startServer(c *api.Controller) {
	// this blocks
	if err := c.Run(); err != nil {
		return
	}
}

func stopServer(c *api.Controller) {
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}
