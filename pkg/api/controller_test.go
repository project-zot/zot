//go:build sync && scrub && metrics && search && ui_base
// +build sync,scrub,metrics,search,ui_base

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
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chartmuseum/auth"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	vldap "github.com/nmcclain/ldap"
	notreg "github.com/notaryproject/notation/pkg/registry"
	distext "github.com/opencontainers/distribution-spec/specs-go/v1/extensions"
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
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
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
	AuthorizationAllRepos  = "**"
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
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)

		globalDir := t.TempDir()

		ctlr.Config.Storage.RootDirectory = globalDir

		go func() {
			if err := ctlr.Run(context.Background()); err != nil {
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

		err := ctlr.Run(context.Background())
		So(err, ShouldNotBeNil)
	})
}

func TestObjectStorageController(t *testing.T) {
	skipIt(t)
	Convey("Negative make a new object storage controller", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port
		storageDriverParams := map[string]interface{}{
			"rootdirectory": "zot",
			"name":          storage.S3StorageDriverName,
		}
		conf.Storage.StorageDriver = storageDriverParams
		ctlr := api.NewController(conf)
		So(ctlr, ShouldNotBeNil)

		ctlr.Config.Storage.RootDirectory = "zot"

		err := ctlr.Run(context.Background())
		So(err, ShouldNotBeNil)
	})

	Convey("Make a new object storage controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		bucket := "zot-storage-test"
		endpoint := os.Getenv("S3MOCK_ENDPOINT")

		storageDriverParams := map[string]interface{}{
			"rootdirectory":  "zot",
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
		test.WaitTillServerReady(baseURL)
	})
}

func TestObjectStorageControllerSubPaths(t *testing.T) {
	skipIt(t)
	Convey("Make a new object storage controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		bucket := "zot-storage-test"
		endpoint := os.Getenv("S3MOCK_ENDPOINT")

		storageDriverParams := map[string]interface{}{
			"rootdirectory":  "zot",
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
		test.WaitTillServerReady(baseURL)
	})
}

func TestHtpasswdSingleCred(t *testing.T) {
	Convey("Single cred", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		singleCredtests := []string{}
		user := ALICE
		password := ALICE
		singleCredtests = append(singleCredtests, getCredString(user, password))
		singleCredtests = append(singleCredtests, getCredString(user, password)+"\n")

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

				ctlr := api.NewController(conf)
				ctlr.Config.Storage.RootDirectory = t.TempDir()

				go startServer(ctlr)
				defer stopServer(ctlr)
				test.WaitTillServerReady(baseURL)

				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				header := []string{"Authorization"}

				resp, _ = resty.R().SetBasicAuth(user, password).Options(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
				So(len(resp.Header()), ShouldEqual, 4)
				So(resp.Header()["Access-Control-Allow-Headers"], ShouldResemble, header)

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
				ctlr := api.NewController(conf)
				ctlr.Config.Storage.RootDirectory = t.TempDir()

				go startServer(ctlr)
				defer stopServer(ctlr)
				test.WaitTillServerReady(baseURL)

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
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()

			go startServer(ctlr)
			defer stopServer(ctlr)
			test.WaitTillServerReady(baseURL)

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
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)
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
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)
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
		htpasswdPath := test.MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := test.MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := api.NewController(conf)
		err := ctlr.Run(context.Background())
		So(err, ShouldEqual, errors.ErrImgStoreNotFound)

		globalDir := t.TempDir()
		subDir := t.TempDir()

		ctlr.Config.Storage.RootDirectory = globalDir
		subPathMap := make(map[string]config.StorageConfig)

		subPathMap["/a"] = config.StorageConfig{RootDirectory: subDir}

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		client := resty.New()

		tagResponse, err := client.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/tags/list")
		So(err, ShouldBeNil)
		So(tagResponse.StatusCode(), ShouldEqual, http.StatusNotFound)
	})

	Convey("Test zot multiple instance", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := test.MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		ctlr := api.NewController(conf)
		globalDir := t.TempDir()
		subDir := t.TempDir()

		ctlr.Config.Storage.RootDirectory = globalDir
		subPathMap := make(map[string]config.StorageConfig)
		subPathMap["/a"] = config.StorageConfig{RootDirectory: subDir}

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		htpasswdPath := test.MakeHtpasswdFile()
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

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		htpasswdPath := test.MakeHtpasswdFile()
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

		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)
	})
}

func TestTLSMutualAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
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

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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

		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

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
		htpasswdPath := test.MakeHtpasswdFile()
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

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		htpasswdPath := test.MakeHtpasswdFile()
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

		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

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
	conn net.Conn,
) (vldap.ServerSearchResult, error) {
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
			LDAP: &config.LDAPConfig{
				Insecure:      true,
				Address:       LDAPAddress,
				Port:          ldapPort,
				BindDN:        LDAPBindDN,
				BindPassword:  LDAPBindPassword,
				BaseDN:        LDAPBaseDN,
				UserAttribute: "uid",
			},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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

func TestBearerAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authTestServer := makeAuthTestServer()
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
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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

		resp, err = resty.R().SetHeader("Authorization",
			fmt.Sprintf("Bearer %s", goodToken.AccessToken)).Options(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)

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
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AuthorizationAllRepos: config.PolicyGroup{
					AnonymousPolicy: []string{"read"},
				},
			},
		}

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := test.MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AuthorizationAllRepos: config.PolicyGroup{
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
		dir := t.TempDir()
		err := test.CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		// unauthenticated clients should not have access to /v2/
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// everybody should have access to /v2/
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// everybody should have access to /v2/_catalog
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// should get 403 without create
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// first let's use global based policies
		// add test user to global policy with create perm
		conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Users = append(conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Users, "test") //nolint:lll // gofumpt conflicts with lll

		conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Actions = append(conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Actions, "create") //nolint:lll // gofumpt conflicts with lll

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

		// head blob should get 403 without read perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
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
		conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Actions = append(conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Actions, "read") //nolint:lll // gofumpt conflicts with lll

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
		conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Actions = append(conf.AccessControl.Repositories[AuthorizationAllRepos].Policies[0].Actions, "delete") //nolint:lll // gofumpt conflicts with lll

		// delete blob should get 202
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// now let's use only repository based policies
		// add test user to repo's policy with create perm
		// longest path matching should match the repo and not **/*
		conf.AccessControl.Repositories[AuthorizationNamespace] = config.PolicyGroup{
			Policies: []config.Policy{
				{
					Users:   []string{},
					Actions: []string{},
				},
			},
			DefaultPolicy: []string{},
		}

		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Users = append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Users, "test")       //nolint:lll // gofumpt conflicts with lll
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "create") //nolint:lll // gofumpt conflicts with lll

		// now it should get 202
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

		// head blob should get 403 without read perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
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
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "read") //nolint:lll // gofumpt conflicts with lll

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

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
		conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions = append(conf.AccessControl.Repositories[AuthorizationNamespace].Policies[0].Actions, "delete") //nolint:lll // gofumpt conflicts with lll

		// delete blob should get 202
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Delete(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		// remove permissions on **/* so it will not interfere with zot-test namespace
		repoPolicy := conf.AccessControl.Repositories[AuthorizationAllRepos]
		repoPolicy.Policies = []config.Policy{}
		repoPolicy.DefaultPolicy = []string{}
		conf.AccessControl.Repositories[AuthorizationAllRepos] = repoPolicy

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
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		// put manifest should get 403 without create perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add create perm on repo
		conf.AccessControl.Repositories["zot-test"].Policies[0].Actions = append(conf.AccessControl.Repositories["zot-test"].Policies[0].Actions, "create") //nolint:lll // gofumpt conflicts with lll

		// should get 201 with create perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// create update config and post it.
		cblob, cdigest := test.GetRandomImageConfig()

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/zot-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)

		// uploading blob should get 201
		resp, err = resty.R().SetBasicAuth(username, passphrase).
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

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/zot-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)
		// uploading blob should get 201
		resp, err = resty.R().SetBasicAuth(username, passphrase).
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
		resp, err = resty.R().SetBasicAuth(username, passphrase).SetBody(updatedManifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get the manifest and check if it's the old one
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldResemble, manifestBlob)

		// add update perm on repo
		conf.AccessControl.Repositories["zot-test"].Policies[0].Actions = append(conf.AccessControl.Repositories["zot-test"].Policies[0].Actions, "update") //nolint:lll // gofumpt conflicts with lll

		// update manifest should get 201 with update perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(updatedManifestBlob).
			Put(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// get the manifest and check if it's the new updated one
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldResemble, updatedManifestBlob)

		// now use default repo policy
		conf.AccessControl.Repositories["zot-test"].Policies[0].Actions = []string{}
		repoPolicy = conf.AccessControl.Repositories["zot-test"]
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

		repoPolicy = conf.AccessControl.Repositories["zot-test"]
		repoPolicy.Policies = []config.Policy{}
		repoPolicy.DefaultPolicy = []string{}
		conf.AccessControl.Repositories["zot-test"] = repoPolicy

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

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

func TestGetUsername(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		htpasswdPath := test.MakeHtpasswdFileFromString(getCredString(username, passphrase))
		defer os.Remove(htpasswdPath)

		conf := config.New()
		conf.HTTP.Port = port
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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

		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)
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
		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				TestRepo: config.PolicyGroup{
					AnonymousPolicy: []string{},
				},
			},
		}

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// should get 403 without create
		resp, err = resty.R().Post(baseURL + "/v2/" + TestRepo + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		if entry, ok := conf.AccessControl.Repositories[TestRepo]; ok {
			entry.AnonymousPolicy = []string{"create", "read"}
			conf.AccessControl.Repositories[TestRepo] = entry
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

		cblob, cdigest := test.GetRandomImageConfig()

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

		// update manifest should get 403 without update perm
		resp, err = resty.R().SetBody(updatedManifestBlob).
			Put(baseURL + "/v2/" + TestRepo + "/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get the manifest and check if it's the old one
		resp, err = resty.R().
			Get(baseURL + "/v2/" + TestRepo + "/manifests/0.0.2")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldResemble, manifestBlob)

		// add update perm on repo
		if entry, ok := conf.AccessControl.Repositories[TestRepo]; ok {
			entry.AnonymousPolicy = []string{"create", "read", "update"}
			conf.AccessControl.Repositories[TestRepo] = entry
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
	})
}

func TestAuthorizationWithMultiplePolicies(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		// have two users: "test" user for  user Policy, and "bob" for default policy
		htpasswdPath := test.MakeHtpasswdFileFromString(getCredString(username, passphrase) +
			"\n" + getCredString("bob", passphrase))
		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		// config with all policy types, to test that the correct one is applied in each case
		conf.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				AuthorizationAllRepos: config.PolicyGroup{
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

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		err := test.CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		// unauthenticated clients should not have access to /v2/, no policy is applied since none exists
		resp, err := resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		repoPolicy := conf.AccessControl.Repositories[AuthorizationAllRepos]
		repoPolicy.AnonymousPolicy = append(repoPolicy.AnonymousPolicy, "read")
		conf.AccessControl.Repositories[AuthorizationAllRepos] = repoPolicy

		// should have access to /v2/, anonymous policy is applied, "read" allowed
		resp, err = resty.R().Get(baseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// add "test" user to global policy with create permission
		repoPolicy.Policies[0].Users = append(repoPolicy.Policies[0].Users, "test")
		repoPolicy.Policies[0].Actions = append(repoPolicy.Policies[0].Actions, "create")

		// now it should get 202, user has the permission set on "create"
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

		// head blob should get 403 without read perm
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Head(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/" + digest)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// get tags without read access should get 403
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		repoPolicy.DefaultPolicy = append(repoPolicy.DefaultPolicy, "read")
		conf.AccessControl.Repositories[AuthorizationAllRepos] = repoPolicy

		// with read permission should get 200, because default policy allows reading now
		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// get tags with default read access should be ok, since the user is now "bob" and default policy is applied
		resp, err = resty.R().SetBasicAuth("bob", passphrase).
			Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// get tags with default policy read access
		resp, err = resty.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// get tags with anonymous read access should be ok
		resp, err = resty.R().Get(baseURL + "/v2/" + AuthorizationNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// without create permission should get 403, since "bob" can only read(default policy applied)
		resp, err = resty.R().SetBasicAuth("bob", passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusForbidden)

		// add read permission to user "bob"
		conf.AccessControl.AdminPolicy.Users = append(conf.AccessControl.AdminPolicy.Users, "bob")
		conf.AccessControl.AdminPolicy.Actions = append(conf.AccessControl.AdminPolicy.Actions, "create")

		// added create permission to user "bob", should be allowed now
		resp, err = resty.R().SetBasicAuth("bob", passphrase).
			Post(baseURL + "/v2/" + AuthorizationNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
	})
}

func TestInvalidCases(t *testing.T) {
	Convey("Invalid repo dir", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := test.MakeHtpasswdFileFromString(getCredString(username, passphrase))

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
		test.WaitTillServerReady(baseURL)

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

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		for _, testString := range singleCredtests {
			func() {
				conf := config.New()
				conf.HTTP.Port = port
				// enable read-only mode
				conf.AccessControl = &config.AccessControlConfig{
					Repositories: config.Repositories{
						AuthorizationAllRepos: config.PolicyGroup{
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
				ctlr := api.NewController(conf)
				ctlr.Config.Storage.RootDirectory = t.TempDir()

				go startServer(ctlr)
				defer stopServer(ctlr)
				test.WaitTillServerReady(baseURL)

				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(baseURL + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				// with creds, any modifications should still fail on read-only mode
				resp, err := resty.R().SetBasicAuth(user, password).
					Post(baseURL + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
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
		htpasswdPath := test.MakeHtpasswdFileFromString(getCredString(username, passphrase))

		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		dir := t.TempDir()

		err := test.CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		params := make(map[string]string)

		var manifestDigest godigest.Digest
		manifestDigest, _, _ = test.GetOciLayoutDigests("../../test/data/zot-cve-test")

		dgst := manifestDigest
		name := "zot-cve-test"
		params["mount"] = string(manifestDigest)
		params["from"] = name

		client := resty.New()
		headResponse, err := client.R().SetBasicAuth(username, passphrase).
			Head(fmt.Sprintf("%s/v2/%s/blobs/%s", baseURL, name, manifestDigest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusOK)

		// All invalid request of mount should return 202.
		params["mount"] = "sha:"

		postResponse, err := client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)
		location, err := postResponse.RawResponse.Location()
		So(err, ShouldBeNil)
		So(location.String(), ShouldStartWith, fmt.Sprintf("%s%s/zot-c-test/%s/%s",
			baseURL, constants.RoutePrefix, constants.Blobs, constants.Uploads))

		incorrectParams := make(map[string]string)
		incorrectParams["mount"] = "sha256:63a795ca90aa6e7dda60941e826810a4cd0a2e73ea02bf458241df2a5c973e29"
		incorrectParams["from"] = "zot-x-test"

		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(incorrectParams).
			Post(baseURL + "/v2/zot-y-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)
		So(test.Location(baseURL, postResponse), ShouldStartWith, fmt.Sprintf("%s%s/zot-y-test/%s/%s",
			baseURL, constants.RoutePrefix, constants.Blobs, constants.Uploads))

		// Use correct request
		// This is correct request but it will return 202 because blob is not present in cache.
		params["mount"] = string(manifestDigest)
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-c-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)
		So(test.Location(baseURL, postResponse), ShouldStartWith, fmt.Sprintf("%s%s/zot-c-test/%s/%s",
			baseURL, constants.RoutePrefix, constants.Blobs, constants.Uploads))

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
			Head(fmt.Sprintf("%s/v2/zot-cv-test/blobs/%s", baseURL, manifestDigest))
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

		blob := manifestDigest.Encoded()

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

		params["mount"] = string(manifestDigest)
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)
		So(test.Location(baseURL, postResponse), ShouldEqual, fmt.Sprintf("%s%s/zot-mount-test/%s/%s:%s",
			baseURL, constants.RoutePrefix, constants.Blobs, godigest.SHA256, blob))

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
		params["mount"] = string(manifestDigest)
		params["from"] = "zot-mount-test"
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount1-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusCreated)
		So(test.Location(baseURL, postResponse), ShouldEqual, fmt.Sprintf("%s%s/zot-mount1-test/%s/%s:%s",
			baseURL, constants.RoutePrefix, constants.Blobs, godigest.SHA256, blob))

		linkPath = path.Join(ctlr.Config.Storage.RootDirectory, "zot-mount1-test", "blobs/sha256", dgst.Hex())

		linkFi, err = os.Stat(linkPath)
		So(err, ShouldBeNil)

		So(os.SameFile(cacheFi, linkFi), ShouldEqual, true)

		headResponse, err = client.R().SetBasicAuth(username, passphrase).
			Head(fmt.Sprintf("%s/v2/zot-cv-test/blobs/%s", baseURL, manifestDigest))
		So(err, ShouldBeNil)
		So(headResponse.StatusCode(), ShouldEqual, http.StatusOK)

		// Invalid request
		params = make(map[string]string)
		params["mount"] = "sha256:"
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusAccepted)

		params = make(map[string]string)
		params["from"] = "zot-cve-test"
		postResponse, err = client.R().
			SetBasicAuth(username, passphrase).SetQueryParams(params).
			Post(baseURL + "/v2/zot-mount-test/blobs/uploads/")
		So(err, ShouldBeNil)
		So(postResponse.StatusCode(), ShouldEqual, http.StatusMethodNotAllowed)
	})

	Convey("Disable dedupe and cache", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := test.MakeHtpasswdFileFromString(getCredString(username, passphrase))

		defer os.Remove(htpasswdPath)

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		dir := t.TempDir()

		err := test.CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.Dedupe = false
		ctlr.Config.Storage.GC = false

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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

	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)

	conf := config.New()
	conf.HTTP.Port = port
	htpasswdPath := test.MakeHtpasswdFileFromString(getCredString(username, passphrase))

	conf.HTTP.Auth = &config.AuthConfig{
		HTPasswd: config.AuthHTPasswd{
			Path: htpasswdPath,
		},
	}

	ctlr := api.NewController(conf)

	dir := t.TempDir()
	firstSubDir := t.TempDir()
	secondSubDir := t.TempDir()

	subPaths := make(map[string]config.StorageConfig)

	subPaths["/a"] = config.StorageConfig{RootDirectory: firstSubDir}
	subPaths["/b"] = config.StorageConfig{RootDirectory: secondSubDir}

	ctlr.Config.Storage.SubPaths = subPaths
	ctlr.Config.Storage.RootDirectory = dir

	go startServer(ctlr)
	test.WaitTillServerReady(baseURL)

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
								if goerrors.Is(err, io.EOF) {
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
				Get(baseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
			assert.Equal(t, err, nil, "Error should be nil")
			assert.Equal(t, repoResponse.StatusCode(), http.StatusOK, "response status code should return success code")
		})
	}
}

func TestHardLink(t *testing.T) {
	Convey("Validate hard link", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		htpasswdPath := test.MakeHtpasswdFileFromString(getCredString(username, passphrase))

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

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

		ctlr.Config.Storage.RootDirectory = dir
		subPaths := make(map[string]config.StorageConfig)

		subPaths["/a"] = config.StorageConfig{RootDirectory: subDir, Dedupe: true}
		ctlr.Config.Storage.SubPaths = subPaths

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir
		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
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
		loc := test.Location(baseURL, resp)
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
		So(resp.Header().Get(constants.DistContentDigestKey), ShouldNotBeEmpty)

		// upload image config blob
		resp, err = resty.R().Post(baseURL + fmt.Sprintf("/v2/%s/blobs/uploads/", repoName))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
		loc = test.Location(baseURL, resp)
		cblob, cdigest := test.GetRandomImageConfig()

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
		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(baseURL + fmt.Sprintf("/v2/%s/manifests/1.0", repoName))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
		d := resp.Header().Get(constants.DistContentDigestKey)
		So(d, ShouldNotBeEmpty)
		So(d, ShouldEqual, digest.String())

		Convey("Validate cosign signatures", func() {
			cwd, err := os.Getwd()
			So(err, ShouldBeNil)
			defer func() { _ = os.Chdir(cwd) }()
			tdir := t.TempDir()
			_ = os.Chdir(tdir)

			// generate a keypair
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", nil)
			So(err, ShouldBeNil)

			// sign the image
			err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
				options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
				options.RegistryOptions{AllowInsecure: true},
				map[string]interface{}{"tag": "1.0"},
				[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())},
				"", "", true, "", "", "", false, false, "")
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
			tdir := t.TempDir()
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

			// check list
			cmd = exec.Command("notation", "list", "--plain-http", image)
			out, err = cmd.CombinedOutput()
			So(err, ShouldBeNil)
			msg = strings.TrimSuffix(string(out), "\n")
			So(msg, ShouldNotBeEmpty)
			_, err = godigest.Parse(msg)
			So(err, ShouldBeNil)

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

//nolint:dupl // duplicated test code
func TestRouteFailures(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		ctlr.Config.Storage.Commit = true

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		rthdlr := api.NewRouteHandler(ctlr)

		// NOTE: the url or method itself doesn't matter below since we are calling the handlers directly,
		// so path routing is bypassed

		Convey("List tags", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.ListTags(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
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

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
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

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
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

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
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

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
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

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
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

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
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
			request, _ := http.NewRequestWithContext(context.TODO(), "HEAD", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.CheckManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "HEAD", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.CheckManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "HEAD", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.CheckManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Get manifest", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.GetManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Update manifest", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "PUT", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "PUT", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.UpdateManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Delete manifest", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.DeleteManifest(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.DeleteManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "reference": ""})
			response = httptest.NewRecorder()

			rthdlr.DeleteManifest(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Check blob", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "HEAD", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.CheckBlob(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "HEAD", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.CheckBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "HEAD", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "digest": ""})
			response = httptest.NewRecorder()

			rthdlr.CheckBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Get blob", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.GetBlob(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.GetBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "digest": ""})
			response = httptest.NewRecorder()

			rthdlr.GetBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Delete blob", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.DeleteBlob(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.DeleteBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "digest": ""})
			response = httptest.NewRecorder()

			rthdlr.DeleteBlob(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Create blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "POST", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.CreateBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "POST", baseURL, nil)
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

			request, _ = http.NewRequestWithContext(context.TODO(), "POST", baseURL, nil)
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
			request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.GetBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.GetBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Patch blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "PATCH", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.PatchBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.PatchBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Update blob upload", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "PUT", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "PUT", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo", "session_id": "bar"})
			response = httptest.NewRecorder()

			rthdlr.UpdateBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)

			request, _ = http.NewRequestWithContext(context.TODO(), "PUT", baseURL, nil)
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
			request, _ := http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.DeleteBlobUpload(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "DELETE", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.DeleteBlobUpload(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)
		})

		Convey("Get referrers", func() {
			request, _ := http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{})
			response := httptest.NewRecorder()

			rthdlr.GetReferrers(response, request)

			resp := response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusNotFound)

			request, _ = http.NewRequestWithContext(context.TODO(), "GET", baseURL, nil)
			request = mux.SetURLVars(request, map[string]string{"name": "foo"})
			response = httptest.NewRecorder()

			rthdlr.GetReferrers(response, request)

			resp = response.Result()
			defer resp.Body.Close()
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode, ShouldEqual, http.StatusBadRequest)
		})
	})
}

func TestStorageCommit(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.Commit = true

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		Convey("Manifests", func() {
			_, _ = Print("\nManifests")
			// create a blob/layer
			resp, err := resty.R().Post(baseURL + "/v2/repo7/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc := test.Location(baseURL, resp)
			So(loc, ShouldNotBeEmpty)

			// since we are not specifying any prefix i.e provided in config while starting server,
			// so it should store repo7 to global root dir
			_, err = os.Stat(path.Join(dir, "repo7"))
			So(err, ShouldBeNil)

			resp, err = resty.R().Get(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNoContent)
			content := []byte("this is a blob5")
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

			// check a non-existent manifest
			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Head(baseURL + "/v2/unknown/manifests/test:1.0")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			// upload image config blob
			resp, err = resty.R().Post(baseURL + "/v2/repo7/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc = test.Location(baseURL, resp)
			cblob, cdigest := test.GetRandomImageConfig()

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

			content = []byte("this is a blob5")
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			// upload image config blob
			resp, err = resty.R().Post(baseURL + "/v2/repo7/blobs/uploads/")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)
			loc = test.Location(baseURL, resp)
			cblob, cdigest = test.GetRandomImageConfig()

			resp, err = resty.R().
				SetContentLength(true).
				SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
				SetHeader("Content-Type", "application/octet-stream").
				SetQueryParam("digest", cdigest.String()).
				SetBody(cblob).
				Put(loc)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			// create a manifest with same blob but a different tag
			manifest = ispec.Manifest{
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

func TestInjectInterruptedImageManifest(t *testing.T) {
	Convey("Make a new controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
			cblob, cdigest := test.GetRandomImageConfig()

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
				injected := test.InjectFailure(0)

				request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, bytes.NewReader(content))
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

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
		injected := test.InjectFailure(0)
		if injected {
			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", loc, bytes.NewReader(content))
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
		cblob, cdigest := test.GetRandomImageConfig()

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
			injected := test.InjectFailure(1)

			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, bytes.NewReader(content))
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
			injected := test.InjectFailure(2)

			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, bytes.NewReader(content))
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
			injected := test.InjectFailure(1)

			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, bytes.NewReader(content))
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
		Convey("code coverage: error inside PutImageManifest method of img store (umoci.OpenLayout error)", func() {
			injected := test.InjectFailure(3)

			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, bytes.NewReader(content))
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
		Convey("code coverage: error inside PutImageManifest method of img store (oci.GC)", func() {
			injected := test.InjectFailure(4)

			request, _ := http.NewRequestWithContext(context.TODO(), "PUT", baseURL, bytes.NewReader(content))
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
			err = ioutil.WriteFile(indexFile, indexContent, 0o600)
			So(err, ShouldBeNil)

			resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
				SetBody(content).Put(baseURL + "/v2/repotest/manifests/v1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})
	})
}

func TestPeriodicGC(t *testing.T) {
	Convey("Periodic gc enabled for default store", t, func() {
		repoName := "test"

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.GC = true
		ctlr.Config.Storage.GCInterval = 1 * time.Hour
		ctlr.Config.Storage.GCDelay = 1 * time.Second

		err = test.CopyFiles("../../test/data/zot-test", path.Join(dir, repoName))
		if err != nil {
			panic(err)
		}

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		time.Sleep(500 * time.Millisecond)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			"\"GC\":true,\"Commit\":false,\"GCDelay\":1000000000,\"GCInterval\":3600000000000")
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Starting periodic background tasks for %s", ctlr.StoreController.DefaultStore.RootDir())) //nolint:lll
		So(string(data), ShouldNotContainSubstring,
			fmt.Sprintf("error while running background task for %s", ctlr.StoreController.DefaultStore.RootDir()))
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("executing GC of orphaned blobs for %s", path.Join(ctlr.StoreController.DefaultStore.RootDir(), repoName))) //nolint:lll
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("GC completed for %s", path.Join(ctlr.StoreController.DefaultStore.RootDir(), repoName))) //nolint:lll
	})

	Convey("Periodic GC enabled for substore", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		subDir := t.TempDir()

		subPaths := make(map[string]config.StorageConfig)

		subPaths["/a"] = config.StorageConfig{RootDirectory: subDir, GC: true, GCDelay: 1 * time.Second, GCInterval: 24 * time.Hour} //nolint:lll // gofumpt conflicts with lll

		ctlr.Config.Storage.SubPaths = subPaths
		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		// periodic GC is not enabled for default store
		So(string(data), ShouldContainSubstring,
			"\"GCDelay\":3600000000000,\"GCInterval\":0,\"RootDirectory\":\""+dir+"\"")
		// periodic GC is enabled for sub store
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("\"SubPaths\":{\"/a\":{\"RootDirectory\":\"%s\",\"GC\":true,\"Dedupe\":false,\"Commit\":false,\"GCDelay\":1000000000,\"GCInterval\":86400000000000", subDir)) //nolint:lll // gofumpt conflicts with lll
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Starting periodic background tasks for %s", ctlr.StoreController.SubStore["/a"].RootDir())) //nolint:lll
	})
}

func TestPeriodicTasks(t *testing.T) {
	Convey("Both periodic gc and periodic scrub enabled for default store with scrubInterval < gcInterval", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.GC = true
		ctlr.Config.Storage.GCInterval = 12 * time.Hour
		ctlr.Config.Storage.GCDelay = 1 * time.Second
		ctlr.Config.Extensions = &extconf.ExtensionConfig{Scrub: &extconf.ScrubConfig{Interval: 8 * time.Hour}}

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Starting periodic background tasks for %s", ctlr.StoreController.DefaultStore.RootDir())) //nolint:lll
		So(string(data), ShouldNotContainSubstring,
			fmt.Sprintf("error while running background task for %s", ctlr.StoreController.DefaultStore.RootDir()))
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Finishing periodic background tasks for %s", ctlr.StoreController.DefaultStore.RootDir())) //nolint:lll
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Periodic interval for %s set to %s",
				ctlr.StoreController.DefaultStore.RootDir(), ctlr.Config.Extensions.Scrub.Interval))
	})

	Convey("Both periodic gc and periodic scrub enabled for default store with gcInterval < scrubInterval", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)
		dir := t.TempDir()
		ctlr.Config.Storage.RootDirectory = dir
		ctlr.Config.Storage.GC = true
		ctlr.Config.Storage.GCInterval = 8 * time.Hour
		ctlr.Config.Storage.GCDelay = 1 * time.Second
		ctlr.Config.Extensions = &extconf.ExtensionConfig{Scrub: &extconf.ScrubConfig{Interval: 12 * time.Hour}}

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Starting periodic background tasks for %s", ctlr.StoreController.DefaultStore.RootDir())) //nolint:lll
		So(string(data), ShouldNotContainSubstring,
			fmt.Sprintf("error while running background task for %s", ctlr.StoreController.DefaultStore.RootDir()))
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Finishing periodic background tasks for %s", ctlr.StoreController.DefaultStore.RootDir())) //nolint:lll
		So(string(data), ShouldContainSubstring,
			fmt.Sprintf("Periodic interval for %s set to %s",
				ctlr.StoreController.DefaultStore.RootDir(), ctlr.Config.Storage.GCInterval))
	})
}

func TestDistSpecExtensions(t *testing.T) {
	Convey("start zot server with search extension", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf.HTTP.Port = port

		defaultVal := true

		searchConfig := &extconf.SearchConfig{
			Enable: &defaultVal,
		}

		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		var extensionList distext.ExtensionList

		resp, err := resty.R().Get(baseURL + constants.RoutePrefix + constants.ExtOciDiscoverPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &extensionList)
		So(err, ShouldBeNil)
		So(len(extensionList.Extensions), ShouldEqual, 1)
		So(len(extensionList.Extensions[0].Endpoints), ShouldEqual, 1)
		So(extensionList.Extensions[0].Name, ShouldEqual, "_zot")
		So(extensionList.Extensions[0].URL, ShouldContainSubstring, "_zot.md")
		So(extensionList.Extensions[0].Description, ShouldNotBeEmpty)
		So(extensionList.Extensions[0].Endpoints[0], ShouldEqual, constants.ExtSearchPrefix)
	})

	Convey("start minimal zot server", t, func(c C) {
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf.HTTP.Port = port

		logFile, err := ioutil.TempFile("", "zot-log*.txt")
		So(err, ShouldBeNil)
		conf.Log.Output = logFile.Name()
		defer os.Remove(logFile.Name()) // clean up

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

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
	ctx := context.Background()
	if err := c.Run(ctx); err != nil {
		return
	}
}

func stopServer(c *api.Controller) {
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}
