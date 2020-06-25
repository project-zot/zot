package api_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/api"
	"github.com/chartmuseum/auth"
	"github.com/mitchellh/mapstructure"
	vldap "github.com/nmcclain/ldap"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

const (
	BaseURL1              = "http://127.0.0.1:8081"
	BaseURL2              = "http://127.0.0.1:8082"
	BaseURL3              = "http://127.0.0.1:8083"
	BaseURL4              = "http://127.0.0.1:8084"
	BaseSecureURL2        = "https://127.0.0.1:8082"
	SecurePort1           = "8081"
	SecurePort2           = "8082"
	SecurePort3           = "8083"
	SecurePort4           = "8084"
	username              = "test"
	passphrase            = "test"
	ServerCert            = "../../test/data/server.cert"
	ServerKey             = "../../test/data/server.key"
	CACert                = "../../test/data/ca.crt"
	AuthorizedNamespace   = "everyone/isallowed"
	UnauthorizedNamespace = "fortknox/notallowed"
	ALICE                 = "alice"
)

type (
	accessTokenResponse struct {
		AccessToken string `json:"access_token"`
	}

	authHeader struct {
		Realm   string
		Service string
		Scope   string
	}
)

func makeHtpasswdFile() string {
	f, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte("test:$2y$05$hlbSXDp6hzDLu6VwACS39ORvVRpr3OMR4RlJ31jtlaOEGnPjKZI1m\n")
	if err := ioutil.WriteFile(f.Name(), content, 0600); err != nil {
		panic(err)
	}

	return f.Name()
}

func makeHtpasswdFileFromString(fileContent string) string {
	f, err := ioutil.TempFile("", "htpasswd-")
	if err != nil {
		panic(err)
	}

	// bcrypt(username="test", passwd="test")
	content := []byte(fileContent)
	if err := ioutil.WriteFile(f.Name(), content, 0600); err != nil {
		panic(err)
	}

	return f.Name()
}

func getCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
}
func TestNew(t *testing.T) {
	Convey("Make a new controller", t, func() {
		config := api.NewConfig()
		So(config, ShouldNotBeNil)
		So(api.NewController(config), ShouldNotBeNil)
	})
}

func TestHtpasswdSingleCred(t *testing.T) {
	Convey("Single cred", t, func() {
		singleCredtests := []string{}
		user := ALICE
		password := ALICE
		singleCredtests = append(singleCredtests, getCredString(user, password))
		singleCredtests = append(singleCredtests, getCredString(user, password)+"\n")

		for _, testString := range singleCredtests {
			func() {
				config := api.NewConfig()
				config.HTTP.Port = SecurePort1

				htpasswdPath := makeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				config.HTTP.Auth = &api.AuthConfig{
					HTPasswd: api.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				c := api.NewController(config)
				dir, err := ioutil.TempDir("", "oci-repo-test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(dir)
				c.Config.Storage.RootDirectory = dir
				c.Config.Extensions.Search.CVE.UpdateInterval = 1
				go func(controller *api.Controller) {
					// this blocks
					if err := controller.Run(); err != nil {
						return
					}
				}(c)
				// wait till ready
				for {
					_, err := resty.R().Get(BaseURL1)
					if err == nil {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				defer func(controller *api.Controller) {
					ctx := context.Background()
					_ = controller.Server.Shutdown(ctx)
				}(c)
				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(BaseURL1 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				//with invalid creds, it should fail
				resp, _ = resty.R().SetBasicAuth("chuck", "chuck").Get(BaseURL1 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 401)
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
				config := api.NewConfig()
				config.HTTP.Port = SecurePort1
				htpasswdPath := makeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				config.HTTP.Auth = &api.AuthConfig{
					HTPasswd: api.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				c := api.NewController(config)
				dir, err := ioutil.TempDir("", "oci-repo-test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(dir)
				c.Config.Storage.RootDirectory = dir
				c.Config.Extensions.Search.CVE.UpdateInterval = 1
				go func(controller *api.Controller) {
					// this blocks
					if err := controller.Run(); err != nil {
						return
					}
				}(c)
				// wait till ready
				for {
					_, err := resty.R().Get(BaseURL1)
					if err == nil {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}

				defer func(controller *api.Controller) {
					ctx := context.Background()
					_ = controller.Server.Shutdown(ctx)
				}(c)
				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user1, password1).Get(BaseURL1 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				resp, _ = resty.R().SetBasicAuth(user2, password2).Get(BaseURL1 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				//with invalid creds, it should fail
				resp, _ = resty.R().SetBasicAuth("chuck", "chuck").Get(BaseURL1 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 401)
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
			config := api.NewConfig()
			config.HTTP.Port = SecurePort1
			htpasswdPath := makeHtpasswdFileFromString(credString.String())
			defer os.Remove(htpasswdPath)
			config.HTTP.Auth = &api.AuthConfig{
				HTPasswd: api.AuthHTPasswd{
					Path: htpasswdPath,
				},
			}
			c := api.NewController(config)
			dir, err := ioutil.TempDir("", "oci-repo-test")
			if err != nil {
				panic(err)
			}
			defer os.RemoveAll(dir)
			c.Config.Storage.RootDirectory = dir
			c.Config.Extensions.Search.CVE.UpdateInterval = 1
			go func(controller *api.Controller) {
				// this blocks
				if err := controller.Run(); err != nil {
					return
				}
			}(c)
			// wait till ready
			for {
				_, err := resty.R().Get(BaseURL1)
				if err == nil {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			defer func(controller *api.Controller) {
				ctx := context.Background()
				_ = controller.Server.Shutdown(ctx)
			}(c)
			// with creds, should get expected status code
			for key, val := range tests {
				resp, _ := resty.R().SetBasicAuth(key, val).Get(BaseURL1 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)
			}

			//with invalid creds, it should fail
			resp, _ := resty.R().SetBasicAuth("chuck", "chuck").Get(BaseURL1 + "/v2/")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, 401)
		}()
	})
}
func TestBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		config := api.NewConfig()
		config.HTTP.Port = SecurePort1
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// without creds, should get access error
		resp, err := resty.R().Get(BaseURL1 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSWithBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.TLS = &api.TLSConfig{
			Cert: ServerCert,
			Key:  ServerKey,
		}
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without creds, should get access error
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSWithBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		config.HTTP.TLS = &api.TLSConfig{
			Cert: ServerCert,
			Key:  ServerKey,
		}
		config.HTTP.AllowReadAccess = true

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without creds, should still be allowed to access
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// without creds, writes should fail
		resp, err = resty.R().Post(BaseSecureURL2 + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
	})
}

func TestTLSMutualAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, should get conn error
		_, err = resty.R().Get(BaseSecureURL2)
		So(err, ShouldNotBeNil)

		// with creds but without certs, should get conn error
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(err, ShouldNotBeNil)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should succeed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSMutualAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}
		config.HTTP.AllowReadAccess = true

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, reads are allowed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with creds but without certs, reads are allowed
		resp, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// without creds, writes should fail
		resp, err = resty.R().Post(BaseSecureURL2 + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should succeed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		// with client certs, creds shouldn't matter
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSMutualAndBasicAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, should fail
		_, err = resty.R().Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, should get access error
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestTLSMutualAndBasicAuthAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		htpasswdPath := makeHtpasswdFile()
		defer os.Remove(htpasswdPath)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		config := api.NewConfig()
		config.HTTP.Port = SecurePort2
		config.HTTP.Auth = &api.AuthConfig{
			HTPasswd: api.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
		config.HTTP.TLS = &api.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}
		config.HTTP.AllowReadAccess = true

		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL2)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// accessing insecure HTTP site should fail
		resp, err := resty.R().Get(BaseURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// without client certs and creds, should fail
		_, err = resty.R().Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// with creds but without certs, should succeed
		_, err = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 400)

		// setup TLS mutual auth
		cert, err := tls.LoadX509KeyPair("../../test/data/client.cert", "../../test/data/client.key")
		So(err, ShouldBeNil)

		resty.SetCertificates(cert)
		defer func() { resty.SetCertificates(tls.Certificate{}) }()

		// with client certs but without creds, reads should succeed
		resp, err = resty.R().Get(BaseSecureURL2 + "/v2/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		// with only client certs, writes should fail
		resp, err = resty.R().Post(BaseSecureURL2 + "/v2/repo/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		// with client certs and creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseSecureURL2 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
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
	l := &testLDAPServer{}
	quitCh := make(chan bool)
	server := vldap.NewServer()
	server.QuitChannel(quitCh)
	server.BindFunc("", l)
	server.SearchFunc("", l)
	l.server = server
	l.quitCh = quitCh

	return l
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
		config := api.NewConfig()
		config.HTTP.Port = SecurePort1
		config.HTTP.Auth = &api.AuthConfig{
			LDAP: &api.LDAPConfig{
				Insecure:      true,
				Address:       LDAPAddress,
				Port:          LDAPPort,
				BindDN:        LDAPBindDN,
				BindPassword:  LDAPBindPassword,
				BaseDN:        LDAPBaseDN,
				UserAttribute: "uid",
			},
		}
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		// without creds, should get access error
		resp, err := resty.R().Get(BaseURL1 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
		var e api.Error
		err = json.Unmarshal(resp.Body(), &e)
		So(err, ShouldBeNil)

		// with creds, should get expected status code
		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 404)

		resp, _ = resty.R().SetBasicAuth(username, passphrase).Get(BaseURL1 + "/v2/")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
	})
}

func TestBearerAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authTestServer := makeAuthTestServer()
		defer authTestServer.Close()

		config := api.NewConfig()
		config.HTTP.Port = SecurePort3

		u, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		config.HTTP.Auth = &api.AuthConfig{
			Bearer: &api.BearerConfig{
				Cert:    ServerCert,
				Realm:   authTestServer.URL + "/auth/token",
				Service: u.Host,
			},
		}
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL3)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		resp, err := resty.R().Get(BaseURL3 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader := parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		var goodToken accessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(BaseURL3 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Post(BaseURL3 + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Post(BaseURL3 + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 202)
		loc := resp.Header().Get("Location")

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(BaseURL3 + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(BaseURL3 + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 201)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(BaseURL3 + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(BaseURL3 + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().
			Post(BaseURL3 + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		var badToken accessTokenResponse
		err = json.Unmarshal(resp.Body(), &badToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", badToken.AccessToken)).
			Post(BaseURL3 + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
	})
}

func TestBearerAuthWithAllowReadAccess(t *testing.T) {
	Convey("Make a new controller", t, func() {
		authTestServer := makeAuthTestServer()
		defer authTestServer.Close()

		config := api.NewConfig()
		config.HTTP.Port = SecurePort3

		u, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		config.HTTP.Auth = &api.AuthConfig{
			Bearer: &api.BearerConfig{
				Cert:    ServerCert,
				Realm:   authTestServer.URL + "/auth/token",
				Service: u.Host,
			},
		}
		config.HTTP.AllowReadAccess = true
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		c.Config.Extensions.Search.CVE.UpdateInterval = 1
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseURL3)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		blob := []byte("hello, blob!")
		digest := godigest.FromBytes(blob).String()

		resp, err := resty.R().Get(BaseURL3 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader := parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		var goodToken accessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(BaseURL3 + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().Post(BaseURL3 + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Post(BaseURL3 + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 202)
		loc := resp.Header().Get("Location")

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(BaseURL3 + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			SetQueryParam("digest", digest).
			SetBody(blob).
			Put(BaseURL3 + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 201)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(BaseURL3 + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(BaseURL3 + "/v2/" + AuthorizedNamespace + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)

		resp, err = resty.R().
			Post(BaseURL3 + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)

		authorizationHeader = parseBearerAuthHeader(resp.Header().Get("Www-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 200)
		var badToken accessTokenResponse
		err = json.Unmarshal(resp.Body(), &badToken)
		So(err, ShouldBeNil)

		resp, err = resty.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", badToken.AccessToken)).
			Post(BaseURL3 + "/v2/" + UnauthorizedNamespace + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, 401)
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

	authTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
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
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token": "%s"}`, token)
	}))

	return authTestServer
}

func parseBearerAuthHeader(authHeaderRaw string) *authHeader {
	re := regexp.MustCompile(`([a-zA-z]+)="(.+?)"`)
	matches := re.FindAllStringSubmatch(authHeaderRaw, -1)
	m := make(map[string]string)

	for i := 0; i < len(matches); i++ {
		m[matches[i][1]] = matches[i][2]
	}

	var h authHeader
	if err := mapstructure.Decode(m, &h); err != nil {
		panic(err)
	}

	return &h
}

func TestHTTPReadOnly(t *testing.T) {
	Convey("Single cred", t, func() {
		singleCredtests := []string{}
		user := ALICE
		password := ALICE
		singleCredtests = append(singleCredtests, getCredString(user, password))
		singleCredtests = append(singleCredtests, getCredString(user, password)+"\n")

		for _, testString := range singleCredtests {
			func() {
				config := api.NewConfig()
				config.HTTP.Port = SecurePort4
				// enable read-only mode
				config.HTTP.ReadOnly = true

				htpasswdPath := makeHtpasswdFileFromString(testString)
				defer os.Remove(htpasswdPath)
				config.HTTP.Auth = &api.AuthConfig{
					HTPasswd: api.AuthHTPasswd{
						Path: htpasswdPath,
					},
				}
				c := api.NewController(config)
				dir, err := ioutil.TempDir("", "oci-repo-test")
				if err != nil {
					panic(err)
				}
				defer os.RemoveAll(dir)
				c.Config.Storage.RootDirectory = dir
				go func(controller *api.Controller) {
					// this blocks
					if err := controller.Run(); err != nil {
						return
					}
				}(c)
				// wait till ready
				for {
					_, err := resty.R().Get(BaseURL4)
					if err == nil {
						break
					}
					time.Sleep(100 * time.Millisecond)
				}
				defer func(controller *api.Controller) {
					ctx := context.Background()
					_ = controller.Server.Shutdown(ctx)
				}(c)
				// with creds, should get expected status code
				resp, _ := resty.R().SetBasicAuth(user, password).Get(BaseURL4 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				// with creds, should get expected status code
				resp, _ = resty.R().SetBasicAuth(user, password).Get(BaseURL4 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 200)

				// with creds, any modifications should still fail on read-only mode
				resp, err = resty.R().SetBasicAuth(user, password).
					Post(BaseURL4 + "/v2/" + AuthorizedNamespace + "/blobs/uploads/")
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 405)

				//with invalid creds, it should fail
				resp, _ = resty.R().SetBasicAuth("chuck", "chuck").Get(BaseURL4 + "/v2/")
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, 401)
			}()
		}
	})
}
