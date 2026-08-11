//go:build search

package client_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/cli/client"
	extConf "zotregistry.dev/zot/v2/pkg/extensions/config"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

func homeCertsDir(hostPort string) string {
	return filepath.Join(".config", "containers", "certs.d", hostPort)
}

func writeHomeClientCerts(t *testing.T, home, hostPort string, caCertPEM, caKeyPEM []byte) {
	t.Helper()

	destCertsDir := filepath.Join(home, homeCertsDir(hostPort))
	//nolint:gosec // test path is tempdir-scoped via HOME override
	err := os.MkdirAll(destCertsDir, 0o755)
	So(err, ShouldBeNil)

	//nolint:gosec // test path is tempdir-scoped via HOME override
	err = os.WriteFile(filepath.Join(destCertsDir, "ca.crt"), caCertPEM, 0o600)
	So(err, ShouldBeNil)

	clientCertPath := filepath.Join(destCertsDir, "client.cert")
	clientKeyPath := filepath.Join(destCertsDir, "client.key")
	clientOpts := &tlsutils.CertificateOptions{
		CommonName:         "testclient",
		OrganizationalUnit: "TestClient",
		NotAfter:           time.Now().AddDate(10, 0, 0),
	}
	err = tlsutils.GenerateClientCertToFile(caCertPEM, caKeyPEM, clientCertPath, clientKeyPath, clientOpts)
	So(err, ShouldBeNil)
}

func TestTLSWithAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		// Generate certificates using tls library
		tempDir := t.TempDir()
		caOpts := &tlsutils.CertificateOptions{
			CommonName: "*",
			NotAfter:   time.Now().AddDate(10, 0, 0),
		}
		caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
		So(err, ShouldBeNil)

		caCertPath := path.Join(tempDir, "ca.crt")
		caKeyPath := path.Join(tempDir, "ca.key")
		err = os.WriteFile(caCertPath, caCertPEM, 0o600)
		So(err, ShouldBeNil)
		err = os.WriteFile(caKeyPath, caKeyPEM, 0o600)
		So(err, ShouldBeNil)

		serverCertPath := path.Join(tempDir, "server.cert")
		serverKeyPath := path.Join(tempDir, "server.key")
		serverOpts := &tlsutils.CertificateOptions{
			Hostname:           "127.0.0.1",
			CommonName:         "*",
			OrganizationalUnit: "TestServer",
			NotAfter:           time.Now().AddDate(10, 0, 0),
		}
		err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		defer func() { resty.SetTLSClientConfig(nil) }()

		conf := config.New()
		conf.HTTP.Port = "0"
		username, seedUser := test.GenerateRandomString()
		password, seedPass := test.GenerateRandomString()

		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		enable := true
		conf.Extensions = &extConf.ExtensionConfig{
			Search: &extConf.SearchConfig{BaseConfig: extConf.BaseConfig{Enable: &enable}},
		}

		ctlr := api.NewController(conf)
		ctlr.Log.Info().Int64("seedUser", seedUser).Int64("seedPass", seedPass).Msg("random seed for username & password")
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		baseURL := cm.StartAndWait()
		defer cm.StopServer()

		hostPort := "127.0.0.1:" + strconv.Itoa(cm.Port())

		Convey("Test with htpassw auth", func() {
			// Client certs are resolved under $HOME; isolate from the real home directory.
			t.Setenv("HOME", t.TempDir())
			writeHomeClientCerts(t, os.Getenv("HOME"), hostPort, caCertPEM, caKeyPEM)

			args := []string{"name", "dummyImageName", "--url", hostPort}
			imageCmd := client.NewImageCommand(client.NewSearchService())
			imageBuff := bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err = imageCmd.Execute()
			So(err, ShouldNotBeNil)
			So(imageBuff.String(), ShouldContainSubstring, "scheme not provided")

			invalidUser := fmt.Sprintf("%s:%s", "wrong_username", "wrong_password")
			args = []string{"-u", invalidUser, "list", "--config", "imagetest"}

			_ = makeConfigFile(t,
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					baseURL, constants.RoutePrefix, constants.ExtCatalogPrefix))

			// Ensure certificates are in the HOME directory that makeConfigFile set
			writeHomeClientCerts(t, os.Getenv("HOME"), hostPort, caCertPEM, caKeyPEM)

			imageCmd = client.NewImageCommand(client.NewSearchService())
			imageBuff = bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err = imageCmd.Execute()
			So(err, ShouldNotBeNil)
			So(imageBuff.String(), ShouldContainSubstring, "check credentials")

			user := fmt.Sprintf("%s:%s", username, password)
			args = []string{"-u", user, "--config", "imagetest"}

			_ = makeConfigFile(t,
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					baseURL, constants.RoutePrefix, constants.ExtCatalogPrefix))

			writeHomeClientCerts(t, os.Getenv("HOME"), hostPort, caCertPEM, caKeyPEM)

			imageCmd = client.NewImageCommand(client.NewSearchService())
			imageBuff = bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err = imageCmd.Execute()
			So(err, ShouldBeNil)
		})
	})
}

func TestTLSWithoutAuth(t *testing.T) {
	Convey("Home certs - Make a new controller", t, func() {
		// Generate certificates using tls library
		tempDir := t.TempDir()
		caOpts := &tlsutils.CertificateOptions{
			CommonName: "*",
			NotAfter:   time.Now().AddDate(10, 0, 0),
		}
		caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
		So(err, ShouldBeNil)

		caCertPath := path.Join(tempDir, "ca.crt")
		caKeyPath := path.Join(tempDir, "ca.key")
		err = os.WriteFile(caCertPath, caCertPEM, 0o600)
		So(err, ShouldBeNil)
		err = os.WriteFile(caKeyPath, caKeyPEM, 0o600)
		So(err, ShouldBeNil)

		serverCertPath := path.Join(tempDir, "server.cert")
		serverKeyPath := path.Join(tempDir, "server.key")
		serverOpts := &tlsutils.CertificateOptions{
			Hostname:           "127.0.0.1",
			CommonName:         "*",
			OrganizationalUnit: "TestServer",
			NotAfter:           time.Now().AddDate(10, 0, 0),
		}
		err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts)
		So(err, ShouldBeNil)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		defer func() { resty.SetTLSClientConfig(nil) }()

		conf := config.New()
		conf.HTTP.Port = "0"
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		enable := true
		conf.Extensions = &extConf.ExtensionConfig{
			Search: &extConf.SearchConfig{BaseConfig: extConf.BaseConfig{Enable: &enable}},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		baseURL := cm.StartAndWait()
		defer cm.StopServer()

		hostPort := "127.0.0.1:" + strconv.Itoa(cm.Port())

		Convey("Certs in user's home", func() {
			_ = makeConfigFile(t,
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					baseURL, constants.RoutePrefix, constants.ExtCatalogPrefix))

			writeHomeClientCerts(t, os.Getenv("HOME"), hostPort, caCertPEM, caKeyPEM)

			args := []string{"list", "--config", "imagetest"}
			imageCmd := client.NewImageCommand(client.NewSearchService())
			imageBuff := bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err = imageCmd.Execute()
			So(err, ShouldBeNil)
		})
	})
}

func TestTLSBadCerts(t *testing.T) {
	Convey("Make a new controller", t, func() {
		// Generate certificates using tls library
		tempDir := t.TempDir()
		caOpts := &tlsutils.CertificateOptions{
			CommonName: "*",
			NotAfter:   time.Now().AddDate(10, 0, 0),
		}
		caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
		So(err, ShouldBeNil)

		caCertPath := path.Join(tempDir, "ca.crt")
		caKeyPath := path.Join(tempDir, "ca.key")
		err = os.WriteFile(caCertPath, caCertPEM, 0o600)
		So(err, ShouldBeNil)
		err = os.WriteFile(caKeyPath, caKeyPEM, 0o600)
		So(err, ShouldBeNil)

		serverCertPath := path.Join(tempDir, "server.cert")
		serverKeyPath := path.Join(tempDir, "server.key")
		serverOpts := &tlsutils.CertificateOptions{
			Hostname:           "127.0.0.1",
			CommonName:         "*",
			OrganizationalUnit: "TestServer",
			NotAfter:           time.Now().AddDate(10, 0, 0),
		}
		err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts)
		So(err, ShouldBeNil)

		// Use a different CA for the client to simulate bad certs
		badCAOpts := &tlsutils.CertificateOptions{
			CommonName: "*",
		}
		badCACertPEM, _, err := tlsutils.GenerateCACert(badCAOpts)
		So(err, ShouldBeNil)

		badCACertPool := x509.NewCertPool()
		badCACertPool.AppendCertsFromPEM(badCACertPEM)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: badCACertPool, MinVersion: tls.VersionTLS12})

		defer func() { resty.SetTLSClientConfig(nil) }()

		conf := config.New()
		conf.HTTP.Port = "0"
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		baseURL := cm.StartAndWait()
		defer cm.StopServer()

		Convey("Test with system certs", func() {
			_ = makeConfigFile(t,
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					baseURL, constants.RoutePrefix, constants.ExtCatalogPrefix))

			args := []string{"list", "--config", "imagetest"}
			imageCmd := client.NewImageCommand(client.NewSearchService())
			imageBuff := bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()
			So(err, ShouldNotBeNil)
			So(imageBuff.String(), ShouldContainSubstring, "certificate signed by unknown authority")
		})
	})
}

func makeConfigFile(t *testing.T, content string) string {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	configPath := filepath.Join(tempDir, ".zot")

	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		panic(err)
	}

	return configPath
}
