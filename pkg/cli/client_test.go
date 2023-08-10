//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extConf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

const (
	BaseURL1       = "http://127.0.0.1:8088"
	BaseSecureURL1 = "https://127.0.0.1:8088"
	HOST1          = "127.0.0.1:8088"
	SecurePort1    = "8088"
	BaseURL2       = "http://127.0.0.1:8089"
	BaseSecureURL2 = "https://127.0.0.1:8089"
	SecurePort2    = "8089"
	BaseURL3       = "http://127.0.0.1:8090"
	BaseSecureURL3 = "https://127.0.0.1:8090"
	SecurePort3    = "8090"
	username       = "test"
	passphrase     = "test"
	ServerCert     = "../../test/data/server.cert"
	ServerKey      = "../../test/data/server.key"
	CACert         = "../../test/data/ca.crt"
	sourceCertsDir = "../../test/data"
	certsDir1      = "/.config/containers/certs.d/127.0.0.1:8088/"
)

func TestTLSWithAuth(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort1
		htpasswdPath := test.MakeHtpasswdFile()
		defer os.Remove(htpasswdPath)

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

		enable := true
		conf.Extensions = &extConf.ExtensionConfig{
			Search: &extConf.SearchConfig{BaseConfig: extConf.BaseConfig{Enable: &enable}},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		Convey("Test with htpassw auth", func() {
			configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
			defer os.Remove(configPath)

			home := os.Getenv("HOME")
			destCertsDir := filepath.Join(home, certsDir1)
			err := test.CopyTestKeysAndCerts(destCertsDir)
			So(err, ShouldBeNil)

			defer os.RemoveAll(destCertsDir)

			args := []string{"imagetest", "--name", "dummyImageName", "--url", HOST1}
			imageCmd := NewImageCommand(new(searchService))
			imageBuff := bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err = imageCmd.Execute()
			So(err, ShouldNotBeNil)
			So(imageBuff.String(), ShouldContainSubstring, "invalid URL format")

			args = []string{"imagetest"}
			configPath = makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					BaseSecureURL1, constants.RoutePrefix, constants.ExtCatalogPrefix))
			defer os.Remove(configPath)
			imageCmd = NewImageCommand(new(searchService))
			imageBuff = bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err = imageCmd.Execute()
			So(err, ShouldNotBeNil)
			So(imageBuff.String(), ShouldContainSubstring, "check credentials")

			user := fmt.Sprintf("%s:%s", username, passphrase)
			args = []string{"imagetest", "-u", user}
			configPath = makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					BaseSecureURL1, constants.RoutePrefix, constants.ExtCatalogPrefix))
			defer os.Remove(configPath)
			imageCmd = NewImageCommand(new(searchService))
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
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort1
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		enable := true
		conf.Extensions = &extConf.ExtensionConfig{
			Search: &extConf.SearchConfig{BaseConfig: extConf.BaseConfig{Enable: &enable}},
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		Convey("Certs in user's home", func() {
			configPath := makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					BaseSecureURL1, constants.RoutePrefix, constants.ExtCatalogPrefix))
			defer os.Remove(configPath)

			home := os.Getenv("HOME")
			destCertsDir := filepath.Join(home, certsDir1)
			test.CopyTestFiles(sourceCertsDir, destCertsDir)
			defer os.RemoveAll(destCertsDir)

			args := []string{"imagetest"}
			imageCmd := NewImageCommand(new(searchService))
			imageBuff := bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()
			So(err, ShouldBeNil)
		})
	})
}

func TestTLSBadCerts(t *testing.T) {
	Convey("Make a new controller", t, func() {
		caCert, err := os.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort3
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		Convey("Test with system certs", func() {
			configPath := makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					BaseSecureURL3, constants.RoutePrefix, constants.ExtCatalogPrefix))
			defer os.Remove(configPath)

			args := []string{"imagetest"}
			imageCmd := NewImageCommand(new(searchService))
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
