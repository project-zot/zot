//go:build extended
// +build extended

package cli //nolint:testpackage

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	. "zotregistry.io/zot/test"
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
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort1
		htpasswdPath := MakeHtpasswdFile()
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

		c := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
		go func() {
			// this blocks
			if err := c.Run(); err != nil {
				return
			}
		}()

		// wait till ready
		for {
			_, err := resty.R().Get(BaseSecureURL1)
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		defer func() {
			ctx := context.Background()
			_ = c.Server.Shutdown(ctx)
		}()

		Convey("Test with htpassw auth", func() {
			configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
			defer os.Remove(configPath)

			home := os.Getenv("HOME")
			destCertsDir := filepath.Join(home, certsDir1)
			if err = CopyFiles(sourceCertsDir, destCertsDir); err != nil {
				panic(err)
			}
			defer os.RemoveAll(destCertsDir)

			args := []string{"imagetest", "--name", "dummyImageName", "--url", HOST1}
			imageCmd := NewImageCommand(new(searchService))
			imageBuff := bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()
			So(err, ShouldNotBeNil)
			So(imageBuff.String(), ShouldContainSubstring, "invalid URL format")

			args = []string{"imagetest"}
			configPath = makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s/v2/_catalog","showspinner":false}]}`,
					BaseSecureURL1))
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
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s/v2/_catalog","showspinner":false}]}`,
					BaseSecureURL1))
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
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort1
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		c := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
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

		Convey("Certs in user's home", func() {
			configPath := makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s/v2/_catalog","showspinner":false}]}`,
					BaseSecureURL1))
			defer os.Remove(configPath)

			home := os.Getenv("HOME")
			destCertsDir := filepath.Join(home, certsDir1)
			if err = CopyFiles(sourceCertsDir, destCertsDir); err != nil {
				panic(err)
			}
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

	Convey("Privileged certs - Make a new controller", t, func() {
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort2
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		c := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
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

		Convey("Certs in privileged path", func() {
			configPath := makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s/v2/_catalog","showspinner":false}]}`,
					BaseSecureURL2))
			defer os.Remove(configPath)

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
		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort3
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		c := api.NewController(conf)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)
		c.Config.Storage.RootDirectory = dir
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

		Convey("Test with system certs", func() {
			configPath := makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s/v2/_catalog","showspinner":false}]}`,
					BaseSecureURL3))
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
