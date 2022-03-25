//go:build extended && needprivileges
// +build extended,needprivileges

package cli //nolint:testpackage

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
)

func TestElevatedPrivilegesTLSNewControllerPrivilegedCert(t *testing.T) {
	Convey("Privileged certs - Make a new controller", t, func() {
		cmd := exec.Command("mkdir", "-p", "/etc/containers/certs.d/127.0.0.1:8089/") // nolint: gosec
		_, err := cmd.Output()
		if err != nil {
			panic(err)
		}

		cmd = exec.Command("cp", "../../test/data/client.*", "../../test/data/ca.*", "/etc/containers/certs.d/127.0.0.1:8089/")
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		cmd = exec.Command("chmod", "a=rwx", "/etc/containers/certs.d/127.0.0.1:8089/*.key")
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		caCert, err := ioutil.ReadFile(CACert)
		So(err, ShouldBeNil)
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})
		defer func() { resty.SetTLSClientConfig(nil) }()
		conf := config.New()
		conf.HTTP.Port = SecurePort2
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		go func() {
			// this blocks
			if err := ctlr.Run(context.Background()); err != nil {
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
			_ = ctlr.Server.Shutdown(ctx)
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

		cmd = exec.Command("rm", "-rf", "/etc/containers/certs.d/127.0.0.1:8089/")
		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}
	})
}
