//go:build search && needprivileges
// +build search,needprivileges

package cli //nolint:testpackage

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
)

func TestElevatedPrivilegesTLSNewControllerPrivilegedCert(t *testing.T) {
	Convey("Privileged certs - Make a new controller", t, func() {
		cmd := exec.Command("mkdir", "-p", "/etc/containers/certs.d/127.0.0.1:8089/") //nolint: gosec
		_, err := cmd.Output()
		if err != nil {
			panic(err)
		}

		defer exec.Command("rm", "-rf", "/etc/containers/certs.d/127.0.0.1:8089/")

		workDir, _ := os.Getwd()
		_ = os.Chdir("../../test/data")

		clientGlob, _ := filepath.Glob("client.*")
		caGlob, _ := filepath.Glob("ca.*")

		for _, file := range clientGlob {
			cmd = exec.Command("cp", file, "/etc/containers/certs.d/127.0.0.1:8089/")
			res, err := cmd.CombinedOutput()
			if err != nil {
				panic(string(res))
			}
		}

		for _, file := range caGlob {
			cmd = exec.Command("cp", file, "/etc/containers/certs.d/127.0.0.1:8089/")
			res, err := cmd.CombinedOutput()
			if err != nil {
				panic(string(res))
			}
		}

		allGlob, _ := filepath.Glob("/etc/containers/certs.d/127.0.0.1:8089/*.key")

		for _, file := range allGlob {
			cmd = exec.Command("chmod", "a=rwx", file)
			res, err := cmd.CombinedOutput()
			if err != nil {
				panic(string(res))
			}
		}

		_ = os.Chdir(workDir)

		caCert, err := os.ReadFile(CACert)
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
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					BaseSecureURL2, constants.RoutePrefix, constants.ExtCatalogPrefix))
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
