//go:build search && needprivileges
// +build search,needprivileges

package client_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/cli/client"
	test "zotregistry.dev/zot/pkg/test/common"
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
		_ = os.Chdir("../../../test/data")

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
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		Convey("Certs in privileged path", func() {
			configPath := makeConfigFile(
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					BaseSecureURL2, constants.RoutePrefix, constants.ExtCatalogPrefix))
			defer os.Remove(configPath)

			args := []string{"list", "--config", "imagetest"}
			imageCmd := client.NewImageCommand(client.NewSearchService())
			imageBuff := bytes.NewBufferString("")
			imageCmd.SetOut(imageBuff)
			imageCmd.SetErr(imageBuff)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()
			So(err, ShouldBeNil)
		})
	})
}
