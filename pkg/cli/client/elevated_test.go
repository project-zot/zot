//go:build search && needprivileges

package client_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	"zotregistry.dev/zot/v2/pkg/cli/client"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

const (
	privilegedCertsDir = "/etc/containers/certs.d/127.0.0.1:8089"
)

func TestElevatedPrivilegesTLSNewControllerPrivilegedCert(t *testing.T) {
	Convey("Privileged certs - Make a new controller", t, func() {
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

		// Generate client certificate
		clientCertPath := path.Join(tempDir, "client.cert")
		clientKeyPath := path.Join(tempDir, "client.key")
		clientOpts := &tlsutils.CertificateOptions{
			CommonName:         "testclient",
			OrganizationalUnit: "TestClient",
			NotAfter:           time.Now().AddDate(10, 0, 0),
		}
		err = tlsutils.GenerateClientCertToFile(caCertPEM, caKeyPEM, clientCertPath, clientKeyPath, clientOpts)
		So(err, ShouldBeNil)

		//nolint: noctx // old code, no context available
		cmd := exec.Command("mkdir", "-p", privilegedCertsDir+"/") //nolint: gosec

		_, err = cmd.Output()
		if err != nil {
			panic(err)
		}

		//nolint: noctx // old code, no context available
		defer exec.Command("rm", "-rf", privilegedCertsDir+"/")

		// Copy generated certificates to privileged location
		//nolint: noctx // old code, no context available
		cmd = exec.Command("cp", clientCertPath, privilegedCertsDir+"/")
		res, err := cmd.CombinedOutput()
		if err != nil {
			panic(string(res))
		}

		//nolint: noctx // old code, no context available
		cmd = exec.Command("cp", clientKeyPath, privilegedCertsDir+"/")
		res, err = cmd.CombinedOutput()
		if err != nil {
			panic(string(res))
		}

		//nolint: noctx // old code, no context available
		cmd = exec.Command("cp", caCertPath, privilegedCertsDir+"/")
		res, err = cmd.CombinedOutput()
		if err != nil {
			panic(string(res))
		}

		//nolint: noctx // old code, no context available
		cmd = exec.Command("cp", caKeyPath, privilegedCertsDir+"/")
		res, err = cmd.CombinedOutput()
		if err != nil {
			panic(string(res))
		}

		allGlob, _ := filepath.Glob(privilegedCertsDir + "/*.key")

		for _, file := range allGlob {
			//nolint: noctx // old code, no context available
			cmd = exec.Command("chmod", "a=rwx", file)

			res, err = cmd.CombinedOutput()
			if err != nil {
				panic(string(res))
			}
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		resty.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		defer func() { resty.SetTLSClientConfig(nil) }()

		conf := config.New()
		conf.HTTP.Port = SecurePort2
		conf.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)

		defer cm.StopServer()

		Convey("Certs in privileged path", func() {
			_ = makeConfigFile(t,
				fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s%s%s","showspinner":false}]}`,
					BaseSecureURL2, constants.RoutePrefix, constants.ExtCatalogPrefix))

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
