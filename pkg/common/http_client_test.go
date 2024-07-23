package common_test

import (
	"crypto/x509"
	"net/http"
	"os"
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.dev/zot/pkg/common"
	test "zotregistry.dev/zot/pkg/test/common"
)

func TestHTTPClient(t *testing.T) {
	Convey("test getTLSConfig()", t, func() {
		caCertPool, _ := x509.SystemCertPool()
		tlsConfig, err := common.GetTLSConfig("wrongPath", caCertPool)
		So(tlsConfig, ShouldBeNil)
		So(err, ShouldNotBeNil)

		tempDir := t.TempDir()
		err = test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(tempDir, "ca.crt"), 0o000)
		So(err, ShouldBeNil)
		_, err = common.GetTLSConfig(tempDir, caCertPool)
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() no permissions on certificate", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(tempDir, "ca.crt"), 0o000)
		So(err, ShouldBeNil)

		_, err = common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: true,
			VerifyTLS:  true,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientCertFile: path.Join(tempDir, common.ClientCertFilename),
				ClientKeyFile:  path.Join(tempDir, common.ClientKeyFilename),
				RootCaCertFile: path.Join(tempDir, common.CaCertFilename),
			},
		})
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() no permissions on key", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(tempDir, "client.key"), 0o000)
		So(err, ShouldBeNil)

		_, err = common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: true,
			VerifyTLS:  true,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientCertFile: path.Join(tempDir, common.ClientCertFilename),
				ClientKeyFile:  path.Join(tempDir, common.ClientKeyFilename),
				RootCaCertFile: path.Join(tempDir, common.CaCertFilename),
			},
		})
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() no TLS", t, func() {
		_, err := common.CreateHTTPClient(&common.HTTPClientOptions{})
		So(err, ShouldBeNil)
	})

	Convey("test CreateHTTPClient() with only client cert configured", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)

		_, err = common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: true,
			VerifyTLS:  true,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientCertFile: path.Join(tempDir, common.ClientCertFilename),
			},
		})
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() with only client key configured", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)

		_, err = common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: true,
			VerifyTLS:  true,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientKeyFile: path.Join(tempDir, common.ClientKeyFilename),
			},
		})
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() with full certificate config", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)

		client, err := common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: true,
			VerifyTLS:  true,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientCertFile: path.Join(tempDir, common.ClientCertFilename),
				ClientKeyFile:  path.Join(tempDir, common.ClientKeyFilename),
				RootCaCertFile: path.Join(tempDir, common.CaCertFilename),
			},
		})
		So(err, ShouldBeNil)

		htr, ok := client.Transport.(*http.Transport)
		So(ok, ShouldBeTrue)
		So(htr.TLSClientConfig.RootCAs, ShouldNotBeNil)
		So(htr.TLSClientConfig.Certificates, ShouldNotBeEmpty)
	})

	Convey("test CreateHTTPClient() with no TLS verify", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)

		client, err := common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: true,
			VerifyTLS:  false,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientCertFile: path.Join(tempDir, common.ClientCertFilename),
				ClientKeyFile:  path.Join(tempDir, common.ClientKeyFilename),
				RootCaCertFile: path.Join(tempDir, common.CaCertFilename),
			},
		})
		So(err, ShouldBeNil)

		htr, ok := client.Transport.(*http.Transport)
		So(ok, ShouldBeTrue)
		So(htr.TLSClientConfig.Certificates, ShouldBeEmpty)
		So(htr.TLSClientConfig.RootCAs, ShouldBeNil)
		So(htr.TLSClientConfig.InsecureSkipVerify, ShouldBeTrue)
	})

	Convey("test CreateHTTPClient() with no TLS, but TLS verify enabled", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)

		client, err := common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: false,
			VerifyTLS:  true,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientCertFile: path.Join(tempDir, common.ClientCertFilename),
				ClientKeyFile:  path.Join(tempDir, common.ClientKeyFilename),
				RootCaCertFile: path.Join(tempDir, common.CaCertFilename),
			},
		})
		So(err, ShouldBeNil)

		htr, ok := client.Transport.(*http.Transport)
		So(ok, ShouldBeTrue)
		So(htr.TLSClientConfig.Certificates, ShouldBeEmpty)
		So(htr.TLSClientConfig.RootCAs, ShouldBeNil)
		So(htr.TLSClientConfig.InsecureSkipVerify, ShouldBeFalse)
	})
}
