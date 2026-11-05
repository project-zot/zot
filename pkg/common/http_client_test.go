package common_test

import (
	"crypto/x509"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

// setupTestCerts generates CA and client certificates for testing.
func setupTestCerts(t *testing.T, tempDir string) {
	t.Helper()

	// Generate CA certificate
	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
		NotAfter:   time.Now().AddDate(10, 0, 0),
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	caCertPath := path.Join(tempDir, "ca.crt")
	err = os.WriteFile(caCertPath, caCertPEM, 0o600)
	if err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}

	// Generate client certificate
	clientCertPath := path.Join(tempDir, "client.cert")
	clientKeyPath := path.Join(tempDir, "client.key")
	clientOpts := &tlsutils.CertificateOptions{
		CommonName:         "testclient",
		OrganizationalUnit: "TestClient",
		NotAfter:           time.Now().AddDate(10, 0, 0),
	}
	err = tlsutils.GenerateClientCertToFile(caCertPEM, caKeyPEM, clientCertPath, clientKeyPath, clientOpts)
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}
}

func TestHTTPClient(t *testing.T) {
	Convey("test getTLSConfig()", t, func() {
		caCertPool, _ := x509.SystemCertPool()
		tlsConfig, err := common.GetTLSConfig("wrongPath", caCertPool)
		So(tlsConfig, ShouldBeNil)
		So(err, ShouldNotBeNil)

		tempDir := t.TempDir()
		setupTestCerts(t, tempDir)
		err = os.Chmod(path.Join(tempDir, "ca.crt"), 0o000)
		So(err, ShouldBeNil)
		_, err = common.GetTLSConfig(tempDir, caCertPool)
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() no permissions on certificate", t, func() {
		tempDir := t.TempDir()
		setupTestCerts(t, tempDir)
		err := os.Chmod(path.Join(tempDir, "ca.crt"), 0o000)
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
		setupTestCerts(t, tempDir)
		err := os.Chmod(path.Join(tempDir, "client.key"), 0o000)
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

	Convey("test CreateHTTPClient() with a root CA file that has no PEM certificate", t, func() {
		tempDir := t.TempDir()
		setupTestCerts(t, tempDir)

		for _, content := range []string{"", "not a certificate\n"} {
			err := os.WriteFile(path.Join(tempDir, common.CaCertFilename), []byte(content), 0o600)
			So(err, ShouldBeNil)

			_, err = common.CreateHTTPClient(&common.HTTPClientOptions{
				TLSEnabled: true,
				VerifyTLS:  true,
				Host:       "localhost",
				CertOptions: common.HTTPClientCertOptions{
					RootCaCertFile: path.Join(tempDir, common.CaCertFilename),
				},
			})
			So(err, ShouldWrap, zerr.ErrBadCACert)
		}
	})

	Convey("test CreateHTTPClient() no TLS", t, func() {
		_, err := common.CreateHTTPClient(&common.HTTPClientOptions{})
		So(err, ShouldBeNil)
	})

	Convey("test CreateHTTPClient() with only client cert configured", t, func() {
		tempDir := t.TempDir()
		setupTestCerts(t, tempDir)

		_, err := common.CreateHTTPClient(&common.HTTPClientOptions{
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
		setupTestCerts(t, tempDir)

		_, err := common.CreateHTTPClient(&common.HTTPClientOptions{
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
		setupTestCerts(t, tempDir)

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
		setupTestCerts(t, tempDir)

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
		setupTestCerts(t, tempDir)

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

func TestCreateHTTPClientExplicitPairTakesPrecedence(t *testing.T) {
	Convey("an explicit client pair wins over one discovered in certs.d", t, func() {
		caOpts := &tlsutils.CertificateOptions{CommonName: "*", NotAfter: time.Now().AddDate(10, 0, 0)}
		caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
		So(err, ShouldBeNil)

		writePair := func(dir, commonName string) {
			So(os.MkdirAll(dir, 0o700), ShouldBeNil)
			So(os.WriteFile(path.Join(dir, common.CaCertFilename), caCertPEM, 0o600), ShouldBeNil)
			So(tlsutils.GenerateClientCertToFile(caCertPEM, caKeyPEM,
				path.Join(dir, common.ClientCertFilename), path.Join(dir, common.ClientKeyFilename),
				&tlsutils.CertificateOptions{CommonName: commonName, NotAfter: time.Now().AddDate(10, 0, 0)}), ShouldBeNil)
		}

		home := t.TempDir()
		t.Setenv("HOME", home)
		writePair(path.Join(home, ".config", "containers", "certs.d", "localhost"), "legacy")

		explicitDir := t.TempDir()
		writePair(explicitDir, "bob")

		client, err := common.CreateHTTPClient(&common.HTTPClientOptions{
			TLSEnabled: true,
			VerifyTLS:  true,
			Host:       "localhost",
			CertOptions: common.HTTPClientCertOptions{
				ClientCertFile: path.Join(explicitDir, common.ClientCertFilename),
				ClientKeyFile:  path.Join(explicitDir, common.ClientKeyFilename),
			},
		})
		So(err, ShouldBeNil)

		htr, ok := client.Transport.(*http.Transport)
		So(ok, ShouldBeTrue)
		So(htr.TLSClientConfig.Certificates, ShouldHaveLength, 2)

		first, err := x509.ParseCertificate(htr.TLSClientConfig.Certificates[0].Certificate[0])
		So(err, ShouldBeNil)
		So(first.Subject.CommonName, ShouldEqual, "bob")
	})
}
