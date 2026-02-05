package api_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

func TestTLSCertReload(t *testing.T) {
	Convey("Test automatic TLS certificate reload", t, func() {
		// Create temporary directory for certificates
		tempDir := t.TempDir()

		// Generate initial CA certificate
		caOpts := &tlsutils.CertificateOptions{
			CommonName: "Test CA",
			NotAfter:   time.Now().AddDate(1, 0, 0),
		}
		caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
		So(err, ShouldBeNil)

		// Generate initial server certificate
		serverCertPath := filepath.Join(tempDir, "server.cert")
		serverKeyPath := filepath.Join(tempDir, "server.key")
		serverOpts := &tlsutils.CertificateOptions{
			Hostname:   "127.0.0.1",
			CommonName: "Server v1",
			NotAfter:   time.Now().AddDate(1, 0, 0),
		}
		err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts)
		So(err, ShouldBeNil)

		// Create config with TLS
		port := test.GetFreePort()
		httpsURL := test.GetSecureBaseURL(port)

		conf := config.New()
		conf.HTTP.Address = "127.0.0.1"
		conf.HTTP.Port = port
		conf.HTTP.TLS = &config.TLSConfig{
			Cert: serverCertPath,
			Key:  serverKeyPath,
		}
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(port)
		defer cm.StopServer()

		// Create client with CA certificate
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		httpClient := resty.New().
			SetTLSClientConfig(&tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			}).
			SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))

		// Verify initial connection works with HTTPS
		resp, err := httpClient.R().Get(httpsURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// Wait a moment to ensure file modification time will be different
		time.Sleep(2 * time.Second)

		// Generate new server certificate with different CommonName
		serverOpts2 := &tlsutils.CertificateOptions{
			Hostname:   "127.0.0.1",
			CommonName: "Server v2",
			NotAfter:   time.Now().AddDate(1, 0, 0),
		}
		err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts2)
		So(err, ShouldBeNil)

		// Wait for certificate to be detected and reloaded
		time.Sleep(1 * time.Second)

		// Verify connection still works with new certificate
		resp2, err := httpClient.R().Get(httpsURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp2.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestCertReloaderDirectly(t *testing.T) {
	Convey("Test CertReloader functionality", t, func() {
		tempDir := t.TempDir()

		// Generate CA certificate
		caOpts := &tlsutils.CertificateOptions{
			CommonName: "Test CA",
			NotAfter:   time.Now().AddDate(1, 0, 0),
		}
		caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
		So(err, ShouldBeNil)

		// Generate initial server certificate
		certPath := filepath.Join(tempDir, "server.cert")
		keyPath := filepath.Join(tempDir, "server.key")
		serverOpts := &tlsutils.CertificateOptions{
			Hostname:   "127.0.0.1",
			CommonName: "Initial Cert",
			NotAfter:   time.Now().AddDate(1, 0, 0),
		}
		err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, serverOpts)
		So(err, ShouldBeNil)

		Convey("NewCertReloader should load initial certificate", func() {
			reloader, err := api.NewCertReloader(certPath, keyPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			So(reloader, ShouldNotBeNil)
			defer reloader.Close()

			// Get certificate via callback
			getCert := reloader.GetCertificateFunc()
			cert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(cert, ShouldNotBeNil)
		})

		Convey("GetCertificateFunc should reload when certificate changes", func() {
			reloader, err := api.NewCertReloader(certPath, keyPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			defer reloader.Close()

			getCert := reloader.GetCertificateFunc()
			initialCert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(initialCert, ShouldNotBeNil)

			// Wait to ensure modification time will be different
			time.Sleep(2 * time.Second)

			// Generate new certificate
			newServerOpts := &tlsutils.CertificateOptions{
				Hostname:   "127.0.0.1",
				CommonName: "Updated Cert",
				NotAfter:   time.Now().AddDate(1, 0, 0),
			}
			err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, newServerOpts)
			So(err, ShouldBeNil)

			// Get certificate again - should reload automatically
			updatedCert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(updatedCert, ShouldNotBeNil)

			// Certificates should be different (different leaf certificates)
			initialLeaf, err := x509.ParseCertificate(initialCert.Certificate[0])
			So(err, ShouldBeNil)
			updatedLeaf, err := x509.ParseCertificate(updatedCert.Certificate[0])
			So(err, ShouldBeNil)

			// Common names should be different
			So(initialLeaf.Subject.CommonName, ShouldEqual, "Initial Cert")
			So(updatedLeaf.Subject.CommonName, ShouldEqual, "Updated Cert")
		})

		Convey("NewCertReloader should fail with invalid paths", func() {
			_, err := api.NewCertReloader("/nonexistent/cert.pem", "/nonexistent/key.pem", log.NewTestLogger())
			So(err, ShouldNotBeNil)
		})

		Convey("GetCertificateFunc should handle missing files gracefully", func() {
			reloader, err := api.NewCertReloader(certPath, keyPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			defer reloader.Close()

			getCert := reloader.GetCertificateFunc()

			// Delete the certificate file
			err = os.Remove(certPath)
			So(err, ShouldBeNil)

			// Should still return the old certificate (not fail)
			cert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(cert, ShouldNotBeNil)
		})

		Convey("GetCertificateFunc should handle certificate and key file modification", func() {
			reloader, err := api.NewCertReloader(certPath, keyPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			defer reloader.Close()

			getCert := reloader.GetCertificateFunc()
			initialCert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(initialCert, ShouldNotBeNil)

			// Wait to ensure modification time will be different
			time.Sleep(2 * time.Second)

			// Generate new certificate (both cert and key files will be modified)
			newServerOpts := &tlsutils.CertificateOptions{
				Hostname:   "127.0.0.1",
				CommonName: "Updated Cert",
				NotAfter:   time.Now().AddDate(1, 0, 0),
			}
			err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, newServerOpts)
			So(err, ShouldBeNil)

			// Get certificate again - should reload
			updatedCert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(updatedCert, ShouldNotBeNil)

			// Verify certificates are different
			initialLeaf, err := x509.ParseCertificate(initialCert.Certificate[0])
			So(err, ShouldBeNil)
			updatedLeaf, err := x509.ParseCertificate(updatedCert.Certificate[0])
			So(err, ShouldBeNil)

			So(initialLeaf.Subject.CommonName, ShouldEqual, "Initial Cert")
			So(updatedLeaf.Subject.CommonName, ShouldEqual, "Updated Cert")
		})

		Convey("GetCertificateFunc should handle concurrent access", func() {
			reloader, err := api.NewCertReloader(certPath, keyPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			defer reloader.Close()

			getCert := reloader.GetCertificateFunc()

			// Launch multiple goroutines to access certificate concurrently
			done := make(chan error, 10)

			for range 10 {
				go func() {
					var lastErr error

					for range 100 {
						cert, err := getCert(nil)
						if err != nil || cert == nil {
							lastErr = err

							break
						}
					}
					done <- lastErr
				}()
			}

			// Wait for all goroutines to complete and check for errors
			for range 10 {
				err := <-done
				So(err, ShouldBeNil)
			}
		})

		Convey("GetCertificateFunc should not reload if files haven't changed", func() {
			reloader, err := api.NewCertReloader(certPath, keyPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			defer reloader.Close()

			getCert := reloader.GetCertificateFunc()

			// Get certificate multiple times
			cert1, err := getCert(nil)
			So(err, ShouldBeNil)
			So(cert1, ShouldNotBeNil)

			cert2, err := getCert(nil)
			So(err, ShouldBeNil)
			So(cert2, ShouldNotBeNil)

			cert3, err := getCert(nil)
			So(err, ShouldBeNil)
			So(cert3, ShouldNotBeNil)

			// All should return the same certificate instance (pointer equality)
			So(cert1, ShouldEqual, cert2)
			So(cert2, ShouldEqual, cert3)
		})

		Convey("GetCertificateFunc should reload when key file changes", func() {
			reloader, err := api.NewCertReloader(certPath, keyPath, log.NewTestLogger())
			So(err, ShouldBeNil)
			defer reloader.Close()

			getCert := reloader.GetCertificateFunc()
			initialCert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(initialCert, ShouldNotBeNil)

			// Wait to ensure modification time will be different
			time.Sleep(2 * time.Second)

			// Generate completely new cert and key
			newServerOpts := &tlsutils.CertificateOptions{
				Hostname:   "127.0.0.1",
				CommonName: "New Key Cert",
				NotAfter:   time.Now().AddDate(1, 0, 0),
			}
			err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, newServerOpts)
			So(err, ShouldBeNil)

			// Get certificate again - should reload due to key change
			updatedCert, err := getCert(nil)
			So(err, ShouldBeNil)
			So(updatedCert, ShouldNotBeNil)

			// Verify certificates are different
			initialLeaf, err := x509.ParseCertificate(initialCert.Certificate[0])
			So(err, ShouldBeNil)
			updatedLeaf, err := x509.ParseCertificate(updatedCert.Certificate[0])
			So(err, ShouldBeNil)

			So(initialLeaf.Subject.CommonName, ShouldEqual, "Initial Cert")
			So(updatedLeaf.Subject.CommonName, ShouldEqual, "New Key Cert")
		})
	})
}
