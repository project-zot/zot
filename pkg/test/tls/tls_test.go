package tls_test

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/test/tls"
)

func TestGenerateCACert(t *testing.T) {
	Convey("Generate CA certificate", t, func() {
		certPEM, keyPEM, err := tls.GenerateCACert()
		So(err, ShouldBeNil)

		Convey("Certificate should be valid PEM", func() {
			certBlock, _ := pem.Decode(certPEM)
			So(certBlock, ShouldNotBeNil)
			So(certBlock.Type, ShouldEqual, "CERTIFICATE")

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.IsCA, ShouldBeTrue)
			So(cert.Subject.Organization[0], ShouldEqual, "Test CA")
		})

		Convey("Private key should be valid PEM", func() {
			keyBlock, _ := pem.Decode(keyPEM)
			So(keyBlock, ShouldNotBeNil)
			So(keyBlock.Type, ShouldEqual, "RSA PRIVATE KEY")

			_, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			So(err, ShouldBeNil)
		})
	})
}

func TestGenerateServerCert(t *testing.T) {
	Convey("Generate server certificate", t, func() {
		caCertPEM, caKeyPEM, err := tls.GenerateCACert()
		So(err, ShouldBeNil)

		Convey("With hostname", func() {
			hostname := "localhost"
			opts := &tls.CertificateOptions{
				Hostname: hostname,
			}
			certPEM, keyPEM, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			So(certBlock, ShouldNotBeNil)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.DNSNames, ShouldContain, hostname)
			So(cert.ExtKeyUsage, ShouldContain, x509.ExtKeyUsageServerAuth)

			keyBlock, _ := pem.Decode(keyPEM)
			So(keyBlock, ShouldNotBeNil)
		})

		Convey("With IP address", func() {
			ipaddr := "127.0.0.1"
			opts := &tls.CertificateOptions{
				Hostname: ipaddr,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(len(cert.IPAddresses), ShouldBeGreaterThan, 0)
			So(cert.IPAddresses[0].String(), ShouldEqual, ipaddr)
		})

		Convey("With invalid CA PEM", func() {
			invalidPEM := []byte("invalid pem")
			opts := &tls.CertificateOptions{
				Hostname: "localhost",
			}
			_, _, err := tls.GenerateServerCert(invalidPEM, invalidPEM, opts)
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})
	})
}

func TestGenerateCertWithCN(t *testing.T) {
	Convey("Generate client certificate with CN", t, func() {
		caCertPEM, caKeyPEM, err := tls.GenerateCACert()
		So(err, ShouldBeNil)

		commonName := "test-client"
		opts := &tls.CertificateOptions{
			CommonName: commonName,
		}
		certPEM, keyPEM, err := tls.GenerateClientCert(caCertPEM, caKeyPEM, opts)
		So(err, ShouldBeNil)

		Convey("Certificate should have correct properties", func() {
			certBlock, _ := pem.Decode(certPEM)
			So(certBlock, ShouldNotBeNil)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.Subject.CommonName, ShouldEqual, commonName)
			So(cert.ExtKeyUsage, ShouldContain, x509.ExtKeyUsageClientAuth)
		})

		Convey("Private key should be valid", func() {
			keyBlock, _ := pem.Decode(keyPEM)
			So(keyBlock, ShouldNotBeNil)
		})
	})
}

func TestGenerateSelfSignedCertWithCN(t *testing.T) {
	Convey("Generate self-signed certificate with CN", t, func() {
		commonName := "self-signed-client"
		opts := &tls.CertificateOptions{
			CommonName: commonName,
		}
		certPEM, keyPEM, err := tls.GenerateClientSelfSignedCert(opts)
		So(err, ShouldBeNil)

		Convey("Certificate should be self-signed", func() {
			certBlock, _ := pem.Decode(certPEM)
			So(certBlock, ShouldNotBeNil)

			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.Subject.CommonName, ShouldEqual, commonName)
			So(cert.Subject.String(), ShouldEqual, cert.Issuer.String())
		})

		Convey("Certificate should have correct validity period", func() {
			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.NotAfter.After(time.Now().AddDate(0, 11, 0)), ShouldBeTrue)
		})

		Convey("Private key should be valid", func() {
			keyBlock, _ := pem.Decode(keyPEM)
			So(keyBlock, ShouldNotBeNil)

			_, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			So(err, ShouldBeNil)
		})
	})
}

func TestApplyOptionsCoverage(t *testing.T) {
	Convey("Test applyOptions with various options", t, func() {
		caCertPEM, caKeyPEM, err := tls.GenerateCACert()
		So(err, ShouldBeNil)

		Convey("Test with custom NotBefore and NotAfter", func() {
			customNotBefore := time.Now().Add(-24 * time.Hour)
			customNotAfter := time.Now().Add(2 * 365 * 24 * time.Hour)

			opts := &tls.CertificateOptions{
				Hostname:  "localhost",
				NotBefore: customNotBefore,
				NotAfter:  customNotAfter,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.NotBefore.Unix(), ShouldEqual, customNotBefore.Unix())
			So(cert.NotAfter.Unix(), ShouldEqual, customNotAfter.Unix())
			// Verify Hostname is encoded in DNSNames (since "localhost" is a DNS name)
			So(cert.DNSNames, ShouldContain, "localhost")
		})

		Convey("Test with explicit IPAddresses", func() {
			customIPs := []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")}
			opts := &tls.CertificateOptions{
				Hostname:    "localhost",
				IPAddresses: customIPs,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(len(cert.IPAddresses), ShouldEqual, 2)
			So(cert.IPAddresses[0].String(), ShouldEqual, "192.168.1.1")
			So(cert.IPAddresses[1].String(), ShouldEqual, "10.0.0.1")
			// Verify explicit IPAddresses are used (not the Hostname IP)
			So(cert.IPAddresses, ShouldNotContain, net.ParseIP("127.0.0.1"))
			// Verify Hostname DNS name is still added to DNSNames when no explicit DNSNames provided
			So(cert.DNSNames, ShouldContain, "localhost")
		})

		Convey("Test with explicit DNSNames", func() {
			customDNS := []string{"example.com", "test.example.com"}
			opts := &tls.CertificateOptions{
				Hostname: "localhost",
				DNSNames: customDNS,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(len(cert.DNSNames), ShouldEqual, 2)
			So(cert.DNSNames, ShouldContain, "example.com")
			So(cert.DNSNames, ShouldContain, "test.example.com")
			// Verify explicit DNSNames take precedence - Hostname should NOT be added
			So(cert.DNSNames, ShouldNotContain, "localhost")
		})

		Convey("Test with EmailAddresses", func() {
			customEmails := []string{"user@example.com", "admin@example.com"}
			opts := &tls.CertificateOptions{
				Hostname:       "localhost",
				EmailAddresses: customEmails,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(len(cert.EmailAddresses), ShouldEqual, 2)
			So(cert.EmailAddresses, ShouldContain, "user@example.com")
			So(cert.EmailAddresses, ShouldContain, "admin@example.com")
		})

		Convey("Test with all options combined", func() {
			customNotBefore := time.Now().Add(-12 * time.Hour)
			customNotAfter := time.Now().Add(365 * 24 * time.Hour)
			customIPs := []net.IP{net.ParseIP("192.168.1.100")}
			customDNS := []string{"combined.example.com"}
			customEmails := []string{"combined@example.com"}

			opts := &tls.CertificateOptions{
				Hostname:       "localhost",
				NotBefore:      customNotBefore,
				NotAfter:       customNotAfter,
				IPAddresses:    customIPs,
				DNSNames:       customDNS,
				EmailAddresses: customEmails,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.NotBefore.Unix(), ShouldEqual, customNotBefore.Unix())
			So(cert.NotAfter.Unix(), ShouldEqual, customNotAfter.Unix())
			So(len(cert.IPAddresses), ShouldEqual, 1)
			So(cert.IPAddresses[0].String(), ShouldEqual, "192.168.1.100")
			So(len(cert.DNSNames), ShouldEqual, 1)
			So(cert.DNSNames[0], ShouldEqual, "combined.example.com")
			So(len(cert.EmailAddresses), ShouldEqual, 1)
			So(cert.EmailAddresses[0], ShouldEqual, "combined@example.com")
			// Verify explicit DNSNames take precedence - Hostname should NOT be added
			So(cert.DNSNames, ShouldNotContain, "localhost")
		})

		Convey("Test Hostname as IP address is encoded in IPAddresses", func() {
			ipHostname := "192.168.2.50"
			opts := &tls.CertificateOptions{
				Hostname: ipHostname,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			// Verify Hostname IP is in IPAddresses
			So(len(cert.IPAddresses), ShouldBeGreaterThan, 0)
			So(cert.IPAddresses[0].String(), ShouldEqual, ipHostname)
			// Verify it's NOT in DNSNames
			So(cert.DNSNames, ShouldNotContain, ipHostname)
		})

		Convey("Test Hostname as DNS name is encoded in DNSNames", func() {
			dnsHostname := "example.test"
			opts := &tls.CertificateOptions{
				Hostname: dnsHostname,
			}
			certPEM, _, err := tls.GenerateServerCert(caCertPEM, caKeyPEM, opts)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			// Verify Hostname DNS is in DNSNames
			So(cert.DNSNames, ShouldContain, dnsHostname)
		})

		Convey("Test with nil options (CA certificate)", func() {
			// This tests the nil check in applyOptions
			certPEM, _, err := tls.GenerateCACert()
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(cert.IsCA, ShouldBeTrue)
		})
	})
}

func TestErrorPaths(t *testing.T) {
	Convey("Test error paths", t, func() {
		caCertPEM, caKeyPEM, err := tls.GenerateCACert()
		So(err, ShouldBeNil)

		Convey("Test parseCA with invalid cert PEM", func() {
			invalidCertPEM := []byte("not a valid PEM")
			_, _, err := tls.GenerateServerCert(invalidCertPEM, caKeyPEM, &tls.CertificateOptions{
				Hostname: "localhost",
			})
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})

		Convey("Test parseCA with invalid key PEM", func() {
			invalidKeyPEM := []byte("not a valid PEM")
			_, _, err := tls.GenerateServerCert(caCertPEM, invalidKeyPEM, &tls.CertificateOptions{
				Hostname: "localhost",
			})
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})

		Convey("Test GenerateServerCertToFile with nil opts", func() {
			tempDir := t.TempDir()
			certPath := path.Join(tempDir, "server.crt")
			keyPath := path.Join(tempDir, "server.key")

			err := tls.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, nil)
			So(err, ShouldEqual, tls.ErrHostnameRequired)
		})

		Convey("Test GenerateCACert with nil option", func() {
			// Test when opts[0] == nil - should still work (uses default options)
			certPEM, keyPEM, err := tls.GenerateCACert(nil)
			So(err, ShouldBeNil)
			So(certPEM, ShouldNotBeNil)
			So(keyPEM, ShouldNotBeNil)
		})

		Convey("Test writeCertAndKeyToFile error when cert file write fails", func() {
			tempDir := t.TempDir()
			// Create a directory path instead of a file path to cause write error
			certPath := tempDir // This is a directory, not a file
			keyPath := path.Join(tempDir, "server.key")

			opts := &tls.CertificateOptions{
				Hostname: "localhost",
			}
			err := tls.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, opts)
			So(err, ShouldNotBeNil)
		})

		Convey("Test writeCertAndKeyToFile error when key file write fails", func() {
			tempDir := t.TempDir()
			certPath := path.Join(tempDir, "server.crt")
			// Create a directory path instead of a file path to cause write error
			keyPath := tempDir // This is a directory, not a file

			opts := &tls.CertificateOptions{
				Hostname: "localhost",
			}
			err := tls.GenerateServerCertToFile(caCertPEM, caKeyPEM, certPath, keyPath, opts)
			So(err, ShouldNotBeNil)
		})

		Convey("Test GenerateServerCertToFile error propagation", func() {
			// Test that error from GenerateServerCert is propagated
			tempDir := t.TempDir()
			certPath := path.Join(tempDir, "server.crt")
			keyPath := path.Join(tempDir, "server.key")

			// Use invalid CA to trigger error in GenerateServerCert
			invalidPEM := []byte("invalid")
			err := tls.GenerateServerCertToFile(invalidPEM, invalidPEM, certPath, keyPath, &tls.CertificateOptions{
				Hostname: "localhost",
			})
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})

		Convey("Test GenerateClientCert with invalid PEM", func() {
			// Test that parseCA error is propagated from GenerateClientCert
			invalidCertPEM := []byte("not a valid PEM")
			_, _, err := tls.GenerateClientCert(invalidCertPEM, caKeyPEM, nil)
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})

		Convey("Test GenerateClientCertToFile error propagation", func() {
			// Test that error from GenerateClientCert is propagated
			tempDir := t.TempDir()
			certPath := path.Join(tempDir, "client.crt")
			keyPath := path.Join(tempDir, "client.key")

			// Use invalid CA to trigger error in GenerateClientCert
			invalidPEM := []byte("invalid")
			err := tls.GenerateClientCertToFile(invalidPEM, invalidPEM, certPath, keyPath, nil)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})

		Convey("Test GenerateIntermediateCACert with invalid PEM", func() {
			// Test that parseCA error is propagated from GenerateIntermediateCACert
			invalidCertPEM := []byte("not a valid PEM")
			_, _, err := tls.GenerateIntermediateCACert(invalidCertPEM, caKeyPEM)
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})

		Convey("Test GenerateClientSelfSignedCertToFile error propagation", func() {
			// Test writeCertAndKeyToFile error path
			tempDir := t.TempDir()
			// Create a directory path instead of a file path to cause write error
			certPath := tempDir // This is a directory, not a file
			keyPath := path.Join(tempDir, "client.key")

			err := tls.GenerateClientSelfSignedCertToFile(certPath, keyPath, nil)
			So(err, ShouldNotBeNil)
		})
	})
}
