package tls_test

import (
	"crypto/x509"
	"encoding/pem"
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
			certPEM, keyPEM, err := tls.GenerateServerCert(hostname, caCertPEM, caKeyPEM)
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
			certPEM, _, err := tls.GenerateServerCert(ipaddr, caCertPEM, caKeyPEM)
			So(err, ShouldBeNil)

			certBlock, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(certBlock.Bytes)
			So(err, ShouldBeNil)
			So(len(cert.IPAddresses), ShouldBeGreaterThan, 0)
			So(cert.IPAddresses[0].String(), ShouldEqual, ipaddr)
		})

		Convey("With invalid CA PEM", func() {
			invalidPEM := []byte("invalid pem")
			_, _, err := tls.GenerateServerCert("localhost", invalidPEM, invalidPEM)
			So(err, ShouldEqual, tls.ErrDecodeCAPEM)
		})
	})
}

func TestGenerateCertWithCN(t *testing.T) {
	Convey("Generate client certificate with CN", t, func() {
		caCertPEM, caKeyPEM, err := tls.GenerateCACert()
		So(err, ShouldBeNil)

		commonName := "test-client"
		certPEM, keyPEM, err := tls.GenerateCertWithCN(commonName, caCertPEM, caKeyPEM)
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
		certPEM, keyPEM, err := tls.GenerateSelfSignedCertWithCN(commonName)
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
