//go:build sync

package sync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetCertificatesKeepsEveryCA(t *testing.T) {
	Convey("a renewed server cert from the same CA verifies against certDir", t, func() {
		newKey := func() *ecdsa.PrivateKey {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			So(err, ShouldBeNil)

			return key
		}

		caKey := newKey()
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "test-ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		So(err, ShouldBeNil)
		caCert, err := x509.ParseCertificate(caDER)
		So(err, ShouldBeNil)

		leaf := func(serial int64) []byte {
			key := newKey()
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(serial),
				Subject:      pkix.Name{CommonName: "peer"},
				DNSNames:     []string{"peer"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
			So(err, ShouldBeNil)

			return der
		}

		toPEM := func(der []byte) []byte {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		}

		certDir := t.TempDir()
		So(os.WriteFile(path.Join(certDir, "ca.crt"), toPEM(caDER), 0o600), ShouldBeNil)
		So(os.WriteFile(path.Join(certDir, "tls.crt"), toPEM(leaf(2)), 0o600), ShouldBeNil)

		_, _, regCert, err := getCertificates(certDir)
		So(err, ShouldBeNil)

		pool := x509.NewCertPool()
		So(pool.AppendCertsFromPEM([]byte(regCert)), ShouldBeTrue)

		renewed, err := x509.ParseCertificate(leaf(3))
		So(err, ShouldBeNil)

		_, err = renewed.Verify(x509.VerifyOptions{DNSName: "peer", Roots: pool})
		So(err, ShouldBeNil)
	})
}
