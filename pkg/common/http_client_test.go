package common_test

import (
	"crypto/x509"
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

		_, err = common.CreateHTTPClient(true, "localhost", tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() no permissions on key", t, func() {
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(tempDir, "client.key"), 0o000)
		So(err, ShouldBeNil)

		_, err = common.CreateHTTPClient(true, "localhost", tempDir)
		So(err, ShouldNotBeNil)
	})
}
