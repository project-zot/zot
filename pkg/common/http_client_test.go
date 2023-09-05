package common_test

import (
	"context"
	"crypto/x509"
	"os"
	"path"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/test"
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

	Convey("test MakeHTTPGetRequest() no permissions on key", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		tempDir := t.TempDir()
		err := test.CopyTestKeysAndCerts(tempDir)
		So(err, ShouldBeNil)
		ctlr.Config.Storage.RootDirectory = tempDir

		cm := test.NewControllerManager(ctlr)
		cm.StartServer()
		defer cm.StopServer()
		test.WaitTillServerReady(baseURL)

		var resultPtr interface{}
		httpClient, err := common.CreateHTTPClient(true, "localhost", tempDir)
		So(err, ShouldBeNil)
		_, _, _, err = common.MakeHTTPGetRequest(context.Background(), httpClient, "", "",
			resultPtr, baseURL+"/v2/", ispec.MediaTypeImageManifest, log.NewLogger("", ""))
		So(err, ShouldBeNil)
	})
}
