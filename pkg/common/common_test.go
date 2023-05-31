package common_test

import (
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

func TestCommon(t *testing.T) {
	Convey("test Contains()", t, func() {
		first := []string{"apple", "biscuit"}
		So(common.Contains(first, "apple"), ShouldBeTrue)
		So(common.Contains(first, "peach"), ShouldBeFalse)
		So(common.Contains([]string{}, "apple"), ShouldBeFalse)
	})

	Convey("test MarshalThroughStruct()", t, func() {
		cfg := config.New()

		newCfg := struct {
			DistSpecVersion string
		}{}

		_, err := common.MarshalThroughStruct(cfg, &newCfg)
		So(err, ShouldBeNil)
		So(newCfg.DistSpecVersion, ShouldEqual, cfg.DistSpecVersion)

		// negative
		obj := make(chan int)
		toObj := config.New()

		_, err = common.MarshalThroughStruct(obj, &toObj)
		So(err, ShouldNotBeNil)

		_, err = common.MarshalThroughStruct(toObj, &obj)
		So(err, ShouldNotBeNil)
	})

	Convey("test getTLSConfig()", t, func() {
		caCertPool, _ := x509.SystemCertPool()
		tlsConfig, err := common.GetTLSConfig("wrongPath", caCertPool)
		So(tlsConfig, ShouldBeNil)
		So(err, ShouldNotBeNil)

		tempDir := t.TempDir()
		err = test.CopyFiles("../../test/data", tempDir)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(tempDir, "ca.crt"), 0o000)
		So(err, ShouldBeNil)
		_, err = common.GetTLSConfig(tempDir, caCertPool)
		So(err, ShouldNotBeNil)
	})

	Convey("test dirExists()", t, func() {
		exists := common.DirExists("testdir")
		So(exists, ShouldBeFalse)
		tempDir := t.TempDir()

		file, err := os.Create(path.Join(tempDir, "file.txt"))
		So(err, ShouldBeNil)
		isDir := common.DirExists(file.Name())
		So(isDir, ShouldBeFalse)
	})

	Convey("test CreateHTTPClient() no permissions on certificate", t, func() {
		tempDir := t.TempDir()
		err := test.CopyFiles("../../test/data", tempDir)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(tempDir, "ca.crt"), 0o000)
		So(err, ShouldBeNil)

		_, err = common.CreateHTTPClient(true, "localhost", tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("test CreateHTTPClient() no permissions on key", t, func() {
		tempDir := t.TempDir()
		err := test.CopyFiles("../../test/data", tempDir)
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
		err := test.CopyFiles("../../test/data", tempDir)
		So(err, ShouldBeNil)
		ctlr.Config.Storage.RootDirectory = tempDir

		cm := test.NewControllerManager(ctlr)
		cm.StartServer()
		defer cm.StopServer()
		test.WaitTillServerReady(baseURL)

		var resultPtr interface{}
		httpClient, err := common.CreateHTTPClient(true, "localhost", tempDir)
		So(err, ShouldBeNil)
		_, _, _, err = common.MakeHTTPGetRequest(httpClient, "", "",
			resultPtr, baseURL+"/v2/", ispec.MediaTypeImageManifest, log.NewLogger("", ""))
		So(err, ShouldBeNil)
	})

	Convey("Index func", t, func() {
		So(common.Index([]string{"a", "b"}, "b"), ShouldEqual, 1)
		So(common.Index([]string{"a", "b"}, "c"), ShouldEqual, -1)
	})
	Convey("Test image dir and digest", t, func() {
		repo, digest := common.GetImageDirAndDigest("image")
		So(repo, ShouldResemble, "image")
		So(digest, ShouldResemble, "")
	})
}
