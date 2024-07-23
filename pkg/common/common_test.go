package common_test

import (
	"os"
	"path"
	"strings"
	"testing"

	notreg "github.com/notaryproject/notation-go/registry"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/common"
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

	Convey("test dirExists()", t, func() {
		exists := common.DirExists("testdir")
		So(exists, ShouldBeFalse)

		tempDir := t.TempDir()

		file, err := os.Create(path.Join(tempDir, "file.txt"))
		So(err, ShouldBeNil)

		isDir := common.DirExists(file.Name())
		So(isDir, ShouldBeFalse)
	})

	Convey("Index func", t, func() {
		So(common.Index([]string{"a", "b"}, "b"), ShouldEqual, 1)
		So(common.Index([]string{"a", "b"}, "c"), ShouldEqual, -1)
	})

	Convey("Test ArtifactTypeNotation const has same value as in notaryproject", t, func() {
		So(common.ArtifactTypeNotation, ShouldEqual, notreg.ArtifactTypeNotation)
	})

	Convey("Test GetLocalIPs", t, func() {
		localIPs, err := common.GetLocalIPs()
		So(err, ShouldBeNil)
		So(localIPs, ShouldNotBeEmpty)
		So(localIPs, ShouldContain, "127.0.0.1")
	})

	Convey("Test GetLocalSockets IPv4", t, func() {
		localSockets, err := common.GetLocalSockets("8765")
		So(err, ShouldBeNil)
		So(localSockets, ShouldNotBeEmpty)
		So(localSockets, ShouldContain, "127.0.0.1:8765")

		for _, socket := range localSockets {
			lastColonIndex := strings.LastIndex(socket, ":")
			So(socket[lastColonIndex+1:], ShouldEqual, "8765")
		}
	})

	Convey("Test GetLocalSockets IPv6", t, func() {
		localSockets, err := common.GetLocalSockets("8766")
		So(err, ShouldBeNil)
		So(localSockets, ShouldNotBeEmpty)
		So(localSockets, ShouldContain, "[::1]:8766")

		for _, socket := range localSockets {
			lastColonIndex := strings.LastIndex(socket, ":")
			So(socket[lastColonIndex+1:], ShouldEqual, "8766")
		}
	})

	Convey("Test GetIPFromHostName with valid hostname", t, func() {
		addrs, err := common.GetIPFromHostName("github.com")
		So(err, ShouldBeNil)
		So(addrs, ShouldNotBeEmpty)
		// we can't check the actual addresses here as they can change
	})

	Convey("Test GetIPFromHostName with non-existent hostname", t, func() {
		addrs, err := common.GetIPFromHostName("thisdoesnotexist")
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "lookup thisdoesnotexist")
		So(addrs, ShouldBeEmpty)
	})

	Convey("Test AreSocketsEqual with equal IPv4 sockets", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.1:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with equal IPv6 sockets", t, func() {
		result, err := common.AreSocketsEqual("[::1]:9000", "[0000:0000:0000:0000:0000:0000:0000:00001]:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with different IPv4 socket ports", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.1:9001")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with different IPv4 socket hosts", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "127.0.0.2:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with 2 equal host names", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "localhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeTrue)
	})

	Convey("Test AreSocketsEqual with 2 different host names", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "notlocalhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with hostname and IP address", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "127.0.0.1:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with IP address and hostname", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1:9000", "localhost:9000")
		So(err, ShouldBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with invalid first socket", t, func() {
		result, err := common.AreSocketsEqual("127.0.0.1", "localhost:9000")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})

	Convey("Test AreSocketsEqual with invalid second socket", t, func() {
		result, err := common.AreSocketsEqual("localhost:9000", "127.0.0.1")
		So(err, ShouldNotBeNil)
		So(result, ShouldBeFalse)
	})
}
