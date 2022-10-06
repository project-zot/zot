//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package test_test

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/test"
)

func TestCopyFiles(t *testing.T) {
	Convey("sourceDir does not exist", t, func() {
		err := test.CopyFiles("/path/to/some/unexisting/directory", os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("destDir is a file", t, func() {
		dir := t.TempDir()

		err := test.CopyFiles("../../test/data", dir)
		if err != nil {
			panic(err)
		}

		err = test.CopyFiles(dir, "/etc/passwd")
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir does not have read permissions", t, func() {
		dir := t.TempDir()

		err := os.Chmod(dir, 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a subfolder that does not have read permissions", t, func() {
		dir := t.TempDir()

		sdir := "subdir"
		err := os.Mkdir(path.Join(dir, sdir), 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("sourceDir has a file that does not have read permissions", t, func() {
		dir := t.TempDir()

		filePath := path.Join(dir, "file.txt")
		err := os.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(filePath, 0o300)
		So(err, ShouldBeNil)

		err = test.CopyFiles(dir, os.TempDir())
		So(err, ShouldNotBeNil)
	})
}

func TestGetOciLayoutDigests(t *testing.T) {
	dir := t.TempDir()

	Convey("image path is wrong", t, func() {
		So(func() { _, _, _ = test.GetOciLayoutDigests("inexistent-image") }, ShouldPanic)
	})

	Convey("no permissions when getting index", t, func() {
		err := test.CopyFiles("../../test/data/zot-test", path.Join(dir, "test-index"))
		if err != nil {
			panic(err)
		}

		err = os.Chmod(path.Join(dir, "test-index", "index.json"), 0o000)
		if err != nil {
			panic(err)
		}

		So(func() { _, _, _ = test.GetOciLayoutDigests(path.Join(dir, "test-index")) }, ShouldPanic)

		err = os.Chmod(path.Join(dir, "test-index", "index.json"), 0o755)
		if err != nil {
			panic(err)
		}
	})

	Convey("can't access manifest digest", t, func() {
		err := test.CopyFiles("../../test/data/zot-test", path.Join(dir, "test-manifest"))
		if err != nil {
			panic(err)
		}

		buf, err := os.ReadFile(path.Join(dir, "test-manifest", "index.json"))
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		if err := json.Unmarshal(buf, &index); err != nil {
			panic(err)
		}

		err = os.Chmod(path.Join(dir, "test-manifest", "blobs/sha256", index.Manifests[0].Digest.Encoded()), 0o000)
		if err != nil {
			panic(err)
		}

		So(func() { _, _, _ = test.GetOciLayoutDigests(path.Join(dir, "test-manifest")) }, ShouldPanic)

		err = os.Chmod(path.Join(dir, "test-manifest", "blobs/sha256", index.Manifests[0].Digest.Encoded()), 0o755)
		if err != nil {
			panic(err)
		}
	})
}

func TestGetImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := test.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
	Convey("finishes successfully", t, func() {
		_, _, _, err := test.GetImageComponents(100)
		So(err, ShouldBeNil)
	})
}

func TestUploadImage(t *testing.T) {
	Convey("Post request results in an error", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		img := test.Image{
			Layers: make([][]byte, 10),
		}

		err := test.UploadImage(img, baseURL, "test")
		So(err, ShouldNotBeNil)
	})

	Convey("Post request status differs from accepted", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		err := os.Chmod(tempDir, 0o400)
		if err != nil {
			t.Fatal(err)
		}

		ctlr := api.NewController(conf)
		go startServer(ctlr)
		defer stopServer(ctlr)

		test.WaitTillServerReady(baseURL)

		img := test.Image{
			Layers: make([][]byte, 10),
		}

		err = test.UploadImage(img, baseURL, "test")
		So(err, ShouldNotBeNil)
	})

	Convey("Put request results in an error", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		go startServer(ctlr)
		defer stopServer(ctlr)

		test.WaitTillServerReady(baseURL)

		img := test.Image{
			Layers: make([][]byte, 10), // invalid format that will result in an error
			Config: ispec.Image{},
		}

		err := test.UploadImage(img, baseURL, "test")
		So(err, ShouldNotBeNil)
	})

	Convey("Image uploaded successfully", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)
		go startServer(ctlr)
		defer stopServer(ctlr)

		test.WaitTillServerReady(baseURL)

		layerBlob := []byte("test")

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		err := test.UploadImage(img, baseURL, "test")
		So(err, ShouldBeNil)
	})

	Convey("Blob upload wrong response status code", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		go startServer(ctlr)
		defer stopServer(ctlr)

		test.WaitTillServerReady(baseURL)

		layerBlob := []byte("test")
		layerBlobDigest := digest.FromBytes(layerBlob)
		layerPath := path.Join(tempDir, "test", "blobs", "sha256")

		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			err = os.MkdirAll(layerPath, 0o700)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.Create(path.Join(layerPath, layerBlobDigest.Encoded()))
			if err != nil {
				t.Fatal(err)
			}

			err = os.Chmod(layerPath, 0o000)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				err = os.Chmod(layerPath, 0o700)
				if err != nil {
					t.Fatal(err)
				}
				os.RemoveAll(file.Name())
			}()
		}

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		err := test.UploadImage(img, baseURL, "test")
		So(err, ShouldNotBeNil)
	})

	Convey("CreateBlobUpload wrong response status code", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		go startServer(ctlr)
		defer stopServer(ctlr)

		test.WaitTillServerReady(baseURL)

		layerBlob := []byte("test")

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		Convey("CreateBlobUpload", func() {
			injected := test.InjectFailure(2)
			if injected {
				err := test.UploadImage(img, baseURL, "test")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload", func() {
			injected := test.InjectFailure(4)
			if injected {
				err := test.UploadImage(img, baseURL, "test")
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func TestInjectUploadImage(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		go startServer(ctlr)
		defer stopServer(ctlr)

		test.WaitTillServerReady(baseURL)

		layerBlob := []byte("test")
		layerPath := path.Join(tempDir, "test", ".uploads")

		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			err = os.MkdirAll(layerPath, 0o700)
			if err != nil {
				t.Fatal(err)
			}
		}

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		Convey("first marshal", func() {
			injected := test.InjectFailure(0)
			if injected {
				err := test.UploadImage(img, baseURL, "test")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("CreateBlobUpload POST call", func() {
			injected := test.InjectFailure(1)
			if injected {
				err := test.UploadImage(img, baseURL, "test")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload PUT call", func() {
			injected := test.InjectFailure(3)
			if injected {
				err := test.UploadImage(img, baseURL, "test")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("second marshal", func() {
			injected := test.InjectFailure(5)
			if injected {
				err := test.UploadImage(img, baseURL, "test")
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func startServer(c *api.Controller) {
	// this blocks
	ctx := context.Background()
	if err := c.Run(ctx); err != nil {
		return
	}
}

func stopServer(c *api.Controller) {
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}
