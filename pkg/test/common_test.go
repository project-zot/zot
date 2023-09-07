//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package test_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/inject"
	"zotregistry.io/zot/pkg/test/mocks"
)

var ErrTestError = errors.New("ErrTestError")

func TestCopyFiles(t *testing.T) {
	Convey("sourceDir does not exist", t, func() {
		err := test.CopyFiles("/path/to/some/unexisting/directory", os.TempDir())
		So(err, ShouldNotBeNil)
	})
	Convey("destDir is a file", t, func() {
		dir := t.TempDir()

		test.CopyTestFiles("../../test/data", dir)

		err := test.CopyFiles(dir, "/etc/passwd")
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
	Convey("sourceDir contains a folder starting with invalid characters", t, func() {
		srcDir := t.TempDir()
		dstDir := t.TempDir()

		err := os.MkdirAll(path.Join(srcDir, "_trivy", "db"), 0o755)
		if err != nil {
			panic(err)
		}

		err = os.MkdirAll(path.Join(srcDir, "test-index"), 0o755)
		if err != nil {
			panic(err)
		}

		filePathTrivy := path.Join(srcDir, "_trivy", "db", "trivy.db")
		err = os.WriteFile(filePathTrivy, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		content, err := json.Marshal(index)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(srcDir, "test-index", "index.json"), content, 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = test.CopyFiles(srcDir, dstDir)
		So(err, ShouldBeNil)

		_, err = os.Stat(path.Join(dstDir, "_trivy", "db", "trivy.db"))
		So(err, ShouldNotBeNil)
		So(os.IsNotExist(err), ShouldBeTrue)

		_, err = os.Stat(path.Join(dstDir, "test-index", "index.json"))
		So(err, ShouldBeNil)
	})
	Convey("panic when sourceDir does not exist", t, func() {
		So(func() { test.CopyTestFiles("/path/to/some/unexisting/directory", os.TempDir()) }, ShouldPanic)
	})
}

func TestGetOciLayoutDigests(t *testing.T) {
	dir := t.TempDir()

	Convey("image path is wrong", t, func() {
		So(func() { _, _, _ = test.GetOciLayoutDigests("inexistent-image") }, ShouldPanic)
	})

	Convey("no permissions when getting index", t, func() {
		storageCtlr := test.GetDefaultStoreController(dir, log.NewLogger("debug", ""))
		image := test.CreateDefaultImage()

		err := test.WriteImageToFileSystem(image, "test-index", "0.0.1", storageCtlr)
		So(err, ShouldBeNil)

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
		storageCtlr := test.GetDefaultStoreController(dir, log.NewLogger("debug", ""))
		image := test.CreateDefaultImage()

		err := test.WriteImageToFileSystem(image, "test-manifest", "0.0.1", storageCtlr)
		So(err, ShouldBeNil)

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
		injected := inject.InjectFailure(0)
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

func TestGetRandomImageComponents(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetRandomImageComponents(100)
			So(err, ShouldNotBeNil)
		}
	})
}

func TestGetImageComponentsWithConfig(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		injected := inject.InjectFailure(0)
		if injected {
			_, _, _, err := test.GetImageComponentsWithConfig(ispec.Image{})
			So(err, ShouldNotBeNil)
		}
	})
}

func TestWaitTillTrivyDBDownloadStarted(t *testing.T) {
	Convey("finishes successfully", t, func() {
		tempDir := t.TempDir()
		go func() {
			test.WaitTillTrivyDBDownloadStarted(tempDir)
		}()

		time.Sleep(test.SleepTime)

		_, err := os.Create(path.Join(tempDir, "trivy.db"))
		So(err, ShouldBeNil)
	})
}

func TestControllerManager(t *testing.T) {
	Convey("Test StartServer Init() panic", t, func() {
		port := test.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		// No storage configured
		So(func() { ctlrManager.StartServer() }, ShouldPanic)
	})

	Convey("Test RunServer panic", t, func() {
		tempDir := t.TempDir()

		// Invalid port
		conf := config.New()
		conf.HTTP.Port = "999999"
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)

		ctx := context.Background()

		err := ctlr.Init(ctx)
		So(err, ShouldBeNil)

		So(func() { ctlrManager.RunServer(ctx) }, ShouldPanic)
	})
}

func TestUploadBlob(t *testing.T) {
	Convey("Post request results in an error", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		err := test.UploadBlob(baseURL, "test", []byte("test"), "zot.com.test")
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

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		err = test.UploadBlob(baseURL, "test", []byte("test"), "zot.com.test")
		So(err, ShouldEqual, test.ErrPostBlob)
	})

	Convey("Put request results in an error", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		blob := new([]byte)

		err := test.UploadBlob(baseURL, "test", *blob, "zot.com.test")
		So(err, ShouldNotBeNil)
	})

	Convey("Put request status differs from accepted", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		blob := []byte("test")
		blobDigest := godigest.FromBytes(blob)
		layerPath := path.Join(tempDir, "test", "blobs", "sha256")
		blobPath := path.Join(layerPath, blobDigest.String())
		if _, err := os.Stat(layerPath); os.IsNotExist(err) {
			err = os.MkdirAll(layerPath, 0o700)
			if err != nil {
				t.Fatal(err)
			}

			file, err := os.Create(blobPath)
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

		err := test.UploadBlob(baseURL, "test", blob, "zot.com.test")
		So(err, ShouldEqual, test.ErrPutBlob)
	})

	Convey("Put request successful", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		blob := []byte("test")

		err := test.UploadBlob(baseURL, "test", blob, "zot.com.test")
		So(err, ShouldEqual, nil)
	})
}

func TestUploadMultiarchImage(t *testing.T) {
	Convey("make controller", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			},
			Manifest: ispec.Manifest{
				Versioned: specs.Versioned{
					SchemaVersion: 2,
				},
				Layers: []ispec.Descriptor{
					{
						Digest:    godigest.FromBytes(layerBlob),
						Size:      int64(len(layerBlob)),
						MediaType: ispec.MediaTypeImageLayerGzip,
					},
				},
				Config: ispec.DescriptorEmptyJSON,
			},
			Config: ispec.Image{},
		}

		manifestBuf, err := json.Marshal(img.Manifest)
		So(err, ShouldBeNil)

		Convey("Multiarch image uploaded successfully", func() {
			err = test.UploadMultiarchImage(test.MultiarchImage{
				Index: ispec.Index{
					Versioned: specs.Versioned{
						SchemaVersion: 2,
					},
					MediaType: ispec.MediaTypeImageIndex,
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromBytes(manifestBuf),
							Size:      int64(len(manifestBuf)),
						},
					},
				},
				Images: []test.Image{img},
			}, baseURL, "test", "index")
			So(err, ShouldBeNil)
		})

		Convey("Multiarch image without schemaVersion should fail validation", func() {
			err = test.UploadMultiarchImage(test.MultiarchImage{
				Index: ispec.Index{
					MediaType: ispec.MediaTypeImageIndex,
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromBytes(manifestBuf),
							Size:      int64(len(manifestBuf)),
						},
					},
				},
				Images: []test.Image{img},
			}, baseURL, "test", "index")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestUploadImage(t *testing.T) {
	Convey("Manifest without schemaVersion should fail validation", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			},
			Manifest: ispec.Manifest{
				Layers: []ispec.Descriptor{
					{
						Digest:    godigest.FromBytes(layerBlob),
						Size:      int64(len(layerBlob)),
						MediaType: ispec.MediaTypeImageLayerGzip,
					},
				},
				Config: ispec.DescriptorEmptyJSON,
			},
			Config: ispec.Image{},
		}

		err := test.UploadImage(img, baseURL, "test", img.DigestStr())
		So(err, ShouldNotBeNil)
	})

	Convey("Post request results in an error", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		img := test.Image{
			Layers: make([][]byte, 10),
		}

		err := test.UploadImage(img, baseURL, "test", "")
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

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		img := test.Image{
			Layers: make([][]byte, 10),
		}

		err = test.UploadImage(img, baseURL, "test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Put request results in an error", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		img := test.Image{
			Layers: make([][]byte, 10), // invalid format that will result in an error
			Config: ispec.Image{},
		}

		err := test.UploadImage(img, baseURL, "test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Image uploaded successfully", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			},
			Manifest: ispec.Manifest{
				Versioned: specs.Versioned{
					SchemaVersion: 2,
				},
				Layers: []ispec.Descriptor{
					{
						Digest:    godigest.FromBytes(layerBlob),
						Size:      int64(len(layerBlob)),
						MediaType: ispec.MediaTypeImageLayerGzip,
					},
				},
				Config: ispec.DescriptorEmptyJSON,
			},
			Config: ispec.Image{},
		}

		err := test.UploadImage(img, baseURL, "test", img.DigestStr())
		So(err, ShouldBeNil)
	})

	Convey("Upload image with authentification", t, func() {
		tempDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		user1 := "test"
		password1 := "test"
		testString1 := test.GetCredString(user1, password1)
		htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		conf.HTTP.Port = port

		conf.HTTP.AccessControl = &config.AccessControlConfig{
			Repositories: config.Repositories{
				"repo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{user1},
							Actions: []string{"read", "create"},
						},
					},
					DefaultPolicy: []string{},
				},
				"inaccessibleRepo": config.PolicyGroup{
					Policies: []config.Policy{
						{
							Users:   []string{user1},
							Actions: []string{"create"},
						},
					},
					DefaultPolicy: []string{},
				},
			},
			AdminPolicy: config.Policy{
				Users:   []string{},
				Actions: []string{},
			},
		}

		ctlr := api.NewController(conf)

		ctlr.Config.Storage.RootDirectory = tempDir

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		Convey("Request fail while pushing layer", func() {
			err := test.UploadImageWithBasicAuth(test.Image{Layers: [][]byte{{1, 2, 3}}}, "badURL", "", "", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request status is not StatusOk while pushing layer", func() {
			err := test.UploadImageWithBasicAuth(test.Image{Layers: [][]byte{{1, 2, 3}}}, baseURL, "", "repo", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request fail while pushing config", func() {
			err := test.UploadImageWithBasicAuth(test.Image{}, "badURL", "", "", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request status is not StatusOk while pushing config", func() {
			err := test.UploadImageWithBasicAuth(test.Image{}, baseURL, "", "repo", "", "")
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Blob upload wrong response status code", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")
		layerBlobDigest := godigest.FromBytes(layerBlob)
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

		err := test.UploadImage(img, baseURL, "test", "")
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

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := test.Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		Convey("CreateBlobUpload", func() {
			injected := inject.InjectFailure(2)
			if injected {
				err := test.UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload", func() {
			injected := inject.InjectFailure(4)
			if injected {
				err := test.UploadImage(img, baseURL, "test", img.DigestStr())
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

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

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
			injected := inject.InjectFailure(0)
			if injected {
				err := test.UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("CreateBlobUpload POST call", func() {
			injected := inject.InjectFailure(1)
			if injected {
				err := test.UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload PUT call", func() {
			injected := inject.InjectFailure(3)
			if injected {
				err := test.UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("second marshal", func() {
			injected := inject.InjectFailure(5)
			if injected {
				err := test.UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func TestReadLogFileAndSearchString(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = test.ReadLogFileAndSearchString("invalidPath", "DB update completed, next update scheduled", 1*time.Second)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := test.ReadLogFileAndSearchString(logPath, "invalid string", time.Microsecond)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})
}

func TestReadLogFileAndCountStringOccurence(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	_, err = logFile.Write([]byte("line1\n line2\n line3 line1 line2\n line1"))
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = test.ReadLogFileAndCountStringOccurence("invalidPath",
			"DB update completed, next update scheduled", 1*time.Second, 1)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := test.ReadLogFileAndCountStringOccurence(logPath, "invalid string", time.Microsecond, 1)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})

	Convey("Count occurrence working", t, func() {
		ok, err := test.ReadLogFileAndCountStringOccurence(logPath, "line1", 90*time.Second, 3)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
	})
}

func TestInjectUploadImageWithBasicAuth(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		user := "user"
		password := "password"
		testString := test.GetCredString(user, password)
		htpasswdPath := test.MakeHtpasswdFileFromString(testString)
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

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
			injected := inject.InjectFailure(0)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("CreateBlobUpload POST call", func() {
			injected := inject.InjectFailure(1)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload PUT call", func() {
			injected := inject.InjectFailure(3)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("second marshal", func() {
			injected := inject.InjectFailure(5)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func TestWriteImageToFileSystem(t *testing.T) {
	Convey("WriteImageToFileSystem errors", t, func() {
		err := test.WriteImageToFileSystem(test.Image{}, "repo", "dig", storage.StoreController{
			DefaultStore: mocks.MockedImageStore{
				InitRepoFn: func(name string) error {
					return ErrTestError
				},
			},
		})
		So(err, ShouldNotBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		count := 0
		err = test.WriteImageToFileSystem(
			test.Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					FullBlobUploadFn: func(repo string, body io.Reader, digest godigest.Digest,
					) (string, int64, error) {
						if count == 0 {
							count++

							return "", 0, nil
						}

						return "", 0, ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{Layers: [][]byte{[]byte("testLayer")}},
			"repo",
			"tag",
			storage.StoreController{
				DefaultStore: mocks.MockedImageStore{
					PutImageManifestFn: func(repo, reference, mediaType string, body []byte,
					) (godigest.Digest, godigest.Digest, error) {
						return "", "", ErrTestError
					},
				},
			})
		So(err, ShouldNotBeNil)
	})
}

func TestBearerServer(t *testing.T) {
	Convey("test MakeAuthTestServer() no serve key", t, func() {
		So(func() { test.MakeAuthTestServer("", "") }, ShouldPanic)
	})
}

func TestCopyTestKeysAndCerts(t *testing.T) {
	Convey("CopyTestKeysAndCerts", t, func() {
		// ------- Make test files unreadable -------
		dir := t.TempDir()
		file := filepath.Join(dir, "ca.crt")

		_, err := os.Create(file)
		So(err, ShouldBeNil)

		err = os.Chmod(file, 0o000)
		So(err, ShouldBeNil)

		err = test.CopyTestKeysAndCerts(dir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(file, 0o777)
		So(err, ShouldBeNil)

		// ------- Copy fails -------

		err = os.Chmod(dir, 0o000)
		So(err, ShouldBeNil)

		err = test.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o777)
		So(err, ShouldBeNil)

		// ------- Folder creation fails -------

		file = filepath.Join(dir, "a-file.file")
		_, err = os.Create(file)
		So(err, ShouldBeNil)

		_, err = os.Stat(file)
		So(err, ShouldBeNil)

		err = test.CopyTestKeysAndCerts(file)
		So(err, ShouldNotBeNil)
	})
}
