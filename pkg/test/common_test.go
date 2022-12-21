//go:build sync && scrub && metrics && search
// +build sync,scrub,metrics,search

package test_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	notconfig "github.com/notaryproject/notation-go/config"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"golang.org/x/crypto/bcrypt"

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
		test.CopyTestFiles("../../test/data/zot-test", path.Join(dir, "test-index"))

		err := os.Chmod(path.Join(dir, "test-index", "index.json"), 0o000)
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
		test.CopyTestFiles("../../test/data/zot-test", path.Join(dir, "test-manifest"))

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

func TestUploadArtifact(t *testing.T) {
	Convey("Put request results in an error", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		artifact := ispec.Artifact{}

		err := test.UploadArtifact(baseURL, "test", &artifact)
		So(err, ShouldNotBeNil)
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

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		err := os.Chmod(tempDir, 0o400)
		if err != nil {
			t.Fatal(err)
		}

		defer func() {
			err = os.Chmod(tempDir, 0o700)
			if err != nil {
				t.Fatal(err)
			}
		}()

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

		ctlr := api.NewController(conf)

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		err := os.Chmod(tempDir, 0o400)
		if err != nil {
			t.Fatal(err)
		}

		defer func() {
			err = os.Chmod(tempDir, 0o700)
			if err != nil {
				t.Fatal(err)
			}
		}()

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

		ctlrManager := test.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

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

		err := test.UploadImage(img, baseURL, "test")
		So(err, ShouldNotBeNil)
	})

	Convey("Upload image with authentification", t, func() {
		tempDir := t.TempDir()
		conf := config.New()
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		user1 := "test"
		password1 := "test"
		testString1 := getCredString(user1, password1)
		htpasswdPath := test.MakeHtpasswdFileFromString(testString1)
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		conf.HTTP.Port = port

		conf.AccessControl = &config.AccessControlConfig{
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
			err := test.UploadImageWithBasicAuth(test.Image{Layers: [][]byte{{1, 2, 3}}}, "badURL", "", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request status is not StatusOk while pushing layer", func() {
			err := test.UploadImageWithBasicAuth(test.Image{Layers: [][]byte{{1, 2, 3}}}, baseURL, "repo", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request fail while pushing config", func() {
			err := test.UploadImageWithBasicAuth(test.Image{}, "badURL", "", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request status is not StatusOk while pushing config", func() {
			err := test.UploadImageWithBasicAuth(test.Image{}, baseURL, "repo", "", "")
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

func getCredString(username, password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		panic(err)
	}

	usernameAndHash := fmt.Sprintf("%s:%s", username, string(hash))

	return usernameAndHash
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

func TestReadLogFileAndSearchString(t *testing.T) {
	logFile, err := os.CreateTemp(t.TempDir(), "zot-log*.txt")
	if err != nil {
		panic(err)
	}

	logPath := logFile.Name()
	defer os.Remove(logPath)

	Convey("Invalid path", t, func() {
		_, err = test.ReadLogFileAndSearchString("invalidPath", "DB update completed, next update scheduled", 90*time.Second)
		So(err, ShouldNotBeNil)
	})

	Convey("Time too short", t, func() {
		ok, err := test.ReadLogFileAndSearchString(logPath, "invalid string", time.Microsecond)
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
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
		testString := getCredString(user, password)
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
			injected := test.InjectFailure(0)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("CreateBlobUpload POST call", func() {
			injected := test.InjectFailure(1)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload PUT call", func() {
			injected := test.InjectFailure(3)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("second marshal", func() {
			injected := test.InjectFailure(5)
			if injected {
				err := test.UploadImageWithBasicAuth(img, baseURL, "test", "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func TestCopyFile(t *testing.T) {
	Convey("destFilePath does not exist", t, func() {
		err := test.CopyFile("/path/to/srcFile", "~/path/to/some/unexisting/destDir/file")
		So(err, ShouldNotBeNil)
	})

	Convey("sourceFile does not exist", t, func() {
		err := test.CopyFile("/path/to/some/unexisting/file", path.Join(t.TempDir(), "destFile.txt"))
		So(err, ShouldNotBeNil)
	})
}

func TestIsDigestReference(t *testing.T) {
	Convey("not digest reference", t, func() {
		res := test.IsDigestReference("notDigestReference/input")
		So(res, ShouldBeFalse)
	})

	Convey("wrong input format", t, func() {
		res := test.IsDigestReference("wrongInput")
		So(res, ShouldBeFalse)
	})
}

func TestLoadNotationSigningkeys(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		_, err := test.LoadNotationSigningkeys(t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("wrong content of signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("not enough permissions to access signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o300) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("signingkeys.json not exists so it is created successfully", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldBeNil)
	})

	Convey("signingkeys.json not exists - error trying to create it", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		// create notation directory without write permissions
		err := os.Mkdir(dir, 0o555)
		So(err, ShouldBeNil)

		_, err = test.LoadNotationSigningkeys(tempDir)
		So(err, ShouldNotBeNil)
	})
}

func TestLoadNotationConfig(t *testing.T) {
	Convey("directory doesn't exist", t, func() {
		_, err := test.LoadNotationConfig(t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("wrong content of signingkeys.json", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		_, err = test.LoadNotationConfig(tempDir)
		So(err, ShouldNotBeNil)
	})

	Convey("check default value of signature format", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("{\"SignatureFormat\": \"\"}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		configInfo, err := test.LoadNotationConfig(tempDir)
		So(err, ShouldBeNil)
		So(configInfo.SignatureFormat, ShouldEqual, "jws")
	})
}

func TestSignWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := test.SignWithNotation("key", "reference", t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("key not found", t, func() {
		tempDir := t.TempDir()
		dir := path.Join(tempDir, "notation")
		err := os.Mkdir(dir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(dir, "signingkeys.json")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "reference", tempDir)
		So(err, ShouldEqual, test.ErrKeyNotFound)
	})

	Convey("not enough permissions to access notation/localkeys dir", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(tdir, "notation", "localkeys"), 0o000)
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "reference", tdir)
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(tdir, "notation", "localkeys"), 0o755)
		So(err, ShouldBeNil)
	})

	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error signing", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.SignWithNotation("key", "localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})
}

func TestVerifyWithNotation(t *testing.T) {
	Convey("notation directory doesn't exist", t, func() {
		err := test.VerifyWithNotation("reference", t.TempDir())
		So(err, ShouldNotBeNil)
	})

	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.VerifyWithNotation("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tdir)

		err = test.GenerateNotationCerts(tdir, "key")
		So(err, ShouldBeNil)

		err = test.VerifyWithNotation("localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("invalid content of trustpolicy.json", t, func() {
		// start a new server
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		dir := t.TempDir()

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = dir

		ctlr := api.NewController(conf)
		cm := test.NewControllerManager(ctlr)
		// this blocks
		cm.StartAndWait(port)
		defer cm.StopServer()

		repoName := "signed-repo"
		tag := "1.0"
		cfg, layers, manifest, err := test.GetImageComponents(2)
		So(err, ShouldBeNil)

		err = test.UploadImage(
			test.Image{
				Config:    cfg,
				Layers:    layers,
				Manifest:  manifest,
				Reference: tag,
			}, baseURL, repoName)
		So(err, ShouldBeNil)

		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		tempDir := t.TempDir()
		notationDir := path.Join(tempDir, "notation")
		err = os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "trustpolicy.json")
		err = os.WriteFile(filePath, []byte("some dummy file content"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.VerifyWithNotation(fmt.Sprintf("localhost:%s/%s:%s", port, repoName, tag), tempDir)
		So(err, ShouldNotBeNil)
	})
}

func TestListNotarySignatures(t *testing.T) {
	Convey("error parsing reference", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		_, err = test.ListNotarySignatures("invalidReference", tdir)
		So(err, ShouldNotBeNil)
	})

	Convey("error trying to get manifest", t, func() {
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)
		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		_, err = test.ListNotarySignatures("localhost:8080/invalidreference:1.0", tdir)
		So(err, ShouldNotBeNil)
	})
}

func TestGenerateNotationCerts(t *testing.T) {
	Convey("write key file with permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "localkeys")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)
	})

	Convey("write cert file with permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation", "localkeys")
		err := os.MkdirAll(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "cert.crt")
		err = os.WriteFile(filePath, []byte("{}"), 0o666) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.Chmod(filePath, 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)

		err = os.Chmod(filePath, 0o755)
		So(err, ShouldBeNil)
	})

	Convey("signingkeys.json file - not enough permission", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		filePath := path.Join(notationDir, "signingkeys.json")
		_, err = os.Create(filePath) //nolint: gosec
		So(err, ShouldBeNil)
		err = os.Chmod(filePath, 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)

		err = os.Remove(filePath)
		So(err, ShouldBeNil)
		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		signingKeysBuf, err := json.Marshal(notconfig.SigningKeys{})
		So(err, ShouldBeNil)
		err = os.WriteFile(filePath, signingKeysBuf, 0o555)
		So(err, ShouldBeNil)
		err = test.GenerateNotationCerts(t.TempDir(), "cert")
		So(err, ShouldNotBeNil)
	})
	Convey("keysuite already exists in signingkeys.json", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		certName := "cert-test"
		filePath := path.Join(notationDir, "signingkeys.json")
		keyPath := path.Join(notationDir, "localkeys", certName+".key")
		certPath := path.Join(notationDir, "localkeys", certName+".crt")
		signingKeys := notconfig.SigningKeys{}
		keySuite := notconfig.KeySuite{
			Name: certName,
			X509KeyPair: &notconfig.X509KeyPair{
				KeyPath:         keyPath,
				CertificatePath: certPath,
			},
		}
		signingKeys.Keys = []notconfig.KeySuite{keySuite}
		signingKeysBuf, err := json.Marshal(signingKeys)
		So(err, ShouldBeNil)
		err = os.WriteFile(filePath, signingKeysBuf, 0o600)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(t.TempDir(), certName)
		So(err, ShouldNotBeNil)
	})
	Convey("truststore files", t, func() {
		tempDir := t.TempDir()

		notationDir := path.Join(tempDir, "notation")
		err := os.Mkdir(notationDir, 0o777)
		So(err, ShouldBeNil)

		certName := "cert-test"
		trustStorePath := path.Join(notationDir, fmt.Sprintf("truststore/x509/ca/%s", certName))
		err = os.MkdirAll(trustStorePath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509"), 0o000)
		So(err, ShouldBeNil)

		test.NotationPathLock.Lock()
		defer test.NotationPathLock.Unlock()

		test.LoadNotationPath(tempDir)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509"), 0o755)
		So(err, ShouldBeNil)
		_, err = os.Create(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(notationDir, "localkeys"))
		So(err, ShouldBeNil)
		err = os.Remove(path.Join(trustStorePath, "cert-test.crt"))
		So(err, ShouldBeNil)
		err = os.Chmod(path.Join(notationDir, "truststore/x509/ca", certName), 0o555)
		So(err, ShouldBeNil)

		err = test.GenerateNotationCerts(tempDir, certName)
		So(err, ShouldNotBeNil)
	})
}
