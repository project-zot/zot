package image_test

import (
	"encoding/json"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	tcommon "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/inject"
)

func TestUploadImage(t *testing.T) {
	Convey("Manifest without schemaVersion should fail validation", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := Image{
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

		err := UploadImage(img, baseURL, "test", img.DigestStr())
		So(err, ShouldNotBeNil)
	})

	Convey("Post request results in an error", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		img := Image{
			Layers: make([][]byte, 10),
		}

		err := UploadImage(img, baseURL, "test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Post request status differs from accepted", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		err := os.Chmod(tempDir, 0o400)
		if err != nil {
			t.Fatal(err)
		}

		defer func() {
			err := os.Chmod(tempDir, 0o700)
			if err != nil {
				t.Fatal(err)
			}
		}()

		img := Image{
			Layers: make([][]byte, 10),
		}

		err = UploadImage(img, baseURL, "test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Put request results in an error", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		img := Image{
			Layers: make([][]byte, 10), // invalid format that will result in an error
			Config: ispec.Image{},
		}

		err := UploadImage(img, baseURL, "test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Image uploaded successfully", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := Image{
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

		err := UploadImage(img, baseURL, "test", img.DigestStr())
		So(err, ShouldBeNil)
	})

	Convey("Upload image with authentification", t, func() {
		tempDir := t.TempDir()
		conf := config.New()
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		user1 := "test"
		password1 := "test"
		testString1 := tcommon.GetCredString(user1, password1)
		htpasswdPath := tcommon.MakeHtpasswdFileFromString(testString1)
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

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		Convey("Request fail while pushing layer", func() {
			err := UploadImageWithBasicAuth(Image{Layers: [][]byte{{1, 2, 3}}}, "badURL", "", "", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request status is not StatusOk while pushing layer", func() {
			err := UploadImageWithBasicAuth(Image{Layers: [][]byte{{1, 2, 3}}}, baseURL, "", "repo", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request fail while pushing config", func() {
			err := UploadImageWithBasicAuth(Image{}, "badURL", "", "", "", "")
			So(err, ShouldNotBeNil)
		})
		Convey("Request status is not StatusOk while pushing config", func() {
			err := UploadImageWithBasicAuth(Image{}, baseURL, "", "repo", "", "")
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Blob upload wrong response status code", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
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

		img := Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		err := UploadImage(img, baseURL, "test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("CreateBlobUpload wrong response status code", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		Convey("CreateBlobUpload", func() {
			injected := inject.InjectFailure(2)
			if injected {
				err := UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload", func() {
			injected := inject.InjectFailure(4)
			if injected {
				err := UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func TestInjectUploadImage(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
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

		img := Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		Convey("first marshal", func() {
			injected := inject.InjectFailure(0)
			if injected {
				err := UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("CreateBlobUpload POST call", func() {
			injected := inject.InjectFailure(1)
			if injected {
				err := UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload PUT call", func() {
			injected := inject.InjectFailure(3)
			if injected {
				err := UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
		Convey("second marshal", func() {
			injected := inject.InjectFailure(5)
			if injected {
				err := UploadImage(img, baseURL, "test", img.DigestStr())
				So(err, ShouldNotBeNil)
			}
		})
	})
}

func TestUploadMultiarchImage(t *testing.T) {
	Convey("make controller", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = t.TempDir()

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
		ctlrManager.StartAndWait(port)
		defer ctlrManager.StopServer()

		layerBlob := []byte("test")

		img := Image{
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
			err = UploadMultiarchImage(MultiarchImage{
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
				Images: []Image{img},
			}, baseURL, "test", "index")
			So(err, ShouldBeNil)
		})

		Convey("Multiarch image without schemaVersion should fail validation", func() {
			err = UploadMultiarchImage(MultiarchImage{
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
				Images: []Image{img},
			}, baseURL, "test", "index")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestInjectUploadImageWithBasicAuth(t *testing.T) {
	Convey("Inject failures for unreachable lines", t, func() {
		port := tcommon.GetFreePort()
		baseURL := tcommon.GetBaseURL(port)

		tempDir := t.TempDir()
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.RootDirectory = tempDir

		user := "user"
		password := "password"
		testString := tcommon.GetCredString(user, password)
		htpasswdPath := tcommon.MakeHtpasswdFileFromString(testString)
		defer os.Remove(htpasswdPath)
		conf.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}

		ctlr := api.NewController(conf)

		ctlrManager := tcommon.NewControllerManager(ctlr)
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

		img := Image{
			Layers: [][]byte{
				layerBlob,
			}, // invalid format that will result in an error
			Config: ispec.Image{},
		}

		Convey("first marshal", func() {
			injected := inject.InjectFailure(0)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("CreateBlobUpload POST call", func() {
			injected := inject.InjectFailure(1)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("UpdateBlobUpload PUT call", func() {
			injected := inject.InjectFailure(3)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
		Convey("second marshal", func() {
			injected := inject.InjectFailure(5)
			if injected {
				err := UploadImageWithBasicAuth(img, baseURL, "test", img.DigestStr(), "user", "password")
				So(err, ShouldNotBeNil)
			}
		})
	})
}
