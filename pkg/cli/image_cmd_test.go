//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/cobra"
	"gopkg.in/resty.v1"

	zotErrors "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/api/constants"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

func TestSearchImageCmd(t *testing.T) {
	Convey("Test image help", t, func() {
		args := []string{"--help"}
		configPath := makeConfigFile("")
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(buff.String(), ShouldContainSubstring, "Usage")
		So(err, ShouldBeNil)
		Convey("with the shorthand", func() {
			args[0] = "-h"
			configPath := makeConfigFile("")
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(mockService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(buff.String(), ShouldContainSubstring, "Usage")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test image no url", t, func() {
		args := []string{"imagetest", "--name", "dummyIdRandom"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zotErrors.ErrNoURLProvided)
	})

	Convey("Test image invalid home directory", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName"}

		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)

		err := os.Setenv("HOME", "nonExistentDirectory")
		if err != nil {
			panic(err)
		}

		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		err = os.Setenv("HOME", home)
		if err != nil {
			log.Fatal(err)
		}
	})

	Convey("Test image no params", t, func() {
		args := []string{"imagetest", "--url", "someUrl"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test image invalid url", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "--url", "invalidUrl"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zotErrors.ErrInvalidURL)
		So(buff.String(), ShouldContainSubstring, "invalid URL format")
	})

	Convey("Test image invalid url port", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "--url", "http://localhost:99999"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid port")

		Convey("without flags", func() {
			args := []string{"imagetest", "--url", "http://localhost:99999"}
			configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
			So(buff.String(), ShouldContainSubstring, "invalid port")
		})
	})

	Convey("Test image unreachable", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "--url", "http://localhost:9999"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image url from config", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag DigestsA false 123kB")
		So(err, ShouldBeNil)
	})

	Convey("Test image by name", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "--url", "someUrlImage"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		imageCmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		imageCmd.SetOut(buff)
		imageCmd.SetErr(buff)
		imageCmd.SetArgs(args)
		err := imageCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag DigestsA false 123kB")
		So(err, ShouldBeNil)
		Convey("using shorthand", func() {
			args := []string{"imagetest", "-n", "dummyImageName", "--url", "someUrlImage"}
			buff := bytes.NewBufferString("")
			configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
			defer os.Remove(configPath)
			imageCmd := NewImageCommand(new(mockService))
			imageCmd.SetOut(buff)
			imageCmd.SetErr(buff)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag DigestsA false 123kB")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test image by digest", t, func() {
		args := []string{"imagetest", "--digest", "DigestsA", "--url", "someUrlImage"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
		defer os.Remove(configPath)
		imageCmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		imageCmd.SetOut(buff)
		imageCmd.SetErr(buff)
		imageCmd.SetArgs(args)
		err := imageCmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE anImage tag DigestsA false 123kB")
		So(err, ShouldBeNil)

		Convey("invalid URL format", func() {
			args := []string{"imagetest", "--digest", "digest", "--url", "invalidURL"}
			configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","showspinner":false}]}`)
			defer os.Remove(configPath)
			imageCmd := NewImageCommand(NewSearchService())
			buff := bytes.NewBufferString("")
			imageCmd.SetOut(buff)
			imageCmd.SetErr(buff)
			imageCmd.SetArgs(args)
			err := imageCmd.Execute()
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zotErrors.ErrInvalidURL)
			So(buff.String(), ShouldContainSubstring, "invalid URL format")
		})
	})
}

func TestSignature(t *testing.T) {
	Convey("Test from real server", t, func() {
		currentWorkingDir, err := os.Getwd()
		So(err, ShouldBeNil)

		currentDir := t.TempDir()
		err = os.Chdir(currentDir)
		So(err, ShouldBeNil)

		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = currentDir
		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)
		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		// create a blob/layer
		resp, _ := resty.R().Post(url + "/v2/repo7/blobs/uploads/")
		loc := test.Location(url, resp)

		content := []byte("this is a blob5")
		digest := godigest.FromBytes(content)
		_, _ = resty.R().SetQueryParam("digest", digest.String()).
			SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)

		// upload image config blob
		resp, _ = resty.R().Post(url + "/v2/repo7/blobs/uploads/")
		loc = test.Location(url, resp)
		cblob, cdigest := test.GetImageConfig()

		_, _ = resty.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", cdigest.String()).
			SetBody(cblob).
			Put(loc)

		// create a manifest
		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(len(content)),
				},
			},
		}
		manifest.SchemaVersion = 2

		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		_, _ = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(url + "/v2/repo7/manifests/test:1.0")

		//	content = []byte("this is a blob5")
		digest = godigest.FromBytes(content)

		// generate a keypair
		if _, err := os.Stat(path.Join(currentDir, "cosign.key")); err != nil {
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", nil)
			So(err, ShouldBeNil)
		}

		_, err = os.Stat(path.Join(currentDir, "cosign.key"))
		So(err, ShouldBeNil)

		// sign the image
		err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
			options.KeyOpts{KeyRef: path.Join(currentDir, "cosign.key"), PassFunc: generate.GetPass},
			options.RegistryOptions{AllowInsecure: true},
			map[string]interface{}{"tag": "test:1.0"},
			[]string{fmt.Sprintf("localhost:%s/%s@%s", port, "repo7", digest.String())},
			"", "", true, "", "", "", false, false, "", true)
		So(err, ShouldBeNil)

		t.Logf("%s", ctlr.Config.Storage.RootDirectory)
		args := []string{"imagetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(searchService))
		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 true")

		err = os.Chdir(currentWorkingDir)
		So(err, ShouldBeNil)
	})
}

//nolint:dupl
func TestDerivedImageList(t *testing.T) {
	Convey("Test from real server", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)
		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		err := uploadManifest(url)
		So(err, ShouldBeNil)
		t.Logf("rootDir: %s", ctlr.Config.Storage.RootDirectory)

		Convey("Test derived images list working", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest", "--derived-images", "repo7:test:1.0"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
		})

		Convey("Test derived images fail", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			err = os.Chmod(ctlr.Config.Storage.RootDirectory, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(ctlr.Config.Storage.RootDirectory, 0o755)
				So(err, ShouldBeNil)
			}()
			args := []string{"imagetest", "--derived-images", "repo7:test:1.0"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("Test derived images list cannot print", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest", "--derived-images", "repo7:test:1.0", "-o", "random"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

//nolint:dupl
func TestBaseImageList(t *testing.T) {
	Convey("Test from real server", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()

		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)
		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		err := uploadManifest(url)
		So(err, ShouldBeNil)
		t.Logf("rootDir: %s", ctlr.Config.Storage.RootDirectory)

		Convey("Test base images list working", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest", "--base-images", "repo7:test:1.0"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
		})

		Convey("Test base images fail", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			err = os.Chmod(ctlr.Config.Storage.RootDirectory, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(ctlr.Config.Storage.RootDirectory, 0o755)
				So(err, ShouldBeNil)
			}()
			args := []string{"imagetest", "--base-images", "repo7:test:1.0"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("Test base images list cannot print", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest", "--base-images", "repo7:test:1.0", "-o", "random"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestListRepos(t *testing.T) {
	Convey("Test listing repositories", t, func() {
		args := []string{"config-test"}
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
	})

	Convey("Test listing repositories with debug flag", t, func() {
		args := []string{"config-test", "--debug"}
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(searchService))

		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "GET")
	})

	Convey("Test error on home directory", t, func() {
		args := []string{"config-test"}

		configPath := makeConfigFile(`{"configs":[{"_name":"config-test","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)

		err := os.Setenv("HOME", "nonExistentDirectory")
		if err != nil {
			panic(err)
		}

		cmd := NewRepoCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		home, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		err = os.Setenv("HOME", home)
		if err != nil {
			log.Fatal(err)
		}
	})

	Convey("Test listing repositories error", t, func() {
		args := []string{"config-test"}
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test",
        	"url":"https://invalid.invalid","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test unable to get config value", t, func() {
		args := []string{"config-test-nonexistent"}
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error - no url provided", t, func() {
		args := []string{"config-test"}
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test","url":"","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error - no args provided", t, func() {
		var args []string
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test","url":"","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error - spinner config invalid", t, func() {
		args := []string{"config-test"}
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test",
       		"url":"https://test-url.com","showspinner":invalid}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test error - verifyTLSConfig fails", t, func() {
		args := []string{"config-test"}
		configPath := makeConfigFile(`{"configs":[{"_name":"config-test",
        	"verify-tls":"invalid", "url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewRepoCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func TestOutputFormat(t *testing.T) {
	Convey("Test text", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "-o", "text"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag DigestsA false 123kB")
		So(err, ShouldBeNil)
	})

	//  get image config functia

	Convey("Test json", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "-o", "json"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, `{ "repoName": "dummyImageName", "tag": "tag", `+
			`"configDigest": "", "digest": "DigestsAreReallyLong", "layers": null, "size": "123445", "isSigned": false }`)
		So(err, ShouldBeNil)
	})

	Convey("Test yaml", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "-o", "yaml"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(
			strings.TrimSpace(str),
			ShouldEqual,
			`reponame: dummyImageName tag: tag configdigest: "" `+
				`digest: DigestsAreReallyLong layers: [] size: "123445" `+
				`issigned: false`,
		)
		So(err, ShouldBeNil)

		Convey("Test yml", func() {
			args := []string{"imagetest", "--name", "dummyImageName", "-o", "yml"}
			configPath := makeConfigFile(
				`{"configs":[{"_name":"imagetest",` +
					`"url":"https://test-url.com","showspinner":false}]}`,
			)
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(mockService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			So(
				strings.TrimSpace(str),
				ShouldEqual,
				`reponame: dummyImageName tag: tag configdigest: "" `+
					`digest: DigestsAreReallyLong layers: [] size: "123445" `+
					`issigned: false`,
			)
			So(err, ShouldBeNil)
		})
	})

	Convey("Test invalid", t, func() {
		args := []string{"imagetest", "--name", "dummyImageName", "-o", "random"}
		configPath := makeConfigFile(`{"configs":[{"_name":"imagetest","url":"https://test-url.com","showspinner":false}]}`)
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(mockService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(buff.String(), ShouldContainSubstring, "invalid output format")
	})
}

func TestServerResponseGQL(t *testing.T) {
	Convey("Test from real server", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)
		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		err := uploadManifest(url)
		t.Logf("%s", ctlr.Config.Storage.RootDirectory)
		So(err, ShouldBeNil)

		Convey("Test all images config url", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")
			Convey("Test all images invalid output format", func() {
				args := []string{"imagetest", "-o", "random"}
				configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
				defer os.Remove(configPath)
				cmd := NewImageCommand(new(searchService))
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldNotBeNil)
				So(buff.String(), ShouldContainSubstring, "invalid output format")
			})
		})

		Convey("Test all images verbose", func() {
			args := []string{"imagetest", "--verbose"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			// Actual cli output should be something similar to (order of images may differ):
			// IMAGE NAME    TAG       DIGEST    CONFIG    LAYERS    SIZE
			// repo7         test:2.0  a0ca253b  b8781e88            15B
			//                                             b8781e88  15B
			// repo7         test:1.0  a0ca253b  b8781e88            15B
			//                                             b8781e88  15B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST CONFIG SIGNED LAYERS SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 3a1d2d0c false 15B b8781e88 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 3a1d2d0c false 15B b8781e88 15B")
		})

		Convey("Test all images with debug flag", func() {
			args := []string{"imagetest", "--debug"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "GET")
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")
		})

		Convey("Test image by name config url", func() {
			args := []string{"imagetest", "--name", "repo7"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")

			Convey("with shorthand", func() {
				args := []string{"imagetest", "-n", "repo7"}
				configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
				defer os.Remove(configPath)
				cmd := NewImageCommand(new(searchService))
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err = cmd.Execute()
				So(err, ShouldBeNil)
				space := regexp.MustCompile(`\s+`)
				str := space.ReplaceAllString(buff.String(), " ")
				actual := strings.TrimSpace(str)
				So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
				So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
				So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")
			})

			Convey("invalid output format", func() {
				args := []string{"imagetest", "--name", "repo7", "-o", "random"}
				configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
				defer os.Remove(configPath)
				cmd := NewImageCommand(new(searchService))
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldNotBeNil)
				So(buff.String(), ShouldContainSubstring, "invalid output format")
			})
		})

		Convey("Test image by digest", func() {
			args := []string{"imagetest", "--digest", "883fc0c5"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			// Actual cli output should be something similar to (order of images may differ):
			// IMAGE NAME    TAG       DIGEST    SIZE
			// repo7         test:2.0  a0ca253b  15B
			// repo7         test:1.0  a0ca253b  15B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")

			Convey("with shorthand", func() {
				args := []string{"imagetest", "-d", "883fc0c5"}
				configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
				defer os.Remove(configPath)
				cmd := NewImageCommand(new(searchService))
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err = cmd.Execute()
				So(err, ShouldBeNil)
				space := regexp.MustCompile(`\s+`)
				str := space.ReplaceAllString(buff.String(), " ")
				actual := strings.TrimSpace(str)
				So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
				So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
				So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")
			})

			Convey("nonexistent digest", func() {
				args := []string{"imagetest", "--digest", "d1g35t"}
				configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
				defer os.Remove(configPath)
				cmd := NewImageCommand(new(searchService))
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldBeNil)
				So(len(buff.String()), ShouldEqual, 0)
			})

			Convey("invalid output format", func() {
				args := []string{"imagetest", "--digest", "883fc0c5", "-o", "random"}
				configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
				defer os.Remove(configPath)
				cmd := NewImageCommand(new(searchService))
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldNotBeNil)
				So(buff.String(), ShouldContainSubstring, "invalid output format")
			})
		})

		Convey("Test image by name nonexistent name", func() {
			args := []string{"imagetest", "--name", "repo777"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			So(len(buff.String()), ShouldEqual, 0)
		})

		Convey("Test list repos error", func() {
			args := []string{"config-test"}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"config-test",
            "url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)

			cmd := NewRepoCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			So(actual, ShouldContainSubstring, "REPOSITORY NAME")
			So(actual, ShouldContainSubstring, "repo7")
		})
	})
}

func TestServerResponse(t *testing.T) {
	Convey("Test from real server", t, func() {
		port := test.GetFreePort()
		url := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{Enable: &defaultVal},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(context.Background()); err != nil {
				return
			}
		}(ctlr)
		// wait till ready
		for {
			_, err := resty.R().Get(url)
			if err == nil {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
		defer func(controller *api.Controller) {
			ctx := context.Background()
			_ = controller.Server.Shutdown(ctx)
		}(ctlr)

		err := uploadManifest(url)
		t.Logf("%s", ctlr.Config.Storage.RootDirectory)
		So(err, ShouldBeNil)

		Convey("Test all images", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := MockNewImageCommand(new(searchService))
			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")
		})

		Convey("Test all images verbose", func() {
			args := []string{"imagetest", "--verbose"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := MockNewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			// Actual cli output should be something similar to (order of images may differ):
			// IMAGE NAME    TAG       DIGEST    CONFIG    LAYERS    SIZE
			// repo7         test:2.0  a0ca253b  b8781e88            15B
			//                                             b8781e88  15B
			// repo7         test:1.0  a0ca253b  b8781e88            15B
			//                                             b8781e88  15B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST CONFIG SIGNED LAYERS SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 3a1d2d0c false 15B b8781e88 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 3a1d2d0c false 15B b8781e88 15B")
		})

		Convey("Test image by name", func() {
			args := []string{"imagetest", "--name", "repo7"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := MockNewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")
		})

		Convey("Test image by digest", func() {
			args := []string{"imagetest", "--digest", "883fc0c5"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := MockNewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			// Actual cli output should be something similar to (order of images may differ):
			// IMAGE NAME    TAG       DIGEST    SIZE
			// repo7         test:2.0  a0ca253b  15B
			// repo7         test:1.0  a0ca253b  15B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 15B")

			Convey("nonexistent digest", func() {
				args := []string{"imagetest", "--digest", "d1g35t"}
				configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
				defer os.Remove(configPath)
				cmd := MockNewImageCommand(new(searchService))
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldBeNil)
				So(len(buff.String()), ShouldEqual, 0)
			})
		})

		Convey("Test image by name nonexistent name", func() {
			args := []string{"imagetest", "--name", "repo777"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := MockNewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
			actual := buff.String()
			So(actual, ShouldContainSubstring, "unknown")
		})
	})
}

func TestServerResponseGQLWithoutPermissions(t *testing.T) {
	port := test.GetFreePort()
	url := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	dir := t.TempDir()

	err := test.CopyFiles("../../test/data/zot-test", path.Join(dir, "zot-test"))
	if err != nil {
		panic(err)
	}

	err = os.Chmod(path.Join(dir, "zot-test", "blobs"), 0o000)
	if err != nil {
		panic(err)
	}

	conf.Storage.RootDirectory = dir
	cveConfig := &extconf.CVEConfig{
		UpdateInterval: 2,
	}
	defaultVal := true
	searchConfig := &extconf.SearchConfig{
		CVE:    cveConfig,
		Enable: &defaultVal,
	}
	conf.Extensions = &extconf.ExtensionConfig{
		Search: searchConfig,
	}

	ctlr := api.NewController(conf)

	go func(controller *api.Controller) {
		// this blocks
		if err := controller.Run(context.Background()); err != nil {
			return
		}
	}(ctlr)
	// wait till ready
	for {
		res, err := resty.R().Get(url + constants.FullSearchPrefix)
		if err == nil && res.StatusCode() == 422 {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(90 * time.Second)

	defer func(controller *api.Controller) {
		err = os.Chmod(path.Join(dir, "zot-test", "blobs"), 0o777)
		if err != nil {
			panic(err)
		}
		ctx := context.Background()
		_ = controller.Server.Shutdown(ctx)
	}(ctlr)

	Convey("Test all images", t, func() {
		args := []string{"imagetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cveCmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cveCmd.SetOut(buff)
		cveCmd.SetErr(buff)
		cveCmd.SetArgs(args)
		err = cveCmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test all images verbose", t, func() {
		args := []string{"imagetest", "--verbose"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image by name", t, func() {
		args := []string{"imagetest", "--name", "zot-test"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})

	Convey("Test image by digest", t, func() {
		args := []string{"imagetest", "--digest", "2bacca16"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
		defer os.Remove(configPath)
		cmd := NewImageCommand(new(searchService))
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func MockNewImageCommand(searchService SearchService) *cobra.Command {
	searchImageParams := make(map[string]*string)

	var servURL, user, outputFormat string

	var verifyTLS, verbose, debug bool

	imageCmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			home, err := os.UserHomeDir()
			if err != nil {
				panic(err)
			}

			configPath := path.Join(home + "/.zot")
			if len(args) > 0 {
				urlFromConfig, err := getConfigValue(configPath, args[0], "url")
				if err != nil {
					cmd.SilenceUsage = true

					return err
				}

				if urlFromConfig == "" {
					return zotErrors.ErrNoURLProvided
				}

				servURL = urlFromConfig
			} else {
				return zotErrors.ErrNoURLProvided
			}

			if len(args) > 0 {
				var err error

				verifyTLS, err = parseBooleanConfig(configPath, args[0], verifyTLSConfig)
				if err != nil {
					cmd.SilenceUsage = true

					return err
				}
			}

			searchConfig := searchConfig{
				params:        searchImageParams,
				searchService: searchService,
				servURL:       &servURL,
				user:          &user,
				outputFormat:  &outputFormat,
				verbose:       &verbose,
				debug:         &debug,
				verifyTLS:     &verifyTLS,
				resultWriter:  cmd.OutOrStdout(),
			}

			err = MockSearchImage(searchConfig)

			if err != nil {
				cmd.SilenceUsage = true

				return err
			}

			return nil
		},
	}

	setupImageFlags(imageCmd, searchImageParams, &servURL, &user, &outputFormat, &verbose, &debug)
	imageCmd.SetUsageTemplate(imageCmd.UsageTemplate() + usageFooter)

	return imageCmd
}

func MockSearchImage(searchConfig searchConfig) error {
	searchers := getImageSearchers()

	for _, searcher := range searchers {
		found, err := searcher.search(searchConfig)
		if found {
			if err != nil {
				return err
			}

			return nil
		}
	}

	return zotErrors.ErrInvalidFlagsCombination
}

func uploadManifest(url string) error {
	// create a blob/layer
	resp, _ := resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc := test.Location(url, resp)

	content := []byte("this is a blob5")
	digest := godigest.FromBytes(content)
	_, _ = resty.R().SetQueryParam("digest", digest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)

	// upload image config blob
	resp, _ = resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc = test.Location(url, resp)
	cblob, cdigest := test.GetImageConfig()

	_, _ = resty.R().
		SetContentLength(true).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)

	// create a manifest
	manifest := ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cdigest,
			Size:      int64(len(cblob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest,
				Size:      int64(len(content)),
			},
		},
	}
	manifest.SchemaVersion = 2

	content, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	_, _ = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(content).Put(url + "/v2/repo7/manifests/test:1.0")

	content = []byte("this is a blob5")
	digest = godigest.FromBytes(content)
	// create a manifest with same blob but a different tag
	manifest = ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cdigest,
			Size:      int64(len(cblob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest,
				Size:      int64(len(content)),
			},
		},
	}
	manifest.SchemaVersion = 2

	content, err = json.Marshal(manifest)
	if err != nil {
		return err
	}
	_, _ = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(content).Put(url + "/v2/repo7/manifests/test:2.0")

	return nil
}

type mockService struct{}

func (service mockService) getRepos(ctx context.Context, config searchConfig, username,
	password string, channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	var catalog [3]string
	catalog[0] = "python"
	catalog[1] = "busybox"
	catalog[2] = "hello-world"

	channel <- stringResult{"", nil}
}

func (service mockService) getDerivedImageListGQL(ctx context.Context, config searchConfig, username, password string,
	derivedImage string,
) (*imageListStructForDerivedImagesGQL, error) {
	imageListGQLResponse := &imageListStructForDerivedImagesGQL{}
	imageListGQLResponse.Data.ImageList = []imageStruct{
		{
			RepoName: "dummyImageName",
			Tag:      "tag",
			Digest:   "DigestsAreReallyLong",
			Size:     "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getBaseImageListGQL(ctx context.Context, config searchConfig, username, password string,
	derivedImage string,
) (*imageListStructForBaseImagesGQL, error) {
	imageListGQLResponse := &imageListStructForBaseImagesGQL{}
	imageListGQLResponse.Data.ImageList = []imageStruct{
		{
			RepoName: "dummyImageName",
			Tag:      "tag",
			Digest:   "DigestsAreReallyLong",
			Size:     "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getImagesGQL(ctx context.Context, config searchConfig, username, password string,
	imageName string,
) (*imageListStructGQL, error) {
	imageListGQLResponse := &imageListStructGQL{}
	imageListGQLResponse.Data.ImageList = []imageStruct{
		{
			RepoName: "dummyImageName",
			Tag:      "tag",
			Digest:   "DigestsAreReallyLong",
			Size:     "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getImagesByDigestGQL(ctx context.Context, config searchConfig, username, password string,
	digest string,
) (*imageListStructForDigestGQL, error) {
	imageListGQLResponse := &imageListStructForDigestGQL{}
	imageListGQLResponse.Data.ImageList = []imageStruct{
		{
			RepoName: "randomimageName",
			Tag:      "tag",
			Digest:   "DigestsAreReallyLong",
			Size:     "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getImagesByCveIDGQL(ctx context.Context, config searchConfig, username, password string,
	digest string,
) (*imagesForCve, error) {
	imagesForCve := &imagesForCve{
		Errors: nil,
		Data: struct {
			ImageList []imageStruct `json:"ImageListForCVE"` //nolint:tagliatelle
		}{},
	}

	imagesForCve.Errors = nil

	mockedImage := service.getMockedImageByName("anImage")
	imagesForCve.Data.ImageList = []imageStruct{mockedImage}

	return imagesForCve, nil
}

func (service mockService) getTagsForCVEGQL(ctx context.Context, config searchConfig, username, password,
	imageName, cveID string,
) (*imagesForCve, error) {
	images := &imagesForCve{
		Errors: nil,
		Data: struct {
			ImageList []imageStruct `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
		}{},
	}

	images.Errors = nil

	mockedImage := service.getMockedImageByName(imageName)
	images.Data.ImageList = []imageStruct{mockedImage}

	return images, nil
}

func (service mockService) getFixedTagsForCVEGQL(ctx context.Context, config searchConfig, username, password,
	imageName, cveID string,
) (*fixedTags, error) {
	fixedTags := &fixedTags{
		Errors: nil,
		Data: struct {
			ImageList []imageStruct `json:"ImageListWithCVEFixed"` //nolint:tagliatelle // graphQL schema
		}{},
	}

	fixedTags.Errors = nil

	mockedImage := service.getMockedImageByName(imageName)
	fixedTags.Data.ImageList = []imageStruct{mockedImage}

	return fixedTags, nil
}

func (service mockService) getCveByImageGQL(ctx context.Context, config searchConfig, username, password,
	imageName string,
) (*cveResult, error) {
	cveRes := &cveResult{}
	cveRes.Data = cveData{
		CVEListForImage: cveListForImage{
			Tag: imageName,
			CVEList: []cve{
				{
					ID:          "dummyCVEID",
					Description: "Description of the CVE",
					Title:       "Title of that CVE",
					Severity:    "HIGH",
					PackageList: []packageList{
						{
							Name:             "packagename",
							FixedVersion:     "fixedver",
							InstalledVersion: "installedver",
						},
					},
				},
			},
		},
	}

	return cveRes, nil
}

//nolint:goconst
func (service mockService) getMockedImageByName(imageName string) imageStruct {
	image := imageStruct{}
	image.RepoName = imageName
	image.Tag = "tag"
	image.Digest = "DigestsAreReallyLong"
	image.Size = "123445"

	return image
}

func (service mockService) getAllImages(ctx context.Context, config searchConfig, username, password string,
	channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	image := &imageStruct{}
	image.RepoName = "randomimageName"
	image.Tag = "tag"
	image.Digest = "DigestsAreReallyLong"
	image.Size = "123445"

	str, err := image.string(*config.outputFormat, len(image.RepoName), len(image.Tag))
	if err != nil {
		channel <- stringResult{"", err}

		return
	}

	channel <- stringResult{str, nil}
}

func (service mockService) getImageByName(ctx context.Context, config searchConfig,
	username, password, imageName string, channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	image := &imageStruct{}
	image.RepoName = imageName
	image.Tag = "tag"
	image.Digest = "DigestsAreReallyLong"
	image.Size = "123445"

	str, err := image.string(*config.outputFormat, len(image.RepoName), len(image.Tag))
	if err != nil {
		channel <- stringResult{"", err}

		return
	}

	channel <- stringResult{str, nil}
}

func (service mockService) getCveByImage(ctx context.Context, config searchConfig, username, password,
	imageName string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(rch)

	cveRes := &cveResult{}
	cveRes.Data = cveData{
		CVEListForImage: cveListForImage{
			Tag: imageName,
			CVEList: []cve{
				{
					ID:          "dummyCVEID",
					Description: "Description of the CVE",
					Title:       "Title of that CVE",
					Severity:    "HIGH",
					PackageList: []packageList{
						{
							Name:             "packagename",
							FixedVersion:     "fixedver",
							InstalledVersion: "installedver",
						},
					},
				},
			},
		},
	}

	str, err := cveRes.string(*config.outputFormat)
	if err != nil {
		rch <- stringResult{"", err}

		return
	}

	rch <- stringResult{str, nil}
}

func (service mockService) getFixedTagsForCVE(ctx context.Context, config searchConfig,
	username, password, imageName, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	service.getImageByName(ctx, config, username, password, imageName, rch, wtgrp)
}

func (service mockService) getImageByNameAndCVEID(ctx context.Context, config searchConfig, username,
	password, imageName, cvid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	service.getImageByName(ctx, config, username, password, imageName, rch, wtgrp)
}

func (service mockService) getImagesByCveID(ctx context.Context, config searchConfig, username, password, cvid string,
	rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	service.getImageByName(ctx, config, username, password, "anImage", rch, wtgrp)
}

func (service mockService) getImagesByDigest(ctx context.Context, config searchConfig, username,
	password, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	service.getImageByName(ctx, config, username, password, "anImage", rch, wtgrp)
}

func makeConfigFile(content string) string {
	os.Setenv("HOME", os.TempDir())

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	configPath := path.Join(home + "/.zot")

	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		panic(err)
	}

	return configPath
}
