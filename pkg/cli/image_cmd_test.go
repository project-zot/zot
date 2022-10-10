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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag 6e2f80bf false 123kB")
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag 6e2f80bf false 123kB")
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
			So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag 6e2f80bf false 123kB")
			So(err, ShouldBeNil)
		})
	})

	Convey("Test image by digest", t, func() {
		args := []string{"imagetest", "--digest", "6e2f80bf", "--url", "someUrlImage"}
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE anImage tag 6e2f80bf false 123kB")
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
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = currentDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		cfg, layers, manifest, err := test.GetImageComponents(1)
		So(err, ShouldBeNil)

		repoName := "repo7"
		err = test.UploadImage(
			test.Image{
				Config:   cfg,
				Layers:   layers,
				Manifest: manifest,
				Tag:      "test:1.0",
			}, url, repoName)
		So(err, ShouldBeNil)

		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest := godigest.FromBytes(content)

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
		So(actual, ShouldContainSubstring, "repo7 test:1.0 6742241d true 447B")

		t.Log("Test getting all images using rest calls to get catalog and individual manifests")
		cmd = MockNewImageCommand(new(searchService))
		buff = &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 test:1.0 6742241d true 447B")

		err = os.Chdir(currentWorkingDir)
		So(err, ShouldBeNil)
	})

	Convey("Test with notation signature", t, func() {
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
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = currentDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		cfg, layers, manifest, err := test.GetImageComponents(1)
		So(err, ShouldBeNil)

		repoName := "repo7"
		err = test.UploadImage(
			test.Image{
				Config:   cfg,
				Layers:   layers,
				Manifest: manifest,
				Tag:      "0.0.1",
			}, url, repoName)
		So(err, ShouldBeNil)

		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		err = test.SignImageUsingNotary("repo7:0.0.1", port)
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
		So(actual, ShouldContainSubstring, "repo7 0.0.1 6742241d true 447B")

		t.Log("Test getting all images using rest calls to get catalog and individual manifests")
		cmd = MockNewImageCommand(new(searchService))
		buff = &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = space.ReplaceAllString(buff.String(), " ")
		actual = strings.TrimSpace(str)
		So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 0.0.1 6742241d true 447B")

		err = os.Chdir(currentWorkingDir)
		So(err, ShouldBeNil)
	})
}

//nolint:dupl
func TestDerivedImageList(t *testing.T) {
	port := test.GetFreePort()
	url := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()

	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	err := uploadManifestDerivedBase(url)
	if err != nil {
		panic(err)
	}

	t.Logf("rootDir: %s", ctlr.Config.Storage.RootDirectory)

	Convey("Test from real server", t, func() {
		Convey("Test derived images list working", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest", "--derived-images", "repo7:test:2.0"}
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
			So(actual, ShouldContainSubstring, "repo7 test:1.0 2694fdb0 false 824B")
		})

		Convey("Test derived images list fails", func() {
			args := []string{"imagetest", "--derived-images", "repo7:test:missing"}
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
			args := []string{"imagetest", "--derived-images", "repo7:test:2.0", "-o", "random"}
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
	port := test.GetFreePort()
	url := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	err := uploadManifestDerivedBase(url)
	if err != nil {
		panic(err)
	}

	t.Logf("rootDir: %s", ctlr.Config.Storage.RootDirectory)

	Convey("Test from real server", t, func() {
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
			So(actual, ShouldContainSubstring, "repo7 test:2.0 3fc80493 false 494B")
		})

		Convey("Test base images list fail", func() {
			args := []string{"imagetest", "--base-images", "repo7:test:missing"}
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIGNED SIZE dummyImageName tag 6e2f80bf false 123kB")
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
			`"configDigest": "sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0", `+
			`"digest": "sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6", `+
			`"layers": [ { "size": "0", `+
			`"digest": "sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6" } ], `+
			`"size": "123445", "isSigned": false }`)
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
			`reponame: dummyImageName tag: tag `+
				`configdigest: sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0 `+
				`digest: sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6 `+
				`layers: - size: 0 digest: sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6 `+
				`size: "123445" issigned: false`,
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
				`reponame: dummyImageName tag: tag `+
					`configdigest: sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0 `+
					`digest: sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6 `+
					`layers: - size: 0 digest: sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6 `+
					`size: "123445" issigned: false`,
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
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = t.TempDir()
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

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
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")
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
			// IMAGE NAME    TAG       DIGEST    CONFIG    SIGNED  LAYERS    SIZE
			// repo7         test:2.0  a0ca253b  b8781e88  false             492B
			//                                                     b8781e88  15B
			// repo7         test:1.0  a0ca253b  b8781e88  false             492B
			//                                                     b8781e88  15B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST CONFIG SIGNED LAYERS SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 3a1d2d0c false 492B b8781e88 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 3a1d2d0c false 492B b8781e88 15B")
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
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")
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
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")

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
				So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
				So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")
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
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")

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
				So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
				So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")
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
	port := test.GetFreePort()
	url := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port
	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	err := uploadManifest(url)
	if err != nil {
		panic(err)
	}

	t.Logf("%s", ctlr.Config.Storage.RootDirectory)

	Convey("Test from real server", t, func() {
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
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")
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
			// IMAGE NAME    TAG       DIGEST    CONFIG    SIGNED  LAYERS    SIZE
			// repo7         test:2.0  a0ca253b  b8781e88  false             492B
			//                                                     b8781e88  15B
			// repo7         test:1.0  a0ca253b  b8781e88  false             492B
			//                                                     b8781e88  15B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST CONFIG SIGNED LAYERS SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 3a1d2d0c false 492B b8781e88 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 3a1d2d0c false 492B b8781e88 15B")
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
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")
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
			// repo7         test:2.0  a0ca253b  492B
			// repo7         test:1.0  a0ca253b  492B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 883fc0c5 false 492B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 883fc0c5 false 492B")

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
	Convey("Test accessing a blobs folder without having permissions fails fast", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		test.CopyTestFiles("../../test/data/zot-test", path.Join(dir, "zot-test"))

		err := os.Chmod(path.Join(dir, "zot-test", "blobs"), 0o000)
		if err != nil {
			panic(err)
		}

		defer func() {
			err = os.Chmod(path.Join(dir, "zot-test", "blobs"), 0o777)
			if err != nil {
				panic(err)
			}
		}()

		conf.Storage.RootDirectory = dir
		defaultVal := true
		searchConfig := &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		}
		conf.Extensions = &extconf.ExtensionConfig{
			Search: searchConfig,
		}

		ctlr := api.NewController(conf)
		if err := ctlr.Init(context.Background()); err != nil {
			So(err, ShouldNotBeNil)
		}
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

func uploadManifestDerivedBase(url string) error {
	// create a blob/layer
	_, _ = resty.R().Post(url + "/v2/repo7/blobs/uploads/")

	content1 := []byte("this is a blob5.0")
	content2 := []byte("this is a blob5.1")
	content3 := []byte("this is a blob5.2")
	digest1 := godigest.FromBytes(content1)
	digest2 := godigest.FromBytes(content2)
	digest3 := godigest.FromBytes(content3)
	_, _ = resty.R().SetQueryParam("digest", digest1.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content1).Post(url + "/v2/repo7/blobs/uploads/")
	_, _ = resty.R().SetQueryParam("digest", digest2.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content2).Post(url + "/v2/repo7/blobs/uploads/")
	_, _ = resty.R().SetQueryParam("digest", digest3.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content3).Post(url + "/v2/repo7/blobs/uploads/")

	// upload image config blob
	resp, _ := resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc := test.Location(url, resp)
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
				Digest:    digest1,
				Size:      int64(len(content1)),
			}, {
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest2,
				Size:      int64(len(content2)),
			}, {
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest3,
				Size:      int64(len(content3)),
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

	content1 = []byte("this is a blob5.0")
	digest1 = godigest.FromBytes(content1)
	// create a manifest with one common layer blob
	manifest = ispec.Manifest{
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cdigest,
			Size:      int64(len(cblob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    digest1,
				Size:      int64(len(content1)),
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
	imageListGQLResponse.Data.ImageList.Results = []imageStruct{
		{
			RepoName:     "dummyImageName",
			Tag:          "tag",
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Size:         "123445",
			Layers:       []layer{{Digest: godigest.FromString("LayerDigest").String()}},
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getBaseImageListGQL(ctx context.Context, config searchConfig, username, password string,
	derivedImage string,
) (*imageListStructForBaseImagesGQL, error) {
	imageListGQLResponse := &imageListStructForBaseImagesGQL{}
	imageListGQLResponse.Data.ImageList.Results = []imageStruct{
		{
			RepoName:     "dummyImageName",
			Tag:          "tag",
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Size:         "123445",
			Layers:       []layer{{Digest: godigest.FromString("LayerDigest").String()}},
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
			RepoName:     "dummyImageName",
			Tag:          "tag",
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Size:         "123445",
			Layers:       []layer{{Digest: godigest.FromString("LayerDigest").String()}},
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
			RepoName:     "randomimageName",
			Tag:          "tag",
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Size:         "123445",
			Layers:       []layer{{Digest: godigest.FromString("LayerDigest").String()}},
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
	image.Digest = godigest.FromString("Digest").String()
	image.ConfigDigest = godigest.FromString("ConfigDigest").String()
	image.Size = "123445"
	image.Layers = []layer{{Digest: godigest.FromString("LayerDigest").String()}}

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
	image.Digest = godigest.FromString("Digest").String()
	image.ConfigDigest = godigest.FromString("ConfigDigest").String()
	image.Size = "123445"
	image.Layers = []layer{{Digest: godigest.FromString("LayerDigest").String()}}

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
	image.Digest = godigest.FromString("Digest").String()
	image.ConfigDigest = godigest.FromString("ConfigDigest").String()
	image.Size = "123445"
	image.Layers = []layer{{Digest: godigest.FromString("LayerDigest").String()}}

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
