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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/cobra"
	"gopkg.in/resty.v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/cli/cmdflags"
	"zotregistry.io/zot/pkg/common"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	zlog "zotregistry.io/zot/pkg/log"
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
		So(err, ShouldEqual, zerr.ErrNoURLProvided)
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
		So(err, ShouldEqual, zerr.ErrInvalidURL)
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
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
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
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
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
			So(strings.TrimSpace(str), ShouldEqual,
				"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
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
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE anImage tag os/arch 6e2f80bf false 123kB")
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
			So(err, ShouldEqual, zerr.ErrInvalidURL)
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

		cfg, layers, manifest, err := test.GetImageComponents(1) //nolint:staticcheck
		So(err, ShouldBeNil)

		repoName := "repo7"
		err = test.UploadImage(
			test.Image{
				Config:   cfg,
				Layers:   layers,
				Manifest: manifest,
			}, url, repoName, "test:1.0")
		So(err, ShouldBeNil)

		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		digest := godigest.FromBytes(content)

		// generate a keypair
		if _, err := os.Stat(path.Join(currentDir, "cosign.key")); err != nil {
			os.Setenv("COSIGN_PASSWORD", "")
			err = generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
			So(err, ShouldBeNil)
		}

		_, err = os.Stat(path.Join(currentDir, "cosign.key"))
		So(err, ShouldBeNil)

		// sign the image
		err = sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
			options.KeyOpts{KeyRef: path.Join(currentDir, "cosign.key"), PassFunc: generate.GetPass},
			options.SignOptions{
				Registry:          options.RegistryOptions{AllowInsecure: true},
				AnnotationOptions: options.AnnotationOptions{Annotations: []string{"tag=test:1.0"}},
				Upload:            true,
			},
			[]string{fmt.Sprintf("localhost:%s/%s@%s", port, "repo7", digest.String())})
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
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 8e59ed3b true 504B")

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
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 8e59ed3b true 504B")

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

		cfg, layers, manifest, err := test.GetImageComponents(1) //nolint:staticcheck
		So(err, ShouldBeNil)

		repoName := "repo7"
		err = test.UploadImage(
			test.Image{
				Config:   cfg,
				Layers:   layers,
				Manifest: manifest,
			}, url, repoName, "0.0.1")
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
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 0.0.1 linux/amd64 8e59ed3b true 504B")

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
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 0.0.1 linux/amd64 8e59ed3b true 504B")

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
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 9d9461ed false 860B")
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
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 214e4bed false 530B")
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
		So(strings.TrimSpace(str), ShouldEqual,
			"REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE dummyImageName tag os/arch 6e2f80bf false 123kB")
		So(err, ShouldBeNil)
	})

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
		// Output is supposed to be in json lines format, keep all spaces as is for verification
		So(buff.String(), ShouldEqual, `{"repoName":"dummyImageName","tag":"tag",`+
			`"digest":"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",`+
			`"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
			`"manifests":[{"digest":"sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6",`+
			`"configDigest":"sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0",`+
			`"lastUpdated":"0001-01-01T00:00:00Z","size":"123445","platform":{"os":"os","arch":"arch",`+
			`"variant":""},"isSigned":false,"downloadCount":0,`+
			`"layers":[{"size":"","digest":"sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6",`+
			`"score":0}],"history":null,"vulnerabilities":{"maxSeverity":"","count":0},`+
			`"referrers":null,"artifactType":"","signatureInfo":null}],"size":"123445",`+
			`"downloadCount":0,"lastUpdated":"0001-01-01T00:00:00Z","description":"","isSigned":false,"licenses":"",`+
			`"labels":"","title":"","source":"","documentation":"","authors":"","vendor":"",`+
			`"vulnerabilities":{"maxSeverity":"","count":0},"referrers":null,"signatureInfo":null}`+"\n")
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
			`--- reponame: dummyImageName tag: tag `+
				`digest: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 `+
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - `+
				`digest: sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6 `+
				`configdigest: sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0 `+
				`lastupdated: 0001-01-01T00:00:00Z size: "123445" platform: os: os arch: arch variant: "" `+
				`issigned: false downloadcount: 0 layers: - size: "" `+
				`digest: sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6 score: 0 `+
				`history: [] vulnerabilities: maxseverity: "" count: 0 referrers: [] artifacttype: "" `+
				`signatureinfo: [] size: "123445" downloadcount: 0 `+
				`lastupdated: 0001-01-01T00:00:00Z description: "" issigned: false licenses: "" labels: "" `+
				`title: "" source: "" documentation: "" authors: "" vendor: "" vulnerabilities: maxseverity: "" `+
				`count: 0 referrers: [] signatureinfo: []`,
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
				`--- reponame: dummyImageName tag: tag `+
					`digest: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 `+
					`mediatype: application/vnd.oci.image.manifest.v1+json `+
					`manifests: - digest: sha256:6e2f80bf9cfaabad474fbaf8ad68fdb652f776ea80b63492ecca404e5f6446a6 `+
					`configdigest: sha256:4c10985c40365538426f2ba8cf0c21384a7769be502a550dcc0601b3736625e0 `+
					`lastupdated: 0001-01-01T00:00:00Z size: "123445" platform: os: os arch: arch variant: "" `+
					`issigned: false downloadcount: 0 layers: - size: "" `+
					`digest: sha256:c122a146f0d02349be211bb95cc2530f4a5793f96edbdfa00860f741e5d8c0e6 score: 0 `+
					`history: [] vulnerabilities: maxseverity: "" count: 0 referrers: [] artifacttype: "" `+
					`signatureinfo: [] size: "123445" downloadcount: 0 `+
					`lastupdated: 0001-01-01T00:00:00Z description: "" issigned: false licenses: "" labels: "" `+
					`title: "" source: "" documentation: "" authors: "" vendor: "" vulnerabilities: maxseverity: `+
					`"" count: 0 referrers: [] signatureinfo: []`,
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

func TestOutputFormatGQL(t *testing.T) {
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

		Convey("Test json", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"imagetest", "--name", "repo7", "-o", "json"}
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))
			defer os.Remove(configPath)
			cmd := NewImageCommand(new(searchService))
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			expectedStr := `{"repoName":"repo7","tag":"test:1.0",` +
				`"digest":"sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06",` +
				`"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
				`"manifests":[{"digest":"sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06",` +
				`"configDigest":"sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e",` +
				`"lastUpdated":"2023-01-01T12:00:00Z","size":"528","platform":{"os":"linux","arch":"amd64",` +
				`"variant":""},"isSigned":false,"downloadCount":0,"layers":[{"size":"15","digest":` +
				`"sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6","score":0}],` +
				`"history":null,"vulnerabilities":{"maxSeverity":"","count":0},` +
				`"referrers":null,"artifactType":"","signatureInfo":null}],` +
				`"size":"528","downloadCount":0,"lastUpdated":"2023-01-01T12:00:00Z","description":"","isSigned":false,` +
				`"licenses":"","labels":"","title":"","source":"","documentation":"","authors":"","vendor":"",` +
				`"vulnerabilities":{"maxSeverity":"","count":0},"referrers":null,"signatureInfo":null}` + "\n" +
				`{"repoName":"repo7","tag":"test:2.0",` +
				`"digest":"sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06",` +
				`"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
				`"manifests":[{"digest":"sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06",` +
				`"configDigest":"sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e",` +
				`"lastUpdated":"2023-01-01T12:00:00Z","size":"528","platform":{"os":"linux","arch":"amd64",` +
				`"variant":""},"isSigned":false,"downloadCount":0,"layers":[{"size":"15","digest":` +
				`"sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6","score":0}],` +
				`"history":null,"vulnerabilities":{"maxSeverity":"","count":0},` +
				`"referrers":null,"artifactType":"","signatureInfo":null}],` +
				`"size":"528","downloadCount":0,"lastUpdated":"2023-01-01T12:00:00Z","description":"","isSigned":false,` +
				`"licenses":"","labels":"","title":"","source":"","documentation":"","authors":"","vendor":"",` +
				`"vulnerabilities":{"maxSeverity":"","count":0},"referrers":null,"signatureInfo":null}` + "\n"
			// Output is supposed to be in json lines format, keep all spaces as is for verification
			So(buff.String(), ShouldEqual, expectedStr)
			So(err, ShouldBeNil)
		})

		Convey("Test yaml", func() {
			args := []string{"imagetest", "--name", "repo7", "-o", "yaml"}
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
			expectedStr := `--- reponame: repo7 tag: test:1.0 ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`configdigest: sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e ` +
				`lastupdated: 2023-01-01T12:00:00Z size: "528" platform: os: linux arch: amd64 variant: "" ` +
				`issigned: false downloadcount: 0 layers: - size: "15" ` +
				`digest: sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6 score: 0 ` +
				`history: [] vulnerabilities: maxseverity: "" ` +
				`count: 0 referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" count: 0 referrers: [] signatureinfo: [] ` +
				`--- reponame: repo7 tag: test:2.0 ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`configdigest: sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e ` +
				`lastupdated: 2023-01-01T12:00:00Z size: "528" platform: os: linux arch: amd64 variant: "" ` +
				`issigned: false downloadcount: 0 layers: - size: "15" ` +
				`digest: sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6 score: 0 ` +
				`history: [] vulnerabilities: maxseverity: "" ` +
				`count: 0 referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" count: 0 referrers: [] signatureinfo: []`
			So(strings.TrimSpace(str), ShouldEqual, expectedStr)
			So(err, ShouldBeNil)
		})

		Convey("Test yml", func() {
			args := []string{"imagetest", "--name", "repo7", "-o", "yml"}
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
			expectedStr := `--- reponame: repo7 tag: test:1.0 ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`configdigest: sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e ` +
				`lastupdated: 2023-01-01T12:00:00Z size: "528" platform: os: linux arch: amd64 variant: "" ` +
				`issigned: false downloadcount: 0 layers: - size: "15" ` +
				`digest: sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6 score: 0 ` +
				`history: [] vulnerabilities: maxseverity: "" ` +
				`count: 0 referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" ` +
				`count: 0 referrers: [] signatureinfo: [] ` +
				`--- reponame: repo7 tag: test:2.0 ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`configdigest: sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e ` +
				`lastupdated: 2023-01-01T12:00:00Z size: "528" platform: os: linux arch: amd64 variant: "" ` +
				`issigned: false downloadcount: 0 layers: - size: "15" ` +
				`digest: sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6 score: 0 ` +
				`history: [] vulnerabilities: maxseverity: "" ` +
				`count: 0 referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" count: 0 referrers: [] signatureinfo: []`
			So(strings.TrimSpace(str), ShouldEqual, expectedStr)
			So(err, ShouldBeNil)
		})

		Convey("Test invalid", func() {
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
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
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
			// REPOSITORY    TAG       OS/ARCH     DIGEST    CONFIG    SIGNED  LAYERS    SIZE
			// repo7         test:2.0  linux/amd64 51e18f50  d14faead  false             528B
			//                                                                 b8781e88  15B
			// repo7         test:1.0  linux/amd64 51e18f50  d14faead  false             528B
			//                                                                 b8781e88  15B
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST CONFIG SIGNED LAYERS SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 d14faead false 528B b8781e88 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 d14faead false 528B b8781e88 15B")
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
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
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
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")

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
				So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
				So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
				So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
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
			args := []string{"imagetest", "--digest", "51e18f50"}
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
			// REPOSITORY    TAG       OS/ARCH DIGEST    SIZE
			// repo7         test:2.0          a0ca253b  15B
			// repo7         test:1.0          a0ca253b  15B
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")

			Convey("with shorthand", func() {
				args := []string{"imagetest", "-d", "51e18f50"}
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
				So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
				So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
				So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
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
				args := []string{"imagetest", "--digest", "51e18f50", "-o", "random"}
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
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
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
			// REPOSITORY    TAG        OS/ARCH     DIGEST    CONFIG     SIGNED  LAYERS    SIZE
			// repo7         test:2.0   linux/amd64 51e18f50  d14faead   false             528B
			//                                                                    b8781e88  15B
			// repo7         test:1.0   linux/amd64 51e18f50  d14faead   false             528B
			//                                                                    b8781e88  15B
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST CONFIG SIGNED LAYERS SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 d14faead false 528B b8781e88 15B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 d14faead false 528B b8781e88 15B")
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
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
		})

		Convey("Test image by digest", func() {
			args := []string{"imagetest", "--digest", "51e18f50"}
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
			// REPOSITORY    TAG       OS/ARCH      DIGEST     SIZE
			// repo7         test:2.0  linux/amd64  51e18f50   528B
			// repo7         test:1.0  linux/amd64  51e18f50   528B
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")

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

		srcStorageCtlr := test.GetDefaultStoreController(dir, zlog.NewLogger("debug", ""))
		err := test.WriteImageToFileSystem(test.CreateDefaultImage(), "zot-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "zot-test", "blobs"), 0o000)
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

func TestDisplayIndex(t *testing.T) {
	Convey("Init Basic Server, No GQL", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port

		Convey("No GQL", func() {
			defaultVal := false
			conf.Extensions = &extconf.ExtensionConfig{
				Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(conf.HTTP.Port)
			defer cm.StopServer()

			runDisplayIndexTests(baseURL)
		})

		Convey("With GQL", func() {
			defaultVal := true
			conf.Extensions = &extconf.ExtensionConfig{
				Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
			}
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = t.TempDir()
			cm := test.NewControllerManager(ctlr)

			cm.StartAndWait(conf.HTTP.Port)
			defer cm.StopServer()

			runDisplayIndexTests(baseURL)
		})
	})
}

func runDisplayIndexTests(baseURL string) {
	Convey("Test Image Index", func() {
		uploadTestMultiarch(baseURL)

		args := []string{"imagetest"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
			baseURL))
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
		// REPOSITORY    TAG        OS/ARCH           DIGEST    SIGNED  SIZE
		// repo          multi-arch *                 28665f71  false   1.5kB
		//                          linux/amd64       02e0ac42  false   644B
		//                          windows/arm64/v6  5e09b7f9  false   444B
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo multi-arch * 28665f71 false 1.5kB ")
		So(actual, ShouldContainSubstring, "linux/amd64 02e0ac42 false 644B ")
		So(actual, ShouldContainSubstring, "windows/arm64/v6 5e09b7f9 false 506B")
	})

	Convey("Test Image Index Verbose", func() {
		uploadTestMultiarch(baseURL)

		args := []string{"imagetest", "--verbose"}
		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
			baseURL))
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
		// REPOSITORY    TAG        OS/ARCH           DIGEST    CONFIG    SIGNED  LAYERS    SIZE
		// repo          multi-arch *                 28665f71            false             1.5kB
		//                          linux/amd64       02e0ac42  58cc9abe  false             644B
		//                                                                        cbb5b121  4B
		//                                                                        a00291e8  4B
		//                          windows/arm64/v6  5e09b7f9  5132a1cd  false             506B
		//                                                                        7d08ce29  4B
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST CONFIG SIGNED LAYERS SIZE")
		So(actual, ShouldContainSubstring, "repo multi-arch * 28665f71 false 1.5kB")
		So(actual, ShouldContainSubstring, "linux/amd64 02e0ac42 58cc9abe false 644B")
		So(actual, ShouldContainSubstring, "cbb5b121 4B")
		So(actual, ShouldContainSubstring, "a00291e8 4B")
		So(actual, ShouldContainSubstring, "windows/arm64/v6 5e09b7f9 5132a1cd false 506B")
		So(actual, ShouldContainSubstring, "7d08ce29 4B")
	})
}

func TestImagesCommandGQL(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
		},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	Convey("commands with gql", t, func() {
		err := test.RemoveLocalStorageContents(ctlr.StoreController.DefaultStore)
		So(err, ShouldBeNil)

		Convey("base and derived command", func() {
			baseImage := test.CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}},
			).DefaultConfig().Build()

			derivedImage := test.CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}, {44, 55, 66}},
			).DefaultConfig().Build()

			err := test.UploadImage(baseImage, baseURL, "repo", "base")
			So(err, ShouldBeNil)

			err = test.UploadImage(derivedImage, baseURL, "repo", "derived")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"base", "repo:derived"}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "repo base linux/amd64 df554ddd false 699B")

			args = []string{"derived", "repo:base"}
			cmd = NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "repo derived linux/amd64 79f4b82e false 854B")
		})

		Convey("base and derived command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"too", "many", "args"}
			cmd := NewImageBaseCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			cmd = NewImageDerivedCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad input
			buff = bytes.NewBufferString("")
			args = []string{"only-repo"}
			cmd = NewImageBaseCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			cmd = NewImageDerivedCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{"repo:tag"}
			cmd = NewImageBaseCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			cmd = NewImageDerivedCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("digest command", func() {
			image := test.CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

			err := test.UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"digest", image.DigestStr()}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, fmt.Sprintf("repo img linux/amd64 %s false 552B",
				image.DigestStr()[7:7+8]))
		})

		Convey("digest command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"too", "many", "args"}
			cmd := NewImageDigestCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad input
			buff = bytes.NewBufferString("")
			args = []string{"bad-digest"}
			cmd = NewImageDigestCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{godigest.FromString("str").String()}
			cmd = NewImageDigestCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("list command", func() {
			image := test.CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

			err := test.UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"list"}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			fmt.Println(actual)
			So(actual, ShouldContainSubstring, fmt.Sprintf("repo img linux/amd64 %s false 552B",
				image.DigestStr()[7:7+8]))
			fmt.Println(actual)
		})

		Convey("list command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"repo:img", "arg"}
			cmd := NewImageListCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{}
			cmd = NewImageListCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("name command", func() {
			image := test.CreateImageWith().RandomLayers(1, 10).DefaultConfig().Build()

			err := test.UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			err = test.UploadImage(test.CreateRandomImage(), baseURL, "repo", "img2")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"name", "repo:img"}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			fmt.Println(actual)
			So(actual, ShouldContainSubstring, fmt.Sprintf("repo img linux/amd64 %s false 552B",
				image.DigestStr()[7:7+8]))
			fmt.Println(actual)
		})

		Convey("name command errors", func() {
			// too many parameters
			buff := bytes.NewBufferString("")
			args := []string{"repo:img", "arg"}
			cmd := NewImageNameCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)

			// bad input
			buff = bytes.NewBufferString("")
			args = []string{":tag"}
			cmd = NewImageNameCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			// no url
			buff = bytes.NewBufferString("")
			args = []string{"repo:tag"}
			cmd = NewImageNameCommand(NewSearchService())
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("CVE", func() {
			vulnImage := test.CreateDefaultVulnerableImage()
			err := test.UploadImage(vulnImage, baseURL, "repo", "vuln")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"cve", "repo:vuln"}
			defer os.Remove(configPath)
			cmd := NewImagesCommand(mockService{})
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "dummyCVEID HIGH Title of that CVE")
		})

		Convey("CVE errors", func() {
			count := 0
			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"cve", "repo:vuln"}
			defer os.Remove(configPath)
			cmd := NewImagesCommand(mockService{
				getCveByImageGQLFn: func(ctx context.Context, config searchConfig, username, password,
					imageName, searchedCVE string) (*cveResult, error,
				) {
					if count == 0 {
						count++
						fmt.Println("Count:", count)

						return &cveResult{}, zerr.ErrCVEDBNotFound
					}

					return &cveResult{}, zerr.ErrInjected
				},
			})
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "[warning] CVE DB is not ready")
		})
	})

	Convey("Config error", t, func() {
		args := []string{"base", "repo:derived"}
		cmd := NewImagesCommand(NewSearchService())
		cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldNotBeNil)
		So(err, ShouldNotBeNil)

		args = []string{"derived", "repo:base"}
		cmd = NewImagesCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"digest", ispec.DescriptorEmptyJSON.Digest.String()}
		cmd = NewImagesCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"list"}
		cmd = NewImagesCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"name", "repo:img"}
		cmd = NewImagesCommand(NewSearchService())
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)

		args = []string{"cve", "repo:vuln"}
		cmd = NewImagesCommand(mockService{})
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldNotBeNil)
	})
}

func TestImageCommandREST(t *testing.T) {
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = t.TempDir()
	cm := test.NewControllerManager(ctlr)

	cm.StartAndWait(conf.HTTP.Port)
	defer cm.StopServer()

	Convey("commands without gql", t, func() {
		err := test.RemoveLocalStorageContents(ctlr.StoreController.DefaultStore)
		So(err, ShouldBeNil)

		Convey("base and derived command", func() {
			baseImage := test.CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}},
			).DefaultConfig().Build()

			derivedImage := test.CreateImageWith().LayerBlobs(
				[][]byte{{1, 2, 3}, {11, 22, 33}, {44, 55, 66}},
			).DefaultConfig().Build()

			err := test.UploadImage(baseImage, baseURL, "repo", "base")
			So(err, ShouldBeNil)

			err = test.UploadImage(derivedImage, baseURL, "repo", "derived")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"base", "repo:derived"}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)

			args = []string{"derived", "repo:base"}
			cmd = NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff = bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("digest command", func() {
			image := test.CreateRandomImage()

			err := test.UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"digest", image.DigestStr()}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("list command", func() {
			image := test.CreateRandomImage()

			err := test.UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"list"}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
			fmt.Println()
		})

		Convey("name command", func() {
			image := test.CreateRandomImage()

			err := test.UploadImage(image, baseURL, "repo", "img")
			So(err, ShouldBeNil)

			err = test.UploadImage(test.CreateRandomImage(), baseURL, "repo", "img2")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			defer os.Remove(configPath)

			args := []string{"name", "repo:img"}
			cmd := NewImagesCommand(NewSearchService())
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
			fmt.Println()
		})

		Convey("CVE", func() {
			vulnImage := test.CreateDefaultVulnerableImage()
			err := test.UploadImage(vulnImage, baseURL, "repo", "vuln")
			So(err, ShouldBeNil)

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`,
				baseURL))
			args := []string{"cve", "repo:vuln"}
			defer os.Remove(configPath)
			cmd := NewImagesCommand(mockService{})
			cmd.PersistentFlags().String(cmdflags.ConfigFlag, "imagetest", "")
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func uploadTestMultiarch(baseURL string) {
	// ------- Define Image1
	layer11 := []byte{11, 12, 13, 14}
	layer12 := []byte{16, 17, 18, 19}

	image1 := test.CreateImageWith().
		LayerBlobs([][]byte{
			layer11,
			layer12,
		}).
		ImageConfig(
			ispec.Image{
				Platform: ispec.Platform{OS: "linux", Architecture: "amd64"},
			},
		).Build()

	// ------ Define Image2
	layer21 := []byte{21, 22, 23, 24}

	image2 := test.CreateImageWith().
		LayerBlobs([][]byte{
			layer21,
		}).
		ImageConfig(
			ispec.Image{
				Platform: ispec.Platform{OS: "windows", Architecture: "arm64", Variant: "v6"},
			},
		).Build()

	// ------- Upload The multiarch image

	multiarch := test.GetMultiarchImageForImages([]test.Image{image1, image2}) //nolint:staticcheck

	err := test.UploadMultiarchImage(multiarch, baseURL, "repo", "multi-arch")
	So(err, ShouldBeNil)
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

			configPath := path.Join(home, "/.zot")
			if len(args) > 0 {
				urlFromConfig, err := getConfigValue(configPath, args[0], "url")
				if err != nil {
					cmd.SilenceUsage = true

					return err
				}

				if urlFromConfig == "" {
					return zerr.ErrNoURLProvided
				}

				servURL = urlFromConfig
			} else {
				return zerr.ErrNoURLProvided
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

	return zerr.ErrInvalidFlagsCombination
}

func uploadManifest(url string) error {
	// create and upload a blob/layer
	resp, _ := resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc := test.Location(url, resp)

	content := []byte("this is a blob5")
	digest := godigest.FromBytes(content)
	_, _ = resty.R().SetQueryParam("digest", digest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)

	// create config
	createdTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	config := ispec.Image{
		Created: &createdTime,
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "some author",
	}

	cblob, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		return err
	}

	cdigest := godigest.FromBytes(cblob)

	// upload image config blob
	resp, _ = resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc = test.Location(url, resp)

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

	// create config
	createdTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	config := ispec.Image{
		Created: &createdTime,
		Platform: ispec.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{},
		},
		Author: "some author",
	}

	cblob, err := json.MarshalIndent(&config, "", "\t")
	if err != nil {
		return err
	}

	cdigest := godigest.FromBytes(cblob)

	// upload image config blob
	resp, _ := resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc := test.Location(url, resp)

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

type mockService struct {
	getAllImagesFn func(ctx context.Context, config searchConfig, username, password string,
		channel chan stringResult, wtgrp *sync.WaitGroup)

	getImagesGQLFn func(ctx context.Context, config searchConfig, username, password string,
		imageName string) (*common.ImageListResponse, error)

	getImageByNameFn func(ctx context.Context, config searchConfig,
		username, password, imageName string, channel chan stringResult, wtgrp *sync.WaitGroup,
	)

	getFixedTagsForCVEFn func(ctx context.Context, config searchConfig,
		username, password, imageName, cveid string, rch chan stringResult, wtgrp *sync.WaitGroup,
	)

	getImageByNameAndCVEIDFn func(ctx context.Context, config searchConfig, username,
		password, imageName, cveid string, rch chan stringResult, wtgrp *sync.WaitGroup,
	)

	getImagesByCveIDFn func(ctx context.Context, config searchConfig, username, password, cveid string,
		rch chan stringResult, wtgrp *sync.WaitGroup,
	)

	getImagesByDigestFn func(ctx context.Context, config searchConfig, username,
		password, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
	)

	getReferrersFn func(ctx context.Context, config searchConfig, username, password string,
		repo, digest string,
	) (referrersResult, error)

	globalSearchGQLFn func(ctx context.Context, config searchConfig, username, password string,
		query string,
	) (*common.GlobalSearch, error)

	getReferrersGQLFn func(ctx context.Context, config searchConfig, username, password string,
		repo, digest string,
	) (*common.ReferrersResp, error)

	getDerivedImageListGQLFn func(ctx context.Context, config searchConfig, username, password string,
		derivedImage string,
	) (*common.DerivedImageListResponse, error)

	getBaseImageListGQLFn func(ctx context.Context, config searchConfig, username, password string,
		derivedImage string,
	) (*common.BaseImageListResponse, error)

	getImagesForDigestGQLFn func(ctx context.Context, config searchConfig, username, password string,
		digest string,
	) (*common.ImagesForDigest, error)

	getCveByImageGQLFn func(ctx context.Context, config searchConfig, username, password,
		imageName, searchedCVE string,
	) (*cveResult, error)

	getImagesByCveIDGQLFn func(ctx context.Context, config searchConfig, username, password string,
		digest string,
	) (*common.ImagesForCve, error)

	getTagsForCVEGQLFn func(ctx context.Context, config searchConfig, username, password,
		imageName, cveID string,
	) (*common.ImagesForCve, error)

	getFixedTagsForCVEGQLFn func(ctx context.Context, config searchConfig, username, password,
		imageName, cveID string,
	) (*common.ImageListWithCVEFixedResponse, error)
}

func (service mockService) getRepos(ctx context.Context, config searchConfig, username,
	password string, channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	fmt.Fprintln(config.resultWriter, "\n\nREPOSITORY NAME")

	fmt.Fprintln(config.resultWriter, "repo1")
	fmt.Fprintln(config.resultWriter, "repo2")
}

func (service mockService) getReferrers(ctx context.Context, config searchConfig, username, password string,
	repo, digest string,
) (referrersResult, error) {
	if service.getReferrersFn != nil {
		return service.getReferrersFn(ctx, config, username, password, repo, digest)
	}

	return referrersResult{
		common.Referrer{
			ArtifactType: "art.type",
			Digest:       ispec.DescriptorEmptyJSON.Digest.String(),
			MediaType:    ispec.MediaTypeImageManifest,
			Size:         100,
		},
	}, nil
}

func (service mockService) globalSearchGQL(ctx context.Context, config searchConfig, username, password string,
	query string,
) (*common.GlobalSearch, error) {
	if service.globalSearchGQLFn != nil {
		return service.globalSearchGQLFn(ctx, config, username, password, query)
	}

	return &common.GlobalSearch{
		Images: []common.ImageSummary{
			{
				RepoName:  "repo",
				MediaType: ispec.MediaTypeImageManifest,
				Size:      "100",
				Manifests: []common.ManifestSummary{
					{
						Digest:       godigest.FromString("str").String(),
						Size:         "100",
						ConfigDigest: ispec.DescriptorEmptyJSON.Digest.String(),
					},
				},
			},
		},
		Repos: []common.RepoSummary{
			{
				Name:        "repo",
				Size:        "100",
				LastUpdated: time.Date(2010, 1, 1, 1, 1, 1, 0, time.UTC),
			},
		},
	}, nil
}

func (service mockService) getReferrersGQL(ctx context.Context, config searchConfig, username, password string,
	repo, digest string,
) (*common.ReferrersResp, error) {
	if service.getReferrersGQLFn != nil {
		return service.getReferrersGQLFn(ctx, config, username, password, repo, digest)
	}

	return &common.ReferrersResp{
		ReferrersResult: common.ReferrersResult{
			Referrers: []common.Referrer{
				{
					MediaType:    "MediaType",
					ArtifactType: "ArtifactType",
					Size:         100,
					Digest:       "Digest",
				},
			},
		},
	}, nil
}

func (service mockService) getDerivedImageListGQL(ctx context.Context, config searchConfig, username, password string,
	derivedImage string,
) (*common.DerivedImageListResponse, error) {
	if service.getDerivedImageListGQLFn != nil {
		return service.getDerivedImageListGQLFn(ctx, config, username, password, derivedImage)
	}

	imageListGQLResponse := &common.DerivedImageListResponse{}
	imageListGQLResponse.DerivedImageList.Results = []common.ImageSummary{
		{
			RepoName: "dummyImageName",
			Tag:      "tag",
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Size:         "123445",
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getBaseImageListGQL(ctx context.Context, config searchConfig, username, password string,
	baseImage string,
) (*common.BaseImageListResponse, error) {
	if service.getBaseImageListGQLFn != nil {
		return service.getBaseImageListGQLFn(ctx, config, username, password, baseImage)
	}

	imageListGQLResponse := &common.BaseImageListResponse{}
	imageListGQLResponse.BaseImageList.Results = []common.ImageSummary{
		{
			RepoName: "dummyImageName",
			Tag:      "tag",
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Size:         "123445",
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getImagesGQL(ctx context.Context, config searchConfig, username, password string,
	imageName string,
) (*common.ImageListResponse, error) {
	if service.getImagesGQLFn != nil {
		return service.getImagesGQLFn(ctx, config, username, password, imageName)
	}

	imageListGQLResponse := &common.ImageListResponse{}
	imageListGQLResponse.PaginatedImagesResult.Results = []common.ImageSummary{
		{
			RepoName:  "dummyImageName",
			Tag:       "tag",
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    godigest.FromString("test").String(),
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Size:         "123445",
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getImagesForDigestGQL(ctx context.Context, config searchConfig, username, password string,
	digest string,
) (*common.ImagesForDigest, error) {
	if service.getImagesForDigestGQLFn != nil {
		return service.getImagesForDigestGQLFn(ctx, config, username, password, digest)
	}

	imageListGQLResponse := &common.ImagesForDigest{}
	imageListGQLResponse.Results = []common.ImageSummary{
		{
			RepoName:  "randomimageName",
			Tag:       "tag",
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    godigest.FromString("test").String(),
			Manifests: []common.ManifestSummary{
				{
					Digest:       godigest.FromString("Digest").String(),
					ConfigDigest: godigest.FromString("ConfigDigest").String(),
					Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
					Size:         "123445",
				},
			},
			Size: "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getImagesByCveIDGQL(ctx context.Context, config searchConfig, username, password string,
	digest string,
) (*common.ImagesForCve, error) {
	if service.getImagesByCveIDGQLFn != nil {
		return service.getImagesByCveIDGQLFn(ctx, config, username, password, digest)
	}

	imagesForCve := &common.ImagesForCve{
		Errors: nil,
		ImagesForCVEList: struct {
			common.PaginatedImagesResult `json:"ImageListForCVE"` //nolint:tagliatelle
		}{},
	}

	imagesForCve.Errors = nil

	mockedImage := service.getMockedImageByName("anImage")
	imagesForCve.Results = []common.ImageSummary{common.ImageSummary(mockedImage)}

	return imagesForCve, nil
}

func (service mockService) getTagsForCVEGQL(ctx context.Context, config searchConfig, username, password,
	imageName, cveID string,
) (*common.ImagesForCve, error) {
	if service.getTagsForCVEGQLFn != nil {
		return service.getTagsForCVEGQLFn(ctx, config, username, password, imageName, cveID)
	}

	images := &common.ImagesForCve{
		Errors: nil,
		ImagesForCVEList: struct {
			common.PaginatedImagesResult `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
		}{},
	}

	if imageName == "" {
		imageName = "image-name"
	}

	images.Errors = nil

	mockedImage := service.getMockedImageByName(imageName)
	images.Results = []common.ImageSummary{common.ImageSummary(mockedImage)}

	return images, nil
}

func (service mockService) getFixedTagsForCVEGQL(ctx context.Context, config searchConfig, username, password,
	imageName, cveID string,
) (*common.ImageListWithCVEFixedResponse, error) {
	if service.getFixedTagsForCVEGQLFn != nil {
		return service.getFixedTagsForCVEGQLFn(ctx, config, username, password, imageName, cveID)
	}

	fixedTags := &common.ImageListWithCVEFixedResponse{
		Errors: nil,
		ImageListWithCVEFixed: struct {
			common.PaginatedImagesResult `json:"ImageListWithCVEFixed"` //nolint:tagliatelle // graphQL schema
		}{},
	}

	fixedTags.Errors = nil

	mockedImage := service.getMockedImageByName(imageName)
	fixedTags.Results = []common.ImageSummary{common.ImageSummary(mockedImage)}

	return fixedTags, nil
}

func (service mockService) getCveByImageGQL(ctx context.Context, config searchConfig, username, password,
	imageName, searchedCVE string,
) (*cveResult, error) {
	if service.getCveByImageGQLFn != nil {
		return service.getCveByImageGQLFn(ctx, config, username, password, imageName, searchedCVE)
	}
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
	image.MediaType = ispec.MediaTypeImageManifest
	image.Manifests = []common.ManifestSummary{
		{
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
			Size:         "123445",
		},
	}
	image.Size = "123445"

	return image
}

func (service mockService) getAllImages(ctx context.Context, config searchConfig, username, password string,
	channel chan stringResult, wtgrp *sync.WaitGroup,
) {
	defer wtgrp.Done()
	defer close(channel)

	if service.getAllImagesFn != nil {
		service.getAllImagesFn(ctx, config, username, password, channel, wtgrp)

		return
	}

	image := &imageStruct{}
	image.RepoName = "randomimageName"
	image.Tag = "tag"
	image.Digest = godigest.FromString("test").String()
	image.MediaType = ispec.MediaTypeImageManifest
	image.Manifests = []common.ManifestSummary{
		{
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
			Size:         "123445",
			Platform:     common.Platform{Os: "os", Arch: "arch"},
		},
	}
	image.Size = "123445"

	str, err := image.string(*config.outputFormat, len(image.RepoName), len(image.Tag), len("os/Arch"), *config.verbose)
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

	if service.getImageByNameFn != nil {
		service.getImageByNameFn(ctx, config, username, password, imageName, channel, wtgrp)

		return
	}

	image := &imageStruct{}
	image.RepoName = imageName
	image.Tag = "tag"
	image.Digest = godigest.FromString("test").String()
	image.MediaType = ispec.MediaTypeImageManifest
	image.Manifests = []common.ManifestSummary{
		{
			Digest:       godigest.FromString("Digest").String(),
			ConfigDigest: godigest.FromString("ConfigDigest").String(),
			Layers:       []common.LayerSummary{{Digest: godigest.FromString("LayerDigest").String()}},
			Size:         "123445",
			Platform:     common.Platform{Os: "os", Arch: "arch"},
		},
	}
	image.Size = "123445"

	str, err := image.string(*config.outputFormat, len(image.RepoName), len(image.Tag), len("os/Arch"), *config.verbose)
	if err != nil {
		channel <- stringResult{"", err}

		return
	}

	channel <- stringResult{str, nil}
}

func (service mockService) getCveByImage(ctx context.Context, config searchConfig, username, password,
	imageName, searchedCVE string, rch chan stringResult, wtgrp *sync.WaitGroup,
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
	username, password, imageName, cveid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	if service.getFixedTagsForCVEFn != nil {
		defer wtgrp.Done()
		defer close(rch)

		service.getFixedTagsForCVEFn(ctx, config, username, password, imageName, cveid, rch, wtgrp)

		return
	}

	service.getImageByName(ctx, config, username, password, imageName, rch, wtgrp)
}

func (service mockService) getImageByNameAndCVEID(ctx context.Context, config searchConfig, username,
	password, imageName, cveid string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	if service.getImageByNameAndCVEIDFn != nil {
		defer wtgrp.Done()
		defer close(rch)

		service.getImageByNameAndCVEIDFn(ctx, config, username, password, imageName, cveid, rch, wtgrp)

		return
	}

	service.getImageByName(ctx, config, username, password, imageName, rch, wtgrp)
}

func (service mockService) getImagesByCveID(ctx context.Context, config searchConfig, username, password, cveid string,
	rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	if service.getImagesByCveIDFn != nil {
		defer wtgrp.Done()
		defer close(rch)

		service.getImagesByCveIDFn(ctx, config, username, password, cveid, rch, wtgrp)

		return
	}

	service.getImageByName(ctx, config, username, password, "anImage", rch, wtgrp)
}

func (service mockService) getImagesByDigest(ctx context.Context, config searchConfig, username,
	password, digest string, rch chan stringResult, wtgrp *sync.WaitGroup,
) {
	if service.getImagesByDigestFn != nil {
		defer wtgrp.Done()
		defer close(rch)

		service.getImagesByDigestFn(ctx, config, username, password, digest, rch, wtgrp)

		return
	}

	service.getImageByName(ctx, config, username, password, "anImage", rch, wtgrp)
}

func makeConfigFile(content string) string {
	os.Setenv("HOME", os.TempDir())

	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	configPath := path.Join(home, "/.zot")

	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		panic(err)
	}

	return configPath
}
