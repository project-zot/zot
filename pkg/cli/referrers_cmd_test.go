//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

func TestReferrerCLI(t *testing.T) {
	Convey("Test GQL", t, func() {
		rootDir := t.TempDir()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false
		defaultVal := true
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = rootDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		repo := "repo"
		image, err := test.GetRandomImage("tag")
		So(err, ShouldBeNil)
		imgDigest, err := image.Digest()
		So(err, ShouldBeNil)

		err = test.UploadImage(image, baseURL, repo)
		So(err, ShouldBeNil)

		// add referrers
		ref1, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		ref1Digest, err := ref1.Digest()
		So(err, ShouldBeNil)

		formattedRef1Digest := ref1Digest.Encoded()[:8]

		ref2, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref2.Manifest.Config.MediaType = "custom.art.type.v1"
		ref2Digest, err := ref2.Digest()
		So(err, ShouldBeNil)

		formattedRef2Digest := ref2Digest.Encoded()[:8]

		ref3, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref3.Manifest.ArtifactType = "custom.art.type.v2"
		ref3.Manifest.Config = ispec.ScratchDescriptor
		ref3Digest, err := ref3.Digest()
		So(err, ShouldBeNil)

		formattedRef3Digest := ref3Digest.Encoded()[:8]

		err = test.UploadImage(ref1, baseURL, repo)
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo)
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo)
		So(err, ShouldBeNil)

		args := []string{"reftest", "--url", baseURL, "--repo", "repo", "--digest", imgDigest.String()}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		cmd := NewReferrersCommand(new(searchService))

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "DIGEST ARTIFACT TYPE SIZE")
		So(str, ShouldContainSubstring, formattedRef1Digest+" application/vnd.oci.image.config.v1+json 557")
		So(str, ShouldContainSubstring, formattedRef2Digest+" custom.art.type.v1 535")
		So(str, ShouldContainSubstring, formattedRef3Digest+" custom.art.type.v2 600")

		fmt.Println(buff.String())
	})

	Convey("Test REST", t, func() {
		rootDir := t.TempDir()

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		conf := config.New()
		conf.HTTP.Port = port
		conf.Storage.GC = false
		defaultVal := false
		conf.Extensions = &extconf.ExtensionConfig{
			Search: &extconf.SearchConfig{BaseConfig: extconf.BaseConfig{Enable: &defaultVal}},
		}
		ctlr := api.NewController(conf)
		ctlr.Config.Storage.RootDirectory = rootDir
		cm := test.NewControllerManager(ctlr)
		cm.StartAndWait(conf.HTTP.Port)
		defer cm.StopServer()

		repo := "repo"
		image, err := test.GetRandomImage("tag")
		So(err, ShouldBeNil)
		imgDigest, err := image.Digest()
		So(err, ShouldBeNil)

		err = test.UploadImage(image, baseURL, repo)
		So(err, ShouldBeNil)

		// add referrers
		ref1, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref1Digest, err := ref1.Digest()
		So(err, ShouldBeNil)

		formattedRef1Digest := ref1Digest.Encoded()[:8]

		ref2, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref2.Manifest.Config.MediaType = "custom.art.type.v1"
		ref2Digest, err := ref2.Digest()
		So(err, ShouldBeNil)

		formattedRef2Digest := ref2Digest.Encoded()[:8]

		ref3, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref3.Manifest.ArtifactType = "custom.art.type.v2"
		ref3.Manifest.Config = ispec.ScratchDescriptor

		ref3Digest, err := ref3.Digest()
		So(err, ShouldBeNil)

		formattedRef3Digest := ref3Digest.Encoded()[:8]

		err = test.UploadImage(ref1, baseURL, repo)
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo)
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo)
		So(err, ShouldBeNil)

		args := []string{"reftest", "--url", baseURL, "--repo", "repo", "--digest", imgDigest.String()}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		cmd := NewReferrersCommand(new(searchService))

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		space := regexp.MustCompile(`\s+`)
		str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "DIGEST ARTIFACT TYPE SIZE")
		So(str, ShouldContainSubstring, formattedRef1Digest+" application/vnd.oci.image.config.v1+json 557")
		So(str, ShouldContainSubstring, formattedRef2Digest+" custom.art.type.v1 535")
		So(str, ShouldContainSubstring, formattedRef3Digest+" custom.art.type.v2 600")

		So(err, ShouldBeNil)

		fmt.Println(buff.String())
	})
}
