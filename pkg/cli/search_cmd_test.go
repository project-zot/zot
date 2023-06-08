//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

func TestSearchCLI(t *testing.T) {
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

		const (
			repo1  = "repo"
			r1tag1 = "repo1tag1"
			r1tag2 = "repo1tag2"

			repo2  = "repo/alpine"
			r2tag1 = "repo2tag1"
			r2tag2 = "repo2tag2"

			repo3  = "repo/test/alpine"
			r3tag1 = "repo3tag1"
			r3tag2 = "repo3tag2"
		)

		image1, err := test.GetRandomImage("")
		So(err, ShouldBeNil)
		// img1Digest, err := image1.Digest()
		// formatterDigest1 := img1Digest.Encoded()[:8]
		So(err, ShouldBeNil)

		image2, err := test.GetRandomImage("")
		So(err, ShouldBeNil)
		// img2Digest, err := image2.Digest()
		// formatterDigest2 := img2Digest.Encoded()[:8]
		So(err, ShouldBeNil)

		// repo1
		image1.Reference = r1tag1
		err = test.UploadImage(image1, baseURL, repo1)
		So(err, ShouldBeNil)

		image2.Reference = r1tag2
		err = test.UploadImage(image2, baseURL, repo1)
		So(err, ShouldBeNil)

		// repo2
		image1.Reference = r2tag1
		err = test.UploadImage(image1, baseURL, repo2)
		So(err, ShouldBeNil)

		image2.Reference = r2tag2
		err = test.UploadImage(image2, baseURL, repo2)
		So(err, ShouldBeNil)

		// repo3
		image1.Reference = r3tag1
		err = test.UploadImage(image1, baseURL, repo3)
		So(err, ShouldBeNil)

		image2.Reference = r3tag2
		err = test.UploadImage(image2, baseURL, repo3)
		So(err, ShouldBeNil)

		// search by repos

		args := []string{"searchtest", "--url", baseURL, "--query", "test/alpin", "--verbose"}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"searchtest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		cmd := NewSearchCommand(new(searchService))

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		// space := regexp.MustCompile(`\s+`)
		// str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))

		fmt.Println("\n", buff.String())
	})
}
