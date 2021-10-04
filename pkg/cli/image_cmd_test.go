// +build extended

package cli //nolint:testpackage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	zotErrors "github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/compliance/v1_0_0"
	"github.com/anuvu/zot/pkg/extensions"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/phayes/freeport"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
)

const (
	BaseURL = "http://127.0.0.1:%s"
)

func getBaseURL(port string) string {
	return fmt.Sprintf(BaseURL, port)
}

func getFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}

	return fmt.Sprint(port)
}

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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE dummyImageName tag DigestsA 123kB")
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE dummyImageName tag DigestsA 123kB")
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
			So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE dummyImageName tag DigestsA 123kB")
			So(err, ShouldBeNil)
		})
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
		So(strings.TrimSpace(str), ShouldEqual, "IMAGE NAME TAG DIGEST SIZE dummyImageName tag DigestsA 123kB")
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
		space := regexp.MustCompile(`\s+`)
		str := space.ReplaceAllString(buff.String(), " ")
		So(strings.TrimSpace(str), ShouldEqual, `{ "name": "dummyImageName", "tag":`+
			` "tag", "configDigest": "", "digest": "DigestsAreReallyLong", "layers": null, "size": "123445" }`)
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
			`name: dummyImageName tag: tag configdigest: "" `+
				`digest: DigestsAreReallyLong layers: [] size: "123445"`,
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
				`name: dummyImageName tag: tag configdigest: "" `+
					`digest: DigestsAreReallyLong layers: [] size: "123445"`,
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

func TestServerResponse(t *testing.T) {
	Convey("Test from real server", t, func() {
		port := getFreePort()
		url := getBaseURL(port)
		config := api.NewConfig()
		config.HTTP.Port = port
		config.Extensions = &extensions.ExtensionConfig{
			Search: &extensions.SearchConfig{Enable: true},
		}
		c := api.NewController(config)
		dir, err := ioutil.TempDir("", "oci-repo-test")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(dir)

		c.Config.Storage.RootDirectory = dir
		go func(controller *api.Controller) {
			// this blocks
			if err := controller.Run(); err != nil {
				return
			}
		}(c)
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
		}(c)

		uploadManifest(url)

		Convey("Test all images config url", func() {
			args := []string{"imagetest"}
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
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 fdf5f251 243B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 9beeea29 243B")
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
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			// Actual cli output should be something similar to (order of images may differ):
			// IMAGE NAME    TAG       DIGEST    CONFIG    LAYERS    SIZE
			// repo7         test:2.0  fdf5f251  dae17351            243B
			//                                             2f2284ba  243B
			// repo7         test:1.0  9beeea29  a09bf3b5            243B
			//                                                		 243B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST CONFIG LAYERS SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 fdf5f251 dae17351 243B 2f2284ba 243B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 9beeea29 a09bf3b5 243B 58f98639 243B")
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
			err = cmd.Execute()
			So(err, ShouldBeNil)
			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 fdf5f251 243B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 9beeea29 243B")

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
				So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
				So(actual, ShouldContainSubstring, "repo7 test:2.0 fdf5f251 243B")
				So(actual, ShouldContainSubstring, "repo7 test:1.0 9beeea29 243B")
			})
		})

		Convey("Test image by digest", func() {
			args := []string{"imagetest", "--digest", "fdf5f251"}
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
			// Actual cli output should be something similar to (order of images may differ):
			// IMAGE NAME    TAG       DIGEST    SIZE
			// repo7 test:2.0 fdf5f251 243B
			So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 fdf5f251 243B")
			Convey("with shorthand", func() {
				args := []string{"imagetest", "-d", "fdf5f251"}
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
				So(actual, ShouldContainSubstring, "IMAGE NAME TAG DIGEST SIZE")
				So(actual, ShouldContainSubstring, "repo7 test:2.0 fdf5f251 243B")
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
			err = cmd.Execute()
			So(err, ShouldBeNil)
			So(len(buff.String()), ShouldEqual, 0)
		})
	})
}

func uploadManifest(url string) {
	// create a blob/layer
	resp, _ := resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc := v1_0_0.Location(url, resp)

	content := []byte("this is a blob")
	layerDigest := godigest.FromBytes(content)
	_, _ = resty.R().SetQueryParam("digest", layerDigest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)

	creationTime1, _ := time.Parse(time.RFC3339, "2021-09-14:45:26.371Z")
	imageConf := ispec.Image{
		Created:      &creationTime1,
		Author:       "",
		Architecture: "amd64",
		OS:           "linux",
		Config:       ispec.ImageConfig{},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{layerDigest},
		},
		History: []ispec.History{{Created: &creationTime1}},
	}

	resp, _ = resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc = v1_0_0.Location(url, resp)

	content, _ = json.Marshal(imageConf)
	imageConfDigest := godigest.FromBytes(content)
	_, _ = resty.R().SetQueryParam("digest", imageConfDigest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)

	// create a manifest
	m := ispec.Manifest{
		Config: ispec.Descriptor{
			Digest: imageConfDigest,
			Size:   int64(len(content)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    layerDigest,
				Size:      int64(len(content)),
			},
		},
	}
	m.SchemaVersion = 2
	content, _ = json.Marshal(m)
	_, _ = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(content).Put(url + "/v2/repo7/manifests/test:1.0")

	// upload another image
	resp, _ = resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc = v1_0_0.Location(url, resp)

	content = []byte("this is a another blob")
	layerDigest = godigest.FromBytes(content)
	_, _ = resty.R().SetQueryParam("digest", layerDigest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)

	creationTime2, _ := time.Parse(time.RFC3339, "2021-09-15:45:26.371Z")
	imageConf = ispec.Image{
		Created:      &creationTime2,
		Author:       "",
		Architecture: "amd64",
		OS:           "linux",
		Config:       ispec.ImageConfig{},
		RootFS: ispec.RootFS{
			Type:    "layers",
			DiffIDs: []godigest.Digest{layerDigest},
		},
		History: []ispec.History{{Created: &creationTime2}},
	}

	resp, _ = resty.R().Post(url + "/v2/repo7/blobs/uploads/")
	loc = v1_0_0.Location(url, resp)

	content, _ = json.Marshal(imageConf)
	imageConfDigest = godigest.FromBytes(content)
	_, _ = resty.R().SetQueryParam("digest", imageConfDigest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)

	m = ispec.Manifest{
		Config: ispec.Descriptor{
			Digest: imageConfDigest,
			Size:   int64(len(content)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    layerDigest,
				Size:      int64(len(content)),
			},
		},
	}
	m.SchemaVersion = 2
	content, _ = json.Marshal(m)
	_, _ = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(content).Put(url + "/v2/repo7/manifests/test:2.0")
}

type mockService struct{}

func (service mockService) getImagesByDigest(ctx context.Context, config searchConfig, username, password string,
	digest string) (*imageListStructForDigestGQL, error) {
	imageListGQLResponse := &imageListStructForDigestGQL{}
	imageListGQLResponse.Data.ImageList = []imageStructGQL{
		{
			Name:   "randomimageName",
			Tag:    "tag",
			Digest: "DigestsAreReallyLong",
			Size:   "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getImages(ctx context.Context, config searchConfig, username, password string,
	imageName string) (*imageListStructGQL, error) {
	imageListGQLResponse := &imageListStructGQL{}
	imageListGQLResponse.Data.ImageList = []imageStructGQL{
		{
			Name:   "dummyImageName",
			Tag:    "tag",
			Digest: "DigestsAreReallyLong",
			Size:   "123445",
		},
	}

	return imageListGQLResponse, nil
}

func (service mockService) getMockedImageByName(imageName string) imageStructGQL {
	image := imageStructGQL{}
	image.Name = imageName
	image.Tag = "tag"
	image.Digest = "DigestsAreReallyLong"
	image.Size = "123445"

	return image
}

func (service mockService) getCveByImage(ctx context.Context, config searchConfig, username, password,
	imageName string) (*cveResult, error) {
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

func (service mockService) getImagesByCveID(ctx context.Context, config searchConfig, username, password string,
	digest string) (*imagesForCveGQL, error) {
	imagesForCVEGQL := &imagesForCveGQL{
		Errors: nil,
		Data: struct {
			ImageListForCVE []imageStructGQL `json:"ImageListForCVE"`
		}{},
	}

	imagesForCVEGQL.Errors = nil

	mockedImage := service.getMockedImageByName("anImage")
	imagesForCVEGQL.Data.ImageListForCVE = []imageStructGQL{mockedImage}

	return imagesForCVEGQL, nil
}

func (service mockService) getTagsForCVE(ctx context.Context, config searchConfig, username, password,
	imageName, cveID string, getFixed bool) (*tagsForCVE, error) {
	fixedTags := &tagsForCVE{
		Errors: nil,
		Data: struct {
			TagListForCve []imageStructGQL `json:"TagListForCve"`
		}{},
	}

	fixedTags.Errors = nil

	mockedImage := service.getMockedImageByName(imageName)
	fixedTags.Data.TagListForCve = []imageStructGQL{mockedImage}

	return fixedTags, nil
}

func makeConfigFile(content string) string {
	os.Setenv("HOME", os.TempDir())
	home, err := os.UserHomeDir()

	if err != nil {
		panic(err)
	}

	configPath := path.Join(home + "/.zot")

	if err := ioutil.WriteFile(configPath, []byte(content), 0600); err != nil {
		panic(err)
	}

	return configPath
}
