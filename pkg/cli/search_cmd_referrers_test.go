//go:build search
// +build search

package cli //nolint:testpackage

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/test"
)

func ref[T any](input T) *T {
	obj := input

	return &obj
}

const (
	customArtTypeV1 = "application/custom.art.type.v1"
	customArtTypeV2 = "application/custom.art.type.v2"
	repoName        = "repo"
)

func TestReferrersSearchers(t *testing.T) {
	refSearcherGQL := referrerSearcherGQL{}
	refSearcher := referrerSearcher{}

	Convey("GQL Searcher", t, func() {
		Convey("Bad parameters", func() {
			ok, err := refSearcherGQL.search(searchConfig{params: map[string]*string{
				"badParam": ref("badParam"),
			}})

			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})

		Convey("GetRepoRefference fails", func() {
			conf := searchConfig{
				params: map[string]*string{
					"subject": ref("bad-subject"),
				},
				user: ref("test:pass"),
			}

			ok, err := refSearcherGQL.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("fetchImageDigest for tags fails", func() {
			conf := searchConfig{
				params: map[string]*string{
					"subject": ref("repo:tag"),
				},
				user:    ref("test:pass"),
				servURL: ref("127.0.0.1:8080"),
			}

			ok, err := refSearcherGQL.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("search service fails", func() {
			port := test.GetFreePort()

			conf := searchConfig{
				params: map[string]*string{
					"subject": ref("repo:tag"),
				},
				searchService: NewSearchService(),
				user:          ref("test:pass"),
				servURL:       ref("http://127.0.0.1:" + port),
				verifyTLS:     ref(false),
				debug:         ref(false),
				verbose:       ref(false),
			}

			server := test.StartTestHTTPServer(test.HTTPRoutes{
				test.RouteHandler{
					Route: "/v2/{repo}/manifests/{ref}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
					},
					AllowedMethods: []string{"HEAD"},
				},
			}, port)

			defer server.Close()

			ok, err := refSearcherGQL.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})
	})

	Convey("REST searcher", t, func() {
		Convey("Bad parameters", func() {
			ok, err := refSearcher.search(searchConfig{params: map[string]*string{
				"badParam": ref("badParam"),
			}})

			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})

		Convey("GetRepoRefference fails", func() {
			conf := searchConfig{
				params: map[string]*string{
					"subject": ref("bad-subject"),
				},
				user: ref("test:pass"),
			}

			ok, err := refSearcher.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("fetchImageDigest for tags fails", func() {
			conf := searchConfig{
				params: map[string]*string{
					"subject": ref("repo:tag"),
				},
				user:    ref("test:pass"),
				servURL: ref("127.0.0.1:1000"),
			}

			ok, err := refSearcher.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("search service fails", func() {
			port := test.GetFreePort()

			conf := searchConfig{
				params: map[string]*string{
					"subject": ref("repo:tag"),
				},
				searchService: NewSearchService(),
				user:          ref("test:pass"),
				servURL:       ref("http://127.0.0.1:" + port),
				verifyTLS:     ref(false),
				debug:         ref(false),
				verbose:       ref(false),
				fixedFlag:     ref(false),
			}

			server := test.StartTestHTTPServer(test.HTTPRoutes{
				test.RouteHandler{
					Route: "/v2/{repo}/manifests/{ref}",
					HandlerFunc: func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(http.StatusOK)
					},
					AllowedMethods: []string{"HEAD"},
				},
			}, port)

			defer server.Close()

			ok, err := refSearcher.search(conf)

			So(err, ShouldNotBeNil)
			So(ok, ShouldBeTrue)
		})
	})
}

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

		repo := repoName
		image := test.CreateRandomImage()

		err := test.UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		ref1 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := test.CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = test.UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		args := []string{"reftest", "--subject", repo + "@" + image.DigestStr()}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		cmd := NewSearchCommand(new(searchService))

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())

		fmt.Println(buff.String())

		os.Remove(configPath)

		args = []string{"reftest", "--subject", repo + ":" + "tag"}

		configPath = makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		cmd = NewSearchCommand(new(searchService))

		buff = &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())

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

		repo := repoName
		image := test.CreateRandomImage()

		err := test.UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		ref1 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := test.CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = test.UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		// get referrers by digest
		args := []string{"reftest", "--subject", repo + "@" + image.DigestStr()}

		configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))

		cmd := NewSearchCommand(new(searchService))

		buff := &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		space := regexp.MustCompile(`\s+`)
		str := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())
		fmt.Println(buff.String())

		os.Remove(configPath)

		args = []string{"reftest", "--subject", repo + ":" + "tag"}

		configPath = makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
			baseURL))
		defer os.Remove(configPath)

		buff = &bytes.Buffer{}
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err = cmd.Execute()
		So(err, ShouldBeNil)
		str = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(str, ShouldContainSubstring, "ARTIFACT TYPE SIZE DIGEST")
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 563 B "+ref1.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v1 551 B "+ref2.DigestStr())
		So(str, ShouldContainSubstring, "custom.art.type.v2 611 B "+ref3.DigestStr())
		fmt.Println(buff.String())
	})
}

func TestFormatsReferrersCLI(t *testing.T) {
	Convey("Create server", t, func() {
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

		repo := repoName
		image := test.CreateRandomImage()

		err := test.UploadImage(image, baseURL, repo, "tag")
		So(err, ShouldBeNil)

		// add referrers
		ref1 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			Subject(image.DescriptorRef()).Build()

		ref2 := test.CreateImageWith().
			RandomLayers(1, 10).
			ArtifactConfig(customArtTypeV1).
			Subject(image.DescriptorRef()).Build()

		ref3 := test.CreateImageWith().
			RandomLayers(1, 10).
			RandomConfig().
			ArtifactType(customArtTypeV2).
			Subject(image.DescriptorRef()).Build()

		err = test.UploadImage(ref1, baseURL, repo, ref1.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo, ref2.DigestStr())
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo, ref3.DigestStr())
		So(err, ShouldBeNil)

		Convey("JSON format", func() {
			args := []string{"reftest", "--output", "json", "--subject", repo + "@" + image.DigestStr()}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			cmd := NewSearchCommand(new(searchService))

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
		})
		Convey("YAML format", func() {
			args := []string{"reftest", "--output", "yaml", "--subject", repo + "@" + image.DigestStr()}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			cmd := NewSearchCommand(new(searchService))

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldBeNil)
			fmt.Println(buff.String())
		})
		Convey("Invalid format", func() {
			args := []string{"reftest", "--output", "invalid_format", "--subject", repo + "@" + image.DigestStr()}

			configPath := makeConfigFile(fmt.Sprintf(`{"configs":[{"_name":"reftest","url":"%s","showspinner":false}]}`,
				baseURL))

			defer os.Remove(configPath)

			cmd := NewSearchCommand(new(searchService))

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err = cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}

func TestReferrersCLIErrors(t *testing.T) {
	Convey("Errors", t, func() {
		cmd := NewSearchCommand(new(searchService))

		Convey("no url provided", func() {
			args := []string{"reftest", "--output", "invalid", "--query", "repo/alpine"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest","showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("getConfigValue", func() {
			args := []string{"reftest", "--subject", "repo/alpine"}

			configPath := makeConfigFile(`bad-json`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad showspinnerConfig ", func() {
			args := []string{"reftest"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":"bad"}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad verifyTLSConfig ", func() {
			args := []string{"reftest"}

			configPath := makeConfigFile(
				`{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":false, "verify-tls": "bad"}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("url from config is empty", func() {
			args := []string{"reftest", "--subject", "repo/alpine"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest", "url":"", "showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("bad params combination", func() {
			args := []string{"reftest"}

			configPath := makeConfigFile(`{"configs":[{"_name":"reftest", "url":"http://127.0.0.1:8080", "showspinner":false}]}`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})

		Convey("no url provided error", func() {
			args := []string{}

			configPath := makeConfigFile(`bad-json`)

			defer os.Remove(configPath)

			buff := &bytes.Buffer{}
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
		})
	})
}
