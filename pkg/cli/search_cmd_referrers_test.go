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

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
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
	customArtTypeV1 = "custom.art.type.v1"
	customArtTypeV2 = "custom.art.type.v2"
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
		image, err := test.GetRandomImage("tag")
		So(err, ShouldBeNil)
		imgDigest, err := image.Digest()
		So(err, ShouldBeNil)

		err = test.UploadImage(image, baseURL, repo)
		So(err, ShouldBeNil)

		// add referrers
		ref1, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref1.Reference = ""

		ref1Digest, err := ref1.Digest()
		So(err, ShouldBeNil)

		ref2, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref2.Reference = ""
		ref2.Manifest.Config.MediaType = customArtTypeV1
		ref2Digest, err := ref2.Digest()
		So(err, ShouldBeNil)

		ref3, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref3.Manifest.ArtifactType = customArtTypeV2
		ref3.Manifest.Config = ispec.DescriptorEmptyJSON
		ref3.Reference = ""
		ref3Digest, err := ref3.Digest()
		So(err, ShouldBeNil)

		err = test.UploadImage(ref1, baseURL, repo)
		So(err, ShouldBeNil)

		err = test.UploadImage(ref2, baseURL, repo)
		So(err, ShouldBeNil)

		err = test.UploadImage(ref3, baseURL, repo)
		So(err, ShouldBeNil)

		args := []string{"reftest", "--subject", repo + "@" + imgDigest.String()}

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
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 557 B "+ref1Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v1 535 B "+ref2Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v2 598 B "+ref3Digest.String())

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
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 557 B "+ref1Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v1 535 B "+ref2Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v2 598 B "+ref3Digest.String())

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

		ref2, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref2.Manifest.Config.MediaType = customArtTypeV1
		ref2Digest, err := ref2.Digest()
		So(err, ShouldBeNil)

		ref3, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref3.Manifest.ArtifactType = customArtTypeV2
		ref3.Manifest.Config = ispec.DescriptorEmptyJSON

		ref3Digest, err := ref3.Digest()
		So(err, ShouldBeNil)

		ref1.Reference = ""
		err = test.UploadImage(ref1, baseURL, repo)
		So(err, ShouldBeNil)

		ref2.Reference = ""
		err = test.UploadImage(ref2, baseURL, repo)
		So(err, ShouldBeNil)

		ref3.Reference = ""
		err = test.UploadImage(ref3, baseURL, repo)
		So(err, ShouldBeNil)

		// get referrers by digest
		args := []string{"reftest", "--subject", repo + "@" + imgDigest.String()}

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
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 557 B "+ref1Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v1 535 B "+ref2Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v2 598 B "+ref3Digest.String())
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
		So(str, ShouldContainSubstring, "application/vnd.oci.image.config.v1+json 557 B "+ref1Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v1 535 B "+ref2Digest.String())
		So(str, ShouldContainSubstring, "custom.art.type.v2 598 B "+ref3Digest.String())
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
		image, err := test.GetRandomImage("tag")
		So(err, ShouldBeNil)
		imgDigest, err := image.Digest()
		So(err, ShouldBeNil)

		err = test.UploadImage(image, baseURL, repo)
		So(err, ShouldBeNil)

		// add referrers
		ref1, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		ref2, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref2.Manifest.Config.MediaType = customArtTypeV1

		ref3, err := test.GetImageWithSubject(imgDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)
		ref3.Manifest.ArtifactType = customArtTypeV2
		ref3.Manifest.Config = ispec.DescriptorEmptyJSON

		ref1.Reference = ""
		err = test.UploadImage(ref1, baseURL, repo)
		So(err, ShouldBeNil)

		ref2.Reference = ""
		err = test.UploadImage(ref2, baseURL, repo)
		So(err, ShouldBeNil)

		ref3.Reference = ""
		err = test.UploadImage(ref3, baseURL, repo)
		So(err, ShouldBeNil)

		Convey("JSON format", func() {
			args := []string{"reftest", "--output", "json", "--subject", repo + "@" + imgDigest.String()}

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
			args := []string{"reftest", "--output", "yaml", "--subject", repo + "@" + imgDigest.String()}

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
			args := []string{"reftest", "--output", "invalid_format", "--subject", repo + "@" + imgDigest.String()}

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
