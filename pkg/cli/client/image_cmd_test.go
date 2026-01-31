//go:build search

package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/cli/client"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
	"zotregistry.dev/zot/v2/pkg/test/signature"
)

//nolint:dupl
func TestSignature(t *testing.T) {
	space := regexp.MustCompile(`\s+`)
	repoName := "repo7"

	Convey("Test with cosign signature(tag)", t, func() {
		currentWorkingDir, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(currentWorkingDir) }()

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

		image := CreateDefaultImage()
		err = UploadImage(image, url, repoName, "1.0")
		So(err, ShouldBeNil)

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
			[]string{fmt.Sprintf("localhost:%s/%s@%s", port, "repo7", image.DigestStr())})
		So(err, ShouldBeNil)

		t.Logf("%s", ctlr.Config.Storage.RootDirectory)

		searchConfig := getTestSearchConfig(url, client.NewSearchService())
		buff := &bytes.Buffer{}
		searchConfig.ResultWriter = buff

		err = client.SearchAllImagesGQL(searchConfig)
		So(err, ShouldBeNil)

		actual := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 1.0 linux/amd64 db573b01 true 854B")

		t.Log("Test getting all images using rest calls to get catalog and individual manifests")

		buff = &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err = client.SearchAllImages(searchConfig)
		So(err, ShouldBeNil)

		actual = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 1.0 linux/amd64 db573b01 true 854B")
	})

	Convey("Test with cosign signature(withReferrers)", t, func() {
		currentWorkingDir, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(currentWorkingDir) }()

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

		err = UploadImage(CreateDefaultImage(), url, repoName, "0.0.1")
		So(err, ShouldBeNil)

		err = signature.SignImageUsingCosign("repo7:0.0.1", port, true)
		So(err, ShouldBeNil)

		searchConfig := getTestSearchConfig(url, client.NewSearchService())

		t.Logf("%s", ctlr.Config.Storage.RootDirectory)

		buff := &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err = client.SearchAllImagesGQL(searchConfig)
		So(err, ShouldBeNil)

		actual := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 0.0.1 linux/amd64 db573b01 true 854B")

		t.Log("Test getting all images using rest calls to get catalog and individual manifests")
		buff = &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err = client.SearchAllImages(searchConfig)
		So(err, ShouldBeNil)

		actual = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 0.0.1 linux/amd64 db573b01 true 854B")
	})

	Convey("Test with notation signature", t, func() {
		currentWorkingDir, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(currentWorkingDir) }()

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

		err = UploadImage(CreateDefaultImage(), url, repoName, "0.0.1")
		So(err, ShouldBeNil)

		err = signature.SignImageUsingNotary("repo7:0.0.1", port, true)
		So(err, ShouldBeNil)

		searchConfig := getTestSearchConfig(url, client.NewSearchService())

		t.Logf("%s", ctlr.Config.Storage.RootDirectory)

		buff := &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err = client.SearchAllImagesGQL(searchConfig)
		So(err, ShouldBeNil)

		actual := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 0.0.1 linux/amd64 db573b01 true 854B")

		t.Log("Test getting all images using rest calls to get catalog and individual manifests")
		buff = &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err = client.SearchAllImages(searchConfig)
		So(err, ShouldBeNil)

		actual = strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo7 0.0.1 linux/amd64 db573b01 true 854B")
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

	space := regexp.MustCompile(`\s+`)
	searchConfig := getTestSearchConfig(url, client.NewSearchService())

	t.Logf("rootDir: %s", ctlr.Config.Storage.RootDirectory)

	Convey("Test from real server", t, func() {
		Convey("Test derived images list working", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)

			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			err := client.SearchDerivedImageListGQL(searchConfig, "repo7:test:2.0")
			So(err, ShouldBeNil)

			actual := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 9d9461ed false 860B")
		})

		Convey("Test derived images list fails", func() {
			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			err := client.SearchDerivedImageListGQL(searchConfig, "repo7:test:missing")
			So(err, ShouldNotBeNil)
		})

		Convey("Test derived images list cannot print", func() {
			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			searchConfig.OutputFormat = "random"
			err := client.SearchDerivedImageListGQL(searchConfig, "repo7:test:2.0")
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

	space := regexp.MustCompile(`\s+`)
	searchConfig := getTestSearchConfig(url, client.NewSearchService())

	t.Logf("rootDir: %s", ctlr.Config.Storage.RootDirectory)

	Convey("Test from real server", t, func() {
		Convey("Test base images list working", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)

			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			err := client.SearchBaseImageListGQL(searchConfig, "repo7:test:1.0")
			So(err, ShouldBeNil)
			actual := strings.TrimSpace(space.ReplaceAllString(buff.String(), " "))
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 214e4bed false 530B")
		})

		Convey("Test base images list fail", func() {
			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			err := client.SearchBaseImageListGQL(searchConfig, "repo7:test:missing")
			So(err, ShouldNotBeNil)
		})

		Convey("Test base images list cannot print", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			buff := &bytes.Buffer{}
			searchConfig.OutputFormat = "random"
			searchConfig.ResultWriter = buff
			err := client.SearchBaseImageListGQL(searchConfig, "repo7:test:missing")
			So(err, ShouldNotBeNil)
		})
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
		So(err, ShouldBeNil)

		t.Logf("%s", ctlr.Config.Storage.RootDirectory)

		Convey("Test json", func() {
			t.Logf("%s", ctlr.Config.Storage.RootDirectory)
			args := []string{"name", "repo7", "--config", "imagetest", "-f", "json"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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
				`"history":null,"vulnerabilities":{"maxSeverity":"","unknownCount":0,"lowCount":0,"mediumCount":0,` +
				`"highCount":0,"criticalCount":0,"count":0},` +
				`"referrers":null,"artifactType":"","signatureInfo":null}],` +
				`"size":"528","downloadCount":0,"lastUpdated":"2023-01-01T12:00:00Z","lastPullTimestamp":"0001-01-01T00:00:00Z",` +
				`"pushTimestamp":"0001-01-01T00:00:00Z","taggedTimestamp":"0001-01-01T00:00:00Z",` +
				`"description":"","isSigned":false,` +
				`"licenses":"","labels":"","title":"","source":"","documentation":"","authors":"","vendor":"",` +
				`"vulnerabilities":{"maxSeverity":"","unknownCount":0,"lowCount":0,"mediumCount":0,` +
				`"highCount":0,"criticalCount":0,"count":0},"referrers":null,"signatureInfo":null}` + "\n" +
				`{"repoName":"repo7","tag":"test:2.0",` +
				`"digest":"sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06",` +
				`"mediaType":"application/vnd.oci.image.manifest.v1+json",` +
				`"manifests":[{"digest":"sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06",` +
				`"configDigest":"sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e",` +
				`"lastUpdated":"2023-01-01T12:00:00Z","size":"528","platform":{"os":"linux","arch":"amd64",` +
				`"variant":""},"isSigned":false,"downloadCount":0,"layers":[{"size":"15","digest":` +
				`"sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6","score":0}],` +
				`"history":null,"vulnerabilities":{"maxSeverity":"","unknownCount":0,"lowCount":0,"mediumCount":0,` +
				`"highCount":0,"criticalCount":0,"count":0},` +
				`"referrers":null,"artifactType":"","signatureInfo":null}],` +
				`"size":"528","downloadCount":0,"lastUpdated":"2023-01-01T12:00:00Z","lastPullTimestamp":"0001-01-01T00:00:00Z",` +
				`"pushTimestamp":"0001-01-01T00:00:00Z","taggedTimestamp":"0001-01-01T00:00:00Z",` +
				`"description":"","isSigned":false,` +
				`"licenses":"","labels":"","title":"","source":"","documentation":"","authors":"","vendor":"",` +
				`"vulnerabilities":{"maxSeverity":"","unknownCount":0,"lowCount":0,"mediumCount":0,` +
				`"highCount":0,"criticalCount":0,"count":0},"referrers":null,"signatureInfo":null}` + "\n"
			// Output is supposed to be in json lines format, keep all spaces as is for verification
			So(buff.String(), ShouldEqual, expectedStr)
			So(err, ShouldBeNil)
		})

		Convey("Test yaml", func() {
			args := []string{"name", "repo7", "--config", "imagetest", "-f", "yaml"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z ` +
				`lastpulltimestamp: 0001-01-01T00:00:00Z pushtimestamp: 0001-01-01T00:00:00Z ` +
				`taggedtimestamp: 0001-01-01T00:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" ` +
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] signatureinfo: [] ` +
				`--- reponame: repo7 tag: test:2.0 ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`configdigest: sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e ` +
				`lastupdated: 2023-01-01T12:00:00Z size: "528" platform: os: linux arch: amd64 variant: "" ` +
				`issigned: false downloadcount: 0 layers: - size: "15" ` +
				`digest: sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6 score: 0 ` +
				`history: [] vulnerabilities: maxseverity: "" ` +
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z ` +
				`lastpulltimestamp: 0001-01-01T00:00:00Z pushtimestamp: 0001-01-01T00:00:00Z ` +
				`taggedtimestamp: 0001-01-01T00:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" ` +
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] signatureinfo: []`
			So(strings.TrimSpace(str), ShouldEqual, expectedStr)
			So(err, ShouldBeNil)
		})

		Convey("Test yml", func() {
			args := []string{"name", "repo7", "--config", "imagetest", "-f", "yml"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z ` +
				`lastpulltimestamp: 0001-01-01T00:00:00Z pushtimestamp: 0001-01-01T00:00:00Z ` +
				`taggedtimestamp: 0001-01-01T00:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" ` +
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] signatureinfo: [] ` +
				`--- reponame: repo7 tag: test:2.0 ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`mediatype: application/vnd.oci.image.manifest.v1+json manifests: - ` +
				`digest: sha256:51e18f508fd7125b0831ff9a22ba74cd79f0b934e77661ff72cfb54896951a06 ` +
				`configdigest: sha256:d14faead7d60053bad0d62e5ceb0031df28037d8c636d7911179b2f874ee004e ` +
				`lastupdated: 2023-01-01T12:00:00Z size: "528" platform: os: linux arch: amd64 variant: "" ` +
				`issigned: false downloadcount: 0 layers: - size: "15" ` +
				`digest: sha256:b8781e8844f5b7bf6f2f8fa343de18ec471c3b278027355bc34c120585ff04f6 score: 0 ` +
				`history: [] vulnerabilities: maxseverity: "" ` +
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] artifacttype: "" signatureinfo: [] ` +
				`size: "528" downloadcount: 0 lastupdated: 2023-01-01T12:00:00Z ` +
				`lastpulltimestamp: 0001-01-01T00:00:00Z pushtimestamp: 0001-01-01T00:00:00Z ` +
				`taggedtimestamp: 0001-01-01T00:00:00Z description: "" ` +
				`issigned: false licenses: "" labels: "" title: "" source: "" documentation: "" ` +
				`authors: "" vendor: "" vulnerabilities: maxseverity: "" ` +
				`unknowncount: 0 lowcount: 0 mediumcount: 0 highcount: 0 criticalcount: 0 count: 0 ` +
				`referrers: [] signatureinfo: []`
			So(strings.TrimSpace(str), ShouldEqual, expectedStr)
			So(err, ShouldBeNil)
		})

		Convey("Test invalid", func() {
			args := []string{"name", "repo7", "--config", "imagetest", "-f", "random"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldNotBeNil)
			So(buff.String(), ShouldContainSubstring, "invalid cli output format")
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
			args := []string{"list", "--config", "imagetest"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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
				args := []string{"list", "--config", "imagetest", "-f", "random"}

				_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

				cmd := client.NewImageCommand(client.NewSearchService())
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldNotBeNil)
				So(buff.String(), ShouldContainSubstring, "invalid cli output format")
			})
		})

		Convey("Test all images verbose", func() {
			args := []string{"list", "--config", "imagetest", "--verbose"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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
			args := []string{"list", "--config", "imagetest", "--debug"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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
			args := []string{"name", "repo7", "--config", "imagetest"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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

			Convey("invalid output format", func() {
				args := []string{"name", "repo7", "--config", "imagetest", "-f", "random"}

				_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

				cmd := client.NewImageCommand(client.NewSearchService())
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldNotBeNil)
				So(buff.String(), ShouldContainSubstring, "invalid cli output format")
			})
		})

		Convey("Test image by digest", func() {
			args := []string{"digest", "51e18f50", "--config", "imagetest"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
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

			Convey("nonexistent digest", func() {
				args := []string{"digest", "d1g35t", "--config", "imagetest"}

				_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

				cmd := client.NewImageCommand(client.NewSearchService())
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldBeNil)
				So(len(buff.String()), ShouldEqual, 0)
			})

			Convey("invalid output format", func() {
				args := []string{"digest", "51e18f50", "--config", "imagetest", "-f", "random"}

				_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

				cmd := client.NewImageCommand(client.NewSearchService())
				buff := bytes.NewBufferString("")
				cmd.SetOut(buff)
				cmd.SetErr(buff)
				cmd.SetArgs(args)
				err := cmd.Execute()
				So(err, ShouldNotBeNil)
				So(buff.String(), ShouldContainSubstring, "invalid cli output format")
			})
		})

		Convey("Test image by name nonexistent name", func() {
			args := []string{"name", "repo777", "--config", "imagetest"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"imagetest","url":"%s","showspinner":false}]}`, url))

			cmd := client.NewImageCommand(client.NewSearchService())
			buff := bytes.NewBufferString("")
			cmd.SetOut(buff)
			cmd.SetErr(buff)
			cmd.SetArgs(args)
			err := cmd.Execute()
			So(err, ShouldBeNil)
			So(len(buff.String()), ShouldEqual, 0)
		})

		Convey("Test list repos error", func() {
			args := []string{"list", "--config", "config-test"}

			_ = makeConfigFile(t, fmt.Sprintf(`{"configs":[{"_name":"config-test",
            "url":"%s","showspinner":false}]}`, url))

			cmd := client.NewRepoCommand(client.NewSearchService())
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

	space := regexp.MustCompile(`\s+`)

	Convey("Test from real server", t, func() {
		searchConfig := getTestSearchConfig(url, client.NewSearchService())

		Convey("Test all images", func() {
			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			err := client.SearchAllImages(searchConfig)
			So(err, ShouldBeNil)

			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
		})

		Convey("Test all images verbose", func() {
			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			searchConfig.Verbose = true

			defer func() { searchConfig.Verbose = false }()

			err := client.SearchAllImages(searchConfig)
			So(err, ShouldBeNil)

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
			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			err := client.SearchImageByName(searchConfig, "repo7")
			So(err, ShouldBeNil)

			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
			So(actual, ShouldContainSubstring, "repo7 test:2.0 linux/amd64 51e18f50 false 528B")
			So(actual, ShouldContainSubstring, "repo7 test:1.0 linux/amd64 51e18f50 false 528B")
		})

		Convey("Test image by digest", func() {
			buff := &bytes.Buffer{}
			searchConfig.ResultWriter = buff
			err := client.SearchImagesByDigest(searchConfig, "51e18f50")
			So(err, ShouldBeNil)

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
				buff := &bytes.Buffer{}
				searchConfig.ResultWriter = buff
				err := client.SearchImagesByDigest(searchConfig, "d1g35t")
				So(err, ShouldBeNil)

				So(len(buff.String()), ShouldEqual, 0)
			})
		})

		Convey("Test image by name nonexistent name", func() {
			err := client.SearchImageByName(searchConfig, "repo777")
			So(err, ShouldNotBeNil)

			So(err.Error(), ShouldContainSubstring, "no repository found")
		})
	})
}

func TestServerResponseGQLWithoutPermissions(t *testing.T) {
	Convey("Test accessing a blobs folder without having permissions fails fast", t, func() {
		port := test.GetFreePort()
		conf := config.New()
		conf.HTTP.Port = port

		dir := t.TempDir()

		srcStorageCtlr := ociutils.GetDefaultStoreController(dir, zlog.NewTestLogger())
		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", srcStorageCtlr)
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
		if err := ctlr.Init(); err != nil {
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
	space := regexp.MustCompile(`\s+`)
	searchConfig := getTestSearchConfig(baseURL, client.NewSearchService())

	Convey("Test Image Index", func() {
		uploadTestMultiarch(baseURL)

		buff := &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		err := client.SearchAllImages(searchConfig)
		So(err, ShouldBeNil)

		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		// Actual cli output should be something similar to (order of images may differ):
		// REPOSITORY    TAG        OS/ARCH           DIGEST    SIGNED  SIZE
		// repo          multi-arch *                 d3818454  false   1.7kB
		//                          linux/amd64       02e0ac42  false   644B
		//                          windows/arm64/v6  5e09b7f9  false   444B
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST SIGNED SIZE")
		So(actual, ShouldContainSubstring, "repo multi-arch * d3818454 false 1.7kB ")
		So(actual, ShouldContainSubstring, "linux/amd64 02e0ac42 false 644B ")
		So(actual, ShouldContainSubstring, "windows/arm64/v6 5e09b7f9 false 506B")
	})

	Convey("Test Image Index Verbose", func() {
		uploadTestMultiarch(baseURL)

		buff := &bytes.Buffer{}
		searchConfig.ResultWriter = buff
		searchConfig.Verbose = true
		err := client.SearchAllImages(searchConfig)
		So(err, ShouldBeNil)

		str := space.ReplaceAllString(buff.String(), " ")
		actual := strings.TrimSpace(str)
		// Actual cli output should be something similar to (order of images may differ):
		// REPOSITORY    TAG        OS/ARCH           DIGEST    CONFIG    SIGNED  LAYERS    SIZE
		// repo          multi-arch *                 d3818454            false             1.7kB
		//                          linux/amd64       02e0ac42  58cc9abe  false             644B
		//                                                                        cbb5b121  4B
		//                                                                        a00291e8  4B
		//                          windows/arm64/v6  5e09b7f9  5132a1cd  false             506B
		//                                                                        7d08ce29  4B
		So(actual, ShouldContainSubstring, "REPOSITORY TAG OS/ARCH DIGEST CONFIG SIGNED LAYERS SIZE")
		So(actual, ShouldContainSubstring, "repo multi-arch * d3818454 false 1.7kB")
		So(actual, ShouldContainSubstring, "linux/amd64 02e0ac42 58cc9abe false 644B")
		So(actual, ShouldContainSubstring, "cbb5b121 4B")
		So(actual, ShouldContainSubstring, "a00291e8 4B")
		So(actual, ShouldContainSubstring, "windows/arm64/v6 5e09b7f9 5132a1cd false 506B")
		So(actual, ShouldContainSubstring, "7d08ce29 4B")
	})
}

func TestImagesSortFlag(t *testing.T) {
	rootDir := t.TempDir()
	port := test.GetFreePort()
	baseURL := test.GetBaseURL(port)
	conf := config.New()
	conf.HTTP.Port = port

	defaultVal := true
	conf.Extensions = &extconf.ExtensionConfig{
		Search: &extconf.SearchConfig{
			BaseConfig: extconf.BaseConfig{Enable: &defaultVal},
			CVE:        nil,
		},
	}
	ctlr := api.NewController(conf)
	ctlr.Config.Storage.RootDirectory = rootDir

	image1 := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2010, 1, 1, 1, 1, 1, 0, time.UTC)}).Build()

	image2 := CreateImageWith().DefaultLayers().
		ImageConfig(ispec.Image{Created: DateRef(2020, 1, 1, 1, 1, 1, 0, time.UTC)}).Build()

	storeController := ociutils.GetDefaultStoreController(rootDir, ctlr.Log)

	err := WriteImageToFileSystem(image1, "a-repo", "tag1", storeController)
	if err != nil {
		t.FailNow()
	}

	err = WriteImageToFileSystem(image2, "b-repo", "tag2", storeController)
	if err != nil {
		t.FailNow()
	}

	cm := test.NewControllerManager(ctlr)
	cm.StartAndWait(conf.HTTP.Port)

	defer cm.StopServer()

	Convey("Sorting", t, func() {
		args := []string{"list", "--sort-by", "alpha-asc", "--url", baseURL}
		cmd := client.NewImageCommand(client.NewSearchService())
		buff := bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)
		err := cmd.Execute()
		So(err, ShouldBeNil)
		str := buff.String()
		So(strings.Index(str, "a-repo"), ShouldBeLessThan, strings.Index(str, "b-repo"))

		args = []string{"list", "--sort-by", "alpha-dsc", "--url", baseURL}
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)

		err = cmd.Execute()
		So(err, ShouldBeNil)

		str = buff.String()
		So(strings.Index(str, "b-repo"), ShouldBeLessThan, strings.Index(str, "a-repo"))

		args = []string{"list", "--sort-by", "update-time", "--url", baseURL}
		buff = bytes.NewBufferString("")
		cmd.SetOut(buff)
		cmd.SetErr(buff)
		cmd.SetArgs(args)

		err = cmd.Execute()
		So(err, ShouldBeNil)

		str = buff.String()
		So(strings.Index(str, "b-repo"), ShouldBeLessThan, strings.Index(str, "a-repo"))
	})
}

func uploadTestMultiarch(baseURL string) {
	// ------- Define Image1
	layer11 := []byte{11, 12, 13, 14}
	layer12 := []byte{16, 17, 18, 19}

	image1 := CreateImageWith().
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

	image2 := CreateImageWith().
		LayerBlobs([][]byte{
			layer21,
		}).
		ImageConfig(
			ispec.Image{
				Platform: ispec.Platform{OS: "windows", Architecture: "arm64", Variant: "v6"},
			},
		).Build()

	// ------- Upload The multiarch image

	multiarch := CreateMultiarchWith().Images([]Image{image1, image2}).Build()

	err := UploadMultiarchImage(multiarch, baseURL, "repo", "multi-arch")
	So(err, ShouldBeNil)
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
		SetHeader("Content-Length", strconv.Itoa(len(cblob))).
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
		SetHeader("Content-Length", strconv.Itoa(len(cblob))).
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

func getTestSearchConfig(url string, searchService client.SearchService) client.SearchConfig {
	var (
		user         string
		outputFormat string
		verbose      bool
		debug        bool
		verifyTLS    bool
	)

	return client.SearchConfig{
		SearchService: searchService,
		SortBy:        "alpha-asc",
		ServURL:       url,
		User:          user,
		OutputFormat:  outputFormat,
		Verbose:       verbose,
		Debug:         debug,
		VerifyTLS:     verifyTLS,
		ResultWriter:  nil,
	}
}
