//go:build lint
// +build lint

package lint_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"os"
	"path"
	"testing"

	webp "github.com/chai2010/webp"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/lint"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

const (
	username               = "test"
	passphrase             = "test"
	repoName               = "test"
	ServerCert             = "../../test/data/server.cert"
	ServerKey              = "../../test/data/server.key"
	CACert                 = "../../test/data/ca.crt"
	AuthorizedNamespace    = "everyone/isallowed"
	UnauthorizedNamespace  = "fortknox/notallowed"
	ALICE                  = "alice"
	AuthorizationNamespace = "authz/image"
	AuthorizationAllRepos  = "**"
	tag                    = "1.0"
	logoKey                = "com.zot.logo"
)

func TestVerifyMandatoryAnnotations(t *testing.T) {
	//nolint: dupl
	Convey("Mandatory annotations disabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enable := false
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}
		conf.Extensions.Lint.Enable = &enable

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
	})

	//nolint: dupl
	Convey("Mandatory annotations enabled, but no list in config", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enable := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enable = &enable

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
	})

	Convey("Mandatory annotations verification passing", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enable := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enable = &enable
		conf.Extensions.Lint.MandatoryAnnotations = []string{"annotation1", "annotation2", "annotation3"}

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testPass1"
		manifest.Annotations["annotation2"] = "testPass2"
		manifest.Annotations["annotation3"] = "testPass3"

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
	})

	Convey("Mandatory annotations verification in manifest and config passing", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enable := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enable = &enable
		conf.Extensions.Lint.MandatoryAnnotations = []string{"annotation1", "annotation2", "annotation3"}

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "annotationPass1"
		manifest.Annotations["annotation2"] = "annotationPass2"

		configDigest := manifest.Config.Digest

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + fmt.Sprintf("/v2/zot-test/blobs/%s", configDigest))
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		configBlob := resp.Body()
		var imageConfig ispec.Image
		err = json.Unmarshal(configBlob, &imageConfig)
		So(err, ShouldBeNil)

		imageConfig.Config.Labels = make(map[string]string)
		imageConfig.Config.Labels["annotation3"] = "annotationPass3"

		configContent, err := json.Marshal(imageConfig)
		So(err, ShouldBeNil)

		configBlobDigestRaw := godigest.FromBytes(configContent)
		manifest.Config.Digest = configBlobDigestRaw
		manifest.Config.Size = int64(len(configContent))
		manifestContent, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		// upload image config blob
		resp, err = resty.R().
			Post(fmt.Sprintf("%s/v2/zot-test/blobs/uploads/", baseURL))
		So(err, ShouldBeNil)
		loc := test.Location(baseURL, resp)

		_, err = resty.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(configContent))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", configBlobDigestRaw.String()).
			SetBody(configContent).
			Put(loc)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestContent).Put(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
	})

	Convey("Mandatory annotations verification in manifest and config failing", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enable := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enable = &enable
		conf.Extensions.Lint.MandatoryAnnotations = []string{"annotation1", "annotation2", "annotation3"}

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testFail1"

		configDigest := manifest.Config.Digest

		resp, err = resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + fmt.Sprintf("/v2/zot-test/blobs/%s", configDigest))
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		configBlob := resp.Body()
		var imageConfig ispec.Image
		err = json.Unmarshal(configBlob, &imageConfig)
		So(err, ShouldBeNil)

		imageConfig.Config.Labels = make(map[string]string)
		imageConfig.Config.Labels["annotation2"] = "testFail2"

		configContent, err := json.Marshal(imageConfig)
		So(err, ShouldBeNil)

		configBlobDigestRaw := godigest.FromBytes(configContent)
		manifest.Config.Digest = configBlobDigestRaw
		manifest.Config.Size = int64(len(configContent))
		manifestContent, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		// upload image config blob
		_, err = resty.R().
			Post(fmt.Sprintf("%s/v2/zot-test/blobs/uploads/", baseURL))
		So(err, ShouldBeNil)
		loc := test.Location(baseURL, resp)

		_, err = resty.R().
			SetContentLength(true).
			SetHeader("Content-Length", fmt.Sprintf("%d", len(configContent))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", configBlobDigestRaw.String()).
			SetBody(configContent).
			Put(loc)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestContent).Put(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
	})

	Convey("Mandatory annotations incomplete in manifest", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enable := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enable = &enable
		conf.Extensions.Lint.MandatoryAnnotations = []string{"annotation1", "annotation2", "annotation3"}

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testFail1"
		manifest.Annotations["annotation3"] = "testFail3"

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusBadRequest)
	})

	Convey("Mandatory annotations verification passing - more annotations than the mandatory list", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enable := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}
		conf.Extensions.Lint.Enable = &enable
		conf.Extensions.Lint.MandatoryAnnotations = []string{"annotation1", "annotation2", "annotation3"}

		ctlr := api.NewController(conf)
		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		ctlr.Config.Storage.RootDirectory = dir

		go startServer(ctlr)
		defer stopServer(ctlr)
		test.WaitTillServerReady(baseURL)

		resp, err := resty.R().SetBasicAuth(username, passphrase).
			Get(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()
		var manifest ispec.Manifest
		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testPassMore1"
		manifest.Annotations["annotation2"] = "testPassMore2"
		manifest.Annotations["annotation3"] = "testPassMore3"
		manifest.Annotations["annotation4"] = "testPassMore4"

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(content).Put(baseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)
	})
}

func TestVerifyMandatoryAnnotationsFunction(t *testing.T) {
	Convey("Mandatory annotations disabled", t, func() {
		enable := false

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enable},
			MandatoryAnnotations: []string{},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := local.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		indexContent, err := imgStore.GetIndexContent("zot-test")
		So(err, ShouldBeNil)
		err = json.Unmarshal(indexContent, &index)
		So(err, ShouldBeNil)

		manifestDigest := index.Manifests[0].Digest

		pass, err := linter.CheckMandatoryAnnotations("zot-test", manifestDigest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	Convey("Mandatory annotations enabled, but no list in config", t, func() {
		enable := true

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enable},
			MandatoryAnnotations: []string{},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := local.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		indexContent, err := imgStore.GetIndexContent("zot-test")
		So(err, ShouldBeNil)
		err = json.Unmarshal(indexContent, &index)
		So(err, ShouldBeNil)

		manifestDigest := index.Manifests[0].Digest

		pass, err := linter.CheckMandatoryAnnotations("zot-test", manifestDigest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	Convey("Mandatory annotations verification passing", t, func() {
		enable := true

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enable},
			MandatoryAnnotations: []string{"annotation1", "annotation2", "annotation3"},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		buf, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &index)
		So(err, ShouldBeNil)

		manifestDigest := index.Manifests[0].Digest

		var manifest ispec.Manifest
		buf, err = os.ReadFile(path.Join(dir, "zot-test", "blobs",
			manifestDigest.Algorithm().String(), manifestDigest.Encoded()))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testPass1"
		manifest.Annotations["annotation2"] = "testPass2"
		manifest.Annotations["annotation3"] = "testPass3"

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		So(content, ShouldNotBeNil)

		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		err = os.WriteFile(path.Join(dir, "zot-test", "blobs",
			digest.Algorithm().String(), digest.Encoded()), content, 0o600)
		So(err, ShouldBeNil)

		manifestDesc := ispec.Descriptor{
			Size:   int64(len(content)),
			Digest: digest,
		}

		index.Manifests = append(index.Manifests, manifestDesc)

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := local.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	Convey("Mandatory annotations incomplete in manifest", t, func() {
		enable := true

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enable},
			MandatoryAnnotations: []string{"annotation1", "annotation2", "annotation3"},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		buf, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &index)
		So(err, ShouldBeNil)

		manifestDigest := index.Manifests[0].Digest

		var manifest ispec.Manifest
		buf, err = os.ReadFile(path.Join(dir, "zot-test", "blobs",
			manifestDigest.Algorithm().String(), manifestDigest.Encoded()))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "test1"
		manifest.Annotations["annotation3"] = "test3"

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		So(content, ShouldNotBeNil)

		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		err = os.WriteFile(path.Join(dir, "zot-test", "blobs",
			digest.Algorithm().String(), digest.Encoded()), content, 0o600)
		So(err, ShouldBeNil)

		manifestDesc := ispec.Descriptor{
			Size:   int64(len(content)),
			Digest: digest,
		}

		index.Manifests = append(index.Manifests, manifestDesc)

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := local.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeFalse)
	})

	Convey("Mandatory annotations verification passing - more annotations than the mandatory list", t, func() {
		enable := true

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enable},
			MandatoryAnnotations: []string{"annotation1", "annotation2", "annotation3"},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		buf, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &index)
		So(err, ShouldBeNil)

		manifestDigest := index.Manifests[0].Digest

		var manifest ispec.Manifest
		buf, err = os.ReadFile(path.Join(dir, "zot-test", "blobs",
			manifestDigest.Algorithm().String(), manifestDigest.Encoded()))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testPassMore1"
		manifest.Annotations["annotation2"] = "testPassMore2"
		manifest.Annotations["annotation3"] = "testPassMore3"
		manifest.Annotations["annotation4"] = "testPassMore4"

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		So(content, ShouldNotBeNil)

		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		err = os.WriteFile(path.Join(dir, "zot-test", "blobs",
			digest.Algorithm().String(), digest.Encoded()), content, 0o600)
		So(err, ShouldBeNil)

		manifestDesc := ispec.Descriptor{
			Size:   int64(len(content)),
			Digest: digest,
		}

		index.Manifests = append(index.Manifests, manifestDesc)

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := local.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	Convey("Cannot unmarshal manifest", t, func() {
		enable := true

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enable},
			MandatoryAnnotations: []string{"annotation1", "annotation2", "annotation3"},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		buf, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &index)
		So(err, ShouldBeNil)

		manifestDigest := index.Manifests[0].Digest

		var manifest ispec.Manifest
		buf, err = os.ReadFile(path.Join(dir, "zot-test", "blobs",
			manifestDigest.Algorithm().String(), manifestDigest.Encoded()))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testUnmarshal1"
		manifest.Annotations["annotation2"] = "testUnmarshal2"
		manifest.Annotations["annotation3"] = "testUnmarshal3"

		manifest.SchemaVersion = 2
		content, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		So(content, ShouldNotBeNil)

		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		err = os.WriteFile(path.Join(dir, "zot-test", "blobs",
			digest.Algorithm().String(), digest.Encoded()), content, 0o600)
		So(err, ShouldBeNil)

		manifestDesc := ispec.Descriptor{
			Size:   int64(len(content)),
			Digest: digest,
		}

		index.Manifests = append(index.Manifests, manifestDesc)

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := local.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		err = os.Chmod(path.Join(dir, "zot-test", "blobs"), 0o000)
		if err != nil {
			panic(err)
		}

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldNotBeNil)
		So(pass, ShouldBeFalse)

		err = os.Chmod(path.Join(dir, "zot-test", "blobs"), 0o755)
		if err != nil {
			panic(err)
		}
	})

	Convey("Cannot get config file", t, func() {
		enable := true

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enable},
			MandatoryAnnotations: []string{"annotation1", "annotation2", "annotation3"},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index
		buf, err := os.ReadFile(path.Join(dir, "zot-test", "index.json"))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &index)
		So(err, ShouldBeNil)

		manifestDigest := index.Manifests[0].Digest

		var manifest ispec.Manifest
		buf, err = os.ReadFile(path.Join(dir, "zot-test", "blobs",
			manifestDigest.Algorithm().String(), manifestDigest.Encoded()))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &manifest)
		So(err, ShouldBeNil)

		manifest.Annotations = make(map[string]string)

		manifest.Annotations["annotation1"] = "testAnnotation1"
		manifest.Annotations["annotation2"] = "testAnnotation2"

		// write config
		var imageConfig ispec.Image
		configDigest := manifest.Config.Digest
		buf, err = os.ReadFile(path.Join(dir, "zot-test", "blobs", "sha256",
			configDigest.Encoded()))
		So(err, ShouldBeNil)
		err = json.Unmarshal(buf, &imageConfig)
		So(err, ShouldBeNil)

		imageConfig.Config.Labels = make(map[string]string)
		imageConfig.Config.Labels["annotation3"] = "testAnnotation3"

		configContent, err := json.Marshal(imageConfig)
		So(err, ShouldBeNil)
		So(configContent, ShouldNotBeNil)

		cfgDigest := godigest.FromBytes(configContent)
		So(cfgDigest, ShouldNotBeNil)

		err = os.WriteFile(path.Join(dir, "zot-test", "blobs", "sha256",
			cfgDigest.Encoded()), configContent, 0o600)
		So(err, ShouldBeNil)

		// write manifest
		manifest.SchemaVersion = 2
		manifest.Config.Size = int64(len(configContent))
		manifest.Config.Digest = cfgDigest
		manifestContent, err := json.Marshal(manifest)
		So(err, ShouldBeNil)
		So(manifestContent, ShouldNotBeNil)

		digest := godigest.FromBytes(manifestContent)
		So(digest, ShouldNotBeNil)

		err = os.WriteFile(path.Join(dir, "zot-test", "blobs",
			digest.Algorithm().String(), digest.Encoded()), manifestContent, 0o600)
		So(err, ShouldBeNil)

		manifestDesc := ispec.Descriptor{
			Size:   int64(len(manifestContent)),
			Digest: digest,
		}

		index.Manifests = append(index.Manifests, manifestDesc)

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := local.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		err = os.Chmod(path.Join(dir, "zot-test", "blobs", "sha256", manifest.Config.Digest.Encoded()), 0o000)
		if err != nil {
			panic(err)
		}

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldNotBeNil)
		So(pass, ShouldBeFalse)

		err = os.Chmod(path.Join(dir, "zot-test", "blobs", "sha256", manifest.Config.Digest.Encoded()), 0o755)
		if err != nil {
			panic(err)
		}
	})
}

func TestValidateLogo(t *testing.T) {
	Convey("Make manifest", t, func(c C) {
		dir := t.TempDir()

		enabled := true

		lintConfig := &extconf.LintConfig{
			BaseConfig:           extconf.BaseConfig{Enable: &enabled},
			MandatoryAnnotations: []string{logoKey},
		}

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := local.NewImageStore(dir, true, storage.DefaultGCDelay, true,
			true, log, metrics, linter)

		content := []byte("this is a blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		_, blen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		cblob, cdigest := test.GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		Convey("Check logo in annotations", func() {
			annotationsMap := make(map[string]string)
			annotationsMap[ispec.AnnotationRefName] = tag

			cblob, cdigest := test.GetRandomImageConfig()
			_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))
			hasBlob, _, err := imgStore.CheckBlob(repoName, cdigest)
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)

			Convey("logo string not in base64 encoding", func() {
				annotationsMap[logoKey] = "invalid"

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(manifestBuf)

				_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldEqual, zerr.ErrImageLintAnnotations)
			})

			Convey("base64 encoded, but not an image format", func() {
				logoEncoding := base64.StdEncoding.EncodeToString([]byte("invalid"))

				annotationsMap[logoKey] = logoEncoding

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(manifestBuf)

				_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldEqual, zerr.ErrImageLintAnnotations)
			})

			Convey("base64 encoded, but invalid image format", func() {
				width := 190
				height := 190

				upLeft := image.Point{0, 0}
				lowRight := image.Point{width, height}
				logoImage := image.NewRGBA(image.Rectangle{upLeft, lowRight})

				buff := new(bytes.Buffer)
				err := webp.Encode(buff, logoImage, nil)
				So(err, ShouldBeNil)
				logoEncoding := base64.StdEncoding.EncodeToString(buff.Bytes())
				annotationsMap[logoKey] = logoEncoding

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(manifestBuf)

				_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldEqual, zerr.ErrImageLintAnnotations)
			})

			Convey("bad logo size", func() {
				width := 250
				height := 190

				upLeft := image.Point{0, 0}
				lowRight := image.Point{width, height}
				logo := image.NewRGBA(image.Rectangle{upLeft, lowRight})

				buff := new(bytes.Buffer)
				err := png.Encode(buff, logo)
				So(err, ShouldBeNil)

				logoEncoding := base64.StdEncoding.EncodeToString(buff.Bytes())

				annotationsMap[logoKey] = logoEncoding

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(manifestBuf)

				_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldEqual, zerr.ErrImageLintAnnotations)
			})

			Convey("logo with good png format", func() {
				width := 190
				height := 190

				upLeft := image.Point{0, 0}
				lowRight := image.Point{width, height}
				logo := image.NewRGBA(image.Rectangle{upLeft, lowRight})

				buff := new(bytes.Buffer)
				err := png.Encode(buff, logo)
				So(err, ShouldBeNil)

				logoEncoding := base64.StdEncoding.EncodeToString(buff.Bytes())

				annotationsMap[logoKey] = logoEncoding

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(manifestBuf)

				_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldBeNil)
			})

			Convey("logo with good jpeg format", func() {
				width := 190
				height := 190

				upLeft := image.Point{0, 0}
				lowRight := image.Point{width, height}
				logo := image.NewRGBA(image.Rectangle{upLeft, lowRight})

				buff := new(bytes.Buffer)
				err := jpeg.Encode(buff, logo, nil)
				So(err, ShouldBeNil)

				logoEncoding := base64.StdEncoding.EncodeToString(buff.Bytes())

				annotationsMap[logoKey] = logoEncoding

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(manifestBuf)

				_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldBeNil)
			})

			Convey("logo with good gif format", func() {
				width := 190
				height := 190

				upLeft := image.Point{0, 0}
				lowRight := image.Point{width, height}
				palette := []color.Color{color.White, color.Black}
				rect := image.Rectangle{upLeft, lowRight}
				logo := image.NewPaletted(rect, palette)

				logo.SetColorIndex(width/2, height/2, 1)

				anim := gif.GIF{Delay: []int{0}, Image: []*image.Paletted{logo}}

				buff := new(bytes.Buffer)
				err := gif.EncodeAll(buff, &anim)

				// err := png.Encode(buff, logo)
				So(err, ShouldBeNil)

				logoEncoding := base64.StdEncoding.EncodeToString(buff.Bytes())

				annotationsMap[logoKey] = logoEncoding

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
					Annotations: annotationsMap,
				}

				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(manifestBuf)

				_, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
				So(err, ShouldBeNil)
			})
		})
	})
}

func startServer(c *api.Controller) {
	// this blocks
	ctx := context.Background()
	if err := c.Run(ctx); err != nil {
		return
	}
}

func stopServer(c *api.Controller) {
	ctx := context.Background()
	_ = c.Server.Shutdown(ctx)
}
