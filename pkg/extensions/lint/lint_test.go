//go:build lint
// +build lint

package lint_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/pkg/api"
	"zotregistry.io/zot/pkg/api/config"
	extconf "zotregistry.io/zot/pkg/extensions/config"
	"zotregistry.io/zot/pkg/extensions/lint"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/test"
)

const (
	username               = "test"
	passphrase             = "test"
	ServerCert             = "../../test/data/server.cert"
	ServerKey              = "../../test/data/server.key"
	CACert                 = "../../test/data/ca.crt"
	AuthorizedNamespace    = "everyone/isallowed"
	UnauthorizedNamespace  = "fortknox/notallowed"
	ALICE                  = "alice"
	AuthorizationNamespace = "authz/image"
	AuthorizationAllRepos  = "**"
)

func TestVerifyMandatoryAnnotations(t *testing.T) {
	// nolint: dupl
	Convey("Mandatory annotations disabled", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enabled := false
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}
		conf.Extensions.Lint.Enabled = &enabled

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

	// nolint: dupl
	Convey("Mandatory annotations enabled, but no list in config", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enabled := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enabled = &enabled

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
		enabled := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enabled = &enabled
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

	Convey("Mandatory annotations incomplete in manifest", t, func() {
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		conf := config.New()
		conf.HTTP.Port = port
		enabled := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}

		conf.Extensions.Lint.Enabled = &enabled
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
		enabled := true
		conf.Extensions = &extconf.ExtensionConfig{Lint: &extconf.LintConfig{}}
		conf.Extensions.Lint.MandatoryAnnotations = []string{}
		conf.Extensions.Lint.Enabled = &enabled
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
		enabled := false

		lintConfig := &extconf.LintConfig{
			Enabled:              &enabled,
			MandatoryAnnotations: []string{},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := storage.NewImageStore(dir, false, 0, false, false,
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
		enabled := true

		lintConfig := &extconf.LintConfig{
			Enabled:              &enabled,
			MandatoryAnnotations: []string{},
		}

		dir := t.TempDir()

		err := test.CopyFiles("../../../test/data", dir)
		if err != nil {
			panic(err)
		}

		var index ispec.Index

		linter := lint.NewLinter(lintConfig, log.NewLogger("debug", ""))
		imgStore := storage.NewImageStore(dir, false, 0, false, false,
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
		enabled := true

		lintConfig := &extconf.LintConfig{
			Enabled:              &enabled,
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
		imgStore := storage.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	Convey("Mandatory annotations incomplete in manifest", t, func() {
		enabled := true

		lintConfig := &extconf.LintConfig{
			Enabled:              &enabled,
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
		imgStore := storage.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeFalse)
	})

	Convey("Mandatory annotations verification passing - more annotations than the mandatory list", t, func() {
		enabled := true

		lintConfig := &extconf.LintConfig{
			Enabled:              &enabled,
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
		imgStore := storage.NewImageStore(dir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), linter)

		pass, err := linter.CheckMandatoryAnnotations("zot-test", digest, imgStore)
		So(err, ShouldBeNil)
		So(pass, ShouldBeTrue)
	})

	Convey("Cannot unmarshal manifest", t, func() {
		enabled := true

		lintConfig := &extconf.LintConfig{
			Enabled:              &enabled,
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
		imgStore := storage.NewImageStore(dir, false, 0, false, false,
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
