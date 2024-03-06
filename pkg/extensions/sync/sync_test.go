//go:build sync
// +build sync

package sync_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"strings"
	goSync "sync"
	"testing"
	"time"

	dockerManifest "github.com/containers/image/v5/manifest"
	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/pkg/api"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/api/constants"
	cli "zotregistry.dev/zot/pkg/cli/server"
	zcommon "zotregistry.dev/zot/pkg/common"
	extconf "zotregistry.dev/zot/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/extensions/sync"
	syncConstants "zotregistry.dev/zot/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	authutils "zotregistry.dev/zot/pkg/test/auth"
	test "zotregistry.dev/zot/pkg/test/common"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/pkg/test/oci-utils"
	"zotregistry.dev/zot/pkg/test/signature"
)

const (
	ServerCert = "../../../test/data/server.cert"
	ServerKey  = "../../../test/data/server.key"
	CACert     = "../../../test/data/ca.crt"
	ClientCert = "../../../test/data/client.cert"
	ClientKey  = "../../../test/data/client.key"

	testImage    = "zot-test"
	testImageTag = "0.0.1"
	testCveImage = "zot-cve-test"

	testSignedImage = "signed-repo"
)

var (
	username     = "test" //nolint: gochecknoglobals
	password     = "test" //nolint: gochecknoglobals
	errSync      = errors.New("sync error, src oci repo differs from dest one")
	errBadStatus = errors.New("bad http status")
)

type TagsList struct {
	Name string
	Tags []string
}

type ReferenceList struct {
	References []ispec.Descriptor `json:"references"`
}

type catalog struct {
	Repositories []string `json:"repositories"`
}

func makeUpstreamServer(
	t *testing.T, secure, basicAuth bool,
) (*api.Controller, string, string, string, *resty.Client) {
	t.Helper()

	srcPort := test.GetFreePort()
	srcConfig := config.New()
	client := resty.New()

	var srcBaseURL string
	if secure {
		srcBaseURL = test.GetSecureBaseURL(srcPort)

		srcConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		caCert, err := os.ReadFile(CACert)
		if err != nil {
			panic(err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(ClientCert, ClientKey)
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
	} else {
		srcBaseURL = test.GetBaseURL(srcPort)
	}

	var htpasswdPath string
	if basicAuth {
		htpasswdPath = test.MakeHtpasswdFileFromString(test.GetCredString(username, password))
		srcConfig.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
	}

	srcConfig.HTTP.Port = srcPort
	srcConfig.Storage.GC = false

	srcDir := t.TempDir()
	srcStorageCtrl := ociutils.GetDefaultStoreController(srcDir, log.NewLogger("debug", ""))

	err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", srcStorageCtrl)
	if err != nil {
		panic(err)
	}

	err = WriteImageToFileSystem(CreateDefaultVulnerableImage(), "zot-cve-test", "0.0.1", srcStorageCtrl)
	if err != nil {
		panic(err)
	}

	srcConfig.Storage.RootDirectory = srcDir

	defVal := true
	srcConfig.Extensions = &extconf.ExtensionConfig{}
	srcConfig.Extensions.Search = &extconf.SearchConfig{
		BaseConfig: extconf.BaseConfig{Enable: &defVal},
	}

	sctlr := api.NewController(srcConfig)

	return sctlr, srcBaseURL, srcDir, htpasswdPath, client
}

func makeDownstreamServer(
	t *testing.T, secure bool, syncConfig *syncconf.Config,
) (*api.Controller, string, string, *resty.Client) {
	t.Helper()

	destPort := test.GetFreePort()
	destConfig := config.New()
	client := resty.New()

	var destBaseURL string
	if secure {
		destBaseURL = test.GetSecureBaseURL(destPort)

		destConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   ServerCert,
			Key:    ServerKey,
			CACert: CACert,
		}

		caCert, err := os.ReadFile(CACert)
		if err != nil {
			panic(err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(ClientCert, ClientKey)
		if err != nil {
			panic(err)
		}

		client.SetCertificates(cert)
	} else {
		destBaseURL = test.GetBaseURL(destPort)
	}

	destConfig.HTTP.Port = destPort

	destDir := t.TempDir()

	destConfig.Storage.RootDirectory = destDir
	destConfig.Storage.Dedupe = false
	destConfig.Storage.GC = false

	destConfig.Extensions = &extconf.ExtensionConfig{}
	defVal := true
	destConfig.Extensions.Search = &extconf.SearchConfig{
		BaseConfig: extconf.BaseConfig{Enable: &defVal},
	}
	destConfig.Extensions.Sync = syncConfig
	destConfig.Log.Output = path.Join(destDir, "sync.log")
	destConfig.Log.Level = "debug"

	dctlr := api.NewController(destConfig)

	return dctlr, destBaseURL, destDir, client
}

func TestOnDemand(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		sctlr, srcBaseURL, _, _, srcClient := makeUpstreamServer(t, false, false)
		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		var tlsVerify bool

		regex := ".*"
		semver := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		Convey("Verify sync on demand feature with one registryConfig", func() {
			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, destDir, destClient := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err := json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + "inexistent" + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			err = os.MkdirAll(path.Join(destDir, testImage), 0o000)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)

			err = os.Chmod(path.Join(destDir, testImage), 0o755)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			err = os.MkdirAll(path.Join(destDir, testImage, syncConstants.SyncBlobUploadDir), 0o000)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			err = os.Chmod(path.Join(destDir, testImage, syncConstants.SyncBlobUploadDir), 0o755)
			if err != nil {
				panic(err)
			}

			err = os.MkdirAll(path.Join(destDir, testImage, "blobs"), 0o000)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			err = os.Chmod(path.Join(destDir, testImage, "blobs"), 0o755)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// for coverage, sync again
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			So(destTagsList, ShouldResemble, srcTagsList)

			// trigger canSkipImage error
			err = os.Chmod(path.Join(destDir, testImage, "index.json"), 0o000)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusInternalServerError)
		})
		Convey("Verify sync on demand feature with multiple registryConfig", func() {
			// make a new upstream server
			sctlr, newSrcBaseURL, srcDir, _, srcClient := makeUpstreamServer(t, false, false)
			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			// remove remote testImage
			err := os.RemoveAll(path.Join(srcDir, testImage))
			So(err, ShouldBeNil)

			// new registryConfig with new server url
			newRegistryConfig := syncRegistryConfig
			newRegistryConfig.URLs = []string{newSrcBaseURL}
			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{newRegistryConfig, syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + "inexistent" + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			So(destTagsList, ShouldResemble, srcTagsList)
		})
	})

	Convey("Sync on Demand errors", t, func() {
		Convey("Signature copier errors", func() {
			// start upstream server
			rootDir := t.TempDir()
			port := test.GetFreePort()
			srcBaseURL := test.GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port
			conf.Storage.GC = false
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = rootDir

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(conf.HTTP.Port)
			defer cm.StopServer()

			image := CreateRandomImage()
			manifestBlob := image.ManifestDescriptor.Data
			manifestDigest := image.ManifestDescriptor.Digest

			err := UploadImage(image, srcBaseURL, "remote-repo", "test")
			So(err, ShouldBeNil)

			// sign using cosign
			err = signature.SignImageUsingCosign(fmt.Sprintf("remote-repo@%s", manifestDigest.String()), port, false)
			So(err, ShouldBeNil)

			// add cosign sbom
			attachSBOM(rootDir, port, "remote-repo", manifestDigest)

			// add OCI Ref
			_ = pushBlob(srcBaseURL, "remote-repo", ispec.DescriptorEmptyJSON.Data)

			OCIRefManifest := ispec.Manifest{
				Versioned: specs.Versioned{
					SchemaVersion: 2,
				},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    manifestDigest,
					Size:      int64(len(manifestBlob)),
				},
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeEmptyJSON,
					Digest:    ispec.DescriptorEmptyJSON.Digest,
					Size:      2,
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeEmptyJSON,
						Digest:    ispec.DescriptorEmptyJSON.Digest,
						Size:      2,
					},
				},
				MediaType: ispec.MediaTypeImageManifest,
			}

			OCIRefManifestBlob, err := json.Marshal(OCIRefManifest)
			So(err, ShouldBeNil)

			resp, err := resty.R().
				SetHeader("Content-type", ispec.MediaTypeImageManifest).
				SetBody(OCIRefManifestBlob).
				Put(srcBaseURL + "/v2/remote-repo/manifests/oci.ref")

			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			//------- Start downstream server

			var tlsVerify bool

			regex := ".*"
			semver := true

			destPort := test.GetFreePort()
			destConfig := config.New()

			destBaseURL := test.GetBaseURL(destPort)

			hostname, err := os.Hostname()
			So(err, ShouldBeNil)

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						Prefix: "remote-repo",
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				// include self url, should be ignored
				URLs: []string{
					fmt.Sprintf("http://%s", hostname), destBaseURL,
					srcBaseURL, fmt.Sprintf("http://localhost:%s", destPort),
				},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  true,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			destConfig.HTTP.Port = destPort

			destDir := t.TempDir()

			destConfig.Storage.RootDirectory = destDir
			destConfig.Storage.Dedupe = false
			destConfig.Storage.GC = false

			destConfig.Extensions = &extconf.ExtensionConfig{}

			destConfig.Extensions.Sync = syncConfig

			dctlr := api.NewController(destConfig)

			// metadb fails for syncCosignSignature"
			dctlr.MetaDB = mocks.MetaDBMock{
				AddManifestSignatureFn: func(repo string, signedManifestDigest godigest.Digest,
					sm mTypes.SignatureMetadata,
				) error {
					if sm.SignatureType == zcommon.CosignSignature || sm.SignatureType == zcommon.NotationSignature {
						return sync.ErrTestError
					}

					return nil
				},
				SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					if strings.HasPrefix(reference, "sha256-") &&
						(strings.HasSuffix(reference, remote.SignatureTagSuffix) ||
							strings.HasSuffix(reference, remote.SBOMTagSuffix)) ||
						strings.HasPrefix(reference, "sha256:") {
						return sync.ErrTestError
					}

					// don't return err for normal image with tag
					return nil
				},
			}

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(destPort)
			defer dcm.StopServer()

			resp, err = resty.R().Get(destBaseURL + "/v2/remote-repo/manifests/test")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})

		Convey("Sync referrers tag errors", func() {
			// start upstream server
			rootDir := t.TempDir()
			port := test.GetFreePort()
			srcBaseURL := test.GetBaseURL(port)
			conf := config.New()
			conf.HTTP.Port = port
			conf.Storage.GC = false
			ctlr := api.NewController(conf)
			ctlr.Config.Storage.RootDirectory = rootDir

			cm := test.NewControllerManager(ctlr)
			cm.StartAndWait(conf.HTTP.Port)
			defer cm.StopServer()

			image := CreateRandomImage()
			manifestBlob := image.ManifestDescriptor.Data
			manifestDigest := image.ManifestDescriptor.Digest

			err := UploadImage(image, srcBaseURL, "remote-repo", "test")
			So(err, ShouldBeNil)

			subjectDesc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(manifestBlob)),
			}

			ociRefImage := CreateDefaultImageWith().Subject(&subjectDesc).Build()

			err = UploadImage(ociRefImage, srcBaseURL, "remote-repo", ociRefImage.ManifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			tag := strings.Replace(manifestDigest.String(), ":", "-", 1)

			// add index with referrers tag
			tagRefIndex := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    ociRefImage.ManifestDescriptor.Digest,
						Size:      int64(len(ociRefImage.ManifestDescriptor.Data)),
					},
				},
				Annotations: map[string]string{ispec.AnnotationRefName: tag},
			}

			tagRefIndex.SchemaVersion = 2

			tagRefIndexBlob, err := json.Marshal(tagRefIndex)
			So(err, ShouldBeNil)

			resp, err := resty.R().
				SetHeader("Content-type", ispec.MediaTypeImageIndex).
				SetBody(tagRefIndexBlob).
				Put(srcBaseURL + "/v2/remote-repo/manifests/" + tag)

			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

			//------- Start downstream server

			var tlsVerify bool

			regex := ".*"
			semver := true

			destPort := test.GetFreePort()
			destConfig := config.New()

			destBaseURL := test.GetBaseURL(destPort)

			hostname, err := os.Hostname()
			So(err, ShouldBeNil)

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						Prefix: "remote-repo",
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				// include self url, should be ignored
				URLs: []string{
					fmt.Sprintf("http://%s", hostname), destBaseURL,
					srcBaseURL, fmt.Sprintf("http://localhost:%s", destPort),
				},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  true,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			destConfig.HTTP.Port = destPort

			destDir := t.TempDir()

			destConfig.Storage.RootDirectory = destDir
			destConfig.Storage.Dedupe = false
			destConfig.Storage.GC = false

			destConfig.Extensions = &extconf.ExtensionConfig{}

			destConfig.Extensions.Sync = syncConfig

			dctlr := api.NewController(destConfig)

			// metadb fails for syncReferrersTag"
			dctlr.MetaDB = mocks.MetaDBMock{
				SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					if imageMeta.Digest.String() == ociRefImage.ManifestDescriptor.Digest.String() {
						return sync.ErrTestError
					}

					return nil
				},
			}

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(destPort)
			defer dcm.StopServer()

			resp, err = resty.R().Get(destBaseURL + "/v2/remote-repo/manifests/test")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = resty.R().Get(destBaseURL + "/v2/remote-repo/manifests/" + tag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})
	})
}

func TestSyncReferenceInLoop(t *testing.T) {
	Convey("Verify sync doesn't end up in an infinite loop when syncing image references", t, func() {
		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		var tlsVerify bool

		maxRetries := 1
		delay := 1 * time.Second

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
				},
			},
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			OnDemand:   true,
			MaxRetries: &maxRetries,
			RetryDelay: &delay,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// we will push references in loop: image A -> sbom A -> oci artifact A -> sbom A (same sbom as before)
		// recursive syncing it should not get in an infinite loop
		// sync testImage and get its digest
		resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		imageDigest := godigest.FromBytes(resp.Body())

		// attach sbom
		attachSBOM(srcDir, sctlr.Config.HTTP.Port, testImage, imageDigest)

		// sbom tag
		sbomTag := strings.Replace(imageDigest.String(), ":", "-", 1) + "." + remote.SBOMTagSuffix

		// sync sbom and get its digest
		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			Get(destBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", testImage, sbomTag))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		sbomManifestBuf := resp.Body()
		sbomDigest := godigest.FromBytes(sbomManifestBuf)

		// push oci ref referencing sbom
		_ = pushBlob(srcBaseURL, testImage, ispec.DescriptorEmptyJSON.Data)

		OCIRefManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Subject: &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    sbomDigest,
				Size:      int64(len(sbomManifestBuf)),
			},
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeEmptyJSON,
				Digest:    ispec.DescriptorEmptyJSON.Digest,
				Size:      2,
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeEmptyJSON,
					Digest:    ispec.DescriptorEmptyJSON.Digest,
					Size:      2,
				},
			},
			MediaType: ispec.MediaTypeImageManifest,
		}

		OCIRefManifestBlob, err := json.Marshal(OCIRefManifest)
		So(err, ShouldBeNil)

		OCIRefDigest := godigest.FromBytes(OCIRefManifestBlob)

		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			SetBody(OCIRefManifestBlob).
			Put(srcBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", testImage, OCIRefDigest))

		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// attach same sbom we attached to image
		// can not use same function attachSBOM because its digest will differ
		sbomTag2 := strings.Replace(OCIRefDigest.String(), ":", "-", 1) + "." + remote.SBOMTagSuffix

		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			SetBody(sbomManifestBuf).
			Put(srcBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", testImage, sbomTag2))

		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		// sync image
		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// check all references are synced
		// first sbom
		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			Get(destBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", testImage, sbomTag))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// oci ref
		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			Get(destBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", testImage, OCIRefDigest))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// second sbom
		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			Get(destBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", testImage, sbomTag2))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestSyncWithNonDistributableBlob(t *testing.T) {
	Convey("Verify sync doesn't copy non distributable blobs", t, func() {
		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		var tlsVerify bool

		maxRetries := 1
		delay := 1 * time.Second
		repoName := "remote-repo"
		tag := "latest"

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: repoName,
				},
			},
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			OnDemand:   true,
			MaxRetries: &maxRetries,
			RetryDelay: &delay,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)

		nonDistributableLayerData := make([]byte, 10)
		nonDistributableDigest := godigest.FromBytes(nonDistributableLayerData)
		nonDistributableLayer := Layer{
			Blob:      nonDistributableLayerData,
			Digest:    nonDistributableDigest,
			MediaType: ispec.MediaTypeImageLayerNonDistributableGzip, //nolint:staticcheck
		}

		layers := append(GetDefaultLayers(), nonDistributableLayer)
		image := CreateImageWith().Layers(layers).DefaultConfig().Build()

		err := UploadImage(image, srcBaseURL, repoName, tag)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(srcDir, repoName, "blobs/sha256", nonDistributableDigest.Encoded()),
			nonDistributableLayerData, 0o600)
		So(err, ShouldBeNil)

		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		time.Sleep(3 * time.Second)

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + tag)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + repoName + "/blobs/" + nonDistributableDigest.String())
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestDockerImagesAreSkipped(t *testing.T) {
	Convey("Verify docker images are skipped when they are already synced", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		var tlsVerify bool

		maxRetries := 1
		delay := 1 * time.Second

		indexRepoName := "index"

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
				},
				{
					Prefix: indexRepoName,
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			MaxRetries:   &maxRetries,
			OnDemand:     true,
			RetryDelay:   &delay,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, _ := makeDownstreamServer(t, false, syncConfig)

		Convey("skipping already synced docker image", func() {
			// because we can not store images in docker format, modify the test image so that it has docker mediatype
			indexContent, err := os.ReadFile(path.Join(srcDir, testImage, "index.json"))
			So(err, ShouldBeNil)
			So(indexContent, ShouldNotBeNil)

			var index ispec.Index
			err = json.Unmarshal(indexContent, &index)
			So(err, ShouldBeNil)

			var configBlobDigest godigest.Digest

			for idx, manifestDesc := range index.Manifests {
				manifestContent, err := os.ReadFile(path.Join(srcDir, testImage, "blobs/sha256", manifestDesc.Digest.Encoded()))
				So(err, ShouldBeNil)

				var manifest ispec.Manifest

				err = json.Unmarshal(manifestContent, &manifest)
				So(err, ShouldBeNil)

				configBlobDigest = manifest.Config.Digest

				manifest.MediaType = dockerManifest.DockerV2Schema2MediaType
				manifest.Config.MediaType = dockerManifest.DockerV2Schema2ConfigMediaType
				index.Manifests[idx].MediaType = dockerManifest.DockerV2Schema2MediaType

				for idx := range manifest.Layers {
					manifest.Layers[idx].MediaType = dockerManifest.DockerV2Schema2LayerMediaType
				}

				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)

				manifestDigest := godigest.FromBytes(manifestBuf)
				index.Manifests[idx].Digest = manifestDigest

				// write modified manifest, remove old one
				err = os.WriteFile(path.Join(srcDir, testImage, "blobs/sha256", manifestDigest.Encoded()),
					manifestBuf, storageConstants.DefaultFilePerms)
				So(err, ShouldBeNil)

				err = os.Remove(path.Join(srcDir, testImage, "blobs/sha256", manifestDesc.Digest.Encoded()))
				So(err, ShouldBeNil)
			}

			indexBuf, err := json.Marshal(index)
			So(err, ShouldBeNil)

			err = os.WriteFile(path.Join(srcDir, testImage, "index.json"), indexBuf, storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			// now it should be skipped
			resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"skipping image because it's already synced", 20*time.Second)
			if err != nil {
				panic(err)
			}

			if !found {
				data, err := os.ReadFile(dctlr.Config.Log.Output)
				So(err, ShouldBeNil)

				t.Logf("downstream log: %s", string(data))
			}

			So(found, ShouldBeTrue)

			Convey("trigger config blob upstream error", func() {
				// remove synced image
				err := os.RemoveAll(path.Join(destDir, testImage))
				So(err, ShouldBeNil)

				err = os.Chmod(path.Join(srcDir, testImage, "blobs/sha256", configBlobDigest.Encoded()), 0o000)
				So(err, ShouldBeNil)

				resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			})
		})

		Convey("skipping already synced multiarch docker image", func() {
			// create an image index on upstream
			multiarchImage := CreateMultiarchWith().Images(
				[]Image{
					CreateRandomImage(),
					CreateRandomImage(),
					CreateRandomImage(),
					CreateRandomImage(),
				},
			).Build()

			// upload the previously defined images
			err := UploadMultiarchImage(multiarchImage, srcBaseURL, indexRepoName, "latest")
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(srcBaseURL + "/v2/index/manifests/latest")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			// 'convert' oci multi arch image to docker multi arch

			indexContent, err := os.ReadFile(path.Join(srcDir, indexRepoName, "index.json"))
			So(err, ShouldBeNil)
			So(indexContent, ShouldNotBeNil)

			var newIndex ispec.Index
			err = json.Unmarshal(indexContent, &newIndex)
			So(err, ShouldBeNil)

			/* first find multiarch manifest in index.json
			so that we can update both multiarch manifest and index.json at the same time*/
			var indexManifest ispec.Index
			indexManifest.Manifests = make([]ispec.Descriptor, 4)

			var indexManifestIdx int
			for idx, manifestDesc := range newIndex.Manifests {
				if manifestDesc.MediaType == ispec.MediaTypeImageIndex {
					indexManifestContent, err := os.ReadFile(path.Join(srcDir, indexRepoName, "blobs/sha256",
						manifestDesc.Digest.Encoded()))
					So(err, ShouldBeNil)

					err = json.Unmarshal(indexManifestContent, &indexManifest)
					So(err, ShouldBeNil)
					indexManifestIdx = idx
				}
			}

			var configBlobDigest godigest.Digest
			var indexManifestContent []byte
			for idx, manifestDesc := range newIndex.Manifests {
				if manifestDesc.MediaType == ispec.MediaTypeImageManifest {
					manifestContent, err := os.ReadFile(path.Join(srcDir, indexRepoName, "blobs/sha256",
						manifestDesc.Digest.Encoded()))
					So(err, ShouldBeNil)

					var manifest ispec.Manifest

					err = json.Unmarshal(manifestContent, &manifest)
					So(err, ShouldBeNil)

					configBlobDigest = manifest.Config.Digest

					manifest.MediaType = dockerManifest.DockerV2Schema2MediaType
					manifest.Config.MediaType = dockerManifest.DockerV2Schema2ConfigMediaType
					newIndex.Manifests[idx].MediaType = dockerManifest.DockerV2Schema2MediaType
					indexManifest.Manifests[idx].MediaType = dockerManifest.DockerV2Schema2MediaType

					for idx := range manifest.Layers {
						manifest.Layers[idx].MediaType = dockerManifest.DockerV2Schema2LayerMediaType
					}

					manifestBuf, err := json.Marshal(manifest)
					So(err, ShouldBeNil)

					manifestDigest := godigest.FromBytes(manifestBuf)
					newIndex.Manifests[idx].Digest = manifestDigest
					indexManifest.Manifests[idx].Digest = manifestDigest

					// write modified manifest, remove old one
					err = os.WriteFile(path.Join(srcDir, indexRepoName, "blobs/sha256", manifestDigest.Encoded()),
						manifestBuf, storageConstants.DefaultFilePerms)
					So(err, ShouldBeNil)

					err = os.Remove(path.Join(srcDir, indexRepoName, "blobs/sha256", manifestDesc.Digest.Encoded()))
					So(err, ShouldBeNil)
				}

				indexManifest.MediaType = dockerManifest.DockerV2ListMediaType
				// write converted multi arch manifest
				indexManifestContent, err = json.Marshal(indexManifest)
				So(err, ShouldBeNil)

				err = os.WriteFile(path.Join(srcDir, indexRepoName, "blobs/sha256",
					godigest.FromBytes(indexManifestContent).Encoded()), indexManifestContent, storageConstants.DefaultFilePerms)
				So(err, ShouldBeNil)
			}

			newIndex.Manifests[indexManifestIdx].MediaType = dockerManifest.DockerV2ListMediaType
			newIndex.Manifests[indexManifestIdx].Digest = godigest.FromBytes(indexManifestContent)

			indexBuf, err := json.Marshal(newIndex)
			So(err, ShouldBeNil)

			err = os.WriteFile(path.Join(srcDir, indexRepoName, "index.json"), indexBuf, storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			// sync
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(destBaseURL + "/v2/" + indexRepoName + "/manifests/" + "latest")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			// sync again, should skip
			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(destBaseURL + "/v2/" + indexRepoName + "/manifests/" + "latest")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"skipping image because it's already synced", 20*time.Second)
			if err != nil {
				panic(err)
			}

			if !found {
				data, err := os.ReadFile(dctlr.Config.Log.Output)
				So(err, ShouldBeNil)

				t.Logf("downstream log: %s", string(data))
			}

			So(found, ShouldBeTrue)

			Convey("trigger config blob upstream error", func() {
				// remove synced image
				err := os.RemoveAll(path.Join(destDir, indexRepoName))
				So(err, ShouldBeNil)

				err = os.Chmod(path.Join(srcDir, indexRepoName, "blobs/sha256", configBlobDigest.Encoded()), 0o000)
				So(err, ShouldBeNil)

				resp, err = resty.R().Get(destBaseURL + "/v2/" + indexRepoName + "/manifests/" + "latest")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			})
		})
	})
}

func TestPeriodically(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, srcClient := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		semver := true
		var tlsVerify bool

		maxRetries := 1
		delay := 1 * time.Second

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			MaxRetries:   &maxRetries,
			RetryDelay:   &delay,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err := json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		for {
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		So(destTagsList, ShouldResemble, srcTagsList)

		Convey("Test sync with more contents", func() {
			regex := ".*"
			semver := true

			invalidRegex := "invalid"

			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						Prefix: testImage,
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
					{
						Prefix: testCveImage,
						Tags: &syncconf.Tags{
							Regex:  &invalidRegex,
							Semver: &semver,
						},
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, err := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			for {
				resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
				if err != nil {
					panic(err)
				}

				err = json.Unmarshal(resp.Body(), &destTagsList)
				if err != nil {
					panic(err)
				}

				if len(destTagsList.Tags) > 0 {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}

			So(destTagsList, ShouldResemble, srcTagsList)

			// testCveImage should not be synced because of regex being "invalid", shouldn't match anything
			resp, _ = srcClient.R().Get(srcBaseURL + "/v2/" + testCveImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = json.Unmarshal(resp.Body(), &srcTagsList)
			So(err, ShouldBeNil)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testCveImage + "/tags/list")
			So(err, ShouldBeNil)

			err = json.Unmarshal(resp.Body(), &destTagsList)
			So(err, ShouldBeNil)

			So(destTagsList, ShouldNotResemble, srcTagsList)

			waitSyncFinish(dctlr.Config.Log.Output)
		})
	})
}

func TestPermsDenied(t *testing.T) {
	Convey("Verify sync feature without perm on sync cache", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)

		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		destConfig.Storage.GC = false
		destConfig.Storage.RootDirectory = destDir

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig
		destConfig.Log.Output = path.Join(destDir, "sync.log")

		dctlr := api.NewController(destConfig)
		dcm := test.NewControllerManager(dctlr)

		defer dcm.StopServer()

		syncSubDir := path.Join(destDir, testImage, syncConstants.SyncBlobUploadDir)

		err := os.MkdirAll(syncSubDir, 0o755)
		So(err, ShouldBeNil)

		err = os.Chmod(syncSubDir, 0o000)
		So(err, ShouldBeNil)

		dcm.StartAndWait(destPort)

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"couldn't get a local image reference", 50*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		err = os.Chmod(syncSubDir, 0o755)
		if err != nil {
			panic(err)
		}

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestConfigReloader(t *testing.T) {
	Convey("Verify periodically sync config reloader works", t, func() {
		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)
		defer os.RemoveAll(srcDir)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		duration, _ := time.ParseDuration("3s")

		var tlsVerify bool
		defaultVal := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: duration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)

		destConfig.HTTP.Port = destPort

		// change
		destDir := t.TempDir()

		defer os.RemoveAll(destDir)

		destConfig.Storage.RootDirectory = destDir

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		destConfig.Log.Output = logFile.Name()

		dctlr := api.NewController(destConfig)

		//nolint: dupl
		Convey("Reload config without sync", func() {
			content := fmt.Sprintf(`{"distSpecVersion": "1.1.0", "storage": {"rootDirectory": "%s"},
			"http": {"address": "127.0.0.1", "port": "%s"},
			"log": {"level": "debug", "output": "%s"}}`, destDir, destPort, logFile.Name())

			cfgfile, err := os.CreateTemp("", "zot-test*.json")
			So(err, ShouldBeNil)

			defer os.Remove(cfgfile.Name()) // clean up

			_, err = cfgfile.WriteString(content)
			So(err, ShouldBeNil)

			hotReloader, err := cli.NewHotReloader(dctlr, cfgfile.Name(), "")
			So(err, ShouldBeNil)

			hotReloader.Start()

			go func() {
				// this blocks
				if err := dctlr.Init(); err != nil {
					return
				}

				if err := dctlr.Run(); err != nil {
					return
				}
			}()

			// wait till ready
			for {
				_, err := resty.R().Get(destBaseURL)
				if err == nil {
					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			defer dctlr.Shutdown()

			// let it sync
			time.Sleep(3 * time.Second)

			// modify config
			_, err = cfgfile.WriteString(" ")
			So(err, ShouldBeNil)

			time.Sleep(2 * time.Second)

			data, err := os.ReadFile(logFile.Name())
			t.Logf("downstream log: %s", string(data))
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring, "reloaded params")
			So(string(data), ShouldContainSubstring, "new configuration settings")
			So(string(data), ShouldContainSubstring, "\"Extensions\":null")

			// reload config from extensions nil to sync
			content = fmt.Sprintf(`{
				"distSpecVersion": "1.1.0",
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"sync": {
						"registries": [{
							"urls": ["https://localhost:9999"],
							"tlsVerify": true,
							"onDemand": true,
							"content":[
								{
									"prefix": "zot-test",
									"tags": {
										"regex": ".*",
										"semver": true
									}
								}
							]
						}]
					}
				}
			}`, destDir, destPort, logFile.Name())

			err = cfgfile.Truncate(0)
			So(err, ShouldBeNil)

			_, err = cfgfile.Seek(0, 0)
			So(err, ShouldBeNil)

			time.Sleep(2 * time.Second)

			_, err = cfgfile.WriteString(content)
			So(err, ShouldBeNil)

			err = cfgfile.Close()
			So(err, ShouldBeNil)

			time.Sleep(2 * time.Second)

			data, err = os.ReadFile(logFile.Name())
			t.Logf("downstream log: %s", string(data))
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring, "reloaded params")
			So(string(data), ShouldContainSubstring, "new configuration settings")
			So(string(data), ShouldContainSubstring, "\"TLSVerify\":true")
			So(string(data), ShouldContainSubstring, "\"OnDemand\":true")
		})

		//nolint: dupl
		Convey("Reload bad sync config", func() {
			content := fmt.Sprintf(`{
				"distSpecVersion": "1.1.0",
				"storage": {
					"rootDirectory": "%s"
				},
				"http": {
					"address": "127.0.0.1",
					"port": "%s"
				},
				"log": {
					"level": "debug",
					"output": "%s"
				},
				"extensions": {
					"sync": {
						"registries": [{
							"urls": ["%%"],
							"tlsVerify": false,
							"onDemand": false,
							"PollInterval": "1s",
							"maxRetries": 3,
							"retryDelay": "15m",
							"certDir": "",
							"content":[
								{
									"prefix": "zot-test",
									"tags": {
										"regex": ".*",
										"semver": true
									}
								}
							]
						}]
					}
				}
			}`, destDir, destPort, logFile.Name())

			cfgfile, err := os.CreateTemp("", "zot-test*.json")
			So(err, ShouldBeNil)

			defer os.Remove(cfgfile.Name()) // clean up

			_, err = cfgfile.WriteString(content)
			So(err, ShouldBeNil)

			hotReloader, err := cli.NewHotReloader(dctlr, cfgfile.Name(), "")
			So(err, ShouldBeNil)

			hotReloader.Start()

			go func() {
				// this blocks
				if err := dctlr.Init(); err != nil {
					return
				}

				if err := dctlr.Run(); err != nil {
					return
				}
			}()

			// wait till ready
			for {
				_, err := resty.R().Get(destBaseURL)
				if err == nil {
					break
				}

				time.Sleep(100 * time.Millisecond)
			}

			defer dctlr.Shutdown()

			// let it sync
			time.Sleep(3 * time.Second)

			// modify config
			_, err = cfgfile.WriteString(" ")
			So(err, ShouldBeNil)

			err = cfgfile.Close()
			So(err, ShouldBeNil)

			time.Sleep(2 * time.Second)

			data, err := os.ReadFile(logFile.Name())
			t.Logf("downstream log: %s", string(data))
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring, "failed to start sync extension")
			So(string(data), ShouldContainSubstring, "\"TLSVerify\":false")
			So(string(data), ShouldContainSubstring, "\"OnDemand\":false")
		})
	})
}

func TestMandatoryAnnotations(t *testing.T) {
	Convey("Verify mandatory annotations failing - on demand disabled", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		var semver bool
		tlsVerify := false

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			OnDemand:     false,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destClient := resty.New()

		destBaseURL := test.GetBaseURL(destPort)

		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		destConfig.Storage.RootDirectory = destDir
		destConfig.Storage.Dedupe = false
		destConfig.Storage.GC = false

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Sync = syncConfig

		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)
		defer os.Remove(logFile.Name())

		destConfig.Log.Output = logFile.Name()

		lintEnable := true
		destConfig.Extensions.Lint = &extconf.LintConfig{}
		destConfig.Extensions.Lint.Enable = &lintEnable
		destConfig.Extensions.Lint.MandatoryAnnotations = []string{"annot1", "annot2", "annot3"}

		dctlr := api.NewController(destConfig)
		dcm := test.NewControllerManager(dctlr)

		dcm.StartAndWait(destPort)

		defer dcm.StopServer()

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"couldn't upload manifest because of missing annotations", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestBadTLS(t *testing.T) {
	Convey("Verify sync TLS feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, true, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		var semver bool
		tlsVerify := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			OnDemand:     true,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, true, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"x509: certificate signed by unknown authority", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		resp, _ := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "invalid")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, _ = destClient.R().Get(destBaseURL + "/v2/" + "invalid" + "/manifests/" + testImageTag)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestTLS(t *testing.T) {
	Convey("Verify sync TLS feature", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, true, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		var srcIndex ispec.Index
		var destIndex ispec.Index

		srcBuf, err := os.ReadFile(path.Join(srcDir, testImage, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		// copy upstream client certs, use them in sync config
		destClientCertDir := t.TempDir()

		destFilePath := path.Join(destClientCertDir, "ca.crt")
		err = test.CopyFile(CACert, destFilePath)
		if err != nil {
			panic(err)
		}

		destFilePath = path.Join(destClientCertDir, "client.cert")
		err = test.CopyFile(ClientCert, destFilePath)
		if err != nil {
			panic(err)
		}

		destFilePath = path.Join(destClientCertDir, "client.key")
		err = test.CopyFile(ClientKey, destFilePath)
		if err != nil {
			panic(err)
		}

		regex := ".*"
		var semver bool
		tlsVerify := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      destClientCertDir,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, _, destDir, _ := makeDownstreamServer(t, true, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// wait till ready
		for {
			destBuf, _ := os.ReadFile(path.Join(destDir, testImage, "index.json"))
			_ = json.Unmarshal(destBuf, &destIndex)
			time.Sleep(500 * time.Millisecond)
			if len(destIndex.Manifests) > 0 {
				break
			}
		}

		var found bool
		for _, manifest := range srcIndex.Manifests {
			if reflect.DeepEqual(manifest.Annotations, destIndex.Manifests[0].Annotations) {
				found = true
			}
		}

		if !found {
			panic(errSync)
		}

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestBearerAuth(t *testing.T) {
	Convey("Verify periodically sync bearer auth", t, func() {
		updateDuration, _ := time.ParseDuration("1h")
		// a repo for which clients do not have access, sync shouldn't be able to sync it
		unauthorizedNamespace := testCveImage

		authTestServer := authutils.MakeAuthTestServer(ServerKey, unauthorizedNamespace)
		defer authTestServer.Close()

		sctlr, srcBaseURL, _, _, srcClient := makeUpstreamServer(t, false, false)

		aurl, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		sctlr.Config.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    ServerCert,
				Realm:   authTestServer.URL + "/auth/token",
				Service: aurl.Host,
			},
		}

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		registryName := sync.StripRegistryTransport(srcBaseURL)
		credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
			registryName, username, password))

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "**", // sync everything
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:          &defaultVal,
			CredentialsFile: credentialsFile,
			Registries:      []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, err := srcClient.R().Get(srcBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader := authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var goodToken authutils.AccessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = srcClient.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(srcBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		goodToken = authutils.AccessTokenResponse{}
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = srcClient.R().SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		for {
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		So(destTagsList, ShouldResemble, srcTagsList)

		waitSyncFinish(dctlr.Config.Log.Output)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// unauthorized namespace
		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testCveImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})

	Convey("Verify ondemand sync bearer auth", t, func() {
		// a repo for which clients do not have access, sync shouldn't be able to sync it
		unauthorizedNamespace := testCveImage

		authTestServer := authutils.MakeAuthTestServer(ServerKey, unauthorizedNamespace)
		defer authTestServer.Close()

		sctlr, srcBaseURL, _, _, srcClient := makeUpstreamServer(t, false, false)

		aurl, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		sctlr.Config.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    ServerCert,
				Realm:   authTestServer.URL + "/auth/token",
				Service: aurl.Host,
			},
		}

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		registryName := sync.StripRegistryTransport(srcBaseURL)
		credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
			registryName, username, password))

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "**", // sync everything
				},
			},
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			OnDemand:  true,
			CertDir:   "",
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:          &defaultVal,
			CredentialsFile: credentialsFile,
			Registries:      []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, err := srcClient.R().Get(srcBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader := authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		var goodToken authutils.AccessTokenResponse
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = srcClient.R().
			SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(srcBaseURL + "/v2/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusUnauthorized)

		authorizationHeader = authutils.ParseBearerAuthHeader(resp.Header().Get("WWW-Authenticate"))
		resp, err = resty.R().
			SetQueryParam("service", authorizationHeader.Service).
			SetQueryParam("scope", authorizationHeader.Scope).
			Get(authorizationHeader.Realm)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		goodToken = authutils.AccessTokenResponse{}
		err = json.Unmarshal(resp.Body(), &goodToken)
		So(err, ShouldBeNil)

		resp, err = srcClient.R().SetHeader("Authorization", fmt.Sprintf("Bearer %s", goodToken.AccessToken)).
			Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		// sync on demand
		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(resp.Body(), &destTagsList)
		if err != nil {
			panic(err)
		}

		So(destTagsList, ShouldResemble, srcTagsList)

		// unauthorized namespace
		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testCveImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestBasicAuth(t *testing.T) {
	Convey("Verify sync basic auth", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		Convey("Verify sync basic auth with file credentials", func() {
			sctlr, srcBaseURL, _, htpasswdPath, srcClient := makeUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			registryName := sync.StripRegistryTransport(srcBaseURL)
			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
				registryName, username, password))

			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						Prefix: testImage,
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries:      []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := srcClient.R().SetBasicAuth(username, password).Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err := json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			for {
				resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
				if err != nil {
					panic(err)
				}

				err = json.Unmarshal(resp.Body(), &destTagsList)
				if err != nil {
					panic(err)
				}

				if len(destTagsList.Tags) > 0 {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}

			So(destTagsList, ShouldResemble, srcTagsList)

			waitSyncFinish(dctlr.Config.Log.Output)
		})

		Convey("Verify sync basic auth with wrong file credentials", func() {
			sctlr, srcBaseURL, _, htpasswdPath, _ := makeUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			destPort := test.GetFreePort()
			destBaseURL := test.GetBaseURL(destPort)

			destConfig := config.New()
			destConfig.HTTP.Port = destPort

			destDir := t.TempDir()

			destConfig.Storage.SubPaths = map[string]config.StorageConfig{
				"a": {
					RootDirectory: destDir,
					GC:            true,
					GCDelay:       storageConstants.DefaultGCDelay,
					Dedupe:        true,
				},
			}

			rootDir := t.TempDir()

			destConfig.Storage.RootDirectory = rootDir

			regex := ".*"
			var semver bool

			registryName := sync.StripRegistryTransport(srcBaseURL)

			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "%s", "password": "invalid"}}`,
				registryName, username))

			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						Prefix: testImage,
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
				OnDemand:     true,
			}

			destConfig.Extensions = &extconf.ExtensionConfig{}
			defaultVal := true
			destConfig.Extensions.Sync = &syncconf.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries:      []syncconf.RegistryConfig{syncRegistryConfig},
			}

			destConfig.Log.Output = path.Join(destDir, "sync.log")

			dctlr := api.NewController(destConfig)
			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(destPort)
			defer dcm.StopServer()

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"authentication required", 15*time.Second)
			if err != nil {
				panic(err)
			}

			if !found {
				data, err := os.ReadFile(dctlr.Config.Log.Output)
				So(err, ShouldBeNil)

				t.Logf("downstream log: %s", string(data))
			}

			So(found, ShouldBeTrue)

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Verify sync basic auth with bad file credentials", func() {
			sctlr, srcBaseURL, _, htpasswdPath, _ := makeUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			registryName := sync.StripRegistryTransport(srcBaseURL)

			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
				registryName, username, password))

			err := os.Chmod(credentialsFile, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				So(os.Chmod(credentialsFile, 0o755), ShouldBeNil)
				So(os.RemoveAll(credentialsFile), ShouldBeNil)
			}()

			regex := ".*"
			var semver bool
			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						Prefix: testImage,
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:         []string{srcBaseURL},
				PollInterval: updateDuration,
				TLSVerify:    &tlsVerify,
				CertDir:      "",
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries:      []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"couldn't get registry credentials from", 15*time.Second)
			if err != nil {
				panic(err)
			}

			if !found {
				data, err := os.ReadFile(dctlr.Config.Log.Output)
				So(err, ShouldBeNil)

				t.Logf("downstream log: %s", string(data))
			}

			So(found, ShouldBeTrue)

			resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Verify on demand sync with basic auth", func() {
			sctlr, srcBaseURL, _, htpasswdPath, srcClient := makeUpstreamServer(t, false, true)
			defer os.Remove(htpasswdPath)

			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			registryName := sync.StripRegistryTransport(srcBaseURL)
			credentialsFile := makeCredentialsFile(fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
				registryName, username, password))

			defaultValue := false
			syncRegistryConfig := syncconf.RegistryConfig{
				URLs:      []string{srcBaseURL},
				TLSVerify: &defaultValue,
				OnDemand:  true,
			}

			unreacheableSyncRegistryConfig1 := syncconf.RegistryConfig{
				URLs:     []string{"localhost:9999"},
				OnDemand: true,
			}

			unreacheableSyncRegistryConfig2 := syncconf.RegistryConfig{
				URLs:     []string{"localhost:9999"},
				OnDemand: false,
			}

			defaultVal := true
			// add file path to the credentials
			syncConfig := &syncconf.Config{
				Enable:          &defaultVal,
				CredentialsFile: credentialsFile,
				Registries: []syncconf.RegistryConfig{
					unreacheableSyncRegistryConfig1,
					unreacheableSyncRegistryConfig2,
					syncRegistryConfig,
				},
			}

			dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			var srcTagsList TagsList
			var destTagsList TagsList

			resp, _ := srcClient.R().SetBasicAuth(username, password).Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err := json.Unmarshal(resp.Body(), &srcTagsList)
			if err != nil {
				panic(err)
			}

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + "inexistent" + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			err = dctlr.StoreController.DefaultStore.DeleteImageManifest(testImage, testImageTag, false)
			So(err, ShouldBeNil)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.1.1")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "inexistent")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			So(destTagsList, ShouldResemble, srcTagsList)
		})
	})
}

func TestBadURL(t *testing.T) {
	Convey("Verify sync with bad url", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{"bad-registry-url]", "%"},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestNoImagesByRegex(t *testing.T) {
	Convey("Verify sync with no images on source based on regex", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := "9.9.9"
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex: &regex,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + constants.RoutePrefix + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		resp, err = destClient.R().Get(destBaseURL + constants.RoutePrefix + constants.ExtCatalogPrefix)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var catalog catalog
		err = json.Unmarshal(resp.Body(), &catalog)
		if err != nil {
			panic(err)
		}

		So(catalog.Repositories, ShouldResemble, []string{})
	})
}

func TestInvalidRegex(t *testing.T) {
	Convey("Verify sync with invalid regex", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := "["
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex: &regex,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			TLSVerify:    &tlsVerify,
			PollInterval: updateDuration,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, _, _, _ := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"failed to compile regex", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)
	})
}

func TestNotSemver(t *testing.T) {
	Convey("Verify sync feature semver compliant", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// get manifest so we can update it with a semver non compliant tag
		resp, err := resty.R().Get(srcBaseURL + "/v2/zot-test/manifests/0.0.1")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()

		resp, err = resty.R().SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBlob).
			Put(srcBaseURL + "/v2/" + testImage + "/manifests/notSemverTag")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		var destTagsList TagsList

		for {
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}
			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		So(len(destTagsList.Tags), ShouldEqual, 1)
		So(destTagsList.Tags[0], ShouldEqual, testImageTag)
	})
}

func TestInvalidCerts(t *testing.T) {
	Convey("Verify sync with bad certs", t, func() {
		updateDuration, _ := time.ParseDuration("1h")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, true, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// copy client certs, use them in sync config
		clientCertDir := t.TempDir()

		destFilePath := path.Join(clientCertDir, "ca.crt")
		err := test.CopyFile(CACert, destFilePath)
		if err != nil {
			panic(err)
		}

		dstfile, err := os.OpenFile(destFilePath, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			panic(err)
		}

		defer dstfile.Close()

		if _, err = dstfile.WriteString("Add Invalid Text In Cert"); err != nil {
			panic(err)
		}

		destFilePath = path.Join(clientCertDir, "client.cert")
		err = test.CopyFile(ClientCert, destFilePath)
		if err != nil {
			panic(err)
		}

		destFilePath = path.Join(clientCertDir, "client.key")
		err = test.CopyFile(ClientKey, destFilePath)
		if err != nil {
			panic(err)
		}

		tlsVerify := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      clientCertDir,
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)
		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestCertsWithWrongPerms(t *testing.T) {
	Convey("Verify sync with wrong permissions on certs", t, func() {
		updateDuration, _ := time.ParseDuration("1h")
		// copy client certs, use them in sync config
		clientCertDir := t.TempDir()

		destFilePath := path.Join(clientCertDir, "ca.crt")
		err := test.CopyFile(CACert, destFilePath)
		if err != nil {
			panic(err)
		}

		err = os.Chmod(destFilePath, 0o000)
		So(err, ShouldBeNil)

		destFilePath = path.Join(clientCertDir, "client.cert")
		err = test.CopyFile(ClientCert, destFilePath)
		if err != nil {
			panic(err)
		}

		destFilePath = path.Join(clientCertDir, "client.key")
		err = test.CopyFile(ClientKey, destFilePath)
		if err != nil {
			panic(err)
		}

		tlsVerify := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
				},
			},
			URLs:         []string{"http://localhost:9999"},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      clientCertDir,
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		// can't create http client because of no perms on ca cert
		destPort := test.GetFreePort()
		destConfig := config.New()
		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		destConfig.Storage.RootDirectory = destDir

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func makeCredentialsFile(fileContent string) string {
	tmpfile, err := os.CreateTemp("", "sync-credentials-")
	if err != nil {
		panic(err)
	}

	content := []byte(fileContent)
	if err := os.WriteFile(tmpfile.Name(), content, 0o600); err != nil {
		panic(err)
	}

	return tmpfile.Name()
}

func TestInvalidUrl(t *testing.T) {
	Convey("Verify sync invalid url", t, func() {
		updateDuration, _ := time.ParseDuration("30m")
		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					// won't match any image on source registry, we will sync on demand
					Prefix: "dummy",
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{"http://invalid.invalid/invalid/"},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestInvalidTags(t *testing.T) {
	Convey("Verify sync invalid tags", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					// won't match any image on source registry, we will sync on demand
					Prefix: "dummy",
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "invalid:tag")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestSubPaths(t *testing.T) {
	Convey("Verify sync with storage subPaths", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		srcPort := test.GetFreePort()
		srcConfig := config.New()
		srcBaseURL := test.GetBaseURL(srcPort)

		srcConfig.HTTP.Port = srcPort

		srcConfig.Storage.GC = false

		srcDir := t.TempDir()

		subpath := "/subpath"
		srcStorageCtlr := ociutils.GetDefaultStoreController(path.Join(srcDir, subpath), log.NewLogger("debug", ""))

		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(CreateDefaultVulnerableImage(), "zot-cve-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		srcConfig.Storage.RootDirectory = srcDir

		sctlr := api.NewController(srcConfig)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(srcPort)
		defer scm.StopServer()

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: path.Join(subpath, testImage),
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()

		destDir := t.TempDir()

		subPathDestDir := t.TempDir()

		destConfig.Storage.RootDirectory = destDir
		destConfig.Log.Output = path.Join(destDir, "sync.log")

		destConfig.Storage.SubPaths = map[string]config.StorageConfig{
			subpath: {
				RootDirectory: subPathDestDir,
				GC:            true,
				GCDelay:       storageConstants.DefaultGCDelay,
				Dedupe:        true,
			},
		}

		destBaseURL := test.GetBaseURL(destPort)
		destConfig.HTTP.Port = destPort

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig

		dctlr := api.NewController(destConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(destPort)
		defer dcm.StopServer()

		var destTagsList TagsList

		for {
			resp, err := resty.R().Get(destBaseURL + constants.RoutePrefix + path.Join(subpath, testImage) + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		// synced image should get into subpath instead of rootDir
		binfo, err := os.Stat(path.Join(subPathDestDir, subpath, testImage, "blobs/sha256"))
		So(binfo, ShouldNotBeNil)
		So(err, ShouldBeNil)

		// check rootDir is not populated with any image.
		binfo, err = os.Stat(path.Join(destDir, subpath))
		So(binfo, ShouldBeNil)
		So(err, ShouldNotBeNil)

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestOnDemandRepoErr(t *testing.T) {
	Convey("Verify sync on demand parseRepositoryReference error", t, func() {
		tlsVerify := false
		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					// will sync on demand, should not be filtered out
					Prefix: testImage,
				},
			},
			URLs:      []string{"docker://invalid"},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestOnDemandContentFiltering(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		Convey("Test image is filtered out by content", func() {
			regex := ".*"
			var semver bool
			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						// should be filtered out
						Prefix: "dummy",
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  true,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Test image is not filtered out by content", func() {
			regex := ".*"
			semver := true
			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						// will sync on demand, should not be filtered out
						Prefix: testImage,
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  true,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		})
	})
}

func TestConfigRules(t *testing.T) {
	Convey("Verify sync config rules", t, func() {
		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		Convey("Test periodically sync is disabled when pollInterval is not set", func() {
			regex := ".*"
			var semver bool
			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				Content: []syncconf.Content{
					{
						Prefix: testImage,
						Tags: &syncconf.Tags{
							Regex:  &regex,
							Semver: &semver,
						},
					},
				},
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  false,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			// image should not be synced
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Test periodically sync is disabled when content is not set", func() {
			var tlsVerify bool
			updateDuration, _ := time.ParseDuration("30m")

			syncRegistryConfig := syncconf.RegistryConfig{
				PollInterval: updateDuration,
				URLs:         []string{srcBaseURL},
				TLSVerify:    &tlsVerify,
				CertDir:      "",
				OnDemand:     false,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Test ondemand sync is disabled when ondemand is false", func() {
			var tlsVerify bool

			syncRegistryConfig := syncconf.RegistryConfig{
				URLs:      []string{srcBaseURL},
				TLSVerify: &tlsVerify,
				CertDir:   "",
				OnDemand:  false,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})
	})
}

func TestMultipleURLs(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, srcClient := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{"badURL", "@!#!$#@%", "http://invalid.invalid/invalid/", srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		var srcTagsList TagsList
		var destTagsList TagsList

		resp, _ := srcClient.R().Get(srcBaseURL + "/v2/" + testImage + "/tags/list")
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err := json.Unmarshal(resp.Body(), &srcTagsList)
		if err != nil {
			panic(err)
		}

		for {
			resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		So(destTagsList, ShouldResemble, srcTagsList)

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestNoURLsLeftInConfig(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{"@!#!$#@%", "@!#!$#@%"},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/tags/list")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestPeriodicallySignaturesErr(t *testing.T) {
	Convey("Verify sync periodically signatures errors", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		err = os.Chdir(tdir)
		So(err, ShouldBeNil)
		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: repoName,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		// trigger permission denied on upstream manifest
		var srcIndex ispec.Index

		srcBuf, err := os.ReadFile(path.Join(srcDir, repoName, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		imageManifestDigest := srcIndex.Manifests[0].Digest

		Convey("Trigger error on image manifest", func() {
			// trigger permission denied on image manifest
			manifestPath := path.Join(srcDir, repoName, "blobs",
				string(imageManifestDigest.Algorithm()), imageManifestDigest.Encoded())
			err = os.Chmod(manifestPath, 0o000)
			So(err, ShouldBeNil)

			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)
			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"finished syncing all repos", 15*time.Second)
			if err != nil {
				panic(err)
			}

			if !found {
				data, err := os.ReadFile(dctlr.Config.Log.Output)
				So(err, ShouldBeNil)

				t.Logf("downstream log: %s", string(data))
			}

			So(found, ShouldBeTrue)

			// should not be synced nor sync on demand
			resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		})

		Convey("Trigger error on cosign signature", func() {
			// trigger permission error on cosign signature on upstream
			cosignTag := string(imageManifestDigest.Algorithm()) + "-" + imageManifestDigest.Encoded() +
				"." + remote.SignatureTagSuffix

			getCosignManifestURL := srcBaseURL + path.Join(constants.RoutePrefix, repoName, "manifests", cosignTag)
			mResp, err := resty.R().Get(getCosignManifestURL)
			So(err, ShouldBeNil)

			var cm ispec.Manifest

			err = json.Unmarshal(mResp.Body(), &cm)
			So(err, ShouldBeNil)

			for _, blob := range cm.Layers {
				blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
				err := os.Chmod(blobPath, 0o000)
				So(err, ShouldBeNil)
			}

			// start downstream server
			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"finished syncing all repos", 15*time.Second)
			if err != nil {
				panic(err)
			}

			if !found {
				data, err := os.ReadFile(dctlr.Config.Log.Output)
				So(err, ShouldBeNil)

				t.Logf("downstream log: %s", string(data))
			}

			So(found, ShouldBeTrue)

			// should not be synced nor sync on demand
			resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + cosignTag)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		})

		Convey("Trigger error on notary signature", func() {
			// trigger permission error on notary signature on upstream
			notaryURLPath := path.Join("/v2/", repoName, "referrers", imageManifestDigest.String())

			// based on image manifest digest get referrers
			resp, err := resty.R().
				SetHeader("Content-Type", "application/json").
				SetQueryParam("artifactType", "application/vnd.cncf.notary.signature").
				Get(srcBaseURL + notaryURLPath)

			So(err, ShouldBeNil)
			So(resp, ShouldNotBeEmpty)

			var referrers ispec.Index

			err = json.Unmarshal(resp.Body(), &referrers)
			So(err, ShouldBeNil)

			// read manifest
			var artifactManifest ispec.Manifest
			for _, ref := range referrers.Manifests {
				refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
				body, err := os.ReadFile(refPath)
				So(err, ShouldBeNil)

				err = json.Unmarshal(body, &artifactManifest)
				So(err, ShouldBeNil)

				// triggers perm denied on sig blobs
				for _, blob := range artifactManifest.Layers {
					blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
					err := os.Chmod(blobPath, 0o000)
					So(err, ShouldBeNil)
				}
			}

			// start downstream server
			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"finished syncing all repos", 15*time.Second)
			if err != nil {
				panic(err)
			}

			if !found {
				data, err := os.ReadFile(dctlr.Config.Log.Output)
				So(err, ShouldBeNil)

				t.Logf("downstream log: %s", string(data))
			}

			So(found, ShouldBeTrue)

			// should not be synced nor sync on demand
			resp, err = resty.R().SetHeader("Content-Type", "application/json").
				SetQueryParam("artifactType", "application/vnd.cncf.notary.signature").
				Get(destBaseURL + notaryURLPath)
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)

			var index ispec.Index

			err = json.Unmarshal(resp.Body(), &index)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 0)
		})

		Convey("Trigger error on oci refs of both mediatypes", func() {
			artifactURLPath := path.Join("/v2", repoName, "referrers", imageManifestDigest.String())

			// based on image manifest digest get referrers
			resp, err := resty.R().
				SetHeader("Content-Type", "application/json").
				SetQueryParam("artifactType", "application/vnd.cncf.icecream").
				Get(srcBaseURL + artifactURLPath)

			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp, ShouldNotBeEmpty)

			var referrers ispec.Index

			err = json.Unmarshal(resp.Body(), &referrers)
			So(err, ShouldBeNil)

			Convey("of type OCI image", func() { //nolint: dupl
				// read manifest
				var artifactManifest ispec.Manifest
				for _, ref := range referrers.Manifests {
					refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
					body, err := os.ReadFile(refPath)
					So(err, ShouldBeNil)

					err = json.Unmarshal(body, &artifactManifest)
					So(err, ShouldBeNil)

					// triggers perm denied on artifact blobs
					for _, blob := range artifactManifest.Layers {
						blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
						err := os.Chmod(blobPath, 0o000)
						So(err, ShouldBeNil)
					}
				}

				// start downstream server
				updateDuration, err = time.ParseDuration("1s")
				So(err, ShouldBeNil)

				syncConfig.Registries[0].PollInterval = updateDuration

				// start downstream server
				dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

				dcm := test.NewControllerManager(dctlr)
				dcm.StartAndWait(dctlr.Config.HTTP.Port)
				defer dcm.StopServer()

				found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
					"couldn't sync image referrer", 15*time.Second)
				if err != nil {
					panic(err)
				}

				if !found {
					data, err := os.ReadFile(dctlr.Config.Log.Output)
					So(err, ShouldBeNil)

					t.Logf("downstream log: %s", string(data))
				}

				So(found, ShouldBeTrue)

				// should not be synced nor sync on demand
				resp, err = resty.R().
					SetHeader("Content-Type", "application/json").
					SetQueryParam("artifactType", "application/vnd.cncf.icecream").
					Get(destBaseURL + artifactURLPath)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				var index ispec.Index

				err = json.Unmarshal(resp.Body(), &index)
				So(err, ShouldBeNil)
				So(len(index.Manifests), ShouldEqual, 0)
			})

			Convey("of type OCI artifact", func() { //nolint: dupl
				// read manifest
				var artifactManifest ispec.Manifest
				for _, ref := range referrers.Manifests {
					refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
					body, err := os.ReadFile(refPath)
					So(err, ShouldBeNil)

					err = json.Unmarshal(body, &artifactManifest)
					So(err, ShouldBeNil)

					// triggers perm denied on artifact blobs
					for _, blob := range artifactManifest.Layers {
						blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
						err := os.Chmod(blobPath, 0o000)
						So(err, ShouldBeNil)
					}
				}

				// start downstream server
				dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

				dcm := test.NewControllerManager(dctlr)
				dcm.StartAndWait(dctlr.Config.HTTP.Port)
				defer dcm.StopServer()

				found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
					"couldn't sync image referrer", 15*time.Second)
				if err != nil {
					panic(err)
				}

				if !found {
					data, err := os.ReadFile(dctlr.Config.Log.Output)
					So(err, ShouldBeNil)

					t.Logf("downstream log: %s", string(data))
				}

				So(found, ShouldBeTrue)

				// should not be synced nor sync on demand
				resp, err = resty.R().
					SetHeader("Content-Type", "application/json").
					SetQueryParam("artifactType", "application/vnd.cncf.icecream").
					Get(destBaseURL + artifactURLPath)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				var index ispec.Index

				err = json.Unmarshal(resp.Body(), &index)
				So(err, ShouldBeNil)
				So(len(index.Manifests), ShouldEqual, 0)
			})

			Convey("of type OCI image, error on downstream in canSkipReference()", func() { //nolint: dupl
				// start downstream server
				updateDuration, err = time.ParseDuration("1s")
				So(err, ShouldBeNil)

				syncConfig.Registries[0].PollInterval = updateDuration
				dctlr, _, destDir, _ := makeDownstreamServer(t, false, syncConfig)

				dcm := test.NewControllerManager(dctlr)
				dcm.StartAndWait(dctlr.Config.HTTP.Port)
				defer dcm.StopServer()

				found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
					"finished syncing all repos", 15*time.Second)
				if err != nil {
					panic(err)
				}

				if !found {
					data, err := os.ReadFile(dctlr.Config.Log.Output)
					So(err, ShouldBeNil)

					t.Logf("downstream log: %s", string(data))
				}

				So(found, ShouldBeTrue)

				time.Sleep(time.Second)

				blob := referrers.Manifests[0]
				blobsDir := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()))
				blobPath := path.Join(blobsDir, blob.Digest.Encoded())
				err = os.MkdirAll(blobsDir, storageConstants.DefaultDirPerms)
				So(err, ShouldBeNil)
				err = os.WriteFile(blobPath, []byte("blob"), storageConstants.DefaultFilePerms)
				So(err, ShouldBeNil)
				err = os.Chmod(blobPath, 0o000)
				So(err, ShouldBeNil)

				found, err = test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
					"couldn't check if the upstream oci references for image can be skipped", 30*time.Second)
				if err != nil {
					panic(err)
				}

				if !found {
					data, err := os.ReadFile(dctlr.Config.Log.Output)
					So(err, ShouldBeNil)

					t.Logf("downstream log: %s", string(data))
				}

				So(found, ShouldBeTrue)
			})
		})
	})
}

func TestSignatures(t *testing.T) {
	Convey("Verify sync signatures", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]
		t.Logf(srcPort)
		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		// attach sbom
		attachSBOM(srcDir, sctlr.Config.HTTP.Port, repoName, digest)

		// sbom tag
		sbomTag := strings.Replace(digest.String(), ":", "-", 1) + "." + remote.SBOMTagSuffix

		// get sbom digest
		resp, err := resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			Get(srcBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, sbomTag))
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		sbomDigest := godigest.FromBytes(resp.Body())

		// sign sbom
		So(func() { signImage(tdir, srcPort, repoName, sbomDigest) }, ShouldNotPanic)

		// attach oci ref to sbom
		// add OCI Ref
		_ = pushBlob(srcBaseURL, repoName, ispec.DescriptorEmptyJSON.Data)

		OCIRefManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Subject: &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    sbomDigest,
				Size:      int64(len(resp.Body())),
			},
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeEmptyJSON,
				Digest:    ispec.DescriptorEmptyJSON.Digest,
				Size:      2,
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeEmptyJSON,
					Digest:    ispec.DescriptorEmptyJSON.Digest,
					Size:      2,
				},
			},
			MediaType: ispec.MediaTypeImageManifest,
		}

		OCIRefManifestBlob, err := json.Marshal(OCIRefManifest)
		So(err, ShouldBeNil)

		ociRefDigest := godigest.FromBytes(OCIRefManifestBlob)

		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			SetBody(OCIRefManifestBlob).
			Put(srcBaseURL + fmt.Sprintf("/v2/%s/manifests/%s", repoName, ociRefDigest.String()))

		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		regex := ".*"
		var semver bool
		var tlsVerify bool
		onlySigned := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "**",
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnlySigned:   &onlySigned,
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// wait for sync
		var destTagsList TagsList

		for {
			resp, err := destClient.R().Get(destBaseURL + "/v2/" + repoName + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		time.Sleep(1 * time.Second)

		// notation verify the image
		image := fmt.Sprintf("localhost:%s/%s@%s", destPort, repoName, digest)

		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			IgnoreTlog:      true,
		}

		signature.LoadNotationPath(tdir)
		// notation verify signed image
		err = signature.VerifyWithNotation(image, tdir)
		So(err, ShouldBeNil)

		// cosign verify signed image
		err = vrfy.Exec(context.TODO(), []string{image})
		So(err, ShouldBeNil)

		// get oci references from downstream, should be synced
		getOCIReferrersURL := destBaseURL + path.Join("/v2", repoName, "referrers", digest.String())
		resp, err = resty.R().Get(getOCIReferrersURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var index ispec.Index

		err = json.Unmarshal(resp.Body(), &index)
		So(err, ShouldBeNil)

		So(len(index.Manifests), ShouldEqual, 3)

		// get cosign sbom
		sbomCosignTag := string(digest.Algorithm()) + "-" + digest.Encoded() +
			"." + remote.SBOMTagSuffix
		resp, err = resty.R().Get(destBaseURL + path.Join("/v2/", repoName, "manifests", sbomCosignTag))
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(godigest.FromBytes(resp.Body()), ShouldEqual, sbomDigest)

		// verify sbom signature
		sbom := fmt.Sprintf("localhost:%s/%s@%s", destPort, repoName, sbomDigest)

		signature.LoadNotationPath(tdir)
		// notation verify signed sbom
		err = signature.VerifyWithNotation(sbom, tdir)
		So(err, ShouldBeNil)

		vrfy = verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			IgnoreTlog:      true,
		}

		// cosign verify signed sbom
		err = vrfy.Exec(context.TODO(), []string{sbom})
		So(err, ShouldBeNil)

		// get oci ref pointing to sbom
		getOCIReferrersURL = destBaseURL + path.Join("/v2", repoName, "referrers", sbomDigest.String())
		resp, err = resty.R().Get(getOCIReferrersURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = json.Unmarshal(resp.Body(), &index)
		So(err, ShouldBeNil)

		So(len(index.Manifests), ShouldEqual, 2)
		So(index.Manifests[1].Digest, ShouldEqual, ociRefDigest)

		// test negative cases (trigger errors)
		// test notary signatures errors

		// based on manifest digest get referrers
		getReferrersURL := srcBaseURL + path.Join("/v2/", repoName, "referrers", digest.String())

		resp, err = resty.R().
			SetHeader("Content-Type", "application/json").
			SetQueryParam("artifactType", "application/vnd.cncf.notary.signature").
			Get(getReferrersURL)

		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)

		var referrers ispec.Index

		err = json.Unmarshal(resp.Body(), &referrers)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		var artifactManifest ispec.Manifest
		for _, ref := range referrers.Manifests {
			refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
			body, err := os.ReadFile(refPath)
			So(err, ShouldBeNil)

			err = json.Unmarshal(body, &artifactManifest)
			So(err, ShouldBeNil)

			// triggers perm denied on notary sig blobs on downstream
			for _, blob := range artifactManifest.Layers {
				blobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
				err := os.MkdirAll(blobPath, 0o755)
				So(err, ShouldBeNil)
				err = os.Chmod(blobPath, 0o000)
				So(err, ShouldBeNil)
			}
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// triggers perm denied on notary manifest on downstream
		for _, ref := range referrers.Manifests {
			refPath := path.Join(destDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
			err := os.MkdirAll(refPath, 0o755)
			So(err, ShouldBeNil)
			err = os.Chmod(refPath, 0o000)
			So(err, ShouldBeNil)
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// triggers perm denied on sig blobs
		for _, blob := range artifactManifest.Layers {
			blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
			err := os.Chmod(blobPath, 0o000)
			So(err, ShouldBeNil)
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// test cosign signatures errors
		// based on manifest digest get cosign manifest
		cosignEncodedDigest := strings.Replace(digest.String(), ":", "-", 1) + ".sig"
		getCosignManifestURL := srcBaseURL + path.Join(constants.RoutePrefix, repoName, "manifests", cosignEncodedDigest)

		mResp, err := resty.R().Get(getCosignManifestURL)
		So(err, ShouldBeNil)
		So(mResp.StatusCode(), ShouldEqual, http.StatusOK)

		var imageManifest ispec.Manifest

		err = json.Unmarshal(mResp.Body(), &imageManifest)
		So(err, ShouldBeNil)

		cosignManifestDigest := godigest.FromBytes(mResp.Body())

		for _, blob := range imageManifest.Layers {
			blobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
			err := os.Chmod(blobPath, 0o000)
			So(err, ShouldBeNil)
		}

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		for _, blob := range imageManifest.Layers {
			srcBlobPath := path.Join(srcDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
			err := os.Chmod(srcBlobPath, 0o755)
			So(err, ShouldBeNil)

			destBlobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
			err = os.MkdirAll(destBlobPath, 0o755)
			So(err, ShouldBeNil)
			err = os.Chmod(destBlobPath, 0o755)
			So(err, ShouldBeNil)
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		for _, blob := range imageManifest.Layers {
			destBlobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
			err = os.Chmod(destBlobPath, 0o755)
			So(err, ShouldBeNil)
			err = os.Remove(destBlobPath)
			So(err, ShouldBeNil)
		}

		// trigger error on upstream config blob
		srcConfigBlobPath := path.Join(srcDir, repoName, "blobs", string(imageManifest.Config.Digest.Algorithm()),
			imageManifest.Config.Digest.Encoded())
		err = os.Chmod(srcConfigBlobPath, 0o000)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = os.Chmod(srcConfigBlobPath, 0o755)
		So(err, ShouldBeNil)

		// trigger error on upstream config blob
		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		destConfigBlobPath := path.Join(destDir, repoName, "blobs", string(imageManifest.Config.Digest.Algorithm()),
			imageManifest.Config.Digest.Encoded())

		err = os.MkdirAll(destConfigBlobPath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(destConfigBlobPath, 0o000)
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// trigger error on downstream manifest
		destManifestPath := path.Join(destDir, repoName, "blobs", string(cosignManifestDigest.Algorithm()),
			cosignManifestDigest.Encoded())
		err = os.MkdirAll(destManifestPath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(destManifestPath, 0o000)
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = os.Chmod(destManifestPath, 0o755)
		So(err, ShouldBeNil)

		getOCIReferrersURL = srcBaseURL + path.Join("/v2", repoName, "referrers", digest.String())

		resp, err = resty.R().Get(getOCIReferrersURL)

		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)

		err = json.Unmarshal(resp.Body(), &index)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		var refManifest ispec.Manifest
		for _, ref := range index.Manifests {
			refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
			body, err := os.ReadFile(refPath)
			So(err, ShouldBeNil)

			err = json.Unmarshal(body, &refManifest)
			So(err, ShouldBeNil)

			// triggers perm denied on notary sig blobs on downstream
			for _, blob := range refManifest.Layers {
				blobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
				err := os.MkdirAll(blobPath, 0o755)
				So(err, ShouldBeNil)
				err = os.Chmod(blobPath, 0o000)
				So(err, ShouldBeNil)
			}
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// cleanup
		for _, blob := range refManifest.Layers {
			blobPath := path.Join(destDir, repoName, "blobs", string(blob.Digest.Algorithm()), blob.Digest.Encoded())
			err = os.Chmod(blobPath, 0o755)
			So(err, ShouldBeNil)
		}

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// trigger error on reference config blob
		referenceConfigBlobPath := path.Join(destDir, repoName, "blobs",
			string(refManifest.Config.Digest.Algorithm()), refManifest.Config.Digest.Encoded())
		err = os.MkdirAll(referenceConfigBlobPath, 0o755)
		So(err, ShouldBeNil)
		err = os.Chmod(referenceConfigBlobPath, 0o000)
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = os.Chmod(referenceConfigBlobPath, 0o755)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// trigger error on pushing oci reference manifest
		for _, ref := range index.Manifests {
			refPath := path.Join(destDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
			err = os.MkdirAll(refPath, 0o755)
			So(err, ShouldBeNil)
			err = os.Chmod(refPath, 0o000)
			So(err, ShouldBeNil)
		}

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// sync on demand again for coverage
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})

	Convey("Verify sync oci1.1 cosign signatures", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]
		t.Logf(srcPort)

		err := signature.SignImageUsingCosign(fmt.Sprintf("%s@%s", repoName, digest.String()), srcPort, true)
		So(err, ShouldBeNil)

		regex := ".*"
		var semver bool
		var tlsVerify bool
		onlySigned := true

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "**",
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnlySigned:   &onlySigned,
			OnDemand:     true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// wait for sync
		var destTagsList TagsList

		for {
			resp, err := destClient.R().Get(destBaseURL + "/v2/" + repoName + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		time.Sleep(1 * time.Second)

		// get oci references from downstream, should be synced
		getOCIReferrersURL := destBaseURL + path.Join("/v2", repoName, "referrers", digest.String())
		resp, err := resty.R().Get(getOCIReferrersURL)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var index ispec.Index

		err = json.Unmarshal(resp.Body(), &index)
		So(err, ShouldBeNil)

		So(len(index.Manifests), ShouldEqual, 3)
	})
}

func getPortFromBaseURL(baseURL string) string {
	slice := strings.Split(baseURL, ":")

	return slice[len(slice)-1]
}

func TestSyncedSignaturesMetaDB(t *testing.T) {
	Convey("Verify that metadb update correctly when syncing a signature", t, func() {
		repoName := "signed-repo"
		tag := "random-signed-image"
		updateDuration := 30 * time.Minute

		// Create source registry

		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)
		t.Log(srcDir)
		srcPort := getPortFromBaseURL(srcBaseURL)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// Push an image
		signedImage := CreateRandomImage()

		err := UploadImage(signedImage, srcBaseURL, repoName, tag)
		So(err, ShouldBeNil)

		err = signature.SignImageUsingNotary(repoName+":"+tag, srcPort, true)
		So(err, ShouldBeNil)

		err = signature.SignImageUsingCosign(repoName+":"+tag, srcPort, true)
		So(err, ShouldBeNil)

		err = signature.SignImageUsingCosign(repoName+":"+tag, srcPort, false)
		So(err, ShouldBeNil)

		// Create destination registry
		var (
			regex      = ".*"
			semver     = false
			tlsVerify  = false
			defaultVal = true
		)

		syncConfig := &syncconf.Config{
			Enable: &defaultVal,
			Registries: []syncconf.RegistryConfig{
				{
					Content: []syncconf.Content{
						{
							Prefix: repoName,
							Tags:   &syncconf.Tags{Regex: &regex, Semver: &semver},
						},
					},
					URLs:         []string{srcBaseURL},
					PollInterval: updateDuration,
					TLSVerify:    &tlsVerify,
					CertDir:      "",
					OnDemand:     true,
				},
			},
		}

		dctlr, destBaseURL, dstDir, _ := makeDownstreamServer(t, false, syncConfig)
		t.Log(dstDir)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// Trigger SyncOnDemand
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + tag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		repoMeta, err := dctlr.MetaDB.GetRepoMeta(context.Background(), repoName)
		So(err, ShouldBeNil)
		So(repoMeta.Tags, ShouldContainKey, tag)
		So(len(repoMeta.Tags), ShouldEqual, 1)
		So(repoMeta.Signatures, ShouldContainKey, signedImage.DigestStr())

		imageSignatures := repoMeta.Signatures[signedImage.DigestStr()]
		So(imageSignatures, ShouldContainKey, zcommon.CosignSignature)
		So(len(imageSignatures[zcommon.CosignSignature]), ShouldEqual, 2)
		So(imageSignatures, ShouldContainKey, zcommon.NotationSignature)
		So(len(imageSignatures[zcommon.NotationSignature]), ShouldEqual, 1)
	})
}

func TestOnDemandRetryGoroutine(t *testing.T) {
	Convey("Verify ondemand sync retries in background on error", t, func() {
		srcPort := test.GetFreePort()
		srcConfig := config.New()
		srcBaseURL := test.GetBaseURL(srcPort)

		srcConfig.HTTP.Port = srcPort
		srcConfig.Storage.GC = false

		srcDir := t.TempDir()

		srcStorageCtlr := ociutils.GetDefaultStoreController(srcDir, log.NewLogger("debug", ""))

		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(CreateDefaultVulnerableImage(), "zot-cve-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		srcConfig.Storage.RootDirectory = srcDir

		sctlr := api.NewController(srcConfig)
		scm := test.NewControllerManager(sctlr)

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			OnDemand:  true,
			TLSVerify: &tlsVerify,
			CertDir:   "",
		}

		maxRetries := 3
		delay := 2 * time.Second
		syncRegistryConfig.MaxRetries = &maxRetries
		syncRegistryConfig.RetryDelay = &delay

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		scm.StartServer()

		defer scm.StopServer()

		// in the meantime ondemand should retry syncing
		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"successfully synced image", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		// now we should have the image synced
		binfo, err := os.Stat(path.Join(destDir, testImage, "index.json"))
		So(err, ShouldBeNil)
		So(binfo, ShouldNotBeNil)
		So(binfo.Size(), ShouldNotBeZeroValue)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestOnDemandWithDigest(t *testing.T) {
	Convey("Verify ondemand sync works with both digests and tags", t, func() {
		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			OnDemand:  true,
			TLSVerify: &tlsVerify,
			CertDir:   "",
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// get manifest digest from source
		resp, err := destClient.R().Get(srcBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		digest := godigest.FromBytes(resp.Body())

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + digest.String())
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestOnDemandRetryGoroutineErr(t *testing.T) {
	Convey("Verify ondemand sync retries in background on error", t, func() {
		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{"http://127.0.0.1"},
			OnDemand:  true,
			TLSVerify: &tlsVerify,
			CertDir:   "",
		}

		maxRetries := 1
		delay := 1 * time.Second
		syncRegistryConfig.MaxRetries = &maxRetries
		syncRegistryConfig.RetryDelay = &delay

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"failed to copy image", 15*time.Second)
		if err != nil {
			panic(err)
		}
		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		resp, err = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
	})
}

func TestOnDemandMultipleImage(t *testing.T) {
	Convey("Verify ondemand sync retries in background on error, multiple calls should spawn one routine", t, func() {
		srcPort := test.GetFreePort()
		srcConfig := config.New()
		srcBaseURL := test.GetBaseURL(srcPort)

		srcConfig.HTTP.Port = srcPort
		srcConfig.Storage.GC = false

		srcDir := t.TempDir()

		srcStorageCtlr := ociutils.GetDefaultStoreController(srcDir, log.NewLogger("debug", ""))

		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(CreateDefaultVulnerableImage(), "zot-cve-test", "0.0.1", srcStorageCtlr)
		So(err, ShouldBeNil)

		srcConfig.Storage.RootDirectory = srcDir

		sctlr := api.NewController(srcConfig)
		scm := test.NewControllerManager(sctlr)

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			URLs:      []string{srcBaseURL},
			OnDemand:  true,
			TLSVerify: &tlsVerify,
			CertDir:   "",
		}

		maxRetries := 5
		delay := 5 * time.Second
		syncRegistryConfig.MaxRetries = &maxRetries
		syncRegistryConfig.RetryDelay = &delay

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := makeDownstreamServer(t, false, syncConfig)
		defer os.RemoveAll(destDir)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		callsNo := 5
		for i := 0; i < callsNo; i++ {
			_, _ = destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		}

		populatedDirs := make(map[string]bool)

		done := make(chan bool)
		go func() {
			/* watch .sync local cache, make sure just one .sync/subdir is populated with image
			the channel from ondemand should prevent spawning multiple go routines for the same image*/
			for {
				time.Sleep(250 * time.Millisecond)
				select {
				case <-done:
					return
				default:
					dirs, err := os.ReadDir(path.Join(destDir, testImage, ".sync"))
					if err == nil {
						for _, dir := range dirs {
							contents, err := os.ReadDir(path.Join(destDir, testImage, ".sync", dir.Name()))
							if err == nil {
								if len(contents) > 0 {
									populatedDirs[dir.Name()] = true
								}
							}
						}
					}
				}
			}
		}()

		// start upstream server
		scm.StartAndWait(srcPort)

		defer scm.StopServer()

		// wait sync
		for {
			_, err := os.Stat(path.Join(destDir, testImage, "index.json"))
			if err == nil {
				// stop watching /.sync/ subdirs
				done <- true

				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		waitSync(destDir, testImage)

		So(len(populatedDirs), ShouldEqual, 1)

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestOnDemandPullsOnce(t *testing.T) {
	Convey("Verify sync on demand pulls only one time", t, func(conv C) {
		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		semver := true
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, _ := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		var wg goSync.WaitGroup

		wg.Add(1)
		go func(conv C) {
			defer wg.Done()
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			conv.So(err, ShouldBeNil)
			conv.So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		}(conv)

		wg.Add(1)
		go func(conv C) {
			defer wg.Done()
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			conv.So(err, ShouldBeNil)
			conv.So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		}(conv)

		wg.Add(1)
		go func(conv C) {
			defer wg.Done()
			resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
			conv.So(err, ShouldBeNil)
			conv.So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		}(conv)

		done := make(chan bool)

		var maxLen int
		syncBlobUploadDir := path.Join(destDir, testImage, syncConstants.SyncBlobUploadDir)

		go func() {
			for {
				select {
				case <-done:
					return
				default:
					dirs, err := os.ReadDir(syncBlobUploadDir)
					if err != nil {
						continue
					}
					// check how many .sync/uuid/ dirs are created, if just one then on demand pulled only once
					if len(dirs) > maxLen {
						maxLen = len(dirs)
					}
				}
			}
		}()

		wg.Wait()
		done <- true

		So(maxLen, ShouldEqual, 1)
	})
}

func TestSignaturesOnDemand(t *testing.T) {
	Convey("Verify sync signatures on demand feature", t, func() {
		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, _ := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// sync on demand
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		// notation verify the synced image
		image := fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)
		err = signature.VerifyWithNotation(image, tdir)
		So(err, ShouldBeNil)

		// cosign verify the synced image
		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			IgnoreTlog:      true,
		}
		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)})
		So(err, ShouldBeNil)

		// test negative case
		cosignEncodedDigest := strings.Replace(digest.String(), ":", "-", 1) + ".sig"
		getCosignManifestURL := srcBaseURL + path.Join(constants.RoutePrefix, repoName, "manifests", cosignEncodedDigest)

		mResp, err := resty.R().Get(getCosignManifestURL)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var imageManifest ispec.Manifest

		err = json.Unmarshal(mResp.Body(), &imageManifest)
		So(err, ShouldBeNil)

		// trigger errors on cosign blobs
		// trigger error on cosign config blob
		srcConfigBlobPath := path.Join(srcDir, repoName, "blobs", string(imageManifest.Config.Digest.Algorithm()),
			imageManifest.Config.Digest.Encoded())
		err = os.Chmod(srcConfigBlobPath, 0o000)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// trigger error on cosign layer blob
		srcSignatureBlobPath := path.Join(srcDir, repoName, "blobs", string(imageManifest.Layers[0].Digest.Algorithm()),
			imageManifest.Layers[0].Digest.Encoded())

		err = os.Chmod(srcConfigBlobPath, 0o755)
		So(err, ShouldBeNil)

		err = os.Chmod(srcSignatureBlobPath, 0o000)
		So(err, ShouldBeNil)

		// remove already synced image
		err = os.RemoveAll(path.Join(destDir, repoName))
		So(err, ShouldBeNil)

		// sync on demand
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		err = os.Chmod(srcSignatureBlobPath, 0o755)
		So(err, ShouldBeNil)
	})

	Convey("Verify sync signatures on demand feature: notation - negative cases", t, func() {
		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)
		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		destConfig.Storage.RootDirectory = destDir
		destConfig.Storage.Dedupe = false
		destConfig.Storage.GC = false

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig
		destConfig.Log.Output = path.Join(destDir, "sync.log")

		dctlr := api.NewController(destConfig)
		dcm := test.NewControllerManager(dctlr)

		dcm.StartAndWait(destPort)

		defer dcm.StopServer()

		// trigger getOCIRefs error
		getReferrersURL := srcBaseURL + path.Join("/v2/", repoName, "referrers", digest.String())

		resp, err := resty.R().
			SetHeader("Content-Type", "application/json").
			SetQueryParam("artifactType", "application/vnd.cncf.notary.signature").
			Get(getReferrersURL)

		So(err, ShouldBeNil)
		So(resp, ShouldNotBeEmpty)

		var referrers ispec.Index

		err = json.Unmarshal(resp.Body(), &referrers)
		So(err, ShouldBeNil)

		for _, ref := range referrers.Manifests {
			refPath := path.Join(srcDir, repoName, "blobs", string(ref.Digest.Algorithm()), ref.Digest.Encoded())
			err := os.Remove(refPath)
			So(err, ShouldBeNil)
		}

		resp, err = resty.R().Get(destBaseURL + "/v2/" + testSignedImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"couldn't find any oci reference", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)
	})
}

func TestOnlySignaturesOnDemand(t *testing.T) {
	Convey("Verify sync signatures on demand feature when we already have the image", t, func() {
		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			URLs:      []string{srcBaseURL},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		syncBadRegistryConfig := syncconf.RegistryConfig{
			URLs:      []string{"http://invalid.invalid:9999"},
			TLSVerify: &tlsVerify,
			CertDir:   "",
			OnDemand:  true,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncBadRegistryConfig, syncRegistryConfig},
		}

		dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// sync on demand
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		imageManifestDigest := godigest.FromBytes(resp.Body())

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		generateKeyPairs(tdir)

		// sync signature on demand when upstream doesn't have the signature
		image := fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)
		err = signature.VerifyWithNotation(image, tdir)
		So(err, ShouldNotBeNil)

		// cosign verify the synced image
		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			IgnoreTlog:      true,
		}

		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)})
		So(err, ShouldNotBeNil)

		// sign upstream image
		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		// now it should sync signatures on demand, even if we already have the image
		image = fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)
		err = signature.VerifyWithNotation(image, tdir)
		So(err, ShouldBeNil)

		// cosign verify the synced image
		vrfy = verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			IgnoreTlog:      true,
		}

		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)})
		So(err, ShouldBeNil)

		// trigger syncing OCI references on demand
		artifactURLPath := path.Join("/v2", repoName, "referrers", imageManifestDigest.String())

		// based on image manifest digest get referrers
		resp, err = resty.R().
			SetHeader("Content-Type", "application/json").
			SetQueryParam("artifactType", "application/vnd.cncf.icecream").
			Get(srcBaseURL + artifactURLPath)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(err, ShouldBeNil)
	})
}

func TestSyncOnlyDiff(t *testing.T) {
	Convey("Verify sync only difference between local and upstream", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "**",
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     false,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)
		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		// copy images so we have them before syncing, sync should not pull them again
		destStorageCtrl := ociutils.GetDefaultStoreController(destDir, log.NewLogger("debug", ""))

		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", destStorageCtrl)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(CreateDefaultVulnerableImage(), "zot-cve-test", "0.0.1", destStorageCtrl)
		So(err, ShouldBeNil)

		destConfig.Storage.RootDirectory = destDir
		destConfig.Storage.Dedupe = false
		destConfig.Storage.GC = false

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig
		destConfig.Log.Output = path.Join(destDir, "sync.log")

		dctlr := api.NewController(destConfig)
		dcm := test.NewControllerManager(dctlr)

		dcm.StartAndWait(destPort)

		defer dcm.StopServer()

		resp, err := resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"skipping image because it's already synced", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestSyncWithDiffDigest(t *testing.T) {
	Convey("Verify sync correctly detects changes in upstream images", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "**",
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     false,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		destPort := test.GetFreePort()
		destConfig := config.New()
		destBaseURL := test.GetBaseURL(destPort)
		destConfig.HTTP.Port = destPort

		destDir := t.TempDir()

		// copy images so we have them before syncing, sync should not pull them again
		srcStorageCtlr := ociutils.GetDefaultStoreController(destDir, log.NewLogger("debug", ""))

		// both default images are present in both upstream and downstream
		image := CreateDefaultImage()

		// original digest
		originalManifestDigest := image.Descriptor().Digest

		err := WriteImageToFileSystem(image, testImage, testImageTag, srcStorageCtlr)
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(CreateDefaultVulnerableImage(), testCveImage, testImageTag, srcStorageCtlr)
		So(err, ShouldBeNil)

		destConfig.Storage.RootDirectory = destDir
		destConfig.Storage.Dedupe = false
		destConfig.Storage.GC = false

		destConfig.Extensions = &extconf.ExtensionConfig{}
		destConfig.Extensions.Search = nil
		destConfig.Extensions.Sync = syncConfig
		destConfig.Log.Output = path.Join(destDir, "sync.log")

		dctlr := api.NewController(destConfig)
		dcm := test.NewControllerManager(dctlr)

		// before starting downstream server, let's modify an image manifest so that sync should pull it
		// change digest of the manifest so that sync should happen
		size := 5 * 1024 * 1024
		blob := make([]byte, size)
		digest := godigest.FromBytes(blob)

		resp, err := resty.R().Get(srcBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		manifestBlob := resp.Body()

		var manifest ispec.Manifest

		err = json.Unmarshal(manifestBlob, &manifest)
		So(err, ShouldBeNil)

		resp, err = resty.R().Post(srcBaseURL + "/v2/" + testImage + "/blobs/uploads/")
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusAccepted)

		loc := resp.Header().Get("Location")

		resp, err = resty.R().
			SetHeader("Content-Length", fmt.Sprintf("%d", len(blob))).
			SetHeader("Content-Type", "application/octet-stream").
			SetQueryParam("digest", digest.String()).
			SetBody(blob).
			Put(srcBaseURL + loc)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)

		newLayer := ispec.Descriptor{
			MediaType: ispec.MediaTypeImageLayer,
			Digest:    digest,
			Size:      int64(size),
		}

		manifest.Layers = append(manifest.Layers, newLayer)

		manifestBody, err := json.Marshal(manifest)
		if err != nil {
			panic(err)
		}

		modifiedUpstreamManifestDigest := godigest.FromBytes(manifestBody)
		So(modifiedUpstreamManifestDigest, ShouldNotEqual, originalManifestDigest)

		resp, err = resty.R().SetHeader("Content-type", "application/vnd.oci.image.manifest.v1+json").
			SetBody(manifestBody).
			Put(srcBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		dcm.StartServer()
		defer dcm.StopServer()

		test.WaitTillServerReady(destBaseURL)

		// wait generator to finish generating tasks.
		waitSyncFinish(dctlr.Config.Log.Output)
		// wait till .sync temp subdir gets removed.
		waitSync(destDir, testImage)

		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		modifiedDownstreamManifestDigest := godigest.FromBytes(resp.Body())
		// should differ from original.
		So(modifiedDownstreamManifestDigest, ShouldNotEqual, originalManifestDigest)
		// should be the same with the one we pushed to upstream.
		So(modifiedDownstreamManifestDigest, ShouldEqual, modifiedUpstreamManifestDigest)
	})
}

func TestSyncSignaturesDiff(t *testing.T) {
	Convey("Verify sync detects changes in the upstream signatures", t, func() {
		updateDuration, _ := time.ParseDuration("10s")

		sctlr, srcBaseURL, srcDir, _, _ := makeUpstreamServer(t, false, false)
		defer os.RemoveAll(srcDir)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		// create repo, push and sign it
		repoName := testSignedImage
		var digest godigest.Digest
		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()

		_ = os.Chdir(tdir)
		generateKeyPairs(tdir)

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		regex := ".*"
		var semver bool
		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: repoName,
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			OnDemand:     false,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, destDir, destClient := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		// wait for sync
		var destTagsList TagsList

		for {
			resp, err := destClient.R().Get(destBaseURL + "/v2/" + repoName + "/tags/list")
			if err != nil {
				panic(err)
			}

			err = json.Unmarshal(resp.Body(), &destTagsList)
			if err != nil {
				panic(err)
			}

			if len(destTagsList.Tags) > 0 {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}

		time.Sleep(3 * time.Second)

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		// notation verify the image
		image := fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)
		err = signature.VerifyWithNotation(image, tdir)
		So(err, ShouldBeNil)

		// cosign verify the image
		vrfy := verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			IgnoreTlog:      true,
		}
		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)})
		So(err, ShouldBeNil)

		// now add new signatures to upstream and let sync detect that upstream signatures changed and pull them
		So(os.RemoveAll(tdir), ShouldBeNil)
		tdir = t.TempDir()
		defer os.RemoveAll(tdir)
		_ = os.Chdir(tdir)
		generateKeyPairs(tdir)
		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		// wait for signatures
		time.Sleep(12 * time.Second)

		// notation verify the image
		image = fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)
		err = signature.VerifyWithNotation(image, tdir)
		So(err, ShouldBeNil)

		// cosign verify the image
		vrfy = verify.VerifyCommand{
			RegistryOptions: options.RegistryOptions{AllowInsecure: true},
			CheckClaims:     true,
			KeyRef:          path.Join(tdir, "cosign.pub"),
			IgnoreTlog:      true,
		}
		err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort, repoName, testImageTag)})
		So(err, ShouldBeNil)

		// compare signatures
		var srcIndex ispec.Index
		var destIndex ispec.Index

		srcBuf, err := os.ReadFile(path.Join(srcDir, repoName, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		destBuf, err := os.ReadFile(path.Join(destDir, repoName, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(destBuf, &destIndex); err != nil {
			panic(err)
		}

		// find image manifest digest (signed-repo) and upstream notary digests
		var upstreamRefsDigests []string
		var downstreamRefsDigests []string

		var manifestDigest string
		for _, manifestDesc := range srcIndex.Manifests {
			if manifestDesc.Annotations[ispec.AnnotationRefName] == testImageTag {
				manifestDigest = string(manifestDesc.Digest)
			} else if manifestDesc.MediaType == notreg.ArtifactTypeNotation {
				upstreamRefsDigests = append(upstreamRefsDigests, manifestDesc.Digest.String())
			}
		}

		for _, manifestDesc := range destIndex.Manifests {
			if manifestDesc.MediaType == notreg.ArtifactTypeNotation {
				downstreamRefsDigests = append(downstreamRefsDigests, manifestDesc.Digest.String())
			}
		}

		// compare notary signatures
		So(upstreamRefsDigests, ShouldResemble, downstreamRefsDigests)

		cosignManifestTag := strings.Replace(manifestDigest, ":", "-", 1) + ".sig"

		// get synced cosign manifest from downstream
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + cosignManifestTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var syncedCosignManifest ispec.Manifest

		err = json.Unmarshal(resp.Body(), &syncedCosignManifest)
		So(err, ShouldBeNil)

		// get cosign manifest from upstream
		resp, err = resty.R().Get(srcBaseURL + "/v2/" + repoName + "/manifests/" + cosignManifestTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var cosignManifest ispec.Manifest

		err = json.Unmarshal(resp.Body(), &cosignManifest)
		So(err, ShouldBeNil)

		// compare cosign signatures
		So(reflect.DeepEqual(cosignManifest, syncedCosignManifest), ShouldEqual, true)

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"skipping syncing cosign reference", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		found, err = test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"skipping oci references", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestOnlySignedFlag(t *testing.T) {
	updateDuration, _ := time.ParseDuration("30m")

	sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false) //nolint: dogsled

	scm := test.NewControllerManager(sctlr)
	scm.StartAndWait(sctlr.Config.HTTP.Port)

	defer scm.StopServer()

	regex := ".*"
	semver := true
	onlySigned := true

	var tlsVerify bool

	syncRegistryConfig := syncconf.RegistryConfig{
		Content: []syncconf.Content{
			{
				Prefix: testImage,
				Tags: &syncconf.Tags{
					Regex:  &regex,
					Semver: &semver,
				},
			},
		},
		URLs:         []string{srcBaseURL},
		PollInterval: updateDuration,
		TLSVerify:    &tlsVerify,
		CertDir:      "",
		OnlySigned:   &onlySigned,
	}

	defaultVal := true

	Convey("Verify sync revokes unsigned images", t, func() {
		syncRegistryConfig.OnDemand = false
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, client := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"skipping image without mandatory signature", 15*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		resp, err := client.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		waitSyncFinish(dctlr.Config.Log.Output)
	})

	Convey("Verify sync ondemand revokes unsigned images", t, func() {
		syncRegistryConfig.OnDemand = true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		dctlr, destBaseURL, _, client := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)
		defer dcm.StopServer()

		resp, err := client.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		waitSyncFinish(dctlr.Config.Log.Output)
	})
}

func TestSyncWithDestination(t *testing.T) {
	Convey("Test sync computes destination option correctly", t, func() {
		repoName := "zot-fold/zot-test"

		testCases := []struct {
			content  syncconf.Content
			expected string
		}{
			{
				expected: "zot-test/zot-fold/zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/zot-test", Destination: "/zot-test", StripPrefix: false},
			},
			{
				expected: "zot-fold/zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/zot-test", Destination: "/", StripPrefix: false},
			},
			{
				expected: "zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/zot-test", Destination: "/zot-test", StripPrefix: true},
			},
			{
				expected: "zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			},
			{
				expected: "zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/zot-test", Destination: "/zot-test", StripPrefix: true},
			},
			{
				expected: "zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			},
			{
				expected: "zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/**", Destination: "/", StripPrefix: true},
			},
			{
				expected: "zot-fold/zot-test",
				content:  syncconf.Content{Prefix: "zot-fold/**", Destination: "/", StripPrefix: false},
			},
		}

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		err := os.MkdirAll(path.Join(sctlr.Config.Storage.RootDirectory, "/zot-fold"), storageConstants.DefaultDirPerms)
		So(err, ShouldBeNil)

		// move upstream images under /zot-fold
		err = os.Rename(
			path.Join(sctlr.Config.Storage.RootDirectory, "zot-test"),
			path.Join(sctlr.Config.Storage.RootDirectory, "/zot-fold/zot-test"),
		)
		So(err, ShouldBeNil)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		generateKeyPairs(tdir)

		// get manifest digest from source
		resp, err := resty.R().Get(srcBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		digest := godigest.FromBytes(resp.Body())

		So(func() { signImage(tdir, srcPort, repoName, digest) }, ShouldNotPanic)

		Convey("Test peridiocally sync", func() {
			for _, testCase := range testCases {
				updateDuration, _ := time.ParseDuration("30m")
				tlsVerify := false
				syncRegistryConfig := syncconf.RegistryConfig{
					Content:      []syncconf.Content{testCase.content},
					URLs:         []string{srcBaseURL},
					OnDemand:     false,
					PollInterval: updateDuration,
					TLSVerify:    &tlsVerify,
				}

				defaultVal := true
				syncConfig := &syncconf.Config{
					Enable:     &defaultVal,
					Registries: []syncconf.RegistryConfig{syncRegistryConfig},
				}

				dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

				dcm := test.NewControllerManager(dctlr)
				dcm.StartAndWait(dctlr.Config.HTTP.Port)
				defer dcm.StopServer()

				// give it time to set up sync
				found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
					"finished syncing repo", 60*time.Second)
				if err != nil {
					panic(err)
				}

				So(found, ShouldBeTrue)

				resp, err := destClient.R().Get(destBaseURL + "/v2/" + testCase.expected + "/manifests/0.0.1")
				t.Logf("testcase: %#v", testCase)
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				splittedURL = strings.SplitAfter(destBaseURL, ":")
				destPort := splittedURL[len(splittedURL)-1]

				// notation verify the synced image
				image := fmt.Sprintf("localhost:%s/%s:%s", destPort, testCase.expected, testImageTag)
				err = signature.VerifyWithNotation(image, tdir)
				So(err, ShouldBeNil)

				// cosign verify the synced image
				vrfy := verify.VerifyCommand{
					RegistryOptions: options.RegistryOptions{AllowInsecure: true},
					CheckClaims:     true,
					KeyRef:          path.Join(tdir, "cosign.pub"),
					IgnoreTlog:      true,
				}
				err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort,
					testCase.expected, testImageTag)})
				So(err, ShouldBeNil)
			}
		})

		// this is the inverse function of getRepoDestination()
		Convey("Test ondemand sync", func() {
			for _, testCase := range testCases {
				tlsVerify := false
				syncRegistryConfig := syncconf.RegistryConfig{
					Content:   []syncconf.Content{testCase.content},
					URLs:      []string{srcBaseURL},
					OnDemand:  true,
					TLSVerify: &tlsVerify,
				}

				defaultVal := true
				syncConfig := &syncconf.Config{
					Enable:     &defaultVal,
					Registries: []syncconf.RegistryConfig{syncRegistryConfig},
				}

				dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

				dcm := test.NewControllerManager(dctlr)
				dcm.StartAndWait(dctlr.Config.HTTP.Port)
				defer dcm.StopServer()

				resp, err := destClient.R().Get(destBaseURL + "/v2/" + testCase.expected + "/manifests/0.0.1")
				t.Logf("testcase: %#v", testCase)
				So(err, ShouldBeNil)
				So(resp, ShouldNotBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

				splittedURL = strings.SplitAfter(destBaseURL, ":")
				destPort := splittedURL[len(splittedURL)-1]

				// notation verify the synced image
				image := fmt.Sprintf("localhost:%s/%s:%s", destPort, testCase.expected, testImageTag)
				err = signature.VerifyWithNotation(image, tdir)
				So(err, ShouldBeNil)

				// cosign verify the synced image
				vrfy := verify.VerifyCommand{
					RegistryOptions: options.RegistryOptions{AllowInsecure: true},
					CheckClaims:     true,
					KeyRef:          path.Join(tdir, "cosign.pub"),
					IgnoreTlog:      true,
				}
				err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s:%s", destPort,
					testCase.expected, testImageTag)})
				So(err, ShouldBeNil)
			}
		})
	})
}

func TestSyncImageIndex(t *testing.T) {
	Convey("Verify syncing image indexes works", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)
		defer scm.StopServer()

		regex := ".*"
		var semver bool
		tlsVerify := false

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "index",
					Tags: &syncconf.Tags{
						Regex:  &regex,
						Semver: &semver,
					},
				},
			},
			URLs:         []string{srcBaseURL},
			OnDemand:     false,
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		multiarchImage := CreateMultiarchWith().Images(
			[]Image{
				CreateRandomImage(),
				CreateRandomImage(),
				CreateRandomImage(),
				CreateRandomImage(),
			},
		).Build()

		// upload the previously defined images
		err := UploadMultiarchImage(multiarchImage, srcBaseURL, "index", "latest")
		So(err, ShouldBeNil)

		resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
			Get(srcBaseURL + "/v2/index/manifests/latest")
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		So(resp.Body(), ShouldNotBeEmpty)
		So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

		Convey("sync periodically", func() {
			// start downstream server
			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			// give it time to set up sync
			t.Logf("waitsync(%s, %s)", dctlr.Config.Storage.RootDirectory, "index")
			waitSync(dctlr.Config.Storage.RootDirectory, "index")

			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(destBaseURL + "/v2/index/manifests/latest")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			var syncedIndex ispec.Index
			err := json.Unmarshal(resp.Body(), &syncedIndex)
			So(err, ShouldBeNil)

			So(reflect.DeepEqual(syncedIndex, multiarchImage.Index), ShouldEqual, true)

			waitSyncFinish(dctlr.Config.Log.Output)
		})

		Convey("sync on demand", func() {
			// start downstream server
			syncConfig.Registries[0].OnDemand = true
			syncConfig.Registries[0].PollInterval = 0

			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(destBaseURL + "/v2/index/manifests/latest")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			var syncedIndex ispec.Index
			err := json.Unmarshal(resp.Body(), &syncedIndex)
			So(err, ShouldBeNil)

			So(reflect.DeepEqual(syncedIndex, multiarchImage.Index), ShouldEqual, true)
		})
	})
}

func generateKeyPairs(tdir string) {
	// generate a keypair
	os.Setenv("COSIGN_PASSWORD", "")

	if _, err := os.Stat(path.Join(tdir, "cosign.key")); err != nil {
		err := generate.GenerateKeyPairCmd(context.TODO(), "", "cosign", nil)
		if err != nil {
			panic(err)
		}
	}

	signature.NotationPathLock.Lock()
	defer signature.NotationPathLock.Unlock()

	signature.LoadNotationPath(tdir)

	err := signature.GenerateNotationCerts(tdir, "good")
	if err != nil {
		panic(err)
	}
}

func attachSBOM(tdir, port, repoName string, digest godigest.Digest) {
	sbomFilePath := path.Join(tdir, "sbom.spdx")

	err := os.WriteFile(sbomFilePath, []byte("sbom example"), storageConstants.DefaultFilePerms)
	if err != nil {
		panic(err)
	}

	err = attach.SBOMCmd(context.Background(), options.RegistryOptions{AllowInsecure: true},
		options.RegistryExperimentalOptions{RegistryReferrersMode: options.RegistryReferrersModeLegacy},
		sbomFilePath, "text/spdx", fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String()),
	)
	if err != nil {
		panic(err)
	}
}

func signImage(tdir, port, repoName string, digest godigest.Digest) {
	// push signatures to upstream server so that we can sync them later
	// sign the image
	err := sign.SignCmd(&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
		options.KeyOpts{KeyRef: path.Join(tdir, "cosign.key"), PassFunc: generate.GetPass},
		options.SignOptions{
			Registry: options.RegistryOptions{AllowInsecure: true},
			Upload:   true,
		},
		[]string{fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())})
	if err != nil {
		panic(err)
	}

	vrfy := verify.VerifyCommand{
		RegistryOptions: options.RegistryOptions{AllowInsecure: true},
		CheckClaims:     true,
		KeyRef:          path.Join(tdir, "cosign.pub"),
		IgnoreTlog:      true,
	}

	err = vrfy.Exec(context.TODO(), []string{fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())})
	if err != nil {
		panic(err)
	}

	signature.NotationPathLock.Lock()
	defer signature.NotationPathLock.Unlock()

	signature.LoadNotationPath(tdir)

	// sign the image
	image := fmt.Sprintf("localhost:%s/%s@%s", port, repoName, digest.String())

	err = signature.SignWithNotation("good", image, tdir, false)
	if err != nil && !strings.Contains(err.Error(), "failed to delete dangling referrers index") {
		panic(err)
	}

	err = signature.VerifyWithNotation(image, tdir)
	if err != nil {
		panic(err)
	}
}

func pushRepo(url, repoName string) godigest.Digest {
	// create a blob/layer
	resp, err := resty.R().Post(url + fmt.Sprintf("/v2/%s/blobs/uploads/", repoName))
	if err != nil {
		panic(err)
	}

	loc := test.Location(url, resp)

	_, err = resty.R().Get(loc)
	if err != nil {
		panic(err)
	}

	content := []byte("this is a blob")
	digest := godigest.FromBytes(content)

	_, err = resty.R().SetQueryParam("digest", digest.String()).
		SetHeader("Content-Type", "application/octet-stream").SetBody(content).Put(loc)
	if err != nil {
		panic(err)
	}

	// upload scratch image config
	resp, err = resty.R().
		Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repoName))
	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusAccepted {
		panic(fmt.Errorf("invalid status code: %d %w", resp.StatusCode(), errBadStatus))
	}

	loc = test.Location(url, resp)
	cblob, cdigest := ispec.DescriptorEmptyJSON.Data, ispec.DescriptorEmptyJSON.Digest

	resp, err = resty.R().
		SetContentLength(true).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusCreated {
		panic(fmt.Errorf("invalid status code: %d %w", resp.StatusCode(), errBadStatus))
	}

	// upload image config blob
	resp, err = resty.R().
		Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repoName))
	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusAccepted {
		panic(fmt.Errorf("invalid status code: %d %w", resp.StatusCode(), errBadStatus))
	}

	loc = test.Location(url, resp)
	cblob, cdigest = GetRandomImageConfig()

	resp, err = resty.R().
		SetContentLength(true).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(cblob))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", cdigest.String()).
		SetBody(cblob).
		Put(loc)
	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusCreated {
		panic(fmt.Errorf("invalid status code: %d %w", resp.StatusCode(), errBadStatus))
	}

	// create a manifest
	manifest := ispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ispec.MediaTypeImageManifest,
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
		panic(err)
	}

	digest = godigest.FromBytes(content)

	_, err = resty.R().SetHeader("Content-Type", "application/vnd.oci.image.manifest.v1+json").
		SetBody(content).Put(url + fmt.Sprintf("/v2/%s/manifests/%s", repoName, testImageTag))
	if err != nil {
		panic(err)
	}

	// create artifact blob
	abuf := []byte("this is an artifact")
	adigest := pushBlob(url, repoName, abuf)

	// create artifact config blob
	acbuf := []byte("{}")
	acdigest := pushBlob(url, repoName, acbuf)

	// push a referrer artifact
	manifest = ispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ispec.MediaTypeImageManifest,
		Config: ispec.Descriptor{
			MediaType: "application/vnd.cncf.icecream",
			Digest:    acdigest,
			Size:      int64(len(acbuf)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/octet-stream",
				Digest:    adigest,
				Size:      int64(len(abuf)),
			},
		},
		Subject: &ispec.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    digest,
			Size:      int64(len(content)),
		},
	}

	artifactManifest := ispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType:    ispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.cncf.icecream",
		Config: ispec.Descriptor{
			MediaType: ispec.MediaTypeEmptyJSON,
			Digest:    ispec.DescriptorEmptyJSON.Digest,
			Size:      2,
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/octet-stream",
				Digest:    adigest,
				Size:      int64(len(abuf)),
			},
		},
		Subject: &ispec.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    digest,
			Size:      int64(len(content)),
		},
	}

	manifest.SchemaVersion = 2

	content, err = json.Marshal(manifest)
	if err != nil {
		panic(err)
	}

	adigest = godigest.FromBytes(content)

	// put OCI reference image mediaType artifact
	_, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(content).Put(url + fmt.Sprintf("/v2/%s/manifests/%s", repoName, adigest.String()))
	if err != nil {
		panic(err)
	}

	content, err = json.Marshal(artifactManifest)
	if err != nil {
		panic(err)
	}

	adigest = godigest.FromBytes(content)

	// put OCI reference artifact mediaType artifact
	_, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageManifest).
		SetBody(content).Put(url + fmt.Sprintf("/v2/%s/manifests/%s", repoName, adigest.String()))
	if err != nil {
		panic(err)
	}

	return digest
}

// will wait until .sync temp dir is removed and the image is moved into local imagestore.
func waitSync(rootDir, repoName string) {
	// wait for .sync subdirs to be removed
	for {
		dirs, err := os.ReadDir(path.Join(rootDir, repoName, syncConstants.SyncBlobUploadDir))
		if err == nil && len(dirs) == 0 {
			// stop watching /.sync/ subdirs
			return
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func pushBlob(url string, repoName string, buf []byte) godigest.Digest {
	resp, err := resty.R().
		Post(fmt.Sprintf("%s/v2/%s/blobs/uploads/", url, repoName))
	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusAccepted {
		panic(fmt.Errorf("invalid status code: %d %w", resp.StatusCode(), errBadStatus))
	}

	loc := test.Location(url, resp)

	digest := godigest.FromBytes(buf)
	resp, err = resty.R().
		SetContentLength(true).
		SetHeader("Content-Length", fmt.Sprintf("%d", len(buf))).
		SetHeader("Content-Type", "application/octet-stream").
		SetQueryParam("digest", digest.String()).
		SetBody(buf).
		Put(loc)

	if err != nil {
		panic(err)
	}

	if resp.StatusCode() != http.StatusCreated {
		panic(fmt.Errorf("invalid status code: %d %w", resp.StatusCode(), errBadStatus))
	}

	return digest
}

// this is waiting for generator to finish working, it doesn't mean sync has finished though.
func waitSyncFinish(logPath string) bool {
	found, err := test.ReadLogFileAndSearchString(logPath,
		"finished syncing all repos", 60*time.Second)
	if err != nil {
		panic(err)
	}

	return found
}
