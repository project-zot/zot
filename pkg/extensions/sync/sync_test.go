//go:build sync

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
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	goSync "sync"
	"testing"
	"time"

	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/attach"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/v3/pkg/oci/remote"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	cli "zotregistry.dev/zot/v2/pkg/cli/server"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/sync"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	authutils "zotregistry.dev/zot/v2/pkg/test/auth"
	test "zotregistry.dev/zot/v2/pkg/test/common"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	ociutils "zotregistry.dev/zot/v2/pkg/test/oci-utils"
	"zotregistry.dev/zot/v2/pkg/test/signature"
	tlsutils "zotregistry.dev/zot/v2/pkg/test/tls"
)

const (
	dockerManifestMediaType       = "application/vnd.docker.distribution.manifest.v2+json"
	dockerIndexManifestMediaType  = "application/vnd.docker.distribution.manifest.list.v2+json"
	dockerManifestConfigMediaType = "application/vnd.docker.container.image.v1+json"
	dockerLayerMediaType          = "application/vnd.docker.image.rootfs.diff.tar.gzip"

	testImage    = "zot-test"
	testImageTag = "0.0.1"
	testCveImage = "zot-cve-test"

	testSignedImage = "signed-repo"
)

var (
	// no retries unless explicitly configured in each test.
	maxRetries   = 1      //nolint: gochecknoglobals
	username     = "test" //nolint: gochecknoglobals
	password     = "test" //nolint: gochecknoglobals
	errSync      = errors.New("sync error, src oci repo differs from dest one")
	errBadStatus = errors.New("bad http status")
	ErrTestError = errors.New("testError")
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

// setupTestCertsForSync generates certificates for sync tests that need file paths.
func setupTestCertsForSync(t *testing.T, tempDir string) (
	string, string, string, string, string, []byte,
) {
	t.Helper()

	// Generate CA certificate
	caOpts := &tlsutils.CertificateOptions{
		CommonName: "*",
	}
	caCertPEM, caKeyPEM, err := tlsutils.GenerateCACert(caOpts)
	if err != nil {
		t.Fatalf("Failed to generate CA cert: %v", err)
	}

	caCertPath := path.Join(tempDir, "ca.crt")
	caKeyPath := path.Join(tempDir, "ca.key")
	err = os.WriteFile(caCertPath, caCertPEM, 0o600)
	if err != nil {
		t.Fatalf("Failed to write CA cert: %v", err)
	}
	_ = os.WriteFile(caKeyPath, caKeyPEM, 0o600)

	// Generate server certificate (10 years validity, matching gen_certs.sh)
	serverCertPath := path.Join(tempDir, "server.cert")
	serverKeyPath := path.Join(tempDir, "server.key")
	serverOpts := &tlsutils.CertificateOptions{
		Hostname:           "127.0.0.1",
		CommonName:         "*",
		OrganizationalUnit: "TestServer",
		NotAfter:           time.Now().AddDate(10, 0, 0),
	}
	err = tlsutils.GenerateServerCertToFile(caCertPEM, caKeyPEM, serverCertPath, serverKeyPath, serverOpts)
	if err != nil {
		t.Fatalf("Failed to generate server cert: %v", err)
	}

	// Generate client certificate (10 years validity, matching gen_certs.sh)
	clientCertPath := path.Join(tempDir, "client.cert")
	clientKeyPath := path.Join(tempDir, "client.key")
	clientOpts := &tlsutils.CertificateOptions{
		CommonName:         "testclient",
		OrganizationalUnit: "TestClient",
		NotAfter:           time.Now().AddDate(10, 0, 0),
	}
	err = tlsutils.GenerateClientCertToFile(caCertPEM, caKeyPEM, clientCertPath, clientKeyPath, clientOpts)
	if err != nil {
		t.Fatalf("Failed to generate client cert: %v", err)
	}

	return caCertPath, serverCertPath, serverKeyPath, clientCertPath, clientKeyPath, caCertPEM
}

// makeUpstreamServerWithCerts creates an upstream server using shared certificates.
func makeUpstreamServerWithCerts(
	t *testing.T, secure, basicAuth bool, certDir string, caCertPEM []byte,
) (*api.Controller, string, string, *resty.Client) {
	t.Helper()

	srcPort := test.GetFreePort()
	srcConfig := config.New()
	client := resty.New()

	var srcBaseURL string
	if secure {
		srcBaseURL = test.GetSecureBaseURL(srcPort)

		// Use shared certificates
		caCertPath := path.Join(certDir, "ca.crt")
		serverCertPath := path.Join(certDir, "server.cert")
		serverKeyPath := path.Join(certDir, "server.key")
		clientCertPath := path.Join(certDir, "client.cert")
		clientKeyPath := path.Join(certDir, "client.key")

		srcConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			t.Fatalf("Failed to load client cert for upstream test client: %v", err)
		}

		client.SetCertificates(cert)
	} else {
		srcBaseURL = test.GetBaseURL(srcPort)
	}

	var htpasswdPath string
	if basicAuth {
		htpasswdPath = test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))
		srcConfig.HTTP.Auth = &config.AuthConfig{
			HTPasswd: config.AuthHTPasswd{
				Path: htpasswdPath,
			},
		}
	}

	srcConfig.HTTP.Port = srcPort
	srcConfig.Storage.GC = false

	srcDir := t.TempDir()
	srcStorageCtrl := ociutils.GetDefaultStoreController(srcDir, log.NewTestLogger())

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

	return sctlr, srcBaseURL, srcDir, client
}

func makeUpstreamServer(
	t *testing.T, secure, basicAuth bool,
) (*api.Controller, string, string, *resty.Client) {
	t.Helper()

	// Generate certificates and delegate to makeUpstreamServerWithCerts
	if secure {
		tempDir := t.TempDir()
		_, _, _, _, _, caCertPEM := setupTestCertsForSync(t, tempDir)

		return makeUpstreamServerWithCerts(t, secure, basicAuth, tempDir, caCertPEM)
	}

	return makeUpstreamServerWithCerts(t, secure, basicAuth, "", nil)
}

// makeDownstreamServerWithCerts creates a downstream server using shared certificates.
func makeDownstreamServerWithCerts(
	t *testing.T, secure bool, syncConfig *syncconf.Config, certDir string, caCertPEM []byte,
) (*api.Controller, string, string, *resty.Client) {
	t.Helper()

	destPort := test.GetFreePort()
	destConfig := config.New()
	client := resty.New()

	var destBaseURL string
	if secure {
		destBaseURL = test.GetSecureBaseURL(destPort)

		// Use shared certificates (same CA as upstream)
		caCertPath := path.Join(certDir, "ca.crt")
		serverCertPath := path.Join(certDir, "server.cert")
		serverKeyPath := path.Join(certDir, "server.key")
		clientCertPath := path.Join(certDir, "client.cert")
		clientKeyPath := path.Join(certDir, "client.key")

		destConfig.HTTP.TLS = &config.TLSConfig{
			Cert:   serverCertPath,
			Key:    serverKeyPath,
			CACert: caCertPath,
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertPEM)

		client.SetTLSClientConfig(&tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12})

		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			t.Fatalf("Failed to load client cert for downstream test client: %v", err)
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

func makeDownstreamServer(
	t *testing.T, secure bool, syncConfig *syncconf.Config,
) (*api.Controller, string, string, *resty.Client) {
	t.Helper()

	// Generate certificates and delegate to makeDownstreamServerWithCerts
	if secure {
		tempDir := t.TempDir()
		_, _, _, _, _, caCertPEM := setupTestCertsForSync(t, tempDir)

		return makeDownstreamServerWithCerts(t, secure, syncConfig, tempDir, caCertPEM)
	}

	return makeDownstreamServerWithCerts(t, secure, syncConfig, "", nil)
}

func makeInsecureDownstreamServerFixedPort(
	t *testing.T, port string, syncConfig *syncconf.Config, clusterConfig *config.ClusterConfig,
) (*api.Controller, string, string, *resty.Client) {
	t.Helper()

	destPort := port
	destConfig := config.New()
	client := resty.New()

	destBaseURL := test.GetBaseURL(destPort)

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

	destConfig.Cluster = clusterConfig

	dctlr := api.NewController(destConfig)

	return dctlr, destBaseURL, destDir, client
}

func TestOnDemand(t *testing.T) {
	Convey("Verify sync on demand feature", t, func() {
		sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, false)
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
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			OnDemand:   true,
			MaxRetries: &maxRetries,
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

			var (
				srcTagsList  TagsList
				destTagsList TagsList
			)

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
			sctlr, newSrcBaseURL, srcDir, srcClient := makeUpstreamServer(t, false, false)
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

			var (
				srcTagsList  TagsList
				destTagsList TagsList
			)

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
			err = signature.SignImageUsingCosign("remote-repo@"+manifestDigest.String(), port, false)
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
			So(hostname, ShouldNotBeEmpty)

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
					fmt.Sprintf("http://%s:%s", hostname, destPort), //nolint:nosprintfhostport
					destBaseURL,
					srcBaseURL,
					"http://localhost:" + destPort,
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
						return ErrTestError
					}

					return nil
				},
				SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					if strings.HasPrefix(reference, "sha256-") &&
						(strings.HasSuffix(reference, remote.SignatureTagSuffix) ||
							strings.HasSuffix(reference, remote.SBOMTagSuffix)) ||
						strings.HasPrefix(reference, "sha256:") {
						return ErrTestError
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
					fmt.Sprintf("http://%s:%s", hostname, destPort), destBaseURL, //nolint:nosprintfhostport
					srcBaseURL, "http://localhost:" + destPort,
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
						return ErrTestError
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

func TestOnDemandWithScaleOutCluster(t *testing.T) {
	Convey("Given 2 downstream zots and one upstream, test that the cluster can sync images", t, func() {
		sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// sync config for both downstreams.
		tlsVerify := false
		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: testImage,
				},
				{
					Prefix: testCveImage,
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

		// Get dynamic ports for cluster members
		clusterPorts := test.GetFreePorts(2)

		// cluster config for member 1.
		clusterCfgDownstream1 := config.ClusterConfig{
			Members: []string{
				"127.0.0.1:" + clusterPorts[0],
				"127.0.0.1:" + clusterPorts[1],
			},
			HashKey: "loremipsumdolors",
		}

		// cluster config copied for member 2.
		clusterCfgDownstream2 := clusterCfgDownstream1

		dctrl1, dctrl1BaseURL, destDir1, dstClient1 := makeInsecureDownstreamServerFixedPort(
			t, clusterPorts[0], syncConfig, &clusterCfgDownstream1)
		dctrl1Scm := test.NewControllerManager(dctrl1)

		dctrl2, dctrl2BaseURL, destDir2, dstClient2 := makeInsecureDownstreamServerFixedPort(
			t, clusterPorts[1], syncConfig, &clusterCfgDownstream2)
		dctrl2Scm := test.NewControllerManager(dctrl2)

		dctrl1Scm.StartAndWait(dctrl1.Config.HTTP.Port)
		defer dctrl1Scm.StopServer()

		dctrl2Scm.StartAndWait(dctrl2.Config.HTTP.Port)
		defer dctrl2Scm.StopServer()

		// verify that all servers are up.
		clients := []*resty.Client{srcClient, dstClient1, dstClient2}
		baseURLs := []string{srcBaseURL, dctrl1BaseURL, dctrl2BaseURL}

		for clientIdx, client := range clients {
			resp, err := client.R().Get(baseURLs[clientIdx] + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		}

		// storage for each downstream should not have image data at the start.
		destDirs := []string{destDir1, destDir2}
		images := []string{testImage, testCveImage}

		for _, image := range images {
			for _, destDir := range destDirs {
				_, err := os.Stat(path.Join(destDir, image))
				So(err, ShouldNotBeNil)
				So(os.IsNotExist(err), ShouldBeTrue)
			}
		}

		repos := []string{testImage, testCveImage}

		// tags list for both images should return 404 at the start.
		// only hit one instance as the request will get proxied anyway.
		for _, repo := range repos {
			resp, err := dstClient1.R().Get(
				fmt.Sprintf("%s/v2/%s/tags/list", dctrl1BaseURL, repo),
			)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		}

		// should successfully sync zot-test image when trying to load manifest.
		// only hit one instance as the request will get proxied anyway.
		resp, err := dstClient1.R().Get(
			fmt.Sprintf("%s/v2/%s/manifests/%s", dctrl1BaseURL, testImage, testImageTag),
		)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// tags list for test image should return data after the sync.
		// only hit one instance as the request will get proxied anyway.
		// get manifest is hit with a GET request.
		resp, err = dstClient1.R().Get(
			fmt.Sprintf("%s/v2/%s/tags/list", dctrl1BaseURL, testImage),
		)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var initialTags TagsList
		err = json.Unmarshal(resp.Body(), &initialTags)
		So(err, ShouldBeNil)
		So(initialTags, ShouldEqual, TagsList{
			Name: testImage,
			Tags: []string{testImageTag},
		})

		// should successfully sync test vulnerable image when trying to check manifest.
		// check manifest is hit with a HEAD or OPTIONS request.
		resp, err = dstClient1.R().Head(
			fmt.Sprintf("%s/v2/%s/manifests/%s", dctrl1BaseURL, testCveImage, testImageTag),
		)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// tags list for test CVE image should return data after the sync.
		// only hit one instance as the request will get proxied anyway.
		// get manifest is hit with a GET request.
		resp, err = dstClient1.R().Get(
			fmt.Sprintf("%s/v2/%s/tags/list", dctrl1BaseURL, testCveImage),
		)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var cveTagsList TagsList
		err = json.Unmarshal(resp.Body(), &cveTagsList)
		So(err, ShouldBeNil)
		So(cveTagsList, ShouldEqual, TagsList{
			Name: testCveImage,
			Tags: []string{testImageTag},
		})

		// storage for only one downstream should have the data for test image.
		// with loremipsumdolors as the hashKey,
		// zot-test is managed by member index 1.
		// zot-cve-test is managed by member index 0.

		_, err = os.Stat(path.Join(destDir1, testImage))
		So(err, ShouldNotBeNil)
		So(os.IsNotExist(err), ShouldBeTrue)

		_, err = os.Stat(path.Join(destDir2, testImage))
		So(err, ShouldBeNil)

		// storage for only one downstream should have the data for the test cve image.
		// with loremipsumdolors as the hashKey,
		// zot-test is managed by member index 1.
		// zot-cve-test is managed by member index 0.

		_, err = os.Stat(path.Join(destDir1, testCveImage))
		So(err, ShouldBeNil)

		_, err = os.Stat(path.Join(destDir2, testCveImage))
		So(err, ShouldNotBeNil)
		So(os.IsNotExist(err), ShouldBeTrue)
	})
}

func TestOnDemandWithScaleOutClusterWithReposNotAddedForSync(t *testing.T) {
	Convey("When repos are not added for sync, cluster should not sync images", t, func() {
		sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, false)
		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// sync config for both downstreams.
		// there is a dummy entry in the Content array
		tlsVerify := false
		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "doesnotexist",
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

		// Get dynamic ports for cluster members
		clusterPorts := test.GetFreePorts(2)

		// cluster config for member 1.
		clusterCfgDownstream1 := config.ClusterConfig{
			Members: []string{
				"127.0.0.1:" + clusterPorts[0],
				"127.0.0.1:" + clusterPorts[1],
			},
			HashKey: "loremipsumdolors",
		}

		// cluster config copied for member 2.
		clusterCfgDownstream2 := clusterCfgDownstream1

		dctrl1, dctrl1BaseURL, destDir1, dstClient1 := makeInsecureDownstreamServerFixedPort(
			t, clusterPorts[0], syncConfig, &clusterCfgDownstream1)
		dctrl1Scm := test.NewControllerManager(dctrl1)

		dctrl2, dctrl2BaseURL, destDir2, dstClient2 := makeInsecureDownstreamServerFixedPort(
			t, clusterPorts[1], syncConfig, &clusterCfgDownstream2)
		dctrl2Scm := test.NewControllerManager(dctrl2)

		dctrl1Scm.StartAndWait(dctrl1.Config.HTTP.Port)
		defer dctrl1Scm.StopServer()

		dctrl2Scm.StartAndWait(dctrl2.Config.HTTP.Port)
		defer dctrl2Scm.StopServer()

		// verify that all servers are up.
		clients := []*resty.Client{srcClient, dstClient1, dstClient2}
		baseURLs := []string{srcBaseURL, dctrl1BaseURL, dctrl2BaseURL}

		for clientIdx, client := range clients {
			resp, err := client.R().Get(baseURLs[clientIdx] + "/v2/")
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
		}

		// storage for each downstream should not have image data at the start.
		destDirs := []string{destDir1, destDir2}
		images := []string{testImage, testCveImage}

		for _, image := range images {
			for _, destDir := range destDirs {
				_, err := os.Stat(path.Join(destDir, image))
				So(err, ShouldNotBeNil)
				So(os.IsNotExist(err), ShouldBeTrue)
			}
		}

		repos := []string{testImage, testCveImage}

		// tags list for both images should return 404 at the start.
		// only hit one instance as the request will get proxied anyway.
		for _, repo := range repos {
			resp, err := dstClient1.R().Get(
				fmt.Sprintf("%s/v2/%s/tags/list", dctrl1BaseURL, repo),
			)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		}

		// should not sync zot-test image when trying to load manifest.
		// only hit one instance as the request will get proxied anyway.
		resp, err := dstClient1.R().Get(
			fmt.Sprintf("%s/v2/%s/manifests/%s", dctrl1BaseURL, testImage, testImageTag),
		)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// should not sync test vulnerable image when trying to check manifest.
		// check manifest is hit with a HEAD or OPTIONS request.
		resp, err = dstClient1.R().Head(
			fmt.Sprintf("%s/v2/%s/manifests/%s", dctrl1BaseURL, testCveImage, testImageTag),
		)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

		// tags list for both images should return 404 after the sync as well.
		// only hit one instance as the request will get proxied anyway.
		for _, repo := range repos {
			resp, err := dstClient1.R().Get(
				fmt.Sprintf("%s/v2/%s/tags/list", dctrl1BaseURL, repo),
			)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
		}

		// storage for neither downstream should have the data for images.
		// with loremipsumdolors as the hashKey,
		// zot-test is managed by member index 1.
		// zot-cve-test is managed by member index 0.
		for _, repo := range repos {
			for _, destDir := range destDirs {
				_, err = os.Stat(path.Join(destDir, repo))
				So(err, ShouldNotBeNil)
				So(os.IsNotExist(err), ShouldBeTrue)
			}
		}
	})
}

func TestSyncReferenceInLoop(t *testing.T) {
	Convey("Verify sync doesn't end up in an infinite loop when syncing image references", t, func() {
		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)

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
		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)

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
	testCases := []struct {
		name           string
		preserveDigest bool
	}{
		{
			name:           "preserveDigest and compat docker2s2 enabled",
			preserveDigest: true,
		},
		{
			name:           "preserve digest and compat docker2s2 disabled",
			preserveDigest: false,
		},
	}

	for _, testCase := range testCases {
		Convey("Verify docker images are skipped when they are already synced, preserveDigest: "+testCase.name, t, func() {
			updateDuration, _ := time.ParseDuration("30m")

			sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)

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
				URLs:           []string{srcBaseURL},
				PollInterval:   updateDuration,
				TLSVerify:      &tlsVerify,
				CertDir:        "",
				MaxRetries:     &maxRetries,
				OnDemand:       true,
				RetryDelay:     &delay,
				PreserveDigest: testCase.preserveDigest,
			}

			defaultVal := true
			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, destDir, _ := makeDownstreamServer(t, false, syncConfig)

			if testCase.preserveDigest {
				dctlr.Config.HTTP.Compat = append(dctlr.Config.HTTP.Compat, "docker2s2")
			}

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

					manifest.MediaType = dockerManifestMediaType
					manifest.Config.MediaType = dockerManifestConfigMediaType
					index.Manifests[idx].MediaType = dockerManifestMediaType

					for idx := range manifest.Layers {
						manifest.Layers[idx].MediaType = dockerLayerMediaType
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

				// trigger not found
				resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + "1.9")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

				// trigger config blob upstream error
				// remove synced image
				err = os.RemoveAll(path.Join(destDir, testImage))
				So(err, ShouldBeNil)

				configBlobPath := path.Join(srcDir, testImage, "blobs/sha256", configBlobDigest.Encoded())
				err = os.Chmod(configBlobPath, 0o000)
				So(err, ShouldBeNil)

				defer func() {
					_ = os.Chmod(configBlobPath, storageConstants.DefaultFilePerms)
				}()

				resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
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

				var (
					configBlobDigest     godigest.Digest
					indexManifestContent []byte
				)

				for idx, manifestDesc := range newIndex.Manifests {
					if manifestDesc.MediaType == ispec.MediaTypeImageManifest {
						manifestContent, err := os.ReadFile(path.Join(srcDir, indexRepoName, "blobs/sha256",
							manifestDesc.Digest.Encoded()))
						So(err, ShouldBeNil)

						var manifest ispec.Manifest

						err = json.Unmarshal(manifestContent, &manifest)
						So(err, ShouldBeNil)

						configBlobDigest = manifest.Config.Digest

						manifest.MediaType = dockerManifestMediaType
						manifest.Config.MediaType = dockerManifestConfigMediaType
						newIndex.Manifests[idx].MediaType = dockerManifestMediaType
						indexManifest.Manifests[idx].MediaType = dockerManifestMediaType

						for idx := range manifest.Layers {
							manifest.Layers[idx].MediaType = dockerLayerMediaType
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

					indexManifest.MediaType = dockerIndexManifestMediaType
					// write converted multi arch manifest
					indexManifestContent, err = json.Marshal(indexManifest)
					So(err, ShouldBeNil)

					err = os.WriteFile(path.Join(srcDir, indexRepoName, "blobs/sha256",
						godigest.FromBytes(indexManifestContent).Encoded()), indexManifestContent, storageConstants.DefaultFilePerms)
					So(err, ShouldBeNil)
				}

				newIndex.Manifests[indexManifestIdx].MediaType = dockerIndexManifestMediaType
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

				// trigger not found
				resp, err = resty.R().Get(destBaseURL + "/v2/" + indexRepoName + "/manifests/" + "1.9")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)

				// trigger config blob upstream error
				// remove synced image
				err = os.RemoveAll(path.Join(destDir, indexRepoName))
				So(err, ShouldBeNil)

				configBlobPath := path.Join(srcDir, indexRepoName, "blobs/sha256", configBlobDigest.Encoded())
				err = os.Chmod(configBlobPath, 0o000)
				So(err, ShouldBeNil)

				defer func() {
					_ = os.Chmod(configBlobPath, storageConstants.DefaultFilePerms)
				}()

				resp, err = resty.R().Get(destBaseURL + "/v2/" + indexRepoName + "/manifests/" + "latest")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusNotFound)
			})
		})
	}
}

func TestPeriodically(t *testing.T) {
	Convey("Verify sync feature", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, false)

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

		var (
			srcTagsList  TagsList
			destTagsList TagsList
		)

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
				MaxRetries:   &maxRetries,
			}

			syncConfig := &syncconf.Config{
				Enable:     &defaultVal,
				Registries: []syncconf.RegistryConfig{syncRegistryConfig},
			}

			dctlr, destBaseURL, _, destClient := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			var (
				srcTagsList  TagsList
				destTagsList TagsList
			)

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

func TestPeriodicallyWithScaleOutCluster(t *testing.T) {
	Convey("Given a zot cluster with periodic sync enabled, test that instances sync only managed repos", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		const zotAlpineTestImageName = "zot-alpine-test"

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// upload additional image to the upstream.
		// upload has to be done before starting the downstreams.
		sampleImage := CreateRandomImage()
		err := UploadImage(sampleImage, srcBaseURL, zotAlpineTestImageName, "0.0.1")
		So(err, ShouldBeNil)

		tlsVerify := false
		maxRetries := 2
		delay := 2 * time.Second

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: zotAlpineTestImageName,
				},
				{
					Prefix: testImage,
				},
				{
					Prefix: testCveImage,
				},
			},
			URLs:         []string{srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			MaxRetries:   &maxRetries,
			RetryDelay:   &delay,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		// add scale out cluster config.
		// we don't need to start multiple downstream instances as we want to just check that
		// a given downstream instance skips images that it does not manage.

		// with loremipsumdolors as the hashKey,
		// zot-test is managed by member index 1.
		// zot-cve-test is managed by member index 0.
		// zot-alpine-test is managed by member index 1.

		// Get dynamic ports for cluster members
		clusterPorts := test.GetFreePorts(2)

		clusterCfg := config.ClusterConfig{
			Members: []string{
				"127.0.0.1:" + clusterPorts[0],
				"127.0.0.1:" + clusterPorts[1],
			},
			HashKey: "loremipsumdolors",
		}

		dctlr, destBaseURL, destDir, destClient := makeInsecureDownstreamServerFixedPort(t,
			clusterPorts[1], syncConfig, &clusterCfg)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)

		defer dcm.StopServer()

		// downstream should not have any of the images in its storage.
		images := []string{testImage, testCveImage, zotAlpineTestImageName}

		for _, image := range images {
			_, err := os.Stat(path.Join(destDir, image))
			So(err, ShouldNotBeNil)
			So(os.IsNotExist(err), ShouldBeTrue)
		}

		// wait for generator to complete.
		waitSyncFinish(dctlr.Config.Log.Output)

		// downstream should sync only expected images from the upstream.
		expectedImages := []string{zotAlpineTestImageName, testImage}

		for _, expected := range expectedImages {
			for {
				resp, err := destClient.R().Get(fmt.Sprintf("%s/v2/%s/tags/list", destBaseURL, expected))
				So(err, ShouldBeNil)

				var destTagsList TagsList

				err = json.Unmarshal(resp.Body(), &destTagsList)
				So(err, ShouldBeNil)

				if len(destTagsList.Tags) > 0 {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}
		}

		// only the zot-test and zot-alpine-test images should be downloaded.
		for _, expected := range expectedImages {
			_, err = os.Stat(path.Join(destDir, expected))
			So(err, ShouldBeNil)
		}

		// the test cve image should not be downloaded.
		_, err = os.Stat(path.Join(destDir, testCveImage))
		So(err, ShouldNotBeNil)
		So(os.IsNotExist(err), ShouldBeTrue)
	})
}

func TestPermsDenied(t *testing.T) {
	Convey("Verify sync feature without perm on sync cache", t, func() {
		updateDuration, _ := time.ParseDuration("30m")

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			MaxRetries:   &maxRetries,
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

		// Ensure permissions are restored on cleanup to allow temp directory removal
		defer func() {
			_ = os.Chmod(syncSubDir, 0o755)
			// Also restore permissions on parent directory in case it was affected
			_ = os.Chmod(path.Join(destDir, testImage), 0o755)
		}()

		dcm.StartAndWait(destPort)

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"failed to sync image", 50*time.Second)
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
		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)
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
			MaxRetries:   &maxRetries,
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

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		destConfig.Log.Output = logPath

		dctlr := api.NewController(destConfig)

		//nolint: dupl
		Convey("Reload config without sync", func() {
			content := fmt.Sprintf(`{"distSpecVersion": "1.1.1", "storage": {"rootDirectory": "%s"},
			"http": {"address": "127.0.0.1", "port": "%s"},
			"log": {"level": "debug", "output": "%s"}}`, destDir, destPort, logPath)

			cfgfile := test.MakeTempFile(t, "zot-test.json")
			defer cfgfile.Close()

			_, err := cfgfile.WriteString(content)
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

			data, err := os.ReadFile(logPath)
			t.Logf("downstream log: %s", string(data))
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring, "reloaded params")
			So(string(data), ShouldContainSubstring, "new configuration settings")
			So(string(data), ShouldContainSubstring, "\"Extensions\":null")

			// reload config from extensions nil to sync
			content = fmt.Sprintf(`{
				"distSpecVersion": "1.1.1",
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
			}`, destDir, destPort, logPath)

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

			data, err = os.ReadFile(logPath)
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
				"distSpecVersion": "1.1.1",
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
			}`, destDir, destPort, logPath)

			cfgfile := test.MakeTempFile(t, "zot-test.json")
			defer cfgfile.Close()

			_, err := cfgfile.WriteString(content)
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

			data, err := os.ReadFile(logPath)
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		regex := ".*"
		tlsVerify := false

		var semver bool

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
			MaxRetries:   &maxRetries,
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

		logPath := test.MakeTempFilePath(t, "zot-log.txt")

		destConfig.Log.Output = logPath

		lintEnable := true
		destConfig.Extensions.Lint = &extconf.LintConfig{}
		destConfig.Extensions.Lint.Enable = &lintEnable
		destConfig.Extensions.Lint.MandatoryAnnotations = []string{"annot1", "annot2", "annot3"}

		dctlr := api.NewController(destConfig)
		dcm := test.NewControllerManager(dctlr)

		dcm.StartAndWait(destPort)

		defer dcm.StopServer()

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"failed to upload manifest because of missing annotations", 15*time.Second)
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, true, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		regex := ".*"
		tlsVerify := true

		var semver bool

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
			MaxRetries:   &maxRetries,
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
			"tls: failed to verify certificate: x509: certificate signed by unknown authority", 40*time.Second)
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

		// Generate shared CA and certificates BEFORE creating servers
		// This ensures all certificates are signed by the same CA
		sharedCertDir := t.TempDir()
		caCertPath, _, _, clientCertPath, clientKeyPath, caCertPEM := setupTestCertsForSync(t, sharedCertDir)

		// Create upstream server with shared certificates
		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServerWithCerts(t, true, false, sharedCertDir, caCertPEM)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		var (
			srcIndex  ispec.Index
			destIndex ispec.Index
		)

		srcBuf, err := os.ReadFile(path.Join(srcDir, testImage, "index.json"))
		if err != nil {
			panic(err)
		}

		if err := json.Unmarshal(srcBuf, &srcIndex); err != nil {
			panic(err)
		}

		// Use the same client certificates for sync (signed by the same CA as upstream server)
		destClientCertDir := t.TempDir()
		// Copy client cert and key to sync config directory
		destClientCertPath := path.Join(destClientCertDir, "client.cert")
		destClientKeyPath := path.Join(destClientCertDir, "client.key")
		destCACertPath := path.Join(destClientCertDir, "ca.crt")

		clientCertData, err := os.ReadFile(clientCertPath)
		if err != nil {
			t.Fatalf("Failed to read client cert: %v", err)
		}
		clientKeyData, err := os.ReadFile(clientKeyPath)
		if err != nil {
			t.Fatalf("Failed to read client key: %v", err)
		}
		caCertData, err := os.ReadFile(caCertPath)
		if err != nil {
			t.Fatalf("Failed to read CA cert: %v", err)
		}

		err = os.WriteFile(destClientCertPath, clientCertData, 0o600)
		if err != nil {
			t.Fatalf("Failed to write client cert: %v", err)
		}
		err = os.WriteFile(destClientKeyPath, clientKeyData, 0o600)
		if err != nil {
			t.Fatalf("Failed to write client key: %v", err)
		}
		err = os.WriteFile(destCACertPath, caCertData, 0o600)
		if err != nil {
			t.Fatalf("Failed to write CA cert: %v", err)
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
			MaxRetries:   &maxRetries,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		// Create downstream server with shared certificates (same CA as upstream)
		dctlr, destBaseURL, destDir, destClient := makeDownstreamServerWithCerts(
			t, true, syncConfig, sharedCertDir, caCertPEM)

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

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestBearerAuth(t *testing.T) {
	Convey("Verify periodically sync bearer auth", t, func() {
		updateDuration, _ := time.ParseDuration("1h")
		// a repo for which clients do not have access, sync shouldn't be able to sync it
		unauthorizedNamespace := testCveImage

		// Generate certificates for bearer auth
		tempDir := t.TempDir()
		_, serverCertPath, serverKeyPath, _, _, _ := setupTestCertsForSync(t, tempDir)

		authTestServer := authutils.MakeAuthTestServer(serverKeyPath, "RS256", unauthorizedNamespace)
		defer authTestServer.Close()

		sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, false)

		aurl, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		sctlr.Config.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    serverCertPath,
				Realm:   authTestServer.URL + "/auth/token",
				Service: aurl.Host,
			},
		}

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		registryName := sync.StripRegistryTransport(srcBaseURL)
		credentialsFile := makeCredentialsFile(t.TempDir(), fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
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
			MaxRetries:   &maxRetries,
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

		var (
			srcTagsList  TagsList
			destTagsList TagsList
		)

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
			SetHeader("Authorization", "Bearer "+goodToken.AccessToken).
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

		resp, err = srcClient.R().SetHeader("Authorization", "Bearer "+goodToken.AccessToken).
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

		// Generate certificates for bearer auth
		tempDir := t.TempDir()
		_, serverCertPath, serverKeyPath, _, _, _ := setupTestCertsForSync(t, tempDir)

		authTestServer := authutils.MakeAuthTestServer(serverKeyPath, "RS256", unauthorizedNamespace)
		defer authTestServer.Close()

		sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, false)

		aurl, err := url.Parse(authTestServer.URL)
		So(err, ShouldBeNil)

		sctlr.Config.HTTP.Auth = &config.AuthConfig{
			Bearer: &config.BearerConfig{
				Cert:    serverCertPath,
				Realm:   authTestServer.URL + "/auth/token",
				Service: aurl.Host,
			},
		}

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		registryName := sync.StripRegistryTransport(srcBaseURL)
		credentialsFile := makeCredentialsFile(t.TempDir(), fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
			registryName, username, password))

		var tlsVerify bool

		syncRegistryConfig := syncconf.RegistryConfig{
			Content: []syncconf.Content{
				{
					Prefix: "**", // sync everything
				},
			},
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			OnDemand:   true,
			CertDir:    "",
			MaxRetries: &maxRetries,
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

		var (
			srcTagsList  TagsList
			destTagsList TagsList
		)

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
			SetHeader("Authorization", "Bearer "+goodToken.AccessToken).
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

		resp, err = srcClient.R().SetHeader("Authorization", "Bearer "+goodToken.AccessToken).
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
			sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, true)

			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			registryName := sync.StripRegistryTransport(srcBaseURL)
			credentialsFile := makeCredentialsFile(t.TempDir(), fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
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
				MaxRetries:   &maxRetries,
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

			var (
				srcTagsList  TagsList
				destTagsList TagsList
			)

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
			sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, true)

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

			credentialsFile := makeCredentialsFile(t.TempDir(), fmt.Sprintf(`{"%s":{"username": "%s", "password": "invalid"}}`,
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
				MaxRetries:   &maxRetries,
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
				"unauthorized", 15*time.Second)
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
			sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, true)

			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			registryName := sync.StripRegistryTransport(srcBaseURL)

			credentialsFile := makeCredentialsFile(t.TempDir(), fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
				registryName, username, password))

			err := os.Chmod(credentialsFile, 0o000)
			So(err, ShouldBeNil)

			defer func() {
				So(os.Chmod(credentialsFile, 0o755), ShouldBeNil)
				So(os.RemoveAll(credentialsFile), ShouldBeNil)
			}()

			regex := ".*"

			var (
				semver    bool
				tlsVerify bool
			)

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
			sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, true)

			scm := test.NewControllerManager(sctlr)
			scm.StartAndWait(sctlr.Config.HTTP.Port)
			defer scm.StopServer()

			registryName := sync.StripRegistryTransport(srcBaseURL)
			credentialsFile := makeCredentialsFile(t.TempDir(), fmt.Sprintf(`{"%s":{"username": "%s", "password": "%s"}}`,
				registryName, username, password))

			defaultValue := false
			syncRegistryConfig := syncconf.RegistryConfig{
				URLs:       []string{srcBaseURL},
				TLSVerify:  &defaultValue,
				OnDemand:   true,
				MaxRetries: &maxRetries,
			}

			unreacheableSyncRegistryConfig1 := syncconf.RegistryConfig{
				URLs:       []string{"localhost:9999"},
				OnDemand:   true,
				MaxRetries: &maxRetries,
			}

			unreacheableSyncRegistryConfig2 := syncconf.RegistryConfig{
				URLs:       []string{"localhost:9999"},
				OnDemand:   false,
				MaxRetries: &maxRetries,
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

			var (
				srcTagsList  TagsList
				destTagsList TagsList
			)

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

		var (
			semver    bool
			tlsVerify bool
		)

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
			MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, true, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// copy client certs, use them in sync config
		clientCertDir := t.TempDir()

		// Generate certificates
		caCertPath, _, _, _, _, _ := setupTestCertsForSync(t, clientCertDir)

		// Modify the CA cert file to add invalid text for testing
		dstfile, err := os.OpenFile(caCertPath, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			panic(err)
		}

		defer dstfile.Close()

		if _, err = dstfile.WriteString("Add Invalid Text In Cert"); err != nil {
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
			MaxRetries:   &maxRetries,
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
		// Generate certificates and copy them to sync config directory
		clientCertDir := t.TempDir()

		caCertPath, _, _, _, _, _ := setupTestCertsForSync(t, clientCertDir)

		// Change permissions on CA cert for testing
		err := os.Chmod(caCertPath, 0o000)
		So(err, ShouldBeNil)

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
			MaxRetries:   &maxRetries,
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

func makeCredentialsFile(tempDir string, fileContent string) string {
	tmpfile, err := os.Create(filepath.Join(tempDir, "sync-credentials.json"))
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

		var (
			semver    bool
			tlsVerify bool
		)

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
			MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		regex := ".*"

		var (
			semver    bool
			tlsVerify bool
		)

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
			MaxRetries:   &maxRetries,
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
		srcStorageCtlr := ociutils.GetDefaultStoreController(path.Join(srcDir, subpath), log.NewTestLogger())

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

		var (
			semver    bool
			tlsVerify bool
		)

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
			MaxRetries:   &maxRetries,
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
			URLs:       []string{"docker://invalid"},
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			OnDemand:   true,
			MaxRetries: &maxRetries,
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
		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		Convey("Test image is filtered out by content", func() {
			regex := ".*"

			var (
				semver    bool
				tlsVerify bool
			)

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
				URLs:       []string{srcBaseURL},
				TLSVerify:  &tlsVerify,
				CertDir:    "",
				OnDemand:   true,
				MaxRetries: &maxRetries,
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
				URLs:       []string{srcBaseURL},
				TLSVerify:  &tlsVerify,
				CertDir:    "",
				OnDemand:   true,
				MaxRetries: &maxRetries,
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
		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		Convey("Test periodically sync is disabled when pollInterval is not set", func() {
			regex := ".*"

			var (
				semver    bool
				tlsVerify bool
			)

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
				URLs:       []string{srcBaseURL},
				TLSVerify:  &tlsVerify,
				CertDir:    "",
				OnDemand:   false,
				MaxRetries: &maxRetries,
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
				MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, _, srcClient := makeUpstreamServer(t, false, false)

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
			URLs:         []string{"http://badURL", srcBaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
			MaxRetries:   &maxRetries,
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

		var (
			srcTagsList  TagsList
			destTagsList TagsList
		)

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
			MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// create repo, push and sign it
		var digest godigest.Digest

		repoName := testSignedImage

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

		var (
			semver    bool
			tlsVerify bool
		)

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
			MaxRetries:   &maxRetries,
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
				"failed to get upstream image manifest details", 60*time.Second)
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
				"failed to sync image", 60*time.Second)
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
				"failed to sync image", 30*time.Second)
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
		})

		Convey("Trigger error on oci ref", func() {
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

					break
				}
			}

			// start downstream server
			updateDuration, err = time.ParseDuration("10m")
			So(err, ShouldBeNil)
			retries := 1
			syncConfig.Registries[0].PollInterval = updateDuration
			syncConfig.Registries[0].MaxRetries = &retries
			// syncConfig.Registries[0].OnDemand = false

			// start downstream server
			dctlr, destBaseURL, _, _ := makeDownstreamServer(t, false, syncConfig)

			dcm := test.NewControllerManager(dctlr)
			dcm.StartAndWait(dctlr.Config.HTTP.Port)
			defer dcm.StopServer()

			found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
				"failed to sync image", 30*time.Second)
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
		})
	})
}

func TestSignatures(t *testing.T) {
	Convey("Verify sync signatures", t, func() {
		updateDuration, _ := time.ParseDuration("1m")

		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)

		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// create repo, push and sign it
		var digest godigest.Digest

		repoName := testSignedImage

		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]
		t.Logf("%s", srcPort)
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

		sbomManifestBlob := resp.Body()
		sbomDigest := godigest.FromBytes(sbomManifestBlob)

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
				Size:      int64(len(sbomManifestBlob)),
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

		var (
			semver    bool
			tlsVerify bool
		)

		onlySigned := true

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
			OnlySigned:   &onlySigned,
			OnDemand:     true,
			MaxRetries:   &maxRetries,
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

		// sync image with all its refs
		resp, err = destClient.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		splittedURL = strings.SplitAfter(destBaseURL, ":")
		destPort := splittedURL[len(splittedURL)-1]

		time.Sleep(5 * time.Second)

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
		syncedSbomManifestBlob := resp.Body()
		So(godigest.FromBytes(syncedSbomManifestBlob), ShouldEqual, sbomDigest)

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

		foundOCIRef := false

		for _, manifest := range index.Manifests {
			if manifest.Digest == ociRefDigest {
				foundOCIRef = true

				break
			}
		}

		So(foundOCIRef, ShouldBeTrue)

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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// create repo, push and sign it
		var digest godigest.Digest

		repoName := testSignedImage

		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]
		t.Logf("%s", srcPort)

		err := signature.SignImageUsingCosign(fmt.Sprintf("%s@%s", repoName, digest.String()), srcPort, true)
		So(err, ShouldBeNil)

		regex := ".*"

		var (
			semver    bool
			tlsVerify bool
		)

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
			MaxRetries:   &maxRetries,
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

		// Create source registry

		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)
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
					URLs:      []string{srcBaseURL},
					TLSVerify: &tlsVerify,
					CertDir:   "",
					OnDemand:  true,
				},
			},
		}

		dctlr, destBaseURL, dstDir, _ := makeDownstreamServer(t, false, syncConfig)
		t.Log(dstDir)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)

		defer dcm.StopServer()

		// trigger SyncOnDemand
		resp, err := resty.R().Get(destBaseURL + "/v2/" + repoName + "/manifests/" + tag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		digest := resp.Header().Get("Docker-Content-Digest")

		// trigger SyncReferrers
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/referrers/" + digest)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		// regclient will put all referrers under ref tag "alg-subjectDigest"
		repoMeta, err := dctlr.MetaDB.GetRepoMeta(context.Background(), repoName)
		So(err, ShouldBeNil)
		So(repoMeta.Tags, ShouldContainKey, tag)
		// one tag for refs and the tag we pushed earlier
		So(len(repoMeta.Tags), ShouldEqual, 2)
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

		srcStorageCtlr := ociutils.GetDefaultStoreController(srcDir, log.NewTestLogger())

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
			"successfully synced image", 60*time.Second)
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
		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			URLs:       []string{srcBaseURL},
			OnDemand:   true,
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			MaxRetries: &maxRetries,
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
			URLs:       []string{"http://127.0.0.1"},
			OnDemand:   true,
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			MaxRetries: &maxRetries,
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
			"failed to sync image", 15*time.Second)
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

		srcStorageCtlr := ociutils.GetDefaultStoreController(srcDir, log.NewTestLogger())

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
		for range callsNo {
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

		// waitSync(destDir, testImage)

		So(len(populatedDirs), ShouldEqual, 1)

		resp, err := destClient.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)
	})
}

func TestOnDemandPullsReferrersOnce(t *testing.T) {
	Convey("Verify sync on demand pulls only one time", t, func(conv C) {
		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			OnDemand:   true,
			MaxRetries: &maxRetries,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		// get digest for target image
		resp, err := resty.R().Get(srcBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		digest := resp.Header().Get("Docker-Content-Digest")

		// add OCI Ref
		_ = pushBlob(srcBaseURL, testImage, ispec.DescriptorEmptyJSON.Data)

		OCIRefManifest := ispec.Manifest{
			Versioned: specs.Versioned{
				SchemaVersion: 2,
			},
			Subject: &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.Digest(digest),
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

		refURL := srcBaseURL + "/v2/" + testImage + "/manifests/oci.ref"
		resp, err = resty.R().
			SetHeader("Content-type", ispec.MediaTypeImageManifest).
			SetBody(OCIRefManifestBlob).
			Put(refURL)

		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusCreated)

		dctlr, destBaseURL, destDir, _ := makeDownstreamServer(t, false, syncConfig)

		dcm := test.NewControllerManager(dctlr)
		dcm.StartAndWait(dctlr.Config.HTTP.Port)

		defer dcm.StopServer()

		var wg goSync.WaitGroup

		// sync image
		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		numConcurrentRequests := 5
		wg.Add(numConcurrentRequests)

		targetURL := destBaseURL + "/v2/" + testImage + "/referrers/" + digest

		for i := range numConcurrentRequests {
			go func(routineID int) {
				defer wg.Done()
				t.Logf("Goroutine %d: Sending request to %s", routineID, targetURL)

				resp, err := resty.R().Get(targetURL)
				if err != nil {
					t.Errorf("Goroutine %d: Request failed: %v", routineID, err)

					return
				}

				if resp.StatusCode() != http.StatusOK {
					t.Errorf("Goroutine %d: Expected status %d, got %d. Body: %s",
						routineID, http.StatusOK, resp.StatusCode(), resp.String())
				}
			}(i)
		}

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

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"referrers for image already demanded", 10*time.Second)
		if err != nil {
			panic(err)
		}

		if !found {
			data, err := os.ReadFile(dctlr.Config.Log.Output)
			So(err, ShouldBeNil)

			t.Logf("downstream log: %s", string(data))
		}

		So(found, ShouldBeTrue)

		// check that referrers are synced
		resp, err = resty.R().Get(destBaseURL + "/v2/" + testImage + "/referrers/" + digest)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		var index ispec.Index

		err = json.Unmarshal(resp.Body(), &index)
		So(err, ShouldBeNil)

		So(len(index.Manifests), ShouldEqual, 1)
	})
}

func TestOnDemandPullsOnce(t *testing.T) {
	Convey("Verify sync on demand pulls only one time", t, func(conv C) {
		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			OnDemand:   true,
			MaxRetries: &maxRetries,
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

		numConcurrentRequests := 5
		wg.Add(numConcurrentRequests)

		targetURL := destBaseURL + "/v2/" + testImage + "/manifests/" + testImageTag

		for i := range numConcurrentRequests {
			go func(routineID int) {
				defer wg.Done()
				t.Logf("Goroutine %d: Sending request to %s", routineID, targetURL)

				resp, err := resty.R().Get(targetURL)
				if err != nil {
					t.Errorf("Goroutine %d: Request failed: %v", routineID, err)

					return
				}

				if resp.StatusCode() != http.StatusOK {
					t.Errorf("Goroutine %d: Expected status %d, got %d. Body: %s",
						routineID, http.StatusOK, resp.StatusCode(), resp.String())
				}
			}(i)
		}

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

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"image already demanded", 10*time.Second)
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

func TestSignaturesOnDemand(t *testing.T) {
	Convey("Verify sync signatures on demand feature", t, func() {
		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// create repo, push and sign it
		var digest godigest.Digest

		repoName := testSignedImage

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
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			OnDemand:   true,
			MaxRetries: &maxRetries,
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
		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// create repo, push and sign it
		var digest godigest.Digest

		repoName := testSignedImage

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
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			OnDemand:   true,
			MaxRetries: &maxRetries,
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

		subjectDigest := resp.Header().Get("Docker-Content-Digest")

		// trigger SyncReferrers
		resp, err = resty.R().Get(destBaseURL + "/v2/" + repoName + "/referrers/" + subjectDigest)
		So(err, ShouldBeNil)
		So(resp.StatusCode(), ShouldEqual, http.StatusOK)

		found, err := test.ReadLogFileAndSearchString(dctlr.Config.Log.Output,
			"failed to sync referrer", 15*time.Second)
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
		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// create repo, push and sign it
		var digest godigest.Digest

		repoName := testSignedImage

		So(func() { digest = pushRepo(srcBaseURL, repoName) }, ShouldNotPanic)

		splittedURL := strings.SplitAfter(srcBaseURL, ":")
		srcPort := splittedURL[len(splittedURL)-1]

		cwd, err := os.Getwd()
		So(err, ShouldBeNil)

		defer func() { _ = os.Chdir(cwd) }()
		tdir := t.TempDir()
		_ = os.Chdir(tdir)

		var tlsVerify bool

		retries := 0

		syncRegistryConfig := syncconf.RegistryConfig{
			URLs:       []string{srcBaseURL},
			TLSVerify:  &tlsVerify,
			CertDir:    "",
			OnDemand:   true,
			MaxRetries: &retries,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable: &defaultVal,
			Registries: []syncconf.RegistryConfig{
				syncRegistryConfig,
			},
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			MaxRetries:   &maxRetries,
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
		destStorageCtrl := ociutils.GetDefaultStoreController(destDir, log.NewTestLogger())

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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
			MaxRetries:   &maxRetries,
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
		srcStorageCtlr := ociutils.GetDefaultStoreController(destDir, log.NewTestLogger())

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
			SetHeader("Content-Length", strconv.Itoa(len(blob))).
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

		sctlr, srcBaseURL, srcDir, _ := makeUpstreamServer(t, false, false)
		defer os.RemoveAll(srcDir)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		// create repo, push and sign it
		var digest godigest.Digest

		repoName := testSignedImage

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

		var (
			semver    bool
			tlsVerify bool
		)

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
			MaxRetries:   &maxRetries,
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

		time.Sleep(15 * time.Second)

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
		time.Sleep(15 * time.Second)

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
		var (
			srcIndex  ispec.Index
			destIndex ispec.Index
		)

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
		var (
			upstreamRefsDigests   []string
			downstreamRefsDigests []string
			manifestDigest        string
		)

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
			"skipping image because it's already synced", 30*time.Second)
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
			"skipping image because it's already synced", 30*time.Second)
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

	sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false) //nolint: dogsled

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
		MaxRetries:   &maxRetries,
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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

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
					MaxRetries:   &maxRetries,
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

				time.Sleep(2 * time.Second)

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
					Content:    []syncconf.Content{testCase.content},
					URLs:       []string{srcBaseURL},
					OnDemand:   true,
					TLSVerify:  &tlsVerify,
					MaxRetries: &maxRetries,
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

				subjectDigest := resp.Header().Get("Docker-Content-Digest")

				// trigger SyncReferrers
				resp, err = resty.R().Get(destBaseURL + "/v2/" + testCase.expected + "/referrers/" + subjectDigest)
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)

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

		sctlr, srcBaseURL, _, _ := makeUpstreamServer(t, false, false)

		scm := test.NewControllerManager(sctlr)
		scm.StartAndWait(sctlr.Config.HTTP.Port)

		defer scm.StopServer()

		regex := ".*"
		tlsVerify := false

		var semver bool

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
			MaxRetries:   &maxRetries,
		}

		defaultVal := true
		syncConfig := &syncconf.Config{
			Enable:     &defaultVal,
			Registries: []syncconf.RegistryConfig{syncRegistryConfig},
		}

		Convey("single index", func() {
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

		Convey("index referencing other index", func() {
			rootMultiarchImage := CreateMultiarchWith().Images(
				[]Image{
					CreateRandomImage(),
					CreateRandomImage(),
					CreateRandomImage(),
					CreateRandomImage(),
				},
			).Build()

			childMultiarchImage := CreateMultiarchWith().Images(
				[]Image{
					CreateRandomImage(),
					CreateRandomImage(),
					CreateRandomImage(),
					CreateRandomImage(),
				},
			).Build()

			childOfChildMultiarchImage := CreateMultiarchWith().Images(
				[]Image{
					CreateRandomImage(),
					CreateRandomImage(),
				},
			).Build()

			err := UploadMultiarchImage(childOfChildMultiarchImage, srcBaseURL, "index", "childofchild")
			So(err, ShouldBeNil)

			childMultiarchImage.Index.Manifests = append(childMultiarchImage.Index.Manifests,
				childOfChildMultiarchImage.IndexDescriptor)
			childMultiarchImage.IndexDescriptor.Data = nil

			err = UploadMultiarchImage(childMultiarchImage, srcBaseURL, "index", "child")
			So(err, ShouldBeNil)

			resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(srcBaseURL + "/v2/index/manifests/childofchild")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(srcBaseURL + "/v2/index/manifests/child")
			So(err, ShouldBeNil)
			So(resp.StatusCode(), ShouldEqual, http.StatusOK)
			So(resp.Body(), ShouldNotBeEmpty)
			So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

			childMultiarchImage.IndexDescriptor.Digest = godigest.FromBytes(resp.Body())

			rootMultiarchImage.Index.Manifests = append(rootMultiarchImage.Index.Manifests, childMultiarchImage.IndexDescriptor)
			rootMultiarchImage.IndexDescriptor.Data = nil

			// upload the previously defined images
			err = UploadMultiarchImage(rootMultiarchImage, srcBaseURL, "index", "root")
			So(err, ShouldBeNil)

			resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
				Get(srcBaseURL + "/v2/index/manifests/root")
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
					Get(destBaseURL + "/v2/index/manifests/root")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

				var rootIndex ispec.Index
				err := json.Unmarshal(resp.Body(), &rootIndex)
				So(err, ShouldBeNil)

				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(destBaseURL + "/v2/index/manifests/child")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

				var childIndex ispec.Index
				err = json.Unmarshal(resp.Body(), &childIndex)
				So(err, ShouldBeNil)

				resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(srcBaseURL + "/v2/index/manifests/childofchild")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

				var childOfChildIndex ispec.Index
				err = json.Unmarshal(resp.Body(), &childOfChildIndex)
				So(err, ShouldBeNil)

				So(reflect.DeepEqual(rootIndex, rootMultiarchImage.Index), ShouldEqual, true)
				So(reflect.DeepEqual(childIndex, childMultiarchImage.Index), ShouldEqual, true)
				So(reflect.DeepEqual(childOfChildIndex, childOfChildMultiarchImage.Index), ShouldEqual, true)

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
					Get(destBaseURL + "/v2/index/manifests/root")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

				var rootIndex ispec.Index
				err := json.Unmarshal(resp.Body(), &rootIndex)
				So(err, ShouldBeNil)

				resp, err = resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(destBaseURL + "/v2/index/manifests/child")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

				var childIndex ispec.Index
				err = json.Unmarshal(resp.Body(), &childIndex)
				So(err, ShouldBeNil)

				resp, err := resty.R().SetHeader("Content-Type", ispec.MediaTypeImageIndex).
					Get(srcBaseURL + "/v2/index/manifests/childofchild")
				So(err, ShouldBeNil)
				So(resp.StatusCode(), ShouldEqual, http.StatusOK)
				So(resp.Body(), ShouldNotBeEmpty)
				So(resp.Header().Get("Content-Type"), ShouldNotBeEmpty)

				var childOfChildIndex ispec.Index
				err = json.Unmarshal(resp.Body(), &childOfChildIndex)
				So(err, ShouldBeNil)

				So(reflect.DeepEqual(rootIndex, rootMultiarchImage.Index), ShouldEqual, true)
				So(reflect.DeepEqual(childIndex, childMultiarchImage.Index), ShouldEqual, true)
				So(reflect.DeepEqual(childOfChildIndex, childOfChildMultiarchImage.Index), ShouldEqual, true)
			})
		})
	})
}

func TestECRCredentialsHelper(t *testing.T) {
	Convey("Test ECR Credentials Helper", t, func() {
		// use getMockECRCredentials for testing purposes
		credentialHelper := sync.NewECRCredentialHelper(log.NewTestLogger(), sync.GetMockECRCredentials)
		url := "https://mockAccount.dkr.ecr.mockRegion.amazonaws.com"
		remoteAddress := sync.StripRegistryTransport(url)

		Convey("Test Credentials Retrieval & Validity", func() {
			creds, err := credentialHelper.GetCredentials([]string{url})
			So(err, ShouldBeNil)
			So(creds, ShouldNotBeNil)
			So(creds[remoteAddress].Username, ShouldEqual, "mockUsername")
			So(creds[remoteAddress].Password, ShouldEqual, "mockPassword")
			So(credentialHelper.AreCredentialsValid(remoteAddress), ShouldBeTrue)
		})

		Convey("Test Credentials Refresh", func() {
			_, err := credentialHelper.RefreshCredentials(remoteAddress)
			So(err, ShouldBeNil)
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
	err := sign.SignCmd(context.TODO(),
		&options.RootOptions{Verbose: true, Timeout: 1 * time.Minute},
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
		SetHeader("Content-Length", strconv.Itoa(len(cblob))).
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
		SetHeader("Content-Length", strconv.Itoa(len(cblob))).
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
		SetHeader("Content-Length", strconv.Itoa(len(buf))).
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
		"finished generating tasks to sync repositories", 60*time.Second)
	if err != nil {
		panic(err)
	}

	return found
}
