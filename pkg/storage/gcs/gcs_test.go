//go:build needprivileges && linux

package gcs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

//nolint:gochecknoglobals // test constants
const (
	repoName = "test"
	tag      = "0.0.1"
)

var (
	trueVal                  bool = true //nolint: gochecknoglobals
	errGCSMockEndpointNotSet      = errors.New("GCSMOCK_ENDPOINT must be set for GCS tests")
	errUnexpectedError            = errors.New("unexpected err")
	errBucketCreateFailed         = errors.New("failed to create bucket")
)

// httpsProxyServer manages an HTTPS proxy server on port 443.
type httpsProxyServer struct {
	server   *http.Server
	listener net.Listener
	wg       sync.WaitGroup
	target   string
	certFile string // Path to the certificate file for cleanup
}

// newHTTPSProxyServer creates a new HTTPS proxy server that forwards requests to the target.
func newHTTPSProxyServer(target string) (*httpsProxyServer, error) {
	// Generate self-signed certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "oauth2.googleapis.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"oauth2.googleapis.com", "www.googleapis.com", "storage.googleapis.com"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	// Write certificate to a temporary file so we can add it to the trusted certificates
	// via SSL_CERT_FILE environment variable. This is the standard way to add custom
	// trusted certificates and works with Go's crypto/x509 package, including OAuth2 clients.
	certFile, err := os.CreateTemp("", "gcs-test-cert-*.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp cert file: %w", err)
	}
	if _, err := certFile.Write(certPEM); err != nil {
		certFile.Close()
		os.Remove(certFile.Name())

		return nil, fmt.Errorf("failed to write cert to file: %w", err)
	}

	if err := certFile.Close(); err != nil {
		os.Remove(certFile.Name())

		return nil, fmt.Errorf("failed to close cert file: %w", err)
	}

	// Create proxy handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Build target URL
		targetURL := target + r.URL.Path
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}

		// Create request to target
		req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		// Copy headers
		for key, values := range r.Header {
			if key != "Host" && key != "Connection" {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}

		// Make request
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)

			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			if key != "Connection" && key != "Transfer-Encoding" {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
		}

		// Copy status and body
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	// Create HTTP server with TLS config (test-only proxy).
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	// Try to listen on port 443 (requires root or CAP_NET_BIND_SERVICE for tests).
	lc := net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", ":443") //nolint:gosec // G102: test proxy must listen on 443
	if err != nil {
		return nil, fmt.Errorf("failed to listen on port 443: %w (may require root or CAP_NET_BIND_SERVICE)", err)
	}

	tlsListener := tls.NewListener(listener, server.TLSConfig)

	return &httpsProxyServer{
		server:   server,
		listener: tlsListener,
		target:   target,
		certFile: certFile.Name(),
	}, nil
}

func (p *httpsProxyServer) Start() {
	p.wg.Add(1) //nolint:modernize // standard sync.WaitGroup usage

	go func() {
		defer p.wg.Done()
		_ = p.server.Serve(p.listener)
	}()
}

func (p *httpsProxyServer) Stop() {
	_ = p.listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.server.Shutdown(ctx)
	p.wg.Wait()
}

var httpsProxy *httpsProxyServer //nolint:gochecknoglobals // Test fixture shared by TestMain.

// setupHostsEntries adds entries to /etc/hosts to redirect Google API domains to localhost.
func setupHostsEntries() error {
	entries := []string{
		"127.0.0.1 www.googleapis.com",
		"127.0.0.1 storage.googleapis.com",
		"127.0.0.1 oauth2.googleapis.com",
	}

	for _, entry := range entries {
		// Check if entry already exists.
		//nolint:gosec // G204: test-only, fixed entries
		cmd := exec.CommandContext(context.Background(), "grep", "-q", strings.Fields(entry)[1], "/etc/hosts")
		if cmd.Run() == nil {
			// Entry already exists, skip
			continue
		}

		// Add entry (requires privileges).
		//nolint:gosec // G204: test-only, controlled entry
		cmd = exec.CommandContext(context.Background(), "sh", "-c", fmt.Sprintf("echo '%s' >> /etc/hosts", entry))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add %s to /etc/hosts: %w", entry, err)
		}
	}

	return nil
}

// teardownHostsEntries removes entries from /etc/hosts that were added for the emulator.
func teardownHostsEntries() {
	domains := []string{
		"www.googleapis.com",
		"storage.googleapis.com",
		"oauth2.googleapis.com",
	}

	for _, domain := range domains {
		// Remove entry (requires privileges).
		//nolint:gosec // G204: test-only, fixed domains
		pattern := fmt.Sprintf("/%s/d", strings.ReplaceAll(domain, ".", "\\."))
		cmd := exec.CommandContext(context.Background(), "sed", "-i", pattern, "/etc/hosts")
		_ = cmd.Run() // Ignore errors - entry might not exist
	}
}

// TestMain sets up and tears down the HTTPS proxy and /etc/hosts entries for all tests in this package.
// TestMain runs once before all tests and once after all tests complete.
// It applies to all test files in the same package (gcs_test package).
func TestMain(m *testing.M) {
	// Setup /etc/hosts entries if GCSMOCK_ENDPOINT is set
	if os.Getenv("GCSMOCK_ENDPOINT") != "" {
		if err := setupHostsEntries(); err != nil {
			fmt.Printf("Warning: Could not modify /etc/hosts: %v\n", err)
			fmt.Printf("Tests may fail if /etc/hosts entries are not present\n")
		} else {
			fmt.Println("Added /etc/hosts entries for Google API domains")
		}
	}

	// Start HTTPS proxy before all tests if GCSMOCK_ENDPOINT is set
	if os.Getenv("GCSMOCK_ENDPOINT") != "" {
		endpoint := os.Getenv("GCSMOCK_ENDPOINT")
		endpoint = strings.TrimSuffix(endpoint, "/")
		target := endpoint

		var err error
		httpsProxy, err = newHTTPSProxyServer(target)
		if err != nil {
			// Fail fast: with /etc/hosts redirecting Google domains to 127.0.0.1,
			// OAuth/token calls will hit localhost:443 and fail with unclear errors
			// if the proxy is not listening. Require the proxy to start.
			fmt.Fprintf(os.Stderr, "Fatal: cannot start HTTPS proxy on port 443: %v\n", err)
			fmt.Fprintf(os.Stderr, "This may require root or CAP_NET_BIND_SERVICE. Exiting.\n")
			os.Exit(1)
		}
		httpsProxy.Start()
		// Set SSL_CERT_FILE to trust our self-signed certificate
		// This is respected by Go's crypto/x509 package when loading the system cert pool
		// and will affect all TLS connections, including those made by OAuth2 clients
		os.Setenv("SSL_CERT_FILE", httpsProxy.certFile)
		fmt.Printf("HTTPS proxy started on port 443, certificate: %s\n", httpsProxy.certFile)
	}

	// Run all tests
	code := m.Run()

	// Stop proxy after all tests finish
	if httpsProxy != nil {
		httpsProxy.Stop()
		fmt.Println("HTTPS proxy stopped")
		httpsProxy = nil
	}

	// Cleanup /etc/hosts entries
	if os.Getenv("GCSMOCK_ENDPOINT") != "" {
		teardownHostsEntries()
		fmt.Println("Removed /etc/hosts entries for Google API domains")
	}

	os.Exit(code)
}

func ensureDummyGCSCreds(t *testing.T) {
	t.Helper()

	if os.Getenv("GCSMOCK_ENDPOINT") != "" {
		credsFile := path.Join(t.TempDir(), "dummy_creds.json")

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}

		privPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		})

		content := fmt.Sprintf(`{"type": "service_account", "project_id": "test-project", `+
			`"client_email": "test@test.com", "private_key": %q}`, string(privPEM))
		err = os.WriteFile(credsFile, []byte(content), 0o600)
		if err != nil {
			t.Fatal(err)
		}

		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile)
	}
}

func cleanupStorage(store driver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

// createObjectsStore creates a GCS-backed store; dedupe is always true at call sites.
//
//nolint:unparam
func createObjectsStore(rootDir string, cacheDir string, dedupe bool) (
	driver.StorageDriver,
	storageTypes.ImageStore,
	error,
) {
	bucket := "zot-storage-test"

	endpoint := os.Getenv("GCSMOCK_ENDPOINT")
	if endpoint == "" {
		return nil, nil, errGCSMockEndpointNotSet
	}

	url := strings.TrimSuffix(endpoint, "/") + "/storage/v1/b?project=test-project"
	body := fmt.Sprintf(`{"name": "%s"}`, bucket)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: Test mock
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Check if bucket was created successfully or already exists.
	okStatus := resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusCreated ||
		resp.StatusCode == http.StatusConflict
	if !okStatus {
		respBody, _ := io.ReadAll(resp.Body)

		return nil, nil, fmt.Errorf("%w %s: status %d body %s",
			errBucketCreateFailed, bucket, resp.StatusCode, string(respBody))
	}

	storageDriverParams := map[string]any{
		"rootDir": rootDir,
		"name":    "gcs",
		"bucket":  bucket,
	}

	storeName := fmt.Sprintf("%v", storageDriverParams["name"])

	store, err := factory.Create(context.Background(), storeName, storageDriverParams)
	if err != nil {
		return nil, nil, err
	}

	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	var cacheDriver storageTypes.Cache

	// from pkg/cli/server/root.go/applyDefaultValues, s3 magic
	s3CacheDBPath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

	if _, err := os.Stat(s3CacheDBPath); dedupe || (!dedupe && err == nil) {
		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     cacheDir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
	}

	il := gcs.NewImageStore(rootDir, cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, il, nil
}

func TestGCSDriver(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	Convey("GCS Driver E2E", t, func() {
		// Create a fresh temp dir for each run to avoid BoltDB lock issues
		tdir := t.TempDir()
		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)

		Convey("Init Repo", func() {
			repoName := "test-repo-init"
			err := imgStore.InitRepo(repoName)
			So(err, ShouldBeNil)

			isValid, err := imgStore.ValidateRepo(repoName)
			So(err, ShouldBeNil)
			So(isValid, ShouldBeTrue)
		})

		Convey("Push and Pull Image", func() {
			repoName := "test-repo-push"
			image := CreateDefaultImage()

			// Upload layers
			for _, content := range image.Layers {
				upload, err := imgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)

				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)

				blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
				So(err, ShouldBeNil)
			}

			// Upload config
			cblob, err := json.Marshal(image.Config)
			So(err, ShouldBeNil)
			cdigest := godigest.FromBytes(cblob)
			_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewBuffer(cblob), cdigest)
			So(err, ShouldBeNil)

			// Upload manifest
			mblob, err := json.Marshal(image.Manifest)
			So(err, ShouldBeNil)
			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mblob)
			So(err, ShouldBeNil)

			// Verify manifest
			_, _, _, err = imgStore.GetImageManifest(repoName, "1.0")
			So(err, ShouldBeNil)

			// Verify blob
			blobReadCloser, _, err := imgStore.GetBlob(repoName, cdigest, ispec.MediaTypeImageConfig)
			So(err, ShouldBeNil)
			defer blobReadCloser.Close()
			content, err := io.ReadAll(blobReadCloser)
			So(err, ShouldBeNil)
			So(content, ShouldResemble, cblob)
		})

		Convey("Delete Image", func() {
			repoName := "test-repo-delete"
			// Setup image
			image := CreateDefaultImage()

			// Upload layers first (required for manifest validation)
			for _, content := range image.Layers {
				upload, err := imgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)

				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)

				blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
				So(err, ShouldBeNil)
			}

			// Upload config
			cblob, err := json.Marshal(image.Config)
			So(err, ShouldBeNil)
			cdigest := godigest.FromBytes(cblob)
			_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewBuffer(cblob), cdigest)
			So(err, ShouldBeNil)

			// Upload manifest
			mblob, err := json.Marshal(image.Manifest)
			So(err, ShouldBeNil)
			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mblob)
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest(repoName, "1.0", false)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, "1.0")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
		})
	})
}

func TestGCSDedupe(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	Convey("Dedupe", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)

		// manifest1
		upload, err := imgStore.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest1 := digest
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		ok, checkBlobSize1, err := imgStore.CheckBlob("dedupe1", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		ok, checkBlobSize1, _, err = imgStore.StatBlob("dedupe1", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize1, err := imgStore.GetBlob("dedupe1", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("dedupe1", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err := imgStore.CheckBlob("dedupe1", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

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
					Size:      int64(buflen),
				},
			},
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe1", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", manifestDigest.String())
		So(err, ShouldBeNil)

		// manifest2
		upload, err = imgStore.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)

		blob, err = imgStore.PutBlobChunkStreamed("dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest2 := digest
		So(blobDigest2, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		ok, checkBlobSize2, err := imgStore.CheckBlob("dedupe2", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		ok, checkBlobSize2, _, err = imgStore.StatBlob("dedupe2", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize2, err := imgStore.GetBlob("dedupe2", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest = GetRandomImageConfig()
		_, clen, err = imgStore.FullBlobUpload("dedupe2", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err = imgStore.CheckBlob("dedupe2", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

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
					Size:      int64(buflen),
				},
			},
		}

		manifest.SchemaVersion = 2
		manifestBuf, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest = godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe2", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", manifestDigest.String())
		So(err, ShouldBeNil)

		So(blobDigest1, ShouldEqual, blobDigest2)
		So(checkBlobSize1, ShouldEqual, checkBlobSize2)
		So(getBlobSize1, ShouldEqual, getBlobSize2)
	})
}

func TestGCSPullRange(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	Convey("Pull range", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)

		upload, err := imgStore.NewBlobUpload("test")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("test", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("test", upload, buf, digest)
		So(err, ShouldBeNil)

		blobReadCloser, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 0, 4)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "test-")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range - "data3" is bytes 5-9 (inclusive) of "test-data3"
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 5, 9)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "data3")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range from negative offset
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", -4, 4)
		So(err, ShouldNotBeNil)
		So(blobReadCloser, ShouldBeNil)
	})
}

func TestGCSGetAllDedupeReposCandidates(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupStorage(storeDriver, testDir)

	Convey("Push repos with deduped blobs", t, func(c C) {
		repoNames := []string{
			"first",
			"second",
			"repo/a",
			"repo/a/b/c/d/e/f",
			"repo/repo-b/blobs",
			"foo/bar/baz",
			"blobs/foo/bar/blobs",
			"blobs",
			"blobs/foo",
		}

		storeController := storage.StoreController{DefaultStore: imgStore}

		image := CreateRandomImage()

		for _, repoName := range repoNames {
			err := WriteImageToFileSystem(image, repoName, tag, storeController)
			So(err, ShouldBeNil)
		}

		randomBlobDigest := image.Manifest.Layers[0].Digest

		repos, err := imgStore.GetAllDedupeReposCandidates(randomBlobDigest)
		So(err, ShouldBeNil)
		slices.Sort(repoNames)
		slices.Sort(repos)
		So(repoNames, ShouldResemble, repos)
	})
}

func TestGCSDeleteBlobsInUse(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	Convey("Setup manifest", t, func() {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)
		// put an unused blob
		content := []byte("unused blob")
		buf := bytes.NewBuffer(content)
		unusedDigest := godigest.FromBytes(content)

		_, _, err = imgStore.FullBlobUpload("repo", bytes.NewReader(buf.Bytes()), unusedDigest)
		So(err, ShouldBeNil)

		content = []byte("test-data1")
		buf = bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)

		_, _, err = imgStore.FullBlobUpload("repo", bytes.NewReader(buf.Bytes()), digest)
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()

		var clen int64
		_, clen, err = imgStore.FullBlobUpload("repo", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		annotationsMap := make(map[string]string)
		annotationsMap[ispec.AnnotationRefName] = tag

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
					Size:      int64(buflen),
				},
			},
			Annotations: annotationsMap,
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest, _, err := imgStore.PutImageManifest("repo", tag, ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		Convey("Try to delete blob currently in use", func() {
			// layer blob
			err := imgStore.DeleteBlob("repo", digest)
			So(err, ShouldEqual, zerr.ErrBlobReferenced)

			// manifest
			err = imgStore.DeleteBlob("repo", manifestDigest)
			So(err, ShouldEqual, zerr.ErrBlobReferenced)

			// config
			err = imgStore.DeleteBlob("repo", cdigest)
			So(err, ShouldEqual, zerr.ErrBlobReferenced)
		})

		Convey("Delete unused blob", func() {
			err := imgStore.DeleteBlob("repo", unusedDigest)
			So(err, ShouldBeNil)
		})

		Convey("Delete manifest first, then blob", func() {
			err := imgStore.DeleteImageManifest("repo", manifestDigest.String(), false)
			So(err, ShouldBeNil)

			err = imgStore.DeleteBlob("repo", digest)
			So(err, ShouldBeNil)

			// config
			err = imgStore.DeleteBlob("repo", cdigest)
			So(err, ShouldBeNil)
		})
	})
}

func TestGCSStorageAPIs(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupStorage(storeDriver, testDir)

	Convey("Repo layout", t, func(c C) {
		repoName := "test"

		Convey("Get all blobs from repo without initialization", func() {
			allBlobs, err := imgStore.GetAllBlobs(repoName)
			So(err, ShouldBeNil)
			So(allBlobs, ShouldBeEmpty)

			ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
			So(ok, ShouldBeFalse)
		})

		Convey("Validate repo without initialization", func() {
			v, err := imgStore.ValidateRepo(repoName)
			So(v, ShouldEqual, false)
			So(err, ShouldNotBeNil)

			ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
			So(ok, ShouldBeFalse)
		})

		Convey("Initialize repo", func() {
			err := imgStore.InitRepo(repoName)
			So(err, ShouldBeNil)

			ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
			So(ok, ShouldBeTrue)

			storeController := storage.StoreController{}
			storeController.DefaultStore = imgStore
			So(storeController.GetImageStore("test"), ShouldResemble, imgStore)
		})

		Convey("Validate repo", func() {
			repos, err := imgStore.ValidateRepo(repoName)
			So(err, ShouldBeNil)
			So(repos, ShouldEqual, true)
		})

		Convey("Get repos", func() {
			repos, err := imgStore.GetRepositories()
			So(err, ShouldBeNil)
			So(repos, ShouldNotBeEmpty)

			repos, more, err := imgStore.GetNextRepositories("", -1, func(repo string) (bool, error) {
				return true, nil
			})

			So(more, ShouldBeFalse)
			So(err, ShouldBeNil)
			So(repos, ShouldNotBeEmpty)
		})

		Convey("Get image tags", func() {
			v, err := imgStore.GetImageTags("test")
			So(err, ShouldBeNil)
			So(v, ShouldBeEmpty)
		})

		Convey("Full blob upload unavailable algorithm", func() {
			body := []byte("this blob will be hashed using an unavailable hashing algorithm")
			buf := bytes.NewBuffer(body)
			digest := godigest.Digest("md5:8114c3f59ef9dcf737410e0f4b00a154")
			upload, n, err := imgStore.FullBlobUpload("test", buf, digest)
			So(err, ShouldEqual, godigest.ErrDigestUnsupported)
			So(n, ShouldEqual, -1)
			So(upload, ShouldEqual, "")

			// Check no blobs are returned and there are no errors
			// if other paths for different algorithms are missing
			digests, err := imgStore.GetAllBlobs("test")
			So(err, ShouldBeNil)
			So(digests, ShouldBeEmpty)
		})

		Convey("Full blob upload", func() {
			body := []byte("this is a blob")
			buf := bytes.NewBuffer(body)
			digest := godigest.FromBytes(body)
			upload, n, err := imgStore.FullBlobUpload("test", buf, digest)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(body))
			So(upload, ShouldNotBeEmpty)

			err = imgStore.VerifyBlobDigestValue("test", digest)
			So(err, ShouldBeNil)

			// Check the blob is returned and there are no errors
			// if other paths for different algorithms are missing
			digests, err := imgStore.GetAllBlobs("test")
			So(err, ShouldBeNil)
			So(digests, ShouldContain, digest)
			So(len(digests), ShouldEqual, 1)
		})

		Convey("Full blob upload sha512", func() {
			body := []byte("this blob will be hashed using sha512")
			buf := bytes.NewBuffer(body)
			digest := godigest.SHA512.FromBytes(body)
			upload, n, err := imgStore.FullBlobUpload("test", buf, digest)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(body))
			So(upload, ShouldNotBeEmpty)

			// Check the blob is returned and there are no errors
			// if other paths for different algorithms are missing
			digests, err := imgStore.GetAllBlobs("test")
			So(err, ShouldBeNil)
			So(digests, ShouldContain, digest)
			// imgStore is reused so look for this digest and
			// the ones uploaded by previous tests
			So(len(digests), ShouldEqual, 2)
		})

		Convey("Full blob upload sha384", func() {
			body := []byte("this blob will be hashed using sha384")
			buf := bytes.NewBuffer(body)
			digest := godigest.SHA384.FromBytes(body)
			upload, n, err := imgStore.FullBlobUpload("test", buf, digest)
			So(err, ShouldBeNil)
			So(n, ShouldEqual, len(body))
			So(upload, ShouldNotBeEmpty)

			// Check the blob is returned and there are no errors
			// if other paths for different algorithms are missing
			digests, err := imgStore.GetAllBlobs("test")
			So(err, ShouldBeNil)
			So(digests, ShouldContain, digest)
			// imgStore is reused so look for this digest and
			// the ones uploaded by previous tests
			So(len(digests), ShouldEqual, 3)
		})

		Convey("New blob upload", func() {
			upload, err := imgStore.NewBlobUpload("test")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			err = imgStore.DeleteBlobUpload("test", upload)
			So(err, ShouldBeNil)

			upload, err = imgStore.NewBlobUpload("test")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			Convey("Get blob upload", func() {
				bupload, err := imgStore.GetBlobUpload("test", "invalid")
				So(err, ShouldNotBeNil)
				So(bupload, ShouldEqual, -1)

				bupload, err = imgStore.GetBlobUpload("hi", " \255")
				So(err, ShouldNotBeNil)
				So(bupload, ShouldEqual, -1)

				bupload, err = imgStore.GetBlobUpload("test", upload)
				So(err, ShouldBeNil)
				So(bupload, ShouldBeGreaterThanOrEqualTo, 0)

				bupload, err = imgStore.BlobUploadInfo("test", upload)
				So(err, ShouldBeNil)
				So(bupload, ShouldBeGreaterThanOrEqualTo, 0)

				content := []byte("test-data1")
				firstChunkContent := []byte("test")
				firstChunkBuf := bytes.NewBuffer(firstChunkContent)
				secondChunkContent := []byte("-data1")
				secondChunkBuf := bytes.NewBuffer(secondChunkContent)
				firstChunkLen := firstChunkBuf.Len()
				secondChunkLen := secondChunkBuf.Len()

				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)
				blobDigest := digest

				// invalid chunk range
				_, err = imgStore.PutBlobChunk("test", upload, 10, int64(buflen), buf)
				So(err, ShouldNotBeNil)

				bupload, err = imgStore.PutBlobChunk("test", upload, 0, int64(firstChunkLen), firstChunkBuf)
				So(err, ShouldBeNil)
				So(bupload, ShouldEqual, firstChunkLen)

				bupload, err = imgStore.GetBlobUpload("test", upload)
				So(err, ShouldBeNil)
				So(bupload, ShouldEqual, int64(firstChunkLen))

				bupload, err = imgStore.BlobUploadInfo("test", upload)
				So(err, ShouldBeNil)
				So(bupload, ShouldEqual, int64(firstChunkLen))

				bupload, err = imgStore.PutBlobChunk("test", upload, int64(firstChunkLen), int64(buflen), secondChunkBuf)
				So(err, ShouldBeNil)
				So(bupload, ShouldEqual, int64(firstChunkLen+secondChunkLen))

				err = imgStore.FinishBlobUpload("test", upload, buf, digest)
				So(err, ShouldBeNil)

				_, _, err = imgStore.CheckBlob("test", digest)
				So(err, ShouldBeNil)

				ok, _, _, err := imgStore.StatBlob("test", digest)
				So(ok, ShouldBeTrue)
				So(err, ShouldBeNil)

				blob, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
				So(err, ShouldBeNil)

				blobBuf := new(strings.Builder)
				n, err := io.Copy(blobBuf, blob)
				// check errors
				So(n, ShouldEqual, buflen)
				So(err, ShouldBeNil)
				So(blobBuf.String(), ShouldEqual, buf.String())

				blobContent, err := imgStore.GetBlobContent("test", digest)
				So(err, ShouldBeNil)
				So(blobContent, ShouldResemble, content)

				err = blob.Close()
				So(err, ShouldBeNil)

				manifest := ispec.Manifest{}
				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)

				Convey("Bad image manifest", func() {
					_, _, err = imgStore.PutImageManifest("test", digest.String(), "application/json",
						manifestBuf)
					So(err, ShouldNotBeNil)

					_, _, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
						[]byte{})
					So(err, ShouldNotBeNil)

					_, _, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
						[]byte(`{"test":true}`))
					So(err, ShouldNotBeNil)

					_, _, err = imgStore.PutImageManifest("test", digest.String(), ispec.MediaTypeImageManifest,
						manifestBuf)
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("test", digest.String())
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("inexistent", digest.String())
					So(err, ShouldNotBeNil)
				})

				Convey("Good image manifest", func() {
					cblob, cdigest := GetRandomImageConfig()
					_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))

					hasBlob, _, err := imgStore.CheckBlob("test", cdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					annotationsMap := make(map[string]string)
					annotationsMap[ispec.AnnotationRefName] = "1.0"
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
								Size:      int64(buflen),
							},
						},
						Annotations: annotationsMap,
					}

					manifest.SchemaVersion = 2
					manifestBuf, err = json.Marshal(manifest)
					So(err, ShouldBeNil)

					digest := godigest.FromBytes(manifestBuf)

					// bad manifest
					manifest.Layers[0].Digest = godigest.FromBytes([]byte("inexistent"))
					badMb, err := json.Marshal(manifest)
					So(err, ShouldBeNil)

					_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, badMb)
					So(err, ShouldNotBeNil)

					_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					// same manifest for coverage
					_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					_, _, err = imgStore.PutImageManifest("test", "2.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					_, _, err = imgStore.PutImageManifest("test", "3.0", ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					_, err = imgStore.GetImageTags("inexistent")
					So(err, ShouldNotBeNil)

					// total tags should be 3 but they have same reference.
					tags, err := imgStore.GetImageTags("test")
					So(err, ShouldBeNil)
					So(len(tags), ShouldEqual, 3)

					_, _, _, err = imgStore.GetImageManifest("test", digest.String())
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("test", "3.0")
					So(err, ShouldBeNil)

					err = imgStore.DeleteImageManifest("test", "1.0", false)
					So(err, ShouldBeNil)

					tags, err = imgStore.GetImageTags("test")
					So(err, ShouldBeNil)
					So(len(tags), ShouldEqual, 2)

					repos, err := imgStore.GetRepositories()
					So(err, ShouldBeNil)
					So(len(repos), ShouldEqual, 1)
					So(repos[0], ShouldEqual, "test")

					repos, more, err := imgStore.GetNextRepositories("", -1, func(repo string) (bool, error) {
						return true, nil
					})
					So(err, ShouldBeNil)
					So(more, ShouldBeFalse)
					So(len(repos), ShouldEqual, 1)
					So(repos[0], ShouldEqual, "test")

					repos, more, err = imgStore.GetNextRepositories("", -1, func(repo string) (bool, error) {
						return false, nil
					})
					So(err, ShouldBeNil)
					So(more, ShouldBeFalse)
					So(len(repos), ShouldEqual, 0)

					// We deleted only one tag, make sure blob should not be removed.
					hasBlob, _, err = imgStore.CheckBlob("test", digest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

					// with detectManifestCollision should get error
					err = imgStore.DeleteImageManifest("test", digest.String(), true)
					So(err, ShouldNotBeNil)

					// If we pass reference all manifest with input reference should be deleted.
					err = imgStore.DeleteImageManifest("test", digest.String(), false)
					So(err, ShouldBeNil)

					tags, err = imgStore.GetImageTags("test")
					So(err, ShouldBeNil)
					So(len(tags), ShouldEqual, 0)

					// All tags/references are deleted, blob should not be present in disk.
					hasBlob, _, err = imgStore.CheckBlob("test", digest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					hasBlob, _, _, err = imgStore.StatBlob("test", digest)
					So(err, ShouldNotBeNil)
					So(hasBlob, ShouldEqual, false)

					err = imgStore.DeleteBlob("test", "inexistent")
					So(err, ShouldNotBeNil)

					err = imgStore.DeleteBlob("test", godigest.FromBytes([]byte("inexistent")))
					So(err, ShouldNotBeNil)

					err = imgStore.DeleteBlob("test", blobDigest)
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("test", digest.String())
					So(err, ShouldNotBeNil)
				})
			})

			err = imgStore.DeleteBlobUpload("test", upload)
			So(err, ShouldNotBeNil)
		})

		Convey("New blob upload streamed", func() {
			bupload, err := imgStore.NewBlobUpload("test")
			So(err, ShouldBeNil)
			So(bupload, ShouldNotBeEmpty)

			Convey("Get blob upload", func() {
				upload, err := imgStore.GetBlobUpload("test", "invalid")
				So(err, ShouldNotBeNil)
				So(upload, ShouldEqual, -1)

				upload, err = imgStore.GetBlobUpload("test", bupload)
				So(err, ShouldBeNil)
				So(upload, ShouldBeGreaterThanOrEqualTo, 0)

				_, err = imgStore.BlobUploadInfo("test", "inexistent")
				So(err, ShouldNotBeNil)

				upload, err = imgStore.BlobUploadInfo("test", bupload)
				So(err, ShouldBeNil)
				So(upload, ShouldBeGreaterThanOrEqualTo, 0)

				content := []byte("test-data2")
				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)
				upload, err = imgStore.PutBlobChunkStreamed("test", bupload, buf)
				So(err, ShouldBeNil)
				So(upload, ShouldEqual, buflen)

				_, err = imgStore.PutBlobChunkStreamed("test", "inexistent", buf)
				So(err, ShouldNotBeNil)

				err = imgStore.FinishBlobUpload("test", "inexistent", buf, digest)
				So(err, ShouldNotBeNil)

				// invalid digest
				err = imgStore.FinishBlobUpload("test", "inexistent", buf, "sha256:invalid")
				So(err, ShouldNotBeNil)

				err = imgStore.FinishBlobUpload("test", bupload, buf, digest)
				So(err, ShouldBeNil)

				ok, _, err := imgStore.CheckBlob("test", digest)
				So(ok, ShouldBeTrue)
				So(err, ShouldBeNil)

				ok, _, _, err = imgStore.StatBlob("test", digest)
				So(ok, ShouldBeTrue)
				So(err, ShouldBeNil)

				_, _, err = imgStore.GetBlob("test", "inexistent", "application/vnd.oci.image.layer.v1.tar+gzip")
				So(err, ShouldNotBeNil)

				blob, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
				So(err, ShouldBeNil)
				err = blob.Close()
				So(err, ShouldBeNil)

				blobContent, err := imgStore.GetBlobContent("test", digest)
				So(err, ShouldBeNil)
				So(content, ShouldResemble, blobContent)

				_, err = imgStore.GetBlobContent("inexistent", digest)
				So(err, ShouldNotBeNil)

				manifest := ispec.Manifest{}
				manifest.SchemaVersion = 2
				manifestBuf, err := json.Marshal(manifest)
				So(err, ShouldBeNil)

				Convey("Bad digests", func() {
					_, _, err := imgStore.FullBlobUpload("test", bytes.NewBuffer([]byte{}), "inexistent")
					So(err, ShouldNotBeNil)

					_, _, err = imgStore.CheckBlob("test", "inexistent")
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.StatBlob("test", "inexistent")
					So(err, ShouldNotBeNil)
				})

				Convey("Bad image manifest", func() {
					_, _, err = imgStore.PutImageManifest("test", digest.String(),
						ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldNotBeNil)

					_, _, err = imgStore.PutImageManifest("test", digest.String(),
						ispec.MediaTypeImageManifest, []byte("bad json"))
					So(err, ShouldNotBeNil)

					_, _, _, err = imgStore.GetImageManifest("test", digest.String())
					So(err, ShouldNotBeNil)
				})

				Convey("Good image manifest", func() {
					cblob, cdigest := GetRandomImageConfig()
					_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
					So(err, ShouldBeNil)
					So(clen, ShouldEqual, len(cblob))

					hasBlob, _, err := imgStore.CheckBlob("test", cdigest)
					So(err, ShouldBeNil)
					So(hasBlob, ShouldEqual, true)

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
								Size:      int64(buflen),
							},
						},
					}
					manifest.SchemaVersion = 2
					manifestBuf, err = json.Marshal(manifest)
					So(err, ShouldBeNil)

					digest := godigest.FromBytes(manifestBuf)
					_, _, err = imgStore.PutImageManifest("test", digest.String(),
						ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					// same manifest for coverage
					_, _, err = imgStore.PutImageManifest("test", digest.String(),
						ispec.MediaTypeImageManifest, manifestBuf)
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("test", digest.String())
					So(err, ShouldBeNil)

					_, err = imgStore.GetIndexContent("inexistent")
					So(err, ShouldNotBeNil)

					indexContent, err := imgStore.GetIndexContent("test")
					So(err, ShouldBeNil)

					var index ispec.Index

					err = json.Unmarshal(indexContent, &index)
					So(err, ShouldBeNil)

					So(len(index.Manifests), ShouldEqual, 1)

					err = imgStore.DeleteImageManifest("test", "1.0", false)
					So(err, ShouldNotBeNil)

					err = imgStore.DeleteImageManifest("inexistent", "1.0", false)
					So(err, ShouldNotBeNil)

					err = imgStore.DeleteImageManifest("test", digest.String(), false)
					So(err, ShouldBeNil)

					_, _, _, err = imgStore.GetImageManifest("test", digest.String())
					So(err, ShouldNotBeNil)
				})
			})

			err = imgStore.DeleteBlobUpload("test", bupload)
			So(err, ShouldNotBeNil)
		})

		Convey("Modify manifest in-place", func() {
			// original blob
			upload, err := imgStore.NewBlobUpload("replace")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content := []byte("test-data-replace-1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)
			blob, err := imgStore.PutBlobChunkStreamed("replace", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			blobDigest1 := strings.Split(digest.String(), ":")[1]
			So(blobDigest1, ShouldNotBeEmpty)

			err = imgStore.FinishBlobUpload("replace", upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			cblob, cdigest := GetRandomImageConfig()
			_, clen, err := imgStore.FullBlobUpload("replace", bytes.NewReader(cblob), cdigest)
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))

			hasBlob, _, err := imgStore.CheckBlob("replace", cdigest)
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)

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
						Size:      int64(buflen),
					},
				},
			}
			manifest.SchemaVersion = 2
			manifestBuf, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			digest = godigest.FromBytes(manifestBuf)
			_, _, err = imgStore.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest("replace", digest.String())
			So(err, ShouldBeNil)

			// new blob to replace
			upload, err = imgStore.NewBlobUpload("replace")
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content = []byte("test-data-replace-2")
			buf = bytes.NewBuffer(content)
			buflen = buf.Len()
			digest = godigest.FromBytes(content)
			blob, err = imgStore.PutBlobChunkStreamed("replace", upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			blobDigest2 := strings.Split(digest.String(), ":")[1]
			So(blobDigest2, ShouldNotBeEmpty)

			err = imgStore.FinishBlobUpload("replace", upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			cblob, cdigest = GetRandomImageConfig()
			_, clen, err = imgStore.FullBlobUpload("replace", bytes.NewReader(cblob), cdigest)
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))

			hasBlob, _, err = imgStore.CheckBlob("replace", cdigest)
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)

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
						Size:      int64(buflen),
					},
				},
			}
			manifest.SchemaVersion = 2
			manifestBuf, err = json.Marshal(manifest)
			So(err, ShouldBeNil)

			_ = godigest.FromBytes(manifestBuf)
			_, _, err = imgStore.PutImageManifest("replace", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldBeNil)
		})

		Convey("Locks", func() {
			// in parallel, a mix of read and write locks - mainly for coverage
			var wg sync.WaitGroup
			for range 1000 {
				wg.Add(2)

				go func() {
					var lockLatency time.Time

					defer wg.Done()
					imgStore.Lock(&lockLatency)
					func() {}()
					imgStore.Unlock(&lockLatency)
				}()
				go func() {
					var lockLatency time.Time

					defer wg.Done()
					imgStore.RLock(&lockLatency)
					func() {}()
					imgStore.RUnlock(&lockLatency)
				}()
			}

			wg.Wait()
		})
	})
}

func TestGCSReuploadCorruptedBlob(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	rawDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupStorage(rawDriver, testDir)

	// Wrap driver for WriteFile access
	gcsDriver := gcs.New(rawDriver)

	Convey("Test errors paths", t, func() {
		storeController := storage.StoreController{DefaultStore: imgStore}

		image := CreateRandomImage()

		err := WriteImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)
	})

	Convey("Test reupload repair corrupted image", t, func() {
		storeController := storage.StoreController{DefaultStore: imgStore}

		image := CreateRandomImage()

		err := WriteImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		blob := image.Layers[0]
		blobDigest := godigest.FromBytes(blob)
		blobSize := len(blob)
		blobPath := imgStore.BlobPath(repoName, blobDigest)

		ok, size, err := imgStore.CheckBlob(repoName, blobDigest)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, blobSize)
		So(err, ShouldBeNil)

		_, err = gcsDriver.WriteFile(blobPath, []byte("corrupted"))
		So(err, ShouldBeNil)

		ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
		So(ok, ShouldBeFalse)
		So(size, ShouldNotEqual, blobSize)
		So(err, ShouldEqual, zerr.ErrBlobNotFound)

		err = WriteImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		ok, size, _, err = imgStore.StatBlob(repoName, blobDigest)
		So(ok, ShouldBeTrue)
		So(blobSize, ShouldEqual, size)
		So(err, ShouldBeNil)

		ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, blobSize)
		So(err, ShouldBeNil)
	})

	Convey("Test reupload repair corrupted image index", t, func() {
		storeController := storage.StoreController{DefaultStore: imgStore}

		image := CreateRandomMultiarch()

		tag := "index"

		err := WriteMultiArchImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		blob := image.Images[0].Layers[0]
		blobDigest := godigest.FromBytes(blob)
		blobSize := len(blob)
		blobPath := imgStore.BlobPath(repoName, blobDigest)

		ok, size, err := imgStore.CheckBlob(repoName, blobDigest)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, blobSize)
		So(err, ShouldBeNil)

		_, err = gcsDriver.WriteFile(blobPath, []byte("corrupted"))
		So(err, ShouldBeNil)

		ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
		So(ok, ShouldBeFalse)
		So(size, ShouldNotEqual, blobSize)
		So(err, ShouldEqual, zerr.ErrBlobNotFound)

		err = WriteMultiArchImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		ok, size, _, err = imgStore.StatBlob(repoName, blobDigest)
		So(ok, ShouldBeTrue)
		So(blobSize, ShouldEqual, size)
		So(err, ShouldBeNil)

		ok, size, err = imgStore.CheckBlob(repoName, blobDigest)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, blobSize)
		So(err, ShouldBeNil)
	})
}

func TestGCSStorageHandler(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	Convey("Test storage handler", t, func() {
		firstRootDir := "/util_test1"
		firstCacheDir := t.TempDir()

		firstStorageDriver, firstStore, err := createObjectsStore(firstRootDir, firstCacheDir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(firstStorageDriver, firstRootDir)

		secondRootDir := "/util_test2"
		secondCacheDir := t.TempDir()

		secondStorageDriver, secondStore, err := createObjectsStore(secondRootDir, secondCacheDir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(secondStorageDriver, secondRootDir)

		thirdRootDir := "/util_test3"
		thirdCacheDir := t.TempDir()

		thirdStorageDriver, thirdStore, err := createObjectsStore(thirdRootDir, thirdCacheDir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(thirdStorageDriver, thirdRootDir)
		storeController := storage.StoreController{}

		storeController.DefaultStore = firstStore

		subStore := make(map[string]storageTypes.ImageStore)

		subStore["/a"] = secondStore
		subStore["/b"] = thirdStore

		storeController.SubStore = subStore

		imgStore := storeController.GetImageStore("zot-x-test")
		So(imgStore.RootDir(), ShouldEqual, firstRootDir)

		imgStore = storeController.GetImageStore("a/zot-a-test")
		So(imgStore.RootDir(), ShouldEqual, secondRootDir)

		imgStore = storeController.GetImageStore("b/zot-b-test")
		So(imgStore.RootDir(), ShouldEqual, thirdRootDir)

		imgStore = storeController.GetImageStore("c/zot-c-test")
		So(imgStore.RootDir(), ShouldEqual, firstRootDir)
	})
}

func TestGCSMandatoryAnnotations(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	testLog := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, testLog)

	storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupStorage(storeDriver, testDir)

	Convey("Setup manifest", t, func() {
		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)

		_, _, err = imgStore.FullBlobUpload("test", bytes.NewReader(buf.Bytes()), digest)
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()

		var clen int64
		_, clen, err = imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		annotationsMap := make(map[string]string)
		annotationsMap[ispec.AnnotationRefName] = "1.0"

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
					Size:      int64(buflen),
				},
			},
			Annotations: annotationsMap,
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		Convey("Missing mandatory annotations", func() {
			// Create imgStore with linter that returns false (missing annotations)
			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     tdir,
				Name:        "cache",
				UseRelPaths: false,
			}, testLog)

			imgStoreWithLinter := gcs.NewImageStore(testDir, tdir, false, false, testLog, metrics,
				&mocks.MockedLint{
					LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error) {
						return false, nil
					},
				}, storeDriver, cacheDriver, nil, nil)

			_, _, err = imgStoreWithLinter.PutImageManifest("test", "1.0.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on mandatory annotations", func() {
			// Create imgStore with linter that returns error
			_, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     tdir,
				Name:        "cache",
				UseRelPaths: false,
			}, testLog)

			imgStoreWithLinter := gcs.NewImageStore(testDir, tdir, false, false, testLog, metrics,
				&mocks.MockedLint{
					LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storageTypes.ImageStore) (bool, error) {
						//nolint: err113
						return false, errors.New("linter error")
					},
				}, storeDriver, nil, nil, nil)

			_, _, err = imgStoreWithLinter.PutImageManifest("test", "1.0.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldNotBeNil)
		})
	})
}

// pushRandomImageIndexGCS is a helper for GC tests.
func pushRandomImageIndexGCS(imgStore storageTypes.ImageStore, repoName string,
) (godigest.Digest, godigest.Digest, godigest.Digest, int64) {
	content := []byte("this is a blob")
	bdgst := godigest.FromBytes(content)
	So(bdgst, ShouldNotBeNil)

	_, bsize, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), bdgst)
	So(err, ShouldBeNil)
	So(bsize, ShouldEqual, len(content))

	var index ispec.Index
	index.SchemaVersion = 2
	index.MediaType = ispec.MediaTypeImageIndex

	var digest godigest.Digest

	for range 4 {
		// upload image config blob
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		cblob, cdigest := GetRandomImageConfig()
		buf := bytes.NewBuffer(cblob)
		buflen := buf.Len()
		blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// create a manifest
		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    bdgst,
					Size:      bsize,
				},
			},
		}
		manifest.SchemaVersion = 2
		content, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		digest = godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)
		_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
		So(err, ShouldBeNil)

		index.Manifests = append(index.Manifests, ispec.Descriptor{
			Digest:    digest,
			MediaType: ispec.MediaTypeImageManifest,
			Size:      int64(len(content)),
		})
	}

	// upload index image
	indexContent, err := json.Marshal(index)
	So(err, ShouldBeNil)

	indexDigest := godigest.FromBytes(indexContent)
	So(indexDigest, ShouldNotBeNil)

	_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageIndex, indexContent)
	So(err, ShouldBeNil)

	return bdgst, digest, indexDigest, int64(len(indexContent))
}

func TestGCSGarbageCollectImageManifest(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	testLog := log.NewTestLogger()
	audit := log.NewAuditLogger("debug", "")

	ctx := context.Background()

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupStorage(storeDriver, testDir)

	Convey("Garbage collect with short delay", t, func(c C) {
		gcDelay := 1 * time.Second

		garbageCollect := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
			Delay: gcDelay,
			ImageRetention: config.ImageRetention{
				Delay: gcDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
						DeleteUntagged:  &trueVal,
					},
				},
			},
		}, audit, testLog)

		// upload orphan blob
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		odigest := godigest.FromBytes(content)

		blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, odigest)
		So(err, ShouldBeNil)

		// sleep so orphan blob can be GC'ed
		time.Sleep(1 * time.Second)

		// upload blob
		upload, err = imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data2")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		bdigest := godigest.FromBytes(content)

		blob, err = imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, bdigest)
		So(err, ShouldBeNil)

		annotationsMap := make(map[string]string)
		annotationsMap[ispec.AnnotationRefName] = tag

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err := imgStore.CheckBlob(repoName, cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    bdigest,
					Size:      int64(buflen),
				},
			},
			Annotations: annotationsMap,
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		digest := godigest.FromBytes(manifestBuf)

		_, _, err = imgStore.PutImageManifest(repoName, tag, ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		// put artifact referencing above image
		artifactBlob := []byte("artifact")
		artifactBlobDigest := godigest.FromBytes(artifactBlob)

		// push layer
		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
		So(err, ShouldBeNil)

		// push config
		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
			ispec.DescriptorEmptyJSON.Digest)
		So(err, ShouldBeNil)

		artifactManifest := ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/octet-stream",
					Digest:    artifactBlobDigest,
					Size:      int64(len(artifactBlob)),
				},
			},
			Config: ispec.DescriptorEmptyJSON,
			Subject: &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    digest,
				Size:      int64(len(manifestBuf)),
			},
		}
		artifactManifest.SchemaVersion = 2

		artifactManifestBuf, err := json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		artifactDigest := godigest.FromBytes(artifactManifestBuf)

		// push artifact manifest
		_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestBuf)
		So(err, ShouldBeNil)

		// push orphan artifact (missing subject)
		artifactManifest.Subject = &ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    godigest.FromBytes([]byte("miss")),
			Size:      int64(30),
		}
		artifactManifest.ArtifactType = "application/orphan"

		artifactManifestBuf, err = json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		orphanArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)

		// push orphan artifact manifest
		_, _, err = imgStore.PutImageManifest(repoName, orphanArtifactManifestDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestBuf)
		So(err, ShouldBeNil)

		err = garbageCollect.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		hasBlob, _, err = imgStore.CheckBlob(repoName, odigest)
		So(err, ShouldNotBeNil)
		So(hasBlob, ShouldEqual, false)

		hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		// sleep so orphan blob can be GC'ed
		time.Sleep(1 * time.Second)

		Convey("Garbage collect blobs after manifest is removed", func() {
			err = imgStore.DeleteImageManifest(repoName, digest.String(), false)
			So(err, ShouldBeNil)

			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, bdigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			// check artifacts are gc'ed
			_, _, _, err := imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
			So(err, ShouldNotBeNil)

			// check it gc'ed repo
			exists := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
			So(exists, ShouldBeFalse)
		})
	})
}

func TestGCSGarbageCollectImageIndex(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	testLog := log.NewTestLogger()
	audit := log.NewAuditLogger("debug", "")

	ctx := context.Background()

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupStorage(storeDriver, testDir)

	Convey("Garbage collect with short delay", t, func(c C) {
		gcDelay := 2 * time.Second
		imageRetentionDelay := 2 * time.Second

		garbageCollect := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
			Delay: gcDelay,
			ImageRetention: config.ImageRetention{
				Delay: imageRetentionDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
						DeleteUntagged:  &trueVal,
					},
				},
			},
		}, audit, testLog)

		// upload orphan blob
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		odigest := godigest.FromBytes(content)

		blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, odigest)
		So(err, ShouldBeNil)

		bdgst, digest, indexDigest, indexSize := pushRandomImageIndexGCS(imgStore, repoName)

		// put artifact referencing above image
		artifactBlob := []byte("artifact")
		artifactBlobDigest := godigest.FromBytes(artifactBlob)

		// push layer
		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
		So(err, ShouldBeNil)

		// push config
		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
			ispec.DescriptorEmptyJSON.Digest)
		So(err, ShouldBeNil)

		// push artifact manifest pointing to index
		artifactManifest := ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/octet-stream",
					Digest:    artifactBlobDigest,
					Size:      int64(len(artifactBlob)),
				},
			},
			Config: ispec.DescriptorEmptyJSON,
			Subject: &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    indexDigest,
				Size:      indexSize,
			},
			ArtifactType: "application/forIndex",
		}
		artifactManifest.SchemaVersion = 2

		artifactManifestBuf, err := json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		artifactDigest := godigest.FromBytes(artifactManifestBuf)

		// push artifact manifest
		_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestBuf)
		So(err, ShouldBeNil)

		hasBlob, _, err := imgStore.CheckBlob(repoName, bdgst)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		time.Sleep(2 * time.Second)

		Convey("delete index manifest, references should not be persisted", func() {
			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest(repoName, indexDigest.String(), false)
			So(err, ShouldBeNil)

			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldNotBeNil)

			// orphan blob
			hasBlob, _, err = imgStore.CheckBlob(repoName, odigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, bdgst)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			// check last manifest from index image
			hasBlob, _, err = imgStore.CheckBlob(repoName, digest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			// check referrer is gc'ed
			_, _, _, err := imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldNotBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			// check it gc'ed repo
			exists := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
			So(exists, ShouldBeFalse)
		})
	})
}

func TestGCSGarbageCollectChainedImageIndexes(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	testLog := log.NewTestLogger()
	audit := log.NewAuditLogger("debug", "")

	ctx := context.Background()

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupStorage(storeDriver, testDir)

	Convey("Garbage collect with short delay", t, func() {
		gcDelay := 5 * time.Second
		imageRetentionDelay := 5 * time.Second

		garbageCollect := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
			Delay: gcDelay,
			ImageRetention: config.ImageRetention{
				Delay: imageRetentionDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
						DeleteUntagged:  &trueVal,
					},
				},
			},
		}, audit, testLog)

		// upload orphan blob
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		odigest := godigest.FromBytes(content)

		blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, odigest)
		So(err, ShouldBeNil)

		content = []byte("this is a blob")
		bdgst := godigest.FromBytes(content)
		So(bdgst, ShouldNotBeNil)

		_, bsize, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), bdgst)
		So(err, ShouldBeNil)
		So(bsize, ShouldEqual, len(content))

		artifactBlob := []byte("artifact")
		artifactBlobDigest := godigest.FromBytes(artifactBlob)

		// push layer
		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(artifactBlob), artifactBlobDigest)
		So(err, ShouldBeNil)

		// push config
		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(ispec.DescriptorEmptyJSON.Data),
			ispec.DescriptorEmptyJSON.Digest)
		So(err, ShouldBeNil)

		var index ispec.Index
		index.SchemaVersion = 2
		index.MediaType = ispec.MediaTypeImageIndex

		var digest godigest.Digest

		for range 4 {
			// upload image config blob
			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := GetRandomImageConfig()
			buf := bytes.NewBuffer(cblob)
			buflen := buf.Len()
			blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    bdgst,
						Size:      bsize,
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)

			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			index.Manifests = append(index.Manifests, ispec.Descriptor{
				Digest:    digest,
				MediaType: ispec.MediaTypeImageManifest,
				Size:      int64(len(content)),
			})

			// for each manifest inside index, push an artifact
			artifactManifest := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Layers: []ispec.Descriptor{
					{
						MediaType: "application/octet-stream",
						Digest:    artifactBlobDigest,
						Size:      int64(len(artifactBlob)),
					},
				},
				Config: ispec.DescriptorEmptyJSON,
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    digest,
					Size:      int64(len(content)),
				},
				ArtifactType: "application/forManifestInInnerIndex",
			}
			artifactManifest.SchemaVersion = 2

			artifactManifestBuf, err := json.Marshal(artifactManifest)
			So(err, ShouldBeNil)

			artifactDigest := godigest.FromBytes(artifactManifestBuf)

			// push artifact manifest
			_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
				ispec.MediaTypeImageManifest, artifactManifestBuf)
			So(err, ShouldBeNil)
		}

		// also add a new image index inside this one
		var innerIndex ispec.Index
		innerIndex.SchemaVersion = 2
		innerIndex.MediaType = ispec.MediaTypeImageIndex

		for range 3 {
			// upload image config blob
			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := GetRandomImageConfig()
			buf := bytes.NewBuffer(cblob)
			buflen := buf.Len()
			blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    bdgst,
						Size:      bsize,
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)

			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			innerIndex.Manifests = append(innerIndex.Manifests, ispec.Descriptor{
				Digest:    digest,
				MediaType: ispec.MediaTypeImageManifest,
				Size:      int64(len(content)),
			})
		}

		// upload inner index image
		innerIndexContent, err := json.Marshal(index)
		So(err, ShouldBeNil)

		innerIndexDigest := godigest.FromBytes(innerIndexContent)
		So(innerIndexDigest, ShouldNotBeNil)

		_, _, err = imgStore.PutImageManifest(repoName, innerIndexDigest.String(),
			ispec.MediaTypeImageIndex, innerIndexContent)
		So(err, ShouldBeNil)

		// add inner index into root index
		index.Manifests = append(index.Manifests, ispec.Descriptor{
			Digest:    innerIndexDigest,
			MediaType: ispec.MediaTypeImageIndex,
			Size:      int64(len(innerIndexContent)),
		})

		// push root index
		// upload index image
		indexContent, err := json.Marshal(index)
		So(err, ShouldBeNil)

		indexDigest := godigest.FromBytes(indexContent)
		So(indexDigest, ShouldNotBeNil)

		_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageIndex, indexContent)
		So(err, ShouldBeNil)

		artifactManifest := ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/octet-stream",
					Digest:    artifactBlobDigest,
					Size:      int64(len(artifactBlob)),
				},
			},
			Config: ispec.DescriptorEmptyJSON,
			Subject: &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    indexDigest,
				Size:      int64(len(indexContent)),
			},
			ArtifactType: "application/forIndex",
		}
		artifactManifest.SchemaVersion = 2

		artifactManifestBuf, err := json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		artifactDigest := godigest.FromBytes(artifactManifestBuf)

		// push artifact manifest
		_, _, err = imgStore.PutImageManifest(repoName, artifactDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestBuf)
		So(err, ShouldBeNil)

		artifactManifest.Subject = &ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    digest,
			Size:      int64(len(content)),
		}
		artifactManifest.ArtifactType = "application/forManifestInIndex"

		artifactManifestIndexBuf, err := json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		artifactManifestIndexDigest := godigest.FromBytes(artifactManifestIndexBuf)

		// push artifact manifest referencing a manifest from index image
		_, _, err = imgStore.PutImageManifest(repoName, artifactManifestIndexDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestIndexBuf)
		So(err, ShouldBeNil)

		artifactManifest.Subject = &ispec.Descriptor{
			MediaType: ispec.MediaTypeImageIndex,
			Digest:    innerIndexDigest,
			Size:      int64(len(innerIndexContent)),
		}
		artifactManifest.ArtifactType = "application/forInnerIndex"

		artifactManifestInnerIndexBuf, err := json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		artifactManifestInnerIndexDigest := godigest.FromBytes(artifactManifestInnerIndexBuf)

		// push artifact manifest referencing a manifest from index image
		_, _, err = imgStore.PutImageManifest(repoName, artifactManifestInnerIndexDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestInnerIndexBuf)
		So(err, ShouldBeNil)

		// push artifact manifest pointing to artifact above

		artifactManifest.Subject = &ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    artifactDigest,
			Size:      int64(len(artifactManifestBuf)),
		}
		artifactManifest.ArtifactType = "application/forArtifact"

		artifactManifestBuf, err = json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		artifactOfArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)
		_, _, err = imgStore.PutImageManifest(repoName, artifactOfArtifactManifestDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestBuf)
		So(err, ShouldBeNil)

		// push orphan artifact (missing subject)
		artifactManifest.Subject = &ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    godigest.FromBytes([]byte("miss")),
			Size:      int64(30),
		}
		artifactManifest.ArtifactType = "application/orphan"

		artifactManifestBuf, err = json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		orphanArtifactManifestDigest := godigest.FromBytes(artifactManifestBuf)

		// push orphan artifact manifest
		_, _, err = imgStore.PutImageManifest(repoName, orphanArtifactManifestDigest.String(),
			ispec.MediaTypeImageManifest, artifactManifestBuf)
		So(err, ShouldBeNil)

		hasBlob, _, err := imgStore.CheckBlob(repoName, bdgst)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		hasBlob, _, _, err = imgStore.StatBlob(repoName, bdgst)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		time.Sleep(5 * time.Second)

		Convey("delete inner referenced manifest", func() {
			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			// check orphan artifact is gc'ed
			_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest(repoName, artifactDigest.String(), false)
			So(err, ShouldBeNil)

			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
			So(err, ShouldBeNil)
		})

		Convey("delete index manifest, references should not be persisted", func() {
			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			// check orphan artifact is gc'ed
			_, _, _, err = imgStore.GetImageManifest(repoName, orphanArtifactManifestDigest.String())
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest(repoName, indexDigest.String(), false)
			So(err, ShouldBeNil)

			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactOfArtifactManifestDigest.String())
			So(err, ShouldNotBeNil)

			// orphan blob
			hasBlob, _, err = imgStore.CheckBlob(repoName, odigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, _, err = imgStore.StatBlob(repoName, odigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			// check artifact is gc'ed
			_, _, _, err := imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldNotBeNil)

			// check inner index artifact is gc'ed
			_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestInnerIndexDigest.String())
			So(err, ShouldNotBeNil)

			// check last manifest from index image
			hasBlob, _, err = imgStore.CheckBlob(repoName, digest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactManifestIndexDigest.String())
			So(err, ShouldNotBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, artifactBlobDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, bdgst)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			// check it gc'ed repo
			exists := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
			So(exists, ShouldBeFalse)
		})
	})
}

func TestGCSCheckAllBlobsIntegrity(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	Convey("test with GCS storage", t, func() {
		uuid, err := guuid.NewV4()
		So(err, ShouldBeNil)

		testDir := path.Join("/oci-repo-test", uuid.String())
		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)

		defer cleanupStorage(storeDriver, testDir)

		testLog := log.NewTestLogger()

		RunGCSCheckAllBlobsIntegrityTests(t, imgStore, gcs.New(storeDriver), testLog)
	})
}

func RunGCSCheckAllBlobsIntegrityTests( //nolint: thelper
	t *testing.T, imgStore storageTypes.ImageStore, driver storageTypes.Driver, testLog log.Logger,
) {
	Convey("Scrub only one repo", func() {
		// initialize repo
		err := imgStore.InitRepo(repoName)
		So(err, ShouldBeNil)

		ok := imgStore.DirExists(path.Join(imgStore.RootDir(), repoName))
		So(ok, ShouldBeTrue)

		storeCtlr := storage.StoreController{}
		storeCtlr.DefaultStore = imgStore
		So(storeCtlr.GetImageStore(repoName), ShouldResemble, imgStore)

		image := CreateRandomImage()

		err = WriteImageToFileSystem(image, repoName, "1.0", storeCtlr)
		So(err, ShouldBeNil)

		Convey("Blobs integrity not affected", func() {
			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")

			err = WriteMultiArchImageToFileSystem(CreateMultiarchWith().RandomImages(0).Build(), repoName, "2.0", storeCtlr)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test 2.0 ok")
		})

		Convey("Blobs integrity with context done", func() {
			buff := bytes.NewBufferString("")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			res, err := storeCtlr.CheckAllBlobsIntegrity(ctx)
			res.PrintScrubResults(buff)
			So(err, ShouldNotBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "test 1.0 ok")
		})

		Convey("Manifest integrity affected", func() {
			// get content of manifest file
			content, _, _, err := imgStore.GetImageManifest(repoName, image.ManifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			defer func() {
				// put manifest content back to file
				_, err = driver.WriteFile(manifestFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "affected")

			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)

			_, err = driver.WriteFile(manifestFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			// verify error message
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s invalid manifest content", manifestDig))

			index, err = common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
			manifestDescriptor := index.Manifests[0]

			_, _, err = storage.CheckManifestAndConfig(repoName, manifestDescriptor, []byte("invalid content"), imgStore)
			So(err, ShouldNotBeNil)
		})

		Convey("Config integrity affected", func() {
			// get content of config file
			content, err := imgStore.GetBlobContent(repoName, image.ConfigDescriptor.Digest)
			So(err, ShouldBeNil)

			// delete content of config file
			configDig := image.ConfigDescriptor.Digest.Encoded()
			configFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", configDig)
			err = driver.Delete(configFile)
			So(err, ShouldBeNil)

			defer func() {
				// put config content back to file
				_, err = driver.WriteFile(configFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", configDig))

			_, err = driver.WriteFile(configFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s invalid server config", configDig))
		})

		Convey("Layers integrity affected", func() {
			// get content of layer
			content, err := imgStore.GetBlobContent(repoName, image.Manifest.Layers[0].Digest)
			So(err, ShouldBeNil)

			// delete content of layer file
			layerDig := image.Manifest.Layers[0].Digest.Encoded()
			layerFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", layerDig)
			_, err = driver.WriteFile(layerFile, []byte(" "))
			So(err, ShouldBeNil)

			defer func() {
				// put layer content back to file
				_, err = driver.WriteFile(layerFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s bad blob digest", layerDig))
		})

		Convey("Layer not found", func() {
			// get content of layer
			digest := image.Manifest.Layers[0].Digest
			content, err := imgStore.GetBlobContent(repoName, digest)
			So(err, ShouldBeNil)

			// change layer file permissions
			layerDig := image.Manifest.Layers[0].Digest.Encoded()
			repoDir := path.Join(imgStore.RootDir(), repoName)
			layerFile := path.Join(repoDir, "/blobs/sha256", layerDig)
			err = driver.Delete(layerFile)
			So(err, ShouldBeNil)

			defer func() {
				_, err := driver.WriteFile(layerFile, content)
				So(err, ShouldBeNil)
			}()

			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)

			// get content of layer
			imageRes := storage.CheckLayers(repoName, "1.0", []ispec.Descriptor{{Digest: digest}}, imgStore)
			So(imageRes.Status, ShouldEqual, "affected")
			So(imageRes.Error, ShouldEqual, "blob not found")

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", layerDig))
		})

		Convey("Scrub index with missing manifest blob - graceful handling", func() {
			// Create a multiarch image with multiple manifests
			multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
			err = WriteMultiArchImageToFileSystem(multiarchImage, repoName, "2.0", storeCtlr)
			So(err, ShouldBeNil)

			// Get the index to find the index manifest digest
			idx, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			// Find the index manifest
			var indexManifestDesc ispec.Descriptor

			for _, desc := range idx.Manifests {
				if desc.MediaType == ispec.MediaTypeImageIndex {
					indexManifestDesc = desc

					break
				}
			}

			// Get the index content to find the manifest digests within it
			indexBlob, err := imgStore.GetBlobContent(repoName, indexManifestDesc.Digest)
			So(err, ShouldBeNil)

			var indexContent ispec.Index
			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			// Delete one of the manifest blobs within the index (but not all)
			missingManifestDig := indexContent.Manifests[0].Digest.Encoded()
			missingManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", missingManifestDig)
			err = driver.Delete(missingManifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the index as affected due to missing manifest
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 2.0 affected")
			// Should continue processing and report the missing manifest
			So(actual, ShouldContainSubstring, missingManifestDig)
		})

		Convey("Scrub index with non-missing error on manifest blob via file permissions", func() {
			// Skip for non-local storage
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			// Create a multiarch image with multiple manifests
			multiarchImage := CreateMultiarchWith().RandomImages(2).Build()
			err = WriteMultiArchImageToFileSystem(multiarchImage, repoName, "2.1", storeCtlr)
			So(err, ShouldBeNil)

			// Get the index to find the index manifest digest
			idx, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			// Find the index manifest
			var indexManifestDesc ispec.Descriptor

			for _, desc := range idx.Manifests {
				if desc.MediaType == ispec.MediaTypeImageIndex {
					indexManifestDesc = desc

					break
				}
			}

			// Get the index content to find the manifest digests within it
			indexBlob, err := imgStore.GetBlobContent(repoName, indexManifestDesc.Digest)
			So(err, ShouldBeNil)

			var indexContent ispec.Index
			err = json.Unmarshal(indexBlob, &indexContent)
			So(err, ShouldBeNil)

			// Remove read permissions on one of the manifest blobs to cause a permission denied error (non-missing error)
			manifestDig := indexContent.Manifests[0].Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = os.Chmod(manifestFile, 0o000)
			So(err, ShouldBeNil)

			// Restore permissions after test
			defer func() {
				_ = os.Chmod(manifestFile, 0o644)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the index as affected due to non-missing error on manifest
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 2.1 affected")
			// Should report the manifest digest as affected blob
			So(actual, ShouldContainSubstring, manifestDig)
			// Should have "bad blob digest" error
			So(actual, ShouldContainSubstring, "bad blob digest")
		})

		Convey("Scrub index", func() {
			newImage := CreateRandomImage()
			newManifestDigest := newImage.ManifestDescriptor.Digest

			err = WriteImageToFileSystem(newImage, repoName, "2.0", storeCtlr)
			So(err, ShouldBeNil)

			idx, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(idx, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			var index ispec.Index
			index.SchemaVersion = 2
			index.Subject = &manifestDescriptor
			index.Manifests = []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    newManifestDigest,
					Size:      newImage.ManifestDescriptor.Size,
				},
			}

			indexBlob, err := json.Marshal(index)
			So(err, ShouldBeNil)
			indexDigest, _, err := imgStore.PutImageManifest(repoName, "", ispec.MediaTypeImageIndex, indexBlob)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test ok")

			// test scrub context done
			buff = bytes.NewBufferString("")

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			res, err = storeCtlr.CheckAllBlobsIntegrity(ctx)
			res.PrintScrubResults(buff)
			So(err, ShouldNotBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, "test 1.0 ok")
			So(actual, ShouldNotContainSubstring, "test ok")

			// test scrub index - errors
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", newManifestDigest.Encoded())
			_, err = driver.WriteFile(manifestFile, []byte("invalid content"))
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			// delete content of manifest file
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			indexFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", indexDigest.Encoded())
			err = driver.Delete(indexFile)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldNotContainSubstring, "test affected")

			index.Manifests[0].MediaType = "invalid"
			indexBlob, err = json.Marshal(index)
			So(err, ShouldBeNil)

			_, err = driver.WriteFile(indexFile, indexBlob)
			So(err, ShouldBeNil)

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			_, _, err = storage.CheckManifestAndConfig(repoName, index.Manifests[0], []byte{}, imgStore)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrBadManifest)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")

			_, err = driver.WriteFile(indexFile, []byte("invalid cotent"))
			So(err, ShouldBeNil)

			defer func() {
				err := driver.Delete(indexFile)
				So(err, ShouldBeNil)
			}()

			buff = bytes.NewBufferString("")

			res, err = storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			str = space.ReplaceAllString(buff.String(), " ")
			actual = strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test affected")
		})

		Convey("Manifest not found", func() {
			// delete manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldNotContainSubstring, fmt.Sprintf("test 1.0 affected %s blob not found", manifestDig))

			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			So(len(index.Manifests), ShouldEqual, 1)
		})

		Convey("use the result of an already scrubed manifest which is the subject of the current manifest", func() {
			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			err = WriteImageToFileSystem(CreateDefaultImageWith().Subject(&manifestDescriptor).Build(),
				repoName, "0.0.1", storeCtlr)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 1.0 ok")
			So(actual, ShouldContainSubstring, "test 0.0.1 ok")
		})

		Convey("preserve affected status when CheckLayers would overwrite it", func() {
			// Create an image with a subject
			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			subjectImage := CreateDefaultImageWith().Subject(&manifestDescriptor).Build()
			err = WriteImageToFileSystem(subjectImage, repoName, "0.0.3", storeCtlr)
			So(err, ShouldBeNil)

			// Delete the subject manifest to mark it as affected
			subjectManifestDig := manifestDescriptor.Digest.Encoded()
			subjectManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", subjectManifestDig)
			err = driver.Delete(subjectManifestFile)
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// The manifest with the missing subject should be marked as affected
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.3 affected")
			// Even if CheckLayers would pass, the affected status from the missing subject should be preserved
			So(actual, ShouldContainSubstring, subjectManifestDig)
		})

		Convey("the subject of the current manifest doesn't exist", func() {
			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			err = WriteImageToFileSystem(CreateDefaultImageWith().Subject(&manifestDescriptor).Build(),
				repoName, "0.0.2", storeCtlr)
			So(err, ShouldBeNil)

			// get content of manifest file
			content, _, _, err := imgStore.GetImageManifest(repoName, manifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			defer func() {
				// put manifest content back to file
				_, err = driver.WriteFile(manifestFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.2 affected")
		})

		Convey("the subject of the current index doesn't exist", func() {
			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			err = WriteMultiArchImageToFileSystem(CreateMultiarchWith().RandomImages(1).Subject(&manifestDescriptor).Build(),
				repoName, "0.0.2", storeCtlr)
			So(err, ShouldBeNil)

			// get content of manifest file
			content, _, _, err := imgStore.GetImageManifest(repoName, manifestDescriptor.Digest.String())
			So(err, ShouldBeNil)

			// delete content of manifest file
			manifestDig := image.ManifestDescriptor.Digest.Encoded()
			manifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", manifestDig)
			err = driver.Delete(manifestFile)
			So(err, ShouldBeNil)

			defer func() {
				// put manifest content back to file
				_, err = driver.WriteFile(manifestFile, content)
				So(err, ShouldBeNil)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.2 affected")
		})

		Convey("test errors", func() {
			mockedImgStore := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{repoName}, nil
				},
				ValidateRepoFn: func(name string) (bool, error) {
					return false, nil
				},
			}

			storeController := storage.StoreController{}
			storeController.DefaultStore = mockedImgStore

			_, err := storeController.CheckAllBlobsIntegrity(context.Background())
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrRepoBadLayout)

			mockedImgStore = mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{repoName}, nil
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte{}, errUnexpectedError
				},
			}

			storeController.DefaultStore = mockedImgStore

			_, err = storeController.CheckAllBlobsIntegrity(context.Background())
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, errUnexpectedError)

			manifestDigest := godigest.FromString("abcd")

			mockedImgStore = mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{repoName}, nil
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					var index ispec.Index
					index.SchemaVersion = 2
					index.Manifests = []ispec.Descriptor{
						{
							MediaType:   "InvalidMediaType",
							Digest:      manifestDigest,
							Size:        int64(100),
							Annotations: map[string]string{ispec.AnnotationRefName: "1.0"},
						},
					}

					return json.Marshal(index)
				},
			}

			storeController.DefaultStore = mockedImgStore

			res, err := storeController.CheckAllBlobsIntegrity(context.Background())
			So(err, ShouldBeNil)

			buff := bytes.NewBufferString("")
			res.PrintScrubResults(buff)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, fmt.Sprintf("%s 1.0 affected %s invalid manifest content",
				repoName, manifestDigest.Encoded()))
		})

		Convey("scrub with non-missing error on manifest subject blob via file permissions", func() {
			// Skip for non-local storage
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			// Create an image with a subject
			subjectImage := CreateDefaultImageWith().Subject(&manifestDescriptor).Build()
			err = WriteImageToFileSystem(subjectImage, repoName, "0.0.6", storeCtlr)
			So(err, ShouldBeNil)

			// Get the subject manifest digest
			subjectManifestDig := manifestDescriptor.Digest.Encoded()
			subjectManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", subjectManifestDig)

			// Remove read permissions to cause a permission denied error (non-missing error)
			err = os.Chmod(subjectManifestFile, 0o000)
			So(err, ShouldBeNil)

			// Restore permissions after test
			defer func() {
				_ = os.Chmod(subjectManifestFile, 0o644)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the manifest as affected due to non-missing error on subject
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.6 affected")
			// Should report the subject digest as affected blob
			So(actual, ShouldContainSubstring, subjectManifestDig)
			// Should have "bad blob digest" error
			So(actual, ShouldContainSubstring, "bad blob digest")
		})

		Convey("scrub with non-missing error on index subject blob via file permissions", func() {
			// Skip for non-local storage
			if driver.Name() != storageConstants.LocalStorageDriverName {
				return
			}

			index, err := common.GetIndex(imgStore, repoName, testLog)
			So(err, ShouldBeNil)

			manifestDescriptor, ok := common.GetManifestDescByReference(index, image.ManifestDescriptor.Digest.String())
			So(ok, ShouldBeTrue)

			// Create a multiarch image with a subject
			err = WriteMultiArchImageToFileSystem(CreateMultiarchWith().RandomImages(1).Subject(&manifestDescriptor).Build(),
				repoName, "0.0.7", storeCtlr)
			So(err, ShouldBeNil)

			// Get the subject manifest digest
			subjectManifestDig := manifestDescriptor.Digest.Encoded()
			subjectManifestFile := path.Join(imgStore.RootDir(), repoName, "/blobs/sha256", subjectManifestDig)

			// Remove read permissions to cause a permission denied error (non-missing error)
			err = os.Chmod(subjectManifestFile, 0o000)
			So(err, ShouldBeNil)

			// Restore permissions after test
			defer func() {
				_ = os.Chmod(subjectManifestFile, 0o644)
			}()

			buff := bytes.NewBufferString("")

			res, err := storeCtlr.CheckAllBlobsIntegrity(context.Background())
			res.PrintScrubResults(buff)
			So(err, ShouldBeNil)

			space := regexp.MustCompile(`\s+`)
			str := space.ReplaceAllString(buff.String(), " ")
			actual := strings.TrimSpace(str)

			// Should mark the index as affected due to non-missing error on subject
			So(actual, ShouldContainSubstring, "REPOSITORY TAG STATUS AFFECTED BLOB ERROR")
			So(actual, ShouldContainSubstring, "test 0.0.7 affected")
			// Should report the subject digest as affected blob
			So(actual, ShouldContainSubstring, subjectManifestDig)
			// Should have "bad blob digest" error
			So(actual, ShouldContainSubstring, "bad blob digest")
		})
	})
}
