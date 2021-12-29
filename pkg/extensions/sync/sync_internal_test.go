package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	goSync "sync"
	"testing"
	"time"

	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/resty.v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	. "zotregistry.io/zot/test"
)

const (
	testImage    = "zot-test"
	testImageTag = "0.0.1"

	host = "127.0.0.1:45117"
)

func TestSyncInternal(t *testing.T) {
	Convey("Verify parseRepositoryReference func", t, func() {
		repositoryReference := fmt.Sprintf("%s/%s", host, testImage)
		ref, err := parseRepositoryReference(repositoryReference)
		So(err, ShouldBeNil)
		So(ref.Name(), ShouldEqual, repositoryReference)

		repositoryReference = fmt.Sprintf("%s/%s:tagged", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldEqual, errors.ErrInvalidRepositoryName)

		repositoryReference = fmt.Sprintf("http://%s/%s", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldNotBeNil)

		repositoryReference = fmt.Sprintf("docker://%s/%s", host, testImage)
		_, err = parseRepositoryReference(repositoryReference)
		So(err, ShouldNotBeNil)

		_, err = getFileCredentials("/path/to/inexistent/file")
		So(err, ShouldNotBeNil)

		tempFile, err := ioutil.TempFile("", "sync-credentials-")
		if err != nil {
			panic(err)
		}

		content := []byte(`{`)
		if err := ioutil.WriteFile(tempFile.Name(), content, 0o600); err != nil {
			panic(err)
		}

		_, err = getFileCredentials(tempFile.Name())
		So(err, ShouldNotBeNil)

		srcCtx := &types.SystemContext{}
		_, err = getImageTags(context.Background(), srcCtx, ref)
		So(err, ShouldNotBeNil)

		taggedRef, err := reference.WithTag(ref, "tag")
		So(err, ShouldBeNil)

		_, err = getImageTags(context.Background(), &types.SystemContext{}, taggedRef)
		So(err, ShouldNotBeNil)

		dockerRef, err := docker.NewReference(taggedRef)
		So(err, ShouldBeNil)

		// tag := getTagFromRef(dockerRef, log.NewLogger("", ""))

		So(getTagFromRef(dockerRef, log.NewLogger("debug", "")), ShouldNotBeNil)

		var tlsVerify bool
		updateDuration := time.Microsecond
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		syncRegistryConfig := RegistryConfig{
			Content: []Content{
				{
					Prefix: testImage,
				},
			},
			URLs:         []string{baseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "",
		}

		cfg := Config{Registries: []RegistryConfig{syncRegistryConfig}, CredentialsFile: "/invalid/path/to/file"}

		So(Run(cfg, storage.StoreController{}, new(goSync.WaitGroup), log.NewLogger("debug", "")), ShouldNotBeNil)

		_, err = getFileCredentials("/invalid/path/to/file")
		So(err, ShouldNotBeNil)
	})

	Convey("Test getUpstreamCatalog() with missing certs", t, func() {
		var tlsVerify bool
		updateDuration := time.Microsecond
		syncRegistryConfig := RegistryConfig{
			Content: []Content{
				{
					Prefix: testImage,
				},
			},
			URLs:         []string{BaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "/tmp/missing_certs/a/b/c/d/z",
		}

		port := GetFreePort()
		baseURL := GetBaseURL(port)

		httpClient, err := getHTTPClient(&syncRegistryConfig, baseURL, Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(httpClient, ShouldBeNil)
		// _, err = getUpstreamCatalog(httpClient, baseURL, log.NewLogger("debug", ""))
		// So(err, ShouldNotBeNil)
	})

	Convey("Test getHttpClient() with bad certs", t, func() {
		badCertsDir, err := ioutil.TempDir("", "bad_certs*")
		if err != nil {
			panic(err)
		}

		if err := os.WriteFile(path.Join(badCertsDir, "ca.crt"), []byte("certificate"), 0o600); err != nil {
			panic(err)
		}

		defer os.RemoveAll(badCertsDir)

		var tlsVerify bool
		updateDuration := time.Microsecond
		port := GetFreePort()
		baseURL := GetBaseURL(port)
		baseSecureURL := GetSecureBaseURL(port)

		syncRegistryConfig := RegistryConfig{
			Content: []Content{
				{
					Prefix: testImage,
				},
			},
			URLs:         []string{baseURL, "invalidUrl]"},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      badCertsDir,
		}

		httpClient, err := getHTTPClient(&syncRegistryConfig, baseURL, Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(httpClient, ShouldBeNil)

		syncRegistryConfig.CertDir = "/path/to/invalid/cert"
		httpClient, err = getHTTPClient(&syncRegistryConfig, baseURL, Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(httpClient, ShouldBeNil)

		syncRegistryConfig.CertDir = ""
		syncRegistryConfig.URLs = []string{baseSecureURL}

		httpClient, err = getHTTPClient(&syncRegistryConfig, baseSecureURL, Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(httpClient, ShouldNotBeNil)

		_, err = getUpstreamCatalog(httpClient, baseURL, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		_, err = getUpstreamCatalog(httpClient, "http://invalid:5000", log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		syncRegistryConfig.URLs = []string{BaseURL}
		httpClient, err = getHTTPClient(&syncRegistryConfig, baseSecureURL, Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(httpClient, ShouldBeNil)

		httpClient, err = getHTTPClient(&syncRegistryConfig, "invalidUrl]", Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(httpClient, ShouldBeNil)
	})

	Convey("Test imagesToCopyFromUpstream()", t, func() {
		repos := []string{"repo1"}
		upstreamCtx := &types.SystemContext{}

		_, err := imagesToCopyFromUpstream("localhost:4566", repos, upstreamCtx, Content{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		_, err = imagesToCopyFromUpstream("docker://localhost:4566", repos, upstreamCtx,
			Content{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})

	Convey("Test OneImage() skips cosign signatures", t, func() {
		err := OneImage(Config{}, storage.StoreController{}, "repo", "sha256-.sig", log.NewLogger("", ""))
		So(err, ShouldBeNil)
	})

	Convey("Test syncSignatures()", t, func() {
		log := log.NewLogger("", "")
		err := syncSignatures(resty.New(), storage.StoreController{}, "%", "repo", "tag", log)
		So(err, ShouldNotBeNil)
		err = syncSignatures(resty.New(), storage.StoreController{}, "http://zot", "repo", "tag", log)
		So(err, ShouldNotBeNil)
		err = syncSignatures(resty.New(), storage.StoreController{}, "https://google.com", "repo", "tag", log)
		So(err, ShouldNotBeNil)
		url, _ := url.Parse("invalid")
		err = syncCosignSignature(resty.New(), storage.StoreController{}, *url, "repo", "tag", log)
		So(err, ShouldNotBeNil)
		err = syncNotarySignature(resty.New(), storage.StoreController{}, *url, "repo", "tag", log)
		So(err, ShouldNotBeNil)
	})

	Convey("Test filterRepos()", t, func() {
		repos := []string{"repo", "repo1", "repo2", "repo/repo2", "repo/repo2/repo3/repo4"}
		contents := []Content{
			{
				Prefix: "repo",
			},
			{
				Prefix: "/repo/**",
			},
			{
				Prefix: "repo*",
			},
		}
		filteredRepos := filterRepos(repos, contents, log.NewLogger("", ""))
		So(filteredRepos[0], ShouldResemble, []string{"repo"})
		So(filteredRepos[1], ShouldResemble, []string{"repo/repo2", "repo/repo2/repo3/repo4"})
		So(filteredRepos[2], ShouldResemble, []string{"repo1", "repo2"})

		contents = []Content{
			{
				Prefix: "[repo%#@",
			},
		}

		filteredRepos = filterRepos(repos, contents, log.NewLogger("", ""))
		So(len(filteredRepos), ShouldEqual, 0)
	})

	Convey("Verify pushSyncedLocalImage func", t, func() {
		storageDir, err := ioutil.TempDir("", "oci-dest-repo-test")
		if err != nil {
			panic(err)
		}

		defer os.RemoveAll(storageDir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := storage.NewImageStore(storageDir, false, false, log, metrics)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imageStore

		err = pushSyncedLocalImage(testImage, testImageTag, "", storeController, log)
		So(err, ShouldNotBeNil)

		testRootDir := path.Join(imageStore.RootDir(), testImage, SyncBlobUploadDir)
		// testImagePath := path.Join(testRootDir, testImage)

		err = os.MkdirAll(testRootDir, 0o755)
		if err != nil {
			panic(err)
		}

		err = CopyFiles("../../../test/data", testRootDir)
		if err != nil {
			panic(err)
		}

		testImageStore := storage.NewImageStore(testRootDir, false, false, log, metrics)
		manifestContent, _, _, err := testImageStore.GetImageManifest(testImage, testImageTag)
		So(err, ShouldBeNil)

		var manifest ispec.Manifest

		if err := json.Unmarshal(manifestContent, &manifest); err != nil {
			panic(err)
		}

		if err := os.Chmod(storageDir, 0o000); err != nil {
			panic(err)
		}

		if os.Geteuid() != 0 {
			So(func() {
				_ = pushSyncedLocalImage(testImage, testImageTag, "", storeController, log)
			},
				ShouldPanic)
		}

		if err := os.Chmod(storageDir, 0o755); err != nil {
			panic(err)
		}

		if err := os.Chmod(path.Join(testRootDir, testImage, "blobs", "sha256",
			manifest.Layers[0].Digest.Hex()), 0o000); err != nil {
			panic(err)
		}

		err = pushSyncedLocalImage(testImage, testImageTag, "", storeController, log)
		So(err, ShouldNotBeNil)

		if err := os.Chmod(path.Join(testRootDir, testImage, "blobs", "sha256",
			manifest.Layers[0].Digest.Hex()), 0o755); err != nil {
			panic(err)
		}

		cachedManifestConfigPath := path.Join(imageStore.RootDir(), testImage, SyncBlobUploadDir,
			testImage, "blobs", "sha256", manifest.Config.Digest.Hex())
		if err := os.Chmod(cachedManifestConfigPath, 0o000); err != nil {
			panic(err)
		}

		err = pushSyncedLocalImage(testImage, testImageTag, "", storeController, log)
		So(err, ShouldNotBeNil)

		if err := os.Chmod(cachedManifestConfigPath, 0o755); err != nil {
			panic(err)
		}

		manifestConfigPath := path.Join(imageStore.RootDir(), testImage, "blobs", "sha256", manifest.Config.Digest.Hex())
		if err := os.MkdirAll(manifestConfigPath, 0o000); err != nil {
			panic(err)
		}

		err = pushSyncedLocalImage(testImage, testImageTag, "", storeController, log)
		So(err, ShouldNotBeNil)

		if err := os.Remove(manifestConfigPath); err != nil {
			panic(err)
		}

		mDigest := godigest.FromBytes(manifestContent)

		manifestPath := path.Join(imageStore.RootDir(), testImage, "blobs", mDigest.Algorithm().String(), mDigest.Encoded())
		if err := os.MkdirAll(manifestPath, 0o000); err != nil {
			panic(err)
		}

		err = pushSyncedLocalImage(testImage, testImageTag, "", storeController, log)
		So(err, ShouldNotBeNil)
	})
}
