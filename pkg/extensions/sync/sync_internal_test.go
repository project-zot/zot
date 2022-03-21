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
	"zotregistry.io/zot/pkg/test"
)

const (
	testImage    = "zot-test"
	testImageTag = "0.0.1"

	host = "127.0.0.1:45117"
)

func TestInjectSyncUtils(t *testing.T) {
	Convey("Inject errors in utils functions", t, func() {
		repositoryReference := fmt.Sprintf("%s/%s", host, testImage)
		ref, err := parseRepositoryReference(repositoryReference)
		So(err, ShouldBeNil)
		So(ref.Name(), ShouldEqual, repositoryReference)

		taggedRef, err := reference.WithTag(ref, "tag")
		So(err, ShouldBeNil)

		injected := test.InjectFailure(0)
		if injected {
			_, err = getImageTags(context.Background(), &types.SystemContext{}, taggedRef)
			So(err, ShouldNotBeNil)
		}

		injected = test.InjectFailure(0)
		_, _, err = getLocalContexts(log.NewLogger("debug", ""))
		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := storage.NewImageStore(t.TempDir(), false, storage.DefaultGCDelay, false, false, log, metrics)

		injected = test.InjectFailure(0)
		_, _, err = getLocalImageRef(imageStore, testImage, testImageTag)
		if injected {
			So(err, ShouldNotBeNil)
		} else {
			So(err, ShouldBeNil)
		}
	})
}

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

		So(getTagFromRef(dockerRef, log.NewLogger("debug", "")), ShouldNotBeNil)

		var tlsVerify bool
		updateDuration := time.Microsecond
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
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

		defaultValue := true
		cfg := Config{
			Registries:      []RegistryConfig{syncRegistryConfig},
			Enable:          &defaultValue,
			CredentialsFile: "/invalid/path/to/file",
		}
		ctx := context.Background()

		So(Run(ctx, cfg, storage.StoreController{}, new(goSync.WaitGroup), log.NewLogger("debug", "")), ShouldNotBeNil)

		_, err = getFileCredentials("/invalid/path/to/file")
		So(err, ShouldNotBeNil)
	})

	Convey("Verify getLocalImageRef()", t, func() {
		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := storage.NewImageStore(t.TempDir(), false, storage.DefaultGCDelay, false, false, log, metrics)

		err := os.Chmod(imageStore.RootDir(), 0o000)
		So(err, ShouldBeNil)

		_, _, err = getLocalImageRef(imageStore, testImage, testImageTag)
		So(err, ShouldNotBeNil)

		err = os.Chmod(imageStore.RootDir(), 0o755)
		So(err, ShouldBeNil)

		_, _, err = getLocalImageRef(imageStore, "zot][]321", "tag_tag][]")
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
			URLs:         []string{test.BaseURL},
			PollInterval: updateDuration,
			TLSVerify:    &tlsVerify,
			CertDir:      "/tmp/missing_certs/a/b/c/d/z",
		}

		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)

		httpClient, err := getHTTPClient(&syncRegistryConfig, baseURL, Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(httpClient, ShouldBeNil)
		// _, err = getUpstreamCatalog(httpClient, baseURL, log.NewLogger("debug", ""))
		// So(err, ShouldNotBeNil)
	})

	Convey("Test getHttpClient() with bad certs", t, func() {
		badCertsDir := t.TempDir()

		if err := os.WriteFile(path.Join(badCertsDir, "ca.crt"), []byte("certificate"), 0o600); err != nil {
			panic(err)
		}

		var tlsVerify bool
		updateDuration := time.Microsecond
		port := test.GetFreePort()
		baseURL := test.GetBaseURL(port)
		baseSecureURL := test.GetSecureBaseURL(port)

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

		syncRegistryConfig.URLs = []string{test.BaseURL}
		httpClient, err = getHTTPClient(&syncRegistryConfig, baseSecureURL, Credentials{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(httpClient, ShouldBeNil)
	})

	Convey("Test imagesToCopyFromUpstream()", t, func() {
		repos := []string{"repo1"}
		upstreamCtx := &types.SystemContext{}

		_, err := imagesToCopyFromUpstream(context.Background(), "localhost:4566", repos, upstreamCtx,
			Content{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		_, err = imagesToCopyFromUpstream(context.Background(), "docker://localhost:4566", repos, upstreamCtx,
			Content{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})

	// Convey("Test OneImage() skips cosign signatures", t, func() {
	// 	err := OneImage(Config{}, storage.StoreController{}, "repo", "sha256-.sig", log.NewLogger("", ""))
	// 	So(err, ShouldBeNil)
	// })

	Convey("Test syncSignatures()", t, func() {
		log := log.NewLogger("debug", "")
		err := syncSignatures(resty.New(), storage.StoreController{}, "%", "repo", "repo", "tag", log)
		So(err, ShouldNotBeNil)
		err = syncSignatures(resty.New(), storage.StoreController{}, "http://zot", "repo", "repo", "tag", log)
		So(err, ShouldNotBeNil)
		err = syncSignatures(resty.New(), storage.StoreController{}, "https://google.com", "repo", "repo", "tag", log)
		So(err, ShouldNotBeNil)
		url, _ := url.Parse("invalid")
		err = syncCosignSignature(resty.New(), storage.StoreController{}, *url, "repo", "repo", "tag", log)
		So(err, ShouldNotBeNil)
		err = syncNotarySignature(resty.New(), storage.StoreController{}, *url, "repo", "repo", "tag", log)
		So(err, ShouldNotBeNil)
	})

	Convey("Test canSkipImage()", t, func() {
		storageDir := t.TempDir()

		err := test.CopyFiles("../../../test/data", storageDir)
		if err != nil {
			panic(err)
		}

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := storage.NewImageStore(storageDir, false, storage.DefaultGCDelay, false, false, log, metrics)

		repoRefStr := fmt.Sprintf("%s/%s", host, testImage)
		repoRef, err := parseRepositoryReference(repoRefStr)
		So(err, ShouldBeNil)
		So(repoRef, ShouldNotBeNil)

		taggedRef, err := reference.WithTag(repoRef, testImageTag)
		So(err, ShouldBeNil)
		So(taggedRef, ShouldNotBeNil)

		upstreamRef, err := docker.NewReference(taggedRef)
		So(err, ShouldBeNil)
		So(taggedRef, ShouldNotBeNil)

		canBeSkipped, err := canSkipImage(context.Background(), testImage, testImageTag, upstreamRef,
			imageStore, &types.SystemContext{}, log)
		So(err, ShouldNotBeNil)
		So(canBeSkipped, ShouldBeFalse)

		err = os.Chmod(path.Join(imageStore.RootDir(), testImage, "index.json"), 0o000)
		if err != nil {
			panic(err)
		}

		canBeSkipped, err = canSkipImage(context.Background(), testImage, testImageTag, upstreamRef,
			imageStore, &types.SystemContext{}, log)
		So(err, ShouldNotBeNil)
		So(canBeSkipped, ShouldBeFalse)
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
		storageDir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := storage.NewImageStore(storageDir, false, storage.DefaultGCDelay, false, false, log, metrics)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imageStore

		testRootDir := path.Join(imageStore.RootDir(), testImage, SyncBlobUploadDir)
		// testImagePath := path.Join(testRootDir, testImage)

		err := pushSyncedLocalImage(testImage, testImageTag, testRootDir, storeController, log)
		So(err, ShouldNotBeNil)

		err = os.MkdirAll(testRootDir, 0o755)
		if err != nil {
			panic(err)
		}

		err = test.CopyFiles("../../../test/data", testRootDir)
		if err != nil {
			panic(err)
		}

		testImageStore := storage.NewImageStore(testRootDir, false, storage.DefaultGCDelay, false, false, log, metrics)
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
				_ = pushSyncedLocalImage(testImage, testImageTag, testRootDir, storeController, log)
			}, ShouldPanic)
		}

		if err := os.Chmod(storageDir, 0o755); err != nil {
			panic(err)
		}

		if err := os.Chmod(path.Join(testRootDir, testImage, "blobs", "sha256",
			manifest.Layers[0].Digest.Hex()), 0o000); err != nil {
			panic(err)
		}

		err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, storeController, log)
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

		err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, storeController, log)
		So(err, ShouldNotBeNil)

		if err := os.Chmod(cachedManifestConfigPath, 0o755); err != nil {
			panic(err)
		}

		manifestConfigPath := path.Join(imageStore.RootDir(), testImage, "blobs", "sha256", manifest.Config.Digest.Hex())
		if err := os.MkdirAll(manifestConfigPath, 0o000); err != nil {
			panic(err)
		}

		err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, storeController, log)
		So(err, ShouldNotBeNil)

		if err := os.Remove(manifestConfigPath); err != nil {
			panic(err)
		}

		mDigest := godigest.FromBytes(manifestContent)

		manifestPath := path.Join(imageStore.RootDir(), testImage, "blobs", mDigest.Algorithm().String(), mDigest.Encoded())
		if err := os.MkdirAll(manifestPath, 0o000); err != nil {
			panic(err)
		}

		err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, storeController, log)
		So(err, ShouldNotBeNil)
	})
}

func TestURLHelperFunctions(t *testing.T) {
	testCases := []struct {
		repo     string
		content  Content
		expected string
	}{
		{
			repo:     "alpine/zot-fold/alpine",
			content:  Content{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: false},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "zot-fold/alpine",
			content:  Content{Prefix: "zot-fold/alpine", Destination: "/", StripPrefix: false},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "alpine",
			content:  Content{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "/",
			content:  Content{Prefix: "zot-fold/alpine", Destination: "/", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "/",
			content:  Content{Prefix: "/", Destination: "/", StripPrefix: true},
			expected: "/",
		},
		{
			repo:     "alpine",
			content:  Content{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "alpine",
			content:  Content{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "alpine",
			content:  Content{Prefix: "zot-fold/**", Destination: "/", StripPrefix: true},
			expected: "zot-fold/alpine",
		},
		{
			repo:     "zot-fold/alpine",
			content:  Content{Prefix: "zot-fold/**", Destination: "/", StripPrefix: false},
			expected: "zot-fold/alpine",
		},
	}

	Convey("Test getRepoDestination()", t, func() {
		for _, test := range testCases {
			actualResult := getRepoDestination(test.expected, test.content)
			So(actualResult, ShouldEqual, test.repo)
		}
	})

	// this is the inverse function of getRepoDestination()
	Convey("Test getRepoSource()", t, func() {
		for _, test := range testCases {
			actualResult := getRepoSource(test.repo, test.content)
			So(actualResult, ShouldEqual, test.expected)
		}
	})
}

func TestFindRepoMatchingContentID(t *testing.T) {
	testCases := []struct {
		repo     string
		content  []Content
		expected struct {
			contentID int
			err       error
		}
	}{
		{
			repo: "alpine/zot-fold/alpine",
			content: []Content{
				{Prefix: "zot-fold/alpine/", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: false},
			},
			expected: struct {
				contentID int
				err       error
			}{contentID: 1, err: nil},
		},
		{
			repo: "alpine/zot-fold/alpine",
			content: []Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: false},
				{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
			},
			expected: struct {
				contentID int
				err       error
			}{contentID: 0, err: nil},
		},
		{
			repo: "myFold/zot-fold/internal/alpine",
			content: []Content{
				{Prefix: "zot-fold/alpine", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/**", Destination: "/myFold", StripPrefix: false},
			},
			expected: struct {
				contentID int
				err       error
			}{contentID: 1, err: nil},
		},
		{
			repo: "alpine",
			content: []Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/alpine", Destination: "/", StripPrefix: true},
			},
			expected: struct {
				contentID int
				err       error
			}{contentID: -1, err: errors.ErrRegistryNoContent},
		},
		{
			repo: "alpine",
			content: []Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			},
			expected: struct {
				contentID int
				err       error
			}{contentID: 1, err: nil},
		},
		{
			repo: "alpine/alpine",
			content: []Content{
				{Prefix: "zot-fold/*", Destination: "/alpine", StripPrefix: true},
				{Prefix: "zot-fold/*", Destination: "/", StripPrefix: true},
			},
			expected: struct {
				contentID int
				err       error
			}{contentID: 0, err: nil},
		},
	}

	Convey("Test findRepoMatchingContentID()", t, func() {
		for _, test := range testCases {
			actualResult, err := findRepoMatchingContentID(test.repo, test.content)
			So(actualResult, ShouldEqual, test.expected.contentID)
			So(err, ShouldResemble, test.expected.err)
		}
	})
}
