package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/errors"
	. "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
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
		imageStore := local.NewImageStore(t.TempDir(), false, storage.DefaultGCDelay,
			false, false, log, metrics, nil, nil,
		)
		injected = test.InjectFailure(0)

		_, err = getLocalCachePath(imageStore, testImage)
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

		tempFile, err := os.CreateTemp("", "sync-credentials-")
		if err != nil {
			panic(err)
		}

		content := []byte(`{`)
		if err := os.WriteFile(tempFile.Name(), content, 0o600); err != nil {
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

		So(Run(ctx, cfg, storage.StoreController{},
			new(goSync.WaitGroup), log.NewLogger("debug", "")), ShouldNotBeNil)

		_, err = getFileCredentials("/invalid/path/to/file")
		So(err, ShouldNotBeNil)
	})

	Convey("Verify syncRegistry func with wrong upstreamURL", t, func() {
		tlsVerify := false
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

		ctx := context.Background()

		log := log.NewLogger("debug", "")

		metrics := monitoring.NewMetricsServer(false, log)
		imageStore := local.NewImageStore(t.TempDir(), false, storage.DefaultGCDelay,
			false, false, log, metrics, nil, nil,
		)

		localCtx, policyCtx, err := getLocalContexts(log)
		So(err, ShouldBeNil)

		err = syncRegistry(ctx, syncRegistryConfig, "randomUpstreamURL",
			storage.StoreController{DefaultStore: imageStore}, localCtx, policyCtx, Credentials{}, nil, log)
		So(err, ShouldNotBeNil)
	})

	Convey("Verify getLocalImageRef() and getLocalCachePath()", t, func() {
		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := local.NewImageStore(t.TempDir(), false, storage.DefaultGCDelay,
			false, false, log, metrics, nil, nil)

		err := os.Chmod(imageStore.RootDir(), 0o000)
		So(err, ShouldBeNil)

		localCachePath, err := getLocalCachePath(imageStore, testImage)
		So(err, ShouldNotBeNil)

		_, err = getLocalImageRef(localCachePath, testImage, testImageTag)
		So(err, ShouldNotBeNil)

		err = os.Chmod(imageStore.RootDir(), 0o544)
		So(err, ShouldBeNil)

		_, err = getLocalCachePath(imageStore, testImage)
		So(err, ShouldNotBeNil)

		err = os.Chmod(imageStore.RootDir(), 0o755)
		So(err, ShouldBeNil)

		localCachePath, err = getLocalCachePath(imageStore, testImage)
		So(err, ShouldBeNil)

		testPath, _ := path.Split(localCachePath)

		err = os.Chmod(testPath, 0o544)
		So(err, ShouldBeNil)

		_, err = getLocalCachePath(imageStore, testImage)
		So(err, ShouldNotBeNil)

		err = os.Chmod(testPath, 0o755)
		So(err, ShouldBeNil)

		_, err = getLocalImageRef(localCachePath, "zot][]321", "tag_tag][]")
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

		httpClient, err := CreateHTTPClient(*syncRegistryConfig.TLSVerify, baseURL, "")
		So(httpClient, ShouldNotBeNil)
		So(err, ShouldBeNil)
		registryURL, err := url.Parse(baseURL)
		So(registryURL, ShouldNotBeNil)
		So(err, ShouldBeNil)
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

		httpClient, err := CreateHTTPClient(*syncRegistryConfig.TLSVerify, baseURL, "")
		So(httpClient, ShouldNotBeNil)
		So(err, ShouldBeNil)
		registryURL, err := url.Parse(baseURL)
		So(registryURL, ShouldNotBeNil)
		So(err, ShouldBeNil)

		syncRegistryConfig.CertDir = "/path/to/invalid/cert"

		httpClient, err = CreateHTTPClient(*syncRegistryConfig.TLSVerify, baseURL, "")
		So(httpClient, ShouldNotBeNil)
		So(err, ShouldBeNil)
		registryURL, err = url.Parse(baseURL)
		So(registryURL, ShouldNotBeNil)
		So(err, ShouldBeNil)

		syncRegistryConfig.CertDir = ""
		syncRegistryConfig.URLs = []string{baseSecureURL}

		httpClient, err = CreateHTTPClient(*syncRegistryConfig.TLSVerify, baseSecureURL, "")
		So(httpClient, ShouldNotBeNil)
		So(err, ShouldBeNil)
		registryURL, err = url.Parse(baseSecureURL)
		So(registryURL, ShouldNotBeNil)
		So(err, ShouldBeNil)

		_, err = GetUpstreamCatalog(httpClient, baseURL, "", "", log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		_, err = GetUpstreamCatalog(httpClient, "http://invalid:5000", "", "", log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		syncRegistryConfig.URLs = []string{test.BaseURL}
		httpClient, err = CreateHTTPClient(*syncRegistryConfig.TLSVerify, test.BaseURL, "")
		So(httpClient, ShouldNotBeNil)
		So(err, ShouldBeNil)
		registryURL, err = url.Parse(test.BaseURL) //nolint
		So(registryURL, ShouldBeNil)
		So(err, ShouldNotBeNil)

		syncRegistryConfig.URLs = []string{"%"}
		httpClient, err = CreateHTTPClient(*syncRegistryConfig.TLSVerify, test.BaseURL, "")
		So(httpClient, ShouldNotBeNil)
		So(err, ShouldBeNil)
		registryURL, err = url.Parse(test.BaseURL) //nolint
		So(registryURL, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})

	Convey("Test imagesToCopyFromUpstream()", t, func() {
		upstreamCtx := &types.SystemContext{}

		_, err := imagesToCopyFromUpstream(context.Background(), "localhost:4566", "repo1", upstreamCtx,
			Content{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		_, err = imagesToCopyFromUpstream(context.Background(), "docker://localhost:4566", "repo1", upstreamCtx,
			Content{}, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})

	Convey("Test signatures", t, func() {
		log := log.NewLogger("debug", "")

		client := &http.Client{}

		regURL, err := url.Parse("http://zot")
		So(err, ShouldBeNil)
		So(regURL, ShouldNotBeNil)

		ref := artifactspec.Descriptor{
			Digest: "fakeDigest",
		}

		desc := ispec.Descriptor{
			Digest: "fakeDigest",
		}

		manifest := ispec.Manifest{
			Layers: []ispec.Descriptor{desc},
		}

		metrics := monitoring.NewMetricsServer(false, log)
		imageStore := local.NewImageStore(t.TempDir(), false, storage.DefaultGCDelay,
			false, false, log, metrics, nil, nil,
		)

		sig := newSignaturesCopier(client, Credentials{}, *regURL, storage.StoreController{DefaultStore: imageStore}, log)

		err = sig.syncCosignSignature(testImage, testImage, testImageTag, &ispec.Manifest{})
		So(err, ShouldNotBeNil)

		err = sig.syncCosignSignature(testImage, testImage, testImageTag, &manifest)
		So(err, ShouldNotBeNil)

		err = sig.syncNotaryRefs(testImage, testImage, "invalidDigest", ReferenceList{[]artifactspec.Descriptor{ref}})
		So(err, ShouldNotBeNil)
	})

	Convey("Test canSkipImage()", t, func() {
		storageDir := t.TempDir()

		test.CopyTestFiles("../../../test/data", storageDir)

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := local.NewImageStore(storageDir, false, storage.DefaultGCDelay,
			false, false, log, metrics, nil, nil)

		refs := ReferenceList{[]artifactspec.Descriptor{
			{
				Digest: "fakeDigest",
			},
		}}

		err := os.Chmod(path.Join(imageStore.RootDir(), testImage, "index.json"), 0o000)
		So(err, ShouldBeNil)

		canBeSkipped, err := canSkipImage(testImage, testImageTag, "fakeDigest", imageStore, log)
		So(err, ShouldNotBeNil)
		So(canBeSkipped, ShouldBeFalse)

		err = os.Chmod(path.Join(imageStore.RootDir(), testImage, "index.json"), 0o755)
		So(err, ShouldBeNil)

		_, testImageManifestDigest, _, err := imageStore.GetImageManifest(testImage, testImageTag)
		So(err, ShouldBeNil)
		So(testImageManifestDigest, ShouldNotBeEmpty)

		regURL, err := url.Parse("http://zot")
		So(err, ShouldBeNil)
		So(regURL, ShouldNotBeNil)

		client := &http.Client{}
		sig := newSignaturesCopier(client, Credentials{}, *regURL, storage.StoreController{DefaultStore: imageStore}, log)

		canBeSkipped, err = sig.canSkipNotaryRefs(testImage, testImageManifestDigest.String(), refs)
		So(err, ShouldBeNil)
		So(canBeSkipped, ShouldBeFalse)

		err = os.Chmod(path.Join(imageStore.RootDir(), testImage, "index.json"), 0o000)
		So(err, ShouldBeNil)

		canBeSkipped, err = sig.canSkipNotaryRefs(testImage, testImageManifestDigest.String(), refs)
		So(err, ShouldNotBeNil)
		So(canBeSkipped, ShouldBeFalse)

		err = sig.syncOCIRefs(testImage, testImage, testImageManifestDigest.String(),
			ispec.Index{Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
				},
			}})
		So(err, ShouldNotBeNil)

		err = syncSignaturesArtifacts(sig, testImage, testImage, testImageManifestDigest.String(), OCIReference)
		So(err, ShouldNotBeNil)

		cosignManifest := ispec.Manifest{
			Layers: []ispec.Descriptor{{Digest: "fakeDigest"}},
		}

		err = os.Chmod(path.Join(imageStore.RootDir(), testImage, "index.json"), 0o755)
		So(err, ShouldBeNil)

		canBeSkipped, err = sig.canSkipCosignSignature(testImage, testImageManifestDigest.String(), &cosignManifest)
		So(err, ShouldBeNil)
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

	Convey("Test filterTagsByRegex()", t, func() {
		tags := []string{"one"}
		filteredTags, err := filterTagsByRegex(tags, ".*", log.NewLogger("", ""))
		So(err, ShouldBeNil)
		So(filteredTags, ShouldResemble, tags)
	})

	Convey("Verify pushSyncedLocalImage func", t, func() {
		storageDir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		imageStore := local.NewImageStore(storageDir, false, storage.DefaultGCDelay,
			false, false, log, metrics, nil, nil)

		storeController := storage.StoreController{}
		storeController.DefaultStore = imageStore

		testRootDir := path.Join(imageStore.RootDir(), testImage, SyncBlobUploadDir)
		// testImagePath := path.Join(testRootDir, testImage)

		err := pushSyncedLocalImage(testImage, testImageTag, testRootDir, imageStore, log)
		So(err, ShouldNotBeNil)

		err = os.MkdirAll(testRootDir, 0o755)
		if err != nil {
			panic(err)
		}

		test.CopyTestFiles("../../../test/data", testRootDir)

		testImageStore := local.NewImageStore(testRootDir, false,
			storage.DefaultGCDelay, false, false, log, metrics, nil, nil)
		manifestContent, _, _, err := testImageStore.GetImageManifest(testImage, testImageTag)
		So(err, ShouldBeNil)

		Convey("index image errors", func() {
			// create an image index on upstream
			repo := "index"

			var index ispec.Index
			index.SchemaVersion = 2
			index.MediaType = ispec.MediaTypeImageIndex

			// upload multiple manifests
			for i := 0; i < 2; i++ {
				config, layers, manifest, err := test.GetImageComponents(1000 + i)
				So(err, ShouldBeNil)

				for _, layer := range layers {
					// upload layer
					_, _, err := testImageStore.FullBlobUpload(repo, bytes.NewReader(layer), godigest.FromBytes(layer))
					So(err, ShouldBeNil)
				}

				configContent, err := json.Marshal(config)
				So(err, ShouldBeNil)

				configDigest := godigest.FromBytes(configContent)

				_, _, err = testImageStore.FullBlobUpload(repo, bytes.NewReader(configContent), configDigest)
				So(err, ShouldBeNil)

				manifestContent, err := json.Marshal(manifest)
				So(err, ShouldBeNil)

				manifestDigest := godigest.FromBytes(manifestContent)

				_, err = testImageStore.PutImageManifest(repo, manifestDigest.String(),
					ispec.MediaTypeImageManifest, manifestContent)
				So(err, ShouldBeNil)

				index.Manifests = append(index.Manifests, ispec.Descriptor{
					Digest:    manifestDigest,
					MediaType: ispec.MediaTypeImageManifest,
					Size:      int64(len(manifestContent)),
				})
			}

			content, err := json.Marshal(index)
			So(err, ShouldBeNil)
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			// upload index image
			_, err = testImageStore.PutImageManifest(repo, "latest", ispec.MediaTypeImageIndex, content)
			So(err, ShouldBeNil)

			err = pushSyncedLocalImage(repo, "latest", testRootDir, imageStore, log)
			So(err, ShouldBeNil)

			// trigger  error on manifest pull
			err = os.Chmod(path.Join(testRootDir, repo, "blobs",
				index.Manifests[0].Digest.Algorithm().String(), index.Manifests[0].Digest.Encoded()), 0o000)
			So(err, ShouldBeNil)

			err = pushSyncedLocalImage(repo, "latest", testRootDir, imageStore, log)
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(testRootDir, repo, "blobs",
				index.Manifests[0].Digest.Algorithm().String(), index.Manifests[0].Digest.Encoded()), local.DefaultDirPerms)
			So(err, ShouldBeNil)

			// trigger linter error on manifest push
			imageStoreWithLinter := local.NewImageStore(t.TempDir(), false, storage.DefaultGCDelay,
				false, false, log, metrics, &mocks.MockedLint{
					LintFn: func(repo string, manifestDigest godigest.Digest, imageStore storage.ImageStore) (bool, error) {
						return false, nil
					},
				}, nil,
			)

			err = pushSyncedLocalImage(repo, "latest", testRootDir, imageStoreWithLinter, log)
			// linter error will be ignored by sync
			So(err, ShouldBeNil)

			// trigger error on blob
			var manifest ispec.Manifest

			manifestContent, _, mediaType, err := testImageStore.GetImageManifest(repo, index.Manifests[0].Digest.String())
			So(err, ShouldBeNil)
			So(mediaType, ShouldEqual, ispec.MediaTypeImageManifest)

			err = json.Unmarshal(manifestContent, &manifest)
			So(err, ShouldBeNil)

			configBlobPath := path.Join(testRootDir, repo, "blobs",
				manifest.Config.Digest.Algorithm().String(), manifest.Config.Digest.Encoded())
			err = os.Chmod(configBlobPath, 0o000)
			So(err, ShouldBeNil)

			// remove destination blob, so that pushSyncedLocalImage will try to push it again
			err = os.Remove(path.Join(imageStore.RootDir(), repo, "blobs",
				manifest.Config.Digest.Algorithm().String(), manifest.Config.Digest.Encoded()))
			So(err, ShouldBeNil)

			err = pushSyncedLocalImage(repo, "latest", testRootDir, imageStore, log)
			So(err, ShouldNotBeNil)

			err = os.Chmod(configBlobPath, local.DefaultDirPerms)
			So(err, ShouldBeNil)

			err = os.RemoveAll(path.Join(imageStore.RootDir(), repo, "index.json"))
			So(err, ShouldBeNil)

			// remove destination blob, so that pushSyncedLocalImage will try to push it again
			indexManifestPath := path.Join(imageStore.RootDir(), repo, "blobs",
				digest.Algorithm().String(), digest.Encoded())
			err = os.Remove(indexManifestPath)
			So(err, ShouldBeNil)

			err = os.MkdirAll(indexManifestPath, 0o000)
			So(err, ShouldBeNil)

			err = pushSyncedLocalImage(repo, "latest", testRootDir, imageStore, log)
			So(err, ShouldNotBeNil)

			err = os.Remove(indexManifestPath)
			So(err, ShouldBeNil)
		})

		Convey("manifest image errors", func() {
			var manifest ispec.Manifest

			if err := json.Unmarshal(manifestContent, &manifest); err != nil {
				panic(err)
			}

			if err := os.Chmod(storageDir, 0o000); err != nil {
				panic(err)
			}

			if os.Geteuid() != 0 {
				So(func() {
					_ = pushSyncedLocalImage(testImage, testImageTag, testRootDir, imageStore, log)
				}, ShouldPanic)
			}

			if err := os.Chmod(storageDir, 0o755); err != nil {
				panic(err)
			}

			if err := os.Chmod(path.Join(testRootDir, testImage, "blobs", "sha256",
				manifest.Layers[0].Digest.Encoded()), 0o000); err != nil {
				panic(err)
			}

			err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, imageStore, log)
			So(err, ShouldNotBeNil)

			if err := os.Chmod(path.Join(testRootDir, testImage, "blobs", "sha256",
				manifest.Layers[0].Digest.Encoded()), 0o755); err != nil {
				panic(err)
			}

			cachedManifestConfigPath := path.Join(imageStore.RootDir(), testImage, SyncBlobUploadDir,
				testImage, "blobs", "sha256", manifest.Config.Digest.Encoded())
			if err := os.Chmod(cachedManifestConfigPath, 0o000); err != nil {
				panic(err)
			}

			err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, imageStore, log)
			So(err, ShouldNotBeNil)

			if err := os.Chmod(cachedManifestConfigPath, 0o755); err != nil {
				panic(err)
			}

			cachedManifestBackup, err := os.ReadFile(cachedManifestConfigPath)
			if err != nil {
				panic(err)
			}

			configDigestBackup := manifest.Config.Digest
			manifest.Config.Digest = "not what it needs to be"
			manifestBuf, err := json.Marshal(manifest)
			if err != nil {
				panic(err)
			}

			if err = os.WriteFile(cachedManifestConfigPath, manifestBuf, 0o600); err != nil {
				panic(err)
			}

			if err = os.Chmod(cachedManifestConfigPath, 0o755); err != nil {
				panic(err)
			}

			err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, imageStore, log)
			So(err, ShouldNotBeNil)

			manifest.Config.Digest = configDigestBackup
			manifestBuf = cachedManifestBackup

			if err := os.Remove(cachedManifestConfigPath); err != nil {
				panic(err)
			}

			if err = os.WriteFile(cachedManifestConfigPath, manifestBuf, 0o600); err != nil {
				panic(err)
			}

			if err = os.Chmod(cachedManifestConfigPath, 0o755); err != nil {
				panic(err)
			}

			mDigest := godigest.FromBytes(manifestContent)

			manifestPath := path.Join(imageStore.RootDir(), testImage, "blobs", mDigest.Algorithm().String(), mDigest.Encoded())
			if err := os.MkdirAll(manifestPath, 0o000); err != nil {
				panic(err)
			}

			err = pushSyncedLocalImage(testImage, testImageTag, testRootDir, imageStore, log)
			So(err, ShouldNotBeNil)
		})
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

func TestCompareManifest(t *testing.T) {
	testCases := []struct {
		manifest1 ispec.Manifest
		manifest2 ispec.Manifest
		expected  bool
	}{
		{
			manifest1: ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: "digest1",
				},
			},
			manifest2: ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: "digest2",
				},
			},
			expected: false,
		},
		{
			manifest1: ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: "digest",
				},
			},
			manifest2: ispec.Manifest{
				Config: ispec.Descriptor{
					Digest: "digest",
				},
			},
			expected: true,
		},
		{
			manifest1: ispec.Manifest{
				Layers: []ispec.Descriptor{{
					Digest: "digest",
					Size:   1,
				}},
			},
			manifest2: ispec.Manifest{
				Layers: []ispec.Descriptor{{
					Digest: "digest",
					Size:   1,
				}},
			},
			expected: true,
		},
		{
			manifest1: ispec.Manifest{
				Layers: []ispec.Descriptor{{
					Digest: "digest1",
					Size:   1,
				}},
			},
			manifest2: ispec.Manifest{
				Layers: []ispec.Descriptor{{
					Digest: "digest2",
					Size:   2,
				}},
			},
			expected: false,
		},
		{
			manifest1: ispec.Manifest{
				Layers: []ispec.Descriptor{
					{
						Digest: "digest",
						Size:   1,
					},
					{
						Digest: "digest1",
						Size:   1,
					},
				},
			},
			manifest2: ispec.Manifest{
				Layers: []ispec.Descriptor{{
					Digest: "digest",
					Size:   1,
				}},
			},
			expected: false,
		},
		{
			manifest1: ispec.Manifest{
				Layers: []ispec.Descriptor{
					{
						Digest: "digest1",
						Size:   1,
					},
					{
						Digest: "digest2",
						Size:   2,
					},
				},
			},
			manifest2: ispec.Manifest{
				Layers: []ispec.Descriptor{
					{
						Digest: "digest1",
						Size:   1,
					},
					{
						Digest: "digest2",
						Size:   2,
					},
				},
			},
			expected: true,
		},
		{
			manifest1: ispec.Manifest{
				Layers: []ispec.Descriptor{
					{
						Digest: "digest",
						Size:   1,
					},
					{
						Digest: "digest1",
						Size:   1,
					},
				},
			},
			manifest2: ispec.Manifest{
				Layers: []ispec.Descriptor{
					{
						Digest: "digest",
						Size:   1,
					},
					{
						Digest: "digest2",
						Size:   2,
					},
				},
			},
			expected: false,
		},
	}

	Convey("Test manifestsEqual()", t, func() {
		for _, test := range testCases {
			actualResult := manifestsEqual(test.manifest1, test.manifest2)
			So(actualResult, ShouldEqual, test.expected)
		}
	})
}

func TestCompareArtifactRefs(t *testing.T) {
	testCases := []struct {
		refs1    []artifactspec.Descriptor
		refs2    []artifactspec.Descriptor
		expected bool
	}{
		{
			refs1: []artifactspec.Descriptor{
				{
					Digest: "digest1",
				},
			},
			refs2: []artifactspec.Descriptor{
				{
					Digest: "digest2",
				},
			},
			expected: false,
		},
		{
			refs1: []artifactspec.Descriptor{
				{
					Digest: "digest",
				},
			},
			refs2: []artifactspec.Descriptor{
				{
					Digest: "digest",
				},
			},
			expected: true,
		},
		{
			refs1: []artifactspec.Descriptor{
				{
					Digest: "digest",
				},
				{
					Digest: "digest2",
				},
			},
			refs2: []artifactspec.Descriptor{
				{
					Digest: "digest",
				},
			},
			expected: false,
		},
		{
			refs1: []artifactspec.Descriptor{
				{
					Digest: "digest1",
				},
				{
					Digest: "digest2",
				},
			},
			refs2: []artifactspec.Descriptor{
				{
					Digest: "digest1",
				},
				{
					Digest: "digest2",
				},
			},
			expected: true,
		},
		{
			refs1: []artifactspec.Descriptor{
				{
					Digest: "digest",
				},
				{
					Digest: "digest1",
				},
			},
			refs2: []artifactspec.Descriptor{
				{
					Digest: "digest1",
				},
				{
					Digest: "digest2",
				},
			},
			expected: false,
		},
	}

	Convey("Test manifestsEqual()", t, func() {
		for _, test := range testCases {
			actualResult := artifactDescriptorsEqual(test.refs1, test.refs2)
			So(actualResult, ShouldEqual, test.expected)
		}
	})
}
