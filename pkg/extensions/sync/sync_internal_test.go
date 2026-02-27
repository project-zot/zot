//go:build sync

package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/ref"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/config"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/lint"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestService(t *testing.T) {
	Convey("trigger fetch tags error", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		err = service.SyncRepo(context.Background(), "repo")
		So(err, ShouldNotBeNil)
	})

	Convey("test context cancellation in SyncRepo without mock", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Create a context that's already cancelled
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = service.SyncRepo(ctx, "repo")
		So(err, ShouldNotBeNil)
		// This will fail at getTags before reaching the cancellation check
	})

	Convey("test context cancellation in SyncRepo with mock", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Create a mock remote that returns tags so we can reach the loop
		mockRemote := &mocks.SyncRemoteMock{
			GetTagsFn: func(ctx context.Context, repo string) ([]string, error) {
				return []string{"tag1", "tag2", "tag3"}, nil
			},
		}
		service.remote = mockRemote

		// Create a context that's already cancelled
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = service.SyncRepo(ctx, "repo")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, context.Canceled), ShouldBeTrue)
	})

	Convey("test SyncReferrers ReferrerList error", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Create a minimal mock remote that only returns tags
		mockRemote := &mocks.SyncRemoteMock{
			GetTagsFn: func(ctx context.Context, repo string) ([]string, error) {
				return []string{"tag1"}, nil
			},
		}
		service.remote = mockRemote

		// Set rc to nil to force a panic at ReferrerList call
		service.rc = nil

		// Use defer to catch the panic - this confirms we reached the ReferrerList call
		var panicOccurred bool
		defer func() {
			if r := recover(); r != nil {
				panicOccurred = true
				t.Logf("SyncReferrers panic (expected): %v", r)
			}
		}()

		ctx := context.Background()
		err = service.SyncReferrers(ctx, "repo", "tag1", []string{"signature"})

		// We expect a panic when rc is nil, which confirms we reached the ReferrerList call
		So(panicOccurred, ShouldBeTrue)
	})

	Convey("test syncImage skips OCI conversion when image already synced", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Mock remote returns isConverted=true so OCI conversion would be attempted if not skipped
		mockRemote := &mocks.SyncRemoteMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				return ref.New("mock-registry/" + repo + ":" + tag)
			},
			GetOCIDigestFn: func(ctx context.Context, repo, tag string) (godigest.Digest, godigest.Digest, bool, error) {
				// isConverted=true means OCI conversion would be attempted
				return godigest.Digest("sha256:abc123"), godigest.Digest("sha256:def456"), true, nil
			},
		}
		service.remote = mockRemote

		commitAllCalled := false

		// Mock destination returns CanSkipImage=true (already synced)
		mockDest := &mocks.SyncDestinationMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				return ref.New("local/" + repo + ":" + tag)
			},
			CanSkipImageFn: func(repo string, tag string, digest godigest.Digest) (bool, error) {
				return true, nil
			},
			CommitAllFn: func(repo string, imageReference ref.Ref) error {
				commitAllCalled = true
				return nil
			},
			CleanupImageFn: func(imageReference ref.Ref, repo string) error {
				return nil
			},
		}
		service.destination = mockDest

		ctx := context.Background()
		err = service.syncImage(ctx, "localrepo", "remoterepo", "tag1", []string{}, false)

		// Should succeed without error (image already synced, no OCI conversion attempted)
		So(err, ShouldBeNil)
		// CommitAll should not be called since we returned early after skip
		So(commitAllCalled, ShouldBeFalse)
	})

	Convey("test syncImage ReferrerList error with OnlySigned", t, func() {
		onlySigned := true
		conf := syncconf.RegistryConfig{
			URLs:       []string{"http://localhost"},
			OnlySigned: &onlySigned,
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Create a mock remote that returns an invalid reference to trigger ReferrerList error
		mockRemote := &mocks.SyncRemoteMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				// Return an invalid reference that will cause ReferrerList to fail with "ref is not set" error
				return ref.Ref{}, nil
			},
			GetDigestFn: func(ctx context.Context, repo, tag string) (godigest.Digest, error) {
				return godigest.Digest("sha256:abc123"), nil
			},
		}
		service.remote = mockRemote

		// Create a mock destination
		mockDest := &mocks.SyncDestinationMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				return ref.New("local/" + repo + ":" + tag)
			},
		}
		service.destination = mockDest

		ctx := context.Background()
		err = service.syncImage(ctx, "localrepo", "remoterepo", "tag1", []string{}, true)

		// We expect an error when ReferrerList fails with "ref is not set" error
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "ref is not set")
	})

	Convey("test syncReferrers ReferrerList error", t, func() {
		conf := syncconf.RegistryConfig{
			URLs: []string{"http://localhost"},
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Create a mock remote that returns valid references
		mockRemote := &mocks.SyncRemoteMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				return ref.New(repo + ":" + tag)
			},
			GetDigestFn: func(ctx context.Context, repo, tag string) (godigest.Digest, error) {
				return godigest.Digest("sha256:abc123"), nil
			},
		}
		service.remote = mockRemote

		// Create a mock destination
		mockDest := &mocks.SyncDestinationMock{
			GetImageReferenceFn: func(repo string, tag string) (ref.Ref, error) {
				return ref.New("local/" + repo + ":" + tag)
			},
		}
		service.destination = mockDest

		ctx := context.Background()
		localImageRef, err := ref.New("local/repo:tag")
		So(err, ShouldBeNil)

		// Create an invalid remote reference that will cause ReferrerList to fail with "ref is not set" error
		remoteImageRef := ref.Ref{}

		err = service.syncReferrers(ctx, []string{"tag"}, "localrepo", "remoterepo", localImageRef, remoteImageRef)

		// The error should be "ref is not set" as defined in regclient ReferrerList function
		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "ref is not set")
	})

	Convey("test LoadOrStore continue path by pre-populating requestStore", t, func() {
		// Strategy: Pre-populate requestStore to force LoadOrStore to return true
		maxRetries := 2
		retryDelay := 100 * time.Millisecond
		conf := syncconf.RegistryConfig{
			URLs:       []string{"http://localhost:32768"}, // Invalid port to force errors
			MaxRetries: &maxRetries,
			RetryDelay: &retryDelay,
		}

		service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(service)
		ctx := context.Background()

		// Step 1: Verify empty requestStore initially
		initialImageCount := 0
		onDemand.requestStore.Range(func(key, value any) bool {
			initialImageCount++
			return true
		})
		So(initialImageCount, ShouldEqual, 0)

		// Step 2: Pre-populate image background retry request
		duplicateImageReq := request{
			repo:         "test-duplicate-repo",
			reference:    "test-duplicate-tag",
			serviceID:    0,
			isBackground: true,
		}
		onDemand.requestStore.Store(duplicateImageReq, struct{}{})

		// Step 3: Verify we now have 1 request
		preImageCount := 0
		onDemand.requestStore.Range(func(key, value any) bool {
			preImageCount++
			return true
		})
		So(preImageCount, ShouldEqual, 1) // Should be 1 after pre-population

		// Step 4: Trigger sync - should execute continue path
		err = onDemand.SyncImage(ctx, "test-duplicate-repo", "test-duplicate-tag")
		So(err, ShouldNotBeNil) // Should still error due to invalid registry

		// Step 5: Verify CONTINUE PATH EXECUTED - no new requests created
		postImageCount := 0
		onDemand.requestStore.Range(func(key, value any) bool {
			postImageCount++
			return true
		})
		So(postImageCount, ShouldEqual, preImageCount) // Count unchanged = continue executed

		// Step 6: Verify image request unchanged (proves no background goroutine started)
		value, exists := onDemand.requestStore.Load(duplicateImageReq)
		So(exists, ShouldBeTrue)
		So(value, ShouldEqual, struct{}{}) // Should still be pre-populated value

		// Step 7: Verify current state before referrer test - we should have 1 request
		initialReferrerCount := 0
		onDemand.requestStore.Range(func(key, value any) bool {
			initialReferrerCount++
			return true
		})
		So(initialReferrerCount, ShouldEqual, 1) // Should have 1 from image test

		// Step 8: Pre-populate referrer background retry request
		duplicateReferrerReq := request{
			repo:         "test-duplicate-referrer-repo",
			reference:    "sha256:duplicate",
			serviceID:    0,
			isBackground: true,
		}
		onDemand.requestStore.Store(duplicateReferrerReq, struct{}{})

		// Step 9: Verify we now have 2 requests (image + referrer)
		preReferrerCount := 0
		onDemand.requestStore.Range(func(key, value any) bool {
			preReferrerCount++
			return true
		})
		So(preReferrerCount, ShouldEqual, 2) // Should have 2 after referrer pre-population

		// Step 10: Trigger referrer sync - should execute continue path
		err = onDemand.SyncReferrers(ctx, "test-duplicate-referrer-repo", "sha256:duplicate", []string{"signature"})
		So(err, ShouldNotBeNil) // Should still error due to invalid registry

		// Step 11: Verify CONTINUE PATH EXECUTED - no new referrer requests created
		postReferrerCount := 0
		onDemand.requestStore.Range(func(key, value any) bool {
			postReferrerCount++
			return true
		})
		So(postReferrerCount, ShouldEqual, preReferrerCount) // Count unchanged = continue executed

		// Step 12: Verify referrer request unchanged (proves no background goroutine started)
		value, exists = onDemand.requestStore.Load(duplicateReferrerReq)
		So(exists, ShouldBeTrue)
		So(value, ShouldEqual, struct{}{}) // Should still be pre-populated value

		// Step 13: Final verification - exactly 2 requests total (both pre-populated, none deleted)
		finalCount := 0
		onDemand.requestStore.Range(func(key, value any) bool {
			finalCount++
			return true
		})
		So(finalCount, ShouldEqual, 2)
	})

	Convey("test continue paths for specific error types in on-demand sync", t, func() {
		// Strategy: Create multiple services where one returns ErrSyncImageFilteredOut
		// This will trigger the continue path when looping through services
		ctx := context.Background()

		// Create first service with content filtering
		maxRetries := 2
		retryDelay := 100 * time.Millisecond

		conf1 := syncconf.RegistryConfig{
			URLs:       []string{"http://localhost:32768"}, // Invalid port to force errors
			MaxRetries: &maxRetries,
			RetryDelay: &retryDelay,
			Content: []syncconf.Content{{
				Prefix: "different-prefix", // Won't match our test repo
			}},
		}

		service1, err := New(conf1, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		// Create second service for normal processing
		conf2 := syncconf.RegistryConfig{
			URLs:       []string{"http://localhost:32768"}, // Invalid port to force errors
			MaxRetries: &maxRetries,
			RetryDelay: &retryDelay,
			Content: []syncconf.Content{{
				Prefix: "test-repo", // Will match our test repo
			}},
		}

		service2, err := New(conf2, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
		So(err, ShouldBeNil)

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(service1) // First service will return ErrSyncImageFilteredOut
		onDemand.Add(service2) // Second service will process normally but error on network

		// Test ErrSyncImageFilteredOut continue path in SyncImage
		// The first service returns ErrSyncImageFilteredOut (causes continue), second service processes but errors
		err = onDemand.SyncImage(ctx, "test-filtered-repo", "test-tag")
		So(err, ShouldNotBeNil) // Should get error from second service (network error)

		// Test ErrSyncImageFilteredOut continue path in SyncReferrers
		err = onDemand.SyncReferrers(ctx, "test-filtered-referrer-repo", "sha256:test", []string{"signature"})
		So(err, ShouldNotBeNil) // Should get error from second service (network error)
	})

	Convey("test continue paths in both SyncImage and SyncReferrers", t, func() {
		// Helper function to create filter test scenario
		createFilteredService := func(prefix string) (*BaseService, *BaseOnDemand) {
			maxRetries := 2
			retryDelay := 100 * time.Millisecond

			conf := syncconf.RegistryConfig{
				URLs:       []string{"http://localhost:32768"}, // Invalid port to force errors
				MaxRetries: &maxRetries,
				RetryDelay: &retryDelay,
				Content: []syncconf.Content{{
					Prefix: prefix, // Won't match our test repo
				}},
			}

			service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
			So(err, ShouldBeNil)

			onDemand := NewOnDemand(log.NewTestLogger())
			onDemand.Add(service)
			return service, onDemand
		}

		ctx := context.Background()

		// Test SyncReferrers continue path
		Convey("SyncReferrers continue path", func() {
			_, onDemand := createFilteredService("different-referrer-prefix")
			err := onDemand.SyncReferrers(ctx, "test-unfiltered-referrer-repo", "sha256:test", []string{"signature"})
			So(err, ShouldNotBeNil) // Should get error from sync process (filtered out -> continue -> network error)
		})

		// Test SyncImage continue path
		Convey("SyncImage continue path", func() {
			_, onDemand := createFilteredService("different-image-prefix")
			err := onDemand.SyncImage(ctx, "test-unfiltered-image-repo", "test-tag")
			So(err, ShouldNotBeNil) // Should get error from sync process (filtered out -> continue -> network error)
		})
	})

	Convey("test background retry goroutines for both SyncImage and SyncReferrers", t, func() {
		// Helper function to create background retry test scenario
		createBackgroundRetryService := func(prefix string) (*BaseService, *BaseOnDemand, time.Duration) {
			maxRetries := 2
			retryDelay := 1 * time.Second

			conf := syncconf.RegistryConfig{
				URLs:       []string{"http://localhost:32768"}, // Invalid port to force errors
				MaxRetries: &maxRetries,                        // Enable retries so CanRetryOnError() returns true
				RetryDelay: &retryDelay,
				Content: []syncconf.Content{{
					Prefix: prefix, // Will match our repo
				}},
			}

			service, err := New(conf, "", nil, t.TempDir(), storage.StoreController{}, mocks.MetaDBMock{}, log.NewTestLogger())
			So(err, ShouldBeNil)

			onDemand := NewOnDemand(log.NewTestLogger())
			onDemand.Add(service)
			return service, onDemand, retryDelay
		}

		// Test SyncReferrers background retry
		Convey("SyncReferrers background retry", func() {
			_, onDemand, retryDelay := createBackgroundRetryService("test-background-retry")
			ctx := context.Background()

			// Verify initial requestStore is empty
			initialCount := 0
			onDemand.requestStore.Range(func(key, value any) bool {
				initialCount++
				return true
			})
			So(initialCount, ShouldEqual, 0)

			// Call SyncReferrers - should trigger background retry since:
			// 1. Network error (not a continue-path error)
			// 2. CanRetryOnError() returns true (maxRetries > 0)
			// 3. No existing background retry
			err := onDemand.SyncReferrers(ctx, "test-background-retry", "sha256:background", []string{"signature"})
			So(err, ShouldNotBeNil) // Should get original network error

			// Wait for background goroutine to start and store request
			time.Sleep(50 * time.Millisecond)

			// Verify background retry request was stored
			reqBackground := request{
				repo:         "test-background-retry",
				reference:    "sha256:background",
				serviceID:    0,
				isBackground: true,
			}
			_, existsBackground := onDemand.requestStore.Load(reqBackground)
			So(existsBackground, ShouldBeTrue) // Background retry request should exist

			// Wait for background retry to complete and cleanup (3x retry delay)
			time.Sleep(3 * retryDelay)

			// Verify background retry request was cleaned up after completion
			_, existsAfterCleanup := onDemand.requestStore.Load(reqBackground)
			So(existsAfterCleanup, ShouldBeFalse) // Should be cleaned up by defer function after retry
		})

		// Test SyncImage background retry
		Convey("SyncImage background retry", func() {
			_, onDemand, retryDelay := createBackgroundRetryService("test-background-image-retry")
			ctx := context.Background()

			// Verify initial requestStore is empty
			initialCount := 0
			onDemand.requestStore.Range(func(key, value any) bool {
				initialCount++
				return true
			})
			So(initialCount, ShouldEqual, 0)

			// Call SyncImage - should trigger background retry since:
			// 1. Network error (not a continue-path error)
			// 2. CanRetryOnError() returns true (maxRetries > 0)
			// 3. No existing background retry
			err := onDemand.SyncImage(ctx, "test-background-image-retry", "background-image-tag")
			So(err, ShouldNotBeNil) // Should get original network error

			// Wait for background goroutine to start and store request
			time.Sleep(50 * time.Millisecond)

			// Verify background retry request was stored
			reqBackground := request{
				repo:         "test-background-image-retry",
				reference:    "background-image-tag",
				serviceID:    0,
				isBackground: true,
			}
			_, existsBackground := onDemand.requestStore.Load(reqBackground)
			So(existsBackground, ShouldBeTrue) // Background retry request should exist

			// Wait for background retry to complete and cleanup (3x retry delay)
			time.Sleep(3 * retryDelay)

			// Verify background retry request was cleaned up after completion
			_, existsAfterCleanup := onDemand.requestStore.Load(reqBackground)
			So(existsAfterCleanup, ShouldBeFalse) // Should be cleaned up by defer function after retry
		})
	})

	Convey("test assured channel waiting path", t, func() {
		// Strategy: Pre-populate requestStore with a channel to GUARANTEE the channel waiting code path
		// This ensures the "waiting on channel" message is logged and the channel receive happens

		Convey("SyncImage assured channel waiting", func() {
			onDemand := NewOnDemand(log.NewTestLogger())

			// Create request and pre-populate with a channel that we control
			req := request{
				repo:         "test-guaranteed-channel-image",
				reference:    "guaranteed-image-tag",
				serviceID:    0,
				isBackground: false,
			}

			// Create a channel that we control completely
			pendingChannel := make(chan error, 1)
			onDemand.requestStore.Store(req, pendingChannel)

			// Start request that will wait on our channel
			requestCompleted := make(chan error)
			go func() {
				err := onDemand.SyncImage(context.Background(), "test-guaranteed-channel-image", "guaranteed-image-tag")
				requestCompleted <- err
			}()

			// Wait a moment for the request to reach the channel waiting code
			time.Sleep(50 * time.Millisecond)

			// Send error through our controlled channel - this proves channel waiting worked
			pendingChannel <- errors.New("guaranteed channel error")

			// Verify the request got our controlled error
			err := <-requestCompleted
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "guaranteed channel error")
		})

		Convey("SyncReferrers assured channel waiting", func() {
			onDemand := NewOnDemand(log.NewTestLogger())

			// Create request and pre-populate with a channel that we control
			req := request{
				repo:         "test-guaranteed-channel-referrers",
				reference:    "sha256:guaranteed",
				serviceID:    0,
				isBackground: false,
			}

			// Create a channel that we control completely
			pendingChannel := make(chan error, 1)
			onDemand.requestStore.Store(req, pendingChannel)

			// Start request that will wait on our channel
			requestCompleted := make(chan error)
			go func() {
				err := onDemand.SyncReferrers(context.Background(), "test-guaranteed-channel-referrers", "sha256:guaranteed", []string{"signature"})
				requestCompleted <- err
			}()

			// Wait a moment for the request to reach the channel waiting code
			time.Sleep(50 * time.Millisecond)

			// Send error through our controlled channel - this proves channel waiting worked
			pendingChannel <- errors.New("guaranteed referrer channel error")

			// Verify the request got our controlled error
			err := <-requestCompleted
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldEqual, "guaranteed referrer channel error")
		})
	})
}

func TestDestinationRegistry(t *testing.T) {
	Convey("make StoreController", t, func() {
		dir := t.TempDir()

		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)
		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		syncImgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)
		repoName := "repo"

		storeController := storage.StoreController{DefaultStore: syncImgStore}
		registry := NewDestinationRegistry(storeController, storeController, nil, log)
		imageReference, err := registry.GetImageReference(repoName, "1.0")
		So(err, ShouldBeNil)
		So(imageReference, ShouldNotBeNil)

		imgStore := getImageStoreFromImageReference(repoName, imageReference, log)

		// create a blob/layer
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("this is a blob1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)
		blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)
		bdgst1 := digest
		bsize1 := len(content)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		// push index image
		var index ispec.Index
		index.SchemaVersion = 2
		index.MediaType = ispec.MediaTypeImageIndex

		for i := 0; i < 4; i++ {
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
						Digest:    bdgst1,
						Size:      int64(bsize1),
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

		Convey("sync index image", func() {
			ok, err := registry.CanSkipImage(repoName, "1.0", indexDigest)
			So(ok, ShouldBeFalse)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldBeNil)
		})

		Convey("CleanupImage()", func() {
			ok, err := registry.CanSkipImage(repoName, "1.0", indexDigest)
			So(ok, ShouldBeFalse)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldBeNil)

			err = registry.CleanupImage(imageReference, repoName)
			So(err, ShouldBeNil)
		})

		Convey("trigger GetImageManifest error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, indexDigest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger linter error in CommitImage()", func() {
			defaultVal := true
			linter := lint.NewLinter(&config.LintConfig{
				BaseConfig: config.BaseConfig{
					Enable: &defaultVal,
				},
				MandatoryAnnotations: []string{"annot1"},
			}, log)

			syncImgStore := local.NewImageStore(dir, true, true, log, metrics, linter, cacheDriver, nil, nil)
			repoName := "repo"

			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, nil, log)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldBeNil)
		})

		Convey("trigger GetBlobContent on manifest error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, digest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger copyBlob() error in CommitImage()", func() {
			err = os.Chmod(imgStore.BlobPath(repoName, bdgst1), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger PutImageManifest error on index manifest in CommitImage()", func() {
			err = os.MkdirAll(syncImgStore.BlobPath(repoName, indexDigest), storageConstants.DefaultDirPerms)
			So(err, ShouldBeNil)

			err = os.Chmod(syncImgStore.BlobPath(repoName, indexDigest), 0o000)
			So(err, ShouldBeNil)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger metaDB error on index manifest in CommitImage()", func() {
			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, mocks.MetaDBMock{
				SetRepoReferenceFn: func(ctx context.Context, repo string, reference string, imageMeta mTypes.ImageMeta) error {
					if reference == "1.0" {
						return zerr.ErrRepoMetaNotFound
					}

					return nil
				},
			}, log)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger metaDB error on image manifest in CommitImage()", func() {
			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, mocks.MetaDBMock{
				SetRepoReferenceFn: func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					return zerr.ErrRepoMetaNotFound
				},
			}, log)

			err = registry.CommitAll(repoName, imageReference)
			So(err, ShouldNotBeNil)
		})

		Convey("trigger GetBlobContent error on manifest within image index in copyManifest()", func() {
			// This test specifically targets the error where GetBlobContent fails for a manifest
			// that is part of an image index.

			// Create a destination registry using the existing syncImgStore as temp storage
			storeController := storage.StoreController{DefaultStore: syncImgStore}
			registry := NewDestinationRegistry(storeController, storeController, nil, log)

			// Get an image reference - this will create a temp session directory
			imageReference, err := registry.GetImageReference(repoName, "test-index")
			So(err, ShouldBeNil)

			// Get the temp image store from the image reference
			tempImgStore := getImageStoreFromImageReference(repoName, imageReference, log)

			// Create an image index with multiple manifests
			var index ispec.Index
			index.SchemaVersion = 2
			index.MediaType = ispec.MediaTypeImageIndex

			// Create child manifests
			for i := 0; i < 2; i++ {
				// Create blob content
				content := []byte(fmt.Sprintf("this is blob %d", i))
				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)

				// Upload blob
				upload, err := tempImgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)
				So(upload, ShouldNotBeEmpty)

				blob, err := tempImgStore.PutBlobChunkStreamed(repoName, upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = tempImgStore.FinishBlobUpload(repoName, upload, buf, digest)
				So(err, ShouldBeNil)

				// Create config blob
				cblob := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","config":{"User":"test%d"}}`, i))
				cdigest := godigest.FromBytes(cblob)
				So(cdigest, ShouldNotBeNil)

				upload, err = tempImgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)
				So(upload, ShouldNotBeEmpty)

				cbuf := bytes.NewBuffer(cblob)
				blob, err = tempImgStore.PutBlobChunkStreamed(repoName, upload, cbuf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, len(cblob))

				err = tempImgStore.FinishBlobUpload(repoName, upload, cbuf, cdigest)
				So(err, ShouldBeNil)

				// Create a manifest
				manifest := ispec.Manifest{
					Config: ispec.Descriptor{
						MediaType: ispec.MediaTypeImageConfig,
						Digest:    cdigest,
						Size:      int64(len(cblob)),
					},
					Layers: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageLayer,
							Digest:    digest,
							Size:      int64(buflen),
						},
					},
				}
				manifest.SchemaVersion = 2

				manifestContent, err := json.Marshal(manifest)
				So(err, ShouldBeNil)
				manifestDigest := godigest.FromBytes(manifestContent)
				So(manifestDigest, ShouldNotBeNil)

				// Store the manifest in the temp image store
				_, _, err = tempImgStore.PutImageManifest(repoName, manifestDigest.String(), ispec.MediaTypeImageManifest, manifestContent)
				So(err, ShouldBeNil)

				// Add to index
				index.Manifests = append(index.Manifests, ispec.Descriptor{
					Digest:    manifestDigest,
					MediaType: ispec.MediaTypeImageManifest,
					Size:      int64(len(manifestContent)),
				})
			}

			// Create the index manifest
			indexContent, err := json.Marshal(index)
			So(err, ShouldBeNil)
			indexDigest := godigest.FromBytes(indexContent)
			So(indexDigest, ShouldNotBeNil)

			// Store the index manifest in the temp image store
			_, _, err = tempImgStore.PutImageManifest(repoName, indexDigest.String(), ispec.MediaTypeImageIndex, indexContent)
			So(err, ShouldBeNil)

			// Now remove one of the child manifest blobs to trigger the error
			childManifestDigest := index.Manifests[1].Digest
			err = os.Remove(tempImgStore.BlobPath(repoName, childManifestDigest))
			So(err, ShouldBeNil)

			// Create a descriptor for the index manifest
			desc := ispec.Descriptor{
				Digest:    indexDigest,
				MediaType: ispec.MediaTypeImageIndex,
				Size:      int64(len(indexContent)),
			}

			// Initialize the seen slice
			seen := &[]godigest.Digest{}

			// Call copyManifest directly with the index manifest - this should trigger the error path at lines 234-239
			// when it tries to get blob content for the child manifest with the removed blob
			err = registry.(*DestinationRegistry).copyManifest(repoName, desc, indexDigest.String(), tempImgStore, seen)

			// Verify the error is returned and contains the expected message
			So(err, ShouldNotBeNil)
			So(err.Error(), ShouldContainSubstring, "blob not found")
		})

		Convey("push image", func() {
			imageReference, err := registry.GetImageReference(repoName, "2.0")
			So(err, ShouldBeNil)
			So(imageReference, ShouldNotBeNil)

			imgStore := getImageStoreFromImageReference(repoName, imageReference, log)

			// upload image

			// create a blob/layer
			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content := []byte("this is a blob1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)
			blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)
			bdgst1 := digest
			bsize1 := len(content)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// upload image config blob
			upload, err = imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed(repoName, upload, buf)
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
						Digest:    bdgst1,
						Size:      int64(bsize1),
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			_, _, err = imgStore.PutImageManifest(repoName, "2.0", ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			Convey("sync image", func() {
				ok, err := registry.CanSkipImage(repoName, "2.0", digest)
				So(ok, ShouldBeFalse)
				So(err, ShouldBeNil)

				err = registry.CommitAll(repoName, imageReference)
				So(err, ShouldBeNil)
			})
		})

		Convey("CommitAll with non-existent directory", func() {
			// Create a registry and get an image reference
			registry := NewDestinationRegistry(storeController, storeController, nil, log)
			imageReference, err := registry.GetImageReference("nonexistent-repo", "1.0")
			So(err, ShouldBeNil)

			// Remove the directory to simulate it not existing
			tempImageStore := getImageStoreFromImageReference("nonexistent-repo", imageReference, log)
			repoDir := path.Join(tempImageStore.RootDir(), "nonexistent-repo")
			err = os.RemoveAll(repoDir)
			So(err, ShouldBeNil)

			// CommitAll should return nil when directory doesn't exist (image was skipped)
			err = registry.CommitAll("nonexistent-repo", imageReference)
			So(err, ShouldBeNil)
		})

		Convey("CommitAll with empty directory", func() {
			// Create a registry and get an image reference
			registry := NewDestinationRegistry(storeController, storeController, nil, log)
			imageReference, err := registry.GetImageReference("empty-repo", "1.0")
			So(err, ShouldBeNil)

			// Create an empty directory (no index.json, no blobs)
			tempImageStore := getImageStoreFromImageReference("empty-repo", imageReference, log)
			repoDir := path.Join(tempImageStore.RootDir(), "empty-repo")
			err = os.MkdirAll(repoDir, 0o755)
			So(err, ShouldBeNil)

			// CommitAll should return nil when directory is empty (image was skipped)
			err = registry.CommitAll("empty-repo", imageReference)
			So(err, ShouldBeNil)
		})

		Convey("CommitAll with directory containing files but no index.json", func() {
			// Create a registry and get an image reference
			registry := NewDestinationRegistry(storeController, storeController, nil, log)
			imageReference, err := registry.GetImageReference("inconsistent-repo", "1.0")
			So(err, ShouldBeNil)

			// Create a directory with some files but no index.json (inconsistent state)
			tempImageStore := getImageStoreFromImageReference("inconsistent-repo", imageReference, log)
			repoDir := path.Join(tempImageStore.RootDir(), "inconsistent-repo")
			err = os.MkdirAll(repoDir, 0o755)
			So(err, ShouldBeNil)

			// Create a dummy file to make directory non-empty
			dummyFile := path.Join(repoDir, "dummy.txt")
			err = os.WriteFile(dummyFile, []byte("dummy"), 0o644)
			So(err, ShouldBeNil)

			// CommitAll should return an error when directory is not empty but index.json is missing
			err = registry.CommitAll("inconsistent-repo", imageReference)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeTrue)
		})

		Convey("CommitAll with ReadDir error (non-ErrNotExist)", func() {
			// Create a registry and get an image reference
			registry := NewDestinationRegistry(storeController, storeController, nil, log)
			imageReference, err := registry.GetImageReference("error-repo", "1.0")
			So(err, ShouldBeNil)

			// Get the repo directory path
			tempImageStore := getImageStoreFromImageReference("error-repo", imageReference, log)
			repoDir := path.Join(tempImageStore.RootDir(), "error-repo")

			// Create a file at the repoDir path instead of a directory
			// This will cause os.ReadDir to fail with an error that is NOT os.ErrNotExist
			err = os.MkdirAll(path.Dir(repoDir), 0o755)
			So(err, ShouldBeNil)

			err = os.WriteFile(repoDir, []byte("not a directory"), 0o644)
			So(err, ShouldBeNil)

			// CommitAll should return the ReadDir error (not ErrNotExist)
			err = registry.CommitAll("error-repo", imageReference)
			So(err, ShouldNotBeNil)
			So(errors.Is(err, os.ErrNotExist), ShouldBeFalse)
		})
	})
}

// TestNewClientTimeoutBehavior verifies that newClient creates a client that respects timeouts.
func TestNewClientTimeoutBehavior(t *testing.T) {
	Convey("Test newClient timeout behavior", t, func() {
		logger := log.NewTestLogger()
		zeroRetries := 0
		retryDelay := 1 * time.Millisecond

		Convey("Client respects ResponseHeaderTimeout from config", func() {
			// Server delay - must be longer than ResponseHeaderTimeout to trigger timeout
			serverDelay := 1 * time.Second

			// Create a test server that accepts connections but delays sending headers
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Sleep longer than the timeout to simulate a server that connects
				// but doesn't send headers quickly
				time.Sleep(serverDelay)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			host := strings.TrimPrefix(server.URL, "http://")

			// Create sync config with short ResponseHeaderTimeout
			opts := syncconf.RegistryConfig{
				URLs:                  []string{server.URL},
				SyncTimeout:           syncConstants.DefaultSyncTimeout,
				ResponseHeaderTimeout: 10 * time.Millisecond,
				MaxRetries:            &zeroRetries,
				RetryDelay:            &retryDelay,
			}

			// Create the client using the actual production function
			client, _, err := newClient(opts, syncconf.CredentialsFile{}, logger)
			So(err, ShouldBeNil)

			// Create a reference to the test server
			r, err := ref.New(host + "/repo:tag")
			So(err, ShouldBeNil)

			// Make a request - it should timeout quickly due to ResponseHeaderTimeout
			start := time.Now()
			// Use ManifestHead as a lightweight operation to trigger the HTTP request
			_, err = client.ManifestHead(context.Background(), r)
			elapsed := time.Since(start)

			// Should timeout quickly (approx 10ms * retries + overhead)
			// With 1ms retry delay and 10ms timeout, retries add overhead but should still be < serverDelay
			So(err, ShouldNotBeNil)
			// Allow small tolerance for timing variability (5ms)
			So(elapsed, ShouldBeGreaterThanOrEqualTo, opts.ResponseHeaderTimeout-5*time.Millisecond)
			So(elapsed, ShouldBeLessThan, serverDelay)
		})

		Convey("Client respects SyncTimeout (overall) from config", func() {
			// Server delay - must be longer than SyncTimeout to trigger timeout
			serverDelay := 1 * time.Second

			// Create a test server that sends headers quickly but delays body transfer
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Send headers immediately with Content-Length to bypass ResponseHeaderTimeout
				// but indicate there's a body coming
				w.Header().Set("Content-Length", "100")
				w.WriteHeader(http.StatusOK)
				// Flush headers to ensure they're sent
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				// Delay sending body data - this will trigger SyncTimeout (overall client timeout)
				time.Sleep(serverDelay)
				// Write body data (client should timeout before this completes)
				w.Write(make([]byte, 100))
			}))
			defer server.Close()

			host := strings.TrimPrefix(server.URL, "http://")

			// Create sync config with short SyncTimeout
			opts := syncconf.RegistryConfig{
				URLs:                  []string{server.URL},
				SyncTimeout:           10 * time.Millisecond,
				ResponseHeaderTimeout: syncConstants.DefaultResponseHeaderTimeout,
				MaxRetries:            &zeroRetries,
				RetryDelay:            &retryDelay,
			}

			// Create the client using the actual production function
			client, _, err := newClient(opts, syncconf.CredentialsFile{}, logger)
			So(err, ShouldBeNil)

			r, err := ref.New(host + "/repo:tag")
			So(err, ShouldBeNil)

			// Make a request - it should timeout due to overall SyncTimeout
			// Use ManifestGet (not ManifestHead) to test body transfer timeout
			start := time.Now()
			_, err = client.ManifestGet(context.Background(), r)
			elapsed := time.Since(start)

			// Should timeout within the SyncTimeout period (+ retries)
			// Elapsed should be >= SyncTimeout (since that's when it times out) and < serverDelay
			So(err, ShouldNotBeNil)
			// Allow small tolerance for timing variability (5ms)
			So(elapsed, ShouldBeGreaterThanOrEqualTo, opts.SyncTimeout-5*time.Millisecond)
			So(elapsed, ShouldBeLessThan, serverDelay)
		})
	})
}
