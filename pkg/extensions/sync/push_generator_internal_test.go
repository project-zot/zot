//go:build sync

package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/compat"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// fakePushService records the repositories the generator hands to it.
type fakePushService struct {
	pushed []string
}

func (service *fakePushService) PushRepo(_ context.Context, repo string) error {
	service.pushed = append(service.pushed, repo)

	return nil
}

func TestPushInitMode(t *testing.T) {
	Convey("Push mode is inert until it has destinations", t, func() {
		disabled := false
		service := &BaseService{
			log:    log.NewTestLogger(),
			config: syncconf.RegistryConfig{Push: &syncconf.PushConfig{Enabled: &disabled}},
		}

		So(service.InitPushMode(), ShouldBeNil)
		So(service.pushTargets, ShouldBeEmpty)

		enabled := true
		service = &BaseService{
			log:    log.NewTestLogger(),
			config: syncconf.RegistryConfig{Push: &syncconf.PushConfig{Enabled: &enabled}},
		}

		So(service.InitPushMode(), ShouldEqual, zerr.ErrSyncNoURLsLeft)

		Convey("A malformed destination is refused", func() {
			service := &BaseService{
				log: log.NewTestLogger(),
				config: syncconf.RegistryConfig{Push: &syncconf.PushConfig{
					Enabled: &enabled,
					URLs:    []string{"https://"},
				}},
			}

			So(service.InitPushMode(), ShouldNotBeNil)
		})

		Convey("Every destination gets its own client", func() {
			service := &BaseService{
				log: log.NewTestLogger(),
				config: syncconf.RegistryConfig{Push: &syncconf.PushConfig{
					Enabled: &enabled,
					URLs:    []string{"https://one.invalid:5000", "http://two.invalid:5000"},
				}},
			}

			So(service.InitPushMode(), ShouldBeNil)
			So(service.pushTargets, ShouldHaveLength, 2)
			So(service.pushTargets[0].URL(), ShouldEqual, "https://one.invalid:5000")
			So(service.pushTargets[1].URL(), ShouldEqual, "http://two.invalid:5000")
		})
	})
}

func TestPushDestinationCanSkipImage(t *testing.T) {
	digest := godigest.FromString("the-image")

	Convey("The delta check reads the destination digest", t, func() {
		var status int

		var served string

		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodHead {
				writer.WriteHeader(http.StatusMethodNotAllowed)

				return
			}

			if status == 0 {
				writer.WriteHeader(http.StatusNotFound)

				return
			}

			writer.Header().Set("Docker-Content-Digest", served)
			writer.Header().Set("Content-Type", ispec.MediaTypeImageManifest)
			writer.Header().Set("Content-Length", "2")
			writer.WriteHeader(status)
		}))
		defer server.Close()

		destination, err := NewPushDestination(server.URL, &syncconf.PushConfig{}, syncconf.RegistryConfig{},
			nil, log.NewTestLogger())
		So(err, ShouldBeNil)

		// A destination that has never seen the repo answers 404.
		skip, err := destination.CanSkipImage(context.Background(), "library/alpine", "3.20", digest)
		So(err, ShouldBeNil)
		So(skip, ShouldBeFalse)

		status = http.StatusOK
		served = digest.String()

		skip, err = destination.CanSkipImage(context.Background(), "library/alpine", "3.20", digest)
		So(err, ShouldBeNil)
		So(skip, ShouldBeTrue)

		served = godigest.FromString("something-else").String()

		skip, err = destination.CanSkipImage(context.Background(), "library/alpine", "3.20", digest)
		So(err, ShouldBeNil)
		So(skip, ShouldBeFalse)

		Convey("A failing destination surfaces the error", func() {
			status = http.StatusInternalServerError
			served = digest.String()

			_, err := destination.CanSkipImage(context.Background(), "library/alpine", "3.20", digest)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestPushDestinationCopyErrors(t *testing.T) {
	Convey("A copy to an unreachable destination is reported and released", t, func() {
		destination, err := NewPushDestination("http://127.0.0.1:1", &syncconf.PushConfig{},
			syncconf.RegistryConfig{}, nil, log.NewTestLogger())
		So(err, ShouldBeNil)

		sourceRef, err := destination.GetImageReference("library/alpine", "3.20")
		So(err, ShouldBeNil)

		So(destination.CopyImage(context.Background(), sourceRef, sourceRef), ShouldNotBeNil)

		// Close must be safe on a ref that was never opened.
		destination.Close(context.Background(), sourceRef)
	})
}

func TestPushTaskGenerator(t *testing.T) {
	Convey("The generator walks every store once and resets for the next cycle", t, func() {
		first := newTestImageStore(t, t.TempDir())
		second := newTestImageStore(t, t.TempDir())

		seedImage(t, first, "library/one", "1.0")
		seedImage(t, second, "library/two", "1.0")

		service := &fakePushService{}
		generator := NewPushTaskGenerator(service,
			[]storageTypes.ImageStore{first, second}, log.NewTestLogger())

		So(generator.Name(), ShouldEqual, "PushGenerator")
		So(generator.IsReady(), ShouldBeTrue)
		So(generator.IsDone(), ShouldBeFalse)

		seen := map[string]bool{}

		for {
			task, err := generator.Next()
			So(err, ShouldBeNil)

			if task == nil {
				break
			}

			So(task.Name(), ShouldEqual, "PushTask")
			So(task.String(), ShouldContainSubstring, task.Name())

			So(task.DoWork(context.Background()), ShouldBeNil)
			seen[service.pushed[len(service.pushed)-1]] = true
		}

		So(seen, ShouldResemble, map[string]bool{"library/one": true, "library/two": true})
		So(generator.IsDone(), ShouldBeTrue)

		Convey("Reset makes the next cycle see the same repositories", func() {
			generator.Reset()

			So(generator.IsDone(), ShouldBeFalse)

			task, err := generator.Next()
			So(err, ShouldBeNil)
			So(task, ShouldNotBeNil)
		})
	})
}

func TestPushRepoSelection(t *testing.T) {
	Convey("Only repositories selected by a content rule are pushed", t, func() {
		store := newTestImageStore(t, t.TempDir())
		seedImage(t, store, "library/alpine", "3.20")

		destination := newRecordingDestination()
		storeController := storage.StoreController{DefaultStore: store}

		service := &BaseService{
			log:             log.NewTestLogger(),
			contentManager:  NewContentManager([]syncconf.Content{{Prefix: "other/**"}}, log.NewTestLogger()),
			storeController: storeController,
			destination:     NewDestinationRegistry(storeController, storeController, nil, log.NewTestLogger()),
			pushTargets:     []pushDestination{destination},
		}

		So(service.PushRepo(context.Background(), "library/alpine"), ShouldBeNil)
		So(destination.copies, ShouldBeEmpty)

		Convey("A repo without tags is a no-op", func() {
			service.contentManager = NewContentManager([]syncconf.Content{{Prefix: "**"}}, log.NewTestLogger())

			So(service.PushRepo(context.Background(), "library/missing"), ShouldBeNil)
			So(destination.copies, ShouldBeEmpty)
		})

		Convey("Overlapping rules still push, the first one governs", func() {
			service.contentManager = NewContentManager([]syncconf.Content{
				{Prefix: "library/**"},
				{Prefix: "library/alpine"},
			}, log.NewTestLogger())

			So(service.PushRepo(context.Background(), "library/alpine"), ShouldBeNil)
			So(destination.copies, ShouldHaveLength, 1)
		})

		Convey("A tag filter that matches nothing pushes nothing", func() {
			service.contentManager = NewContentManager([]syncconf.Content{
				{Prefix: "library/**", Tags: &syncconf.Tags{Regex: strPtr(`^9\.`)}},
			}, log.NewTestLogger())

			So(service.PushRepo(context.Background(), "library/alpine"), ShouldBeNil)
			So(destination.copies, ShouldBeEmpty)
		})
	})
}

func TestPushRepoPropagatesDestinationErrors(t *testing.T) {
	Convey("A destination that cannot answer the delta check fails the repo", t, func() {
		store := newTestImageStore(t, t.TempDir())
		seedImage(t, store, "library/alpine", "3.20")

		service := &BaseService{
			log:             log.NewTestLogger(),
			contentManager:  NewContentManager([]syncconf.Content{{Prefix: "**"}}, log.NewTestLogger()),
			storeController: storage.StoreController{DefaultStore: store},
			pushTargets:     []pushDestination{&failingDeltaDestination{}},
		}

		So(service.PushRepo(context.Background(), "library/alpine"), ShouldNotBeNil)
	})
}

// failingDeltaDestination fails the cheap check, the first thing the loop asks a destination.
type failingDeltaDestination struct{}

func (fake *failingDeltaDestination) URL() string { return "http://broken.invalid:5000" }

func (fake *failingDeltaDestination) GetImageReference(repo, reference string) (ref.Ref, error) {
	return (&PushDestination{host: "broken.invalid:5000"}).GetImageReference(repo, reference)
}

func (fake *failingDeltaDestination) CanSkipImage(context.Context, string, string, godigest.Digest) (bool, error) {
	return false, context.DeadlineExceeded
}

func (fake *failingDeltaDestination) CopyImage(context.Context, ref.Ref, ref.Ref) error {
	return nil
}

func (fake *failingDeltaDestination) PutManifest(context.Context, ref.Ref, manifest.Manifest) error {
	return nil
}

func (fake *failingDeltaDestination) Close(context.Context, ref.Ref) {}

func TestMaterializeFailures(t *testing.T) {
	Convey("A manifest the store does not hold fails the walk", t, func() {
		source := newTestImageStore(t, t.TempDir())
		staging := newTestImageStore(t, t.TempDir())
		service := &BaseService{log: log.NewTestLogger()}

		_, err := service.materializeTree(context.Background(), source, staging, "library/missing",
			godigest.FromString("absent"), ispec.MediaTypeImageManifest, nil)
		So(err, ShouldNotBeNil)
	})

	Convey("A blob the store does not hold fails the walk", t, func() {
		source := newTestImageStore(t, t.TempDir())
		staging := newTestImageStore(t, t.TempDir())
		service := &BaseService{log: log.NewTestLogger()}

		err := service.materializeBlob(context.Background(), source, staging, "library/missing",
			descriptor.Descriptor{Digest: godigest.FromString("absent"), MediaType: ispec.MediaTypeImageLayer})
		So(err, ShouldNotBeNil)
	})
}

func TestLocalReferrersMissingRepo(t *testing.T) {
	Convey("A repository without referrers yields an empty index, not an error", t, func() {
		store := newTestImageStore(t, t.TempDir())
		service := &BaseService{log: log.NewTestLogger()}

		index, err := service.localReferrers(store, "library/missing", godigest.FromString("subject"))
		So(err, ShouldBeNil)
		So(index.Manifests, ShouldBeEmpty)
	})
}

func TestPushPlatforms(t *testing.T) {
	Convey("Platform allowlists come from the push block when there is one", t, func() {
		service := &BaseService{}
		So(service.pushPlatforms(), ShouldBeNil)

		service.config = syncconf.RegistryConfig{Push: &syncconf.PushConfig{Platforms: []string{"linux/amd64"}}}
		So(service.pushPlatforms(), ShouldResemble, []string{"linux/amd64"})
	})
}

// seedIndex stores an index with two platform children and returns the index digest plus both
// child digests.
func seedIndex(t *testing.T, store storageTypes.ImageStore, repo string,
) (godigest.Digest, godigest.Digest, godigest.Digest) {
	t.Helper()

	ctx := context.Background()

	child := func(arch string) ispec.Descriptor {
		configContent := []byte(`{"architecture":"` + arch + `","os":"linux"}`)
		layerContent := []byte("layer-" + arch)

		configDigest := uploadBlob(t, store, repo, configContent)
		layerDigest := uploadBlob(t, store, repo, layerContent)

		man := ispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageManifest,
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig, Digest: configDigest, Size: int64(len(configContent)),
			},
			Layers: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageLayerGzip, Digest: layerDigest, Size: int64(len(layerContent))},
			},
		}

		body, err := json.Marshal(man)
		So(err, ShouldBeNil)

		digest, _, err := store.PutImageManifest(ctx, repo, "child-"+arch, ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		return ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    digest,
			Size:      int64(len(body)),
			Platform:  &ispec.Platform{OS: "linux", Architecture: arch},
		}
	}

	amd64 := child("amd64")
	arm64 := child("arm64")

	index := ispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{amd64, arm64},
	}

	body, err := json.Marshal(index)
	So(err, ShouldBeNil)

	indexDigest, _, err := store.PutImageManifest(ctx, repo, "1.0", ispec.MediaTypeImageIndex, body, nil)
	So(err, ShouldBeNil)

	return indexDigest, amd64.Digest, arm64.Digest
}

func TestPushFilteredCopy(t *testing.T) {
	Convey("A platform allowlist copies the selected children and the unchanged index", t, func() {
		ctx := context.Background()
		repo := "library/multi"

		store := newTestImageStore(t, t.TempDir())
		indexDigest, amd64Digest, arm64Digest := seedIndex(t, store, repo)

		platforms := []string{"linux/amd64"}
		fake := newRecordingDestination()
		storeController := storage.StoreController{DefaultStore: store}

		service := &BaseService{
			log: log.NewTestLogger(),
			contentManager: NewContentManager([]syncconf.Content{
				{Prefix: "**", Platforms: &platforms},
			}, log.NewTestLogger()),
			storeController: storeController,
			destination:     NewDestinationRegistry(storeController, storeController, nil, log.NewTestLogger()),
			pushTargets:     []pushDestination{fake},
		}

		So(service.pushTag(ctx, store, repo, "1.0"), ShouldBeNil)

		// The index goes through PutManifest, only the selected child through ImageCopy.
		So(fake.copies, ShouldResemble, []godigest.Digest{amd64Digest})
		So(fake.puts, ShouldResemble, []godigest.Digest{indexDigest})

		Convey("Without a filter the whole tree travels in one copy", func() {
			fake := newRecordingDestination()
			service.contentManager = NewContentManager([]syncconf.Content{{Prefix: "**"}}, log.NewTestLogger())
			service.pushTargets = []pushDestination{fake}

			So(service.pushTag(ctx, store, repo, "1.0"), ShouldBeNil)
			So(fake.copies, ShouldResemble, []godigest.Digest{indexDigest})
			So(fake.puts, ShouldBeEmpty)
			So(fake.copies, ShouldNotContain, arm64Digest)
		})
	})
}

func TestPushContinuesAfterDestinationFailure(t *testing.T) {
	Convey("One unreachable destination does not starve the healthy ones", t, func() {
		store := newTestImageStore(t, t.TempDir())
		seedImage(t, store, "library/alpine", "3.20")

		good := newRecordingDestination()
		storeController := storage.StoreController{DefaultStore: store}

		service := &BaseService{
			log:             log.NewTestLogger(),
			contentManager:  NewContentManager([]syncconf.Content{{Prefix: "**"}}, log.NewTestLogger()),
			storeController: storeController,
			destination:     NewDestinationRegistry(storeController, storeController, nil, log.NewTestLogger()),
			pushTargets:     []pushDestination{&failingDeltaDestination{}, good},
		}

		err := service.pushTag(context.Background(), store, "library/alpine", "3.20")
		So(err, ShouldNotBeNil)
		So(good.copies, ShouldHaveLength, 1)
	})
}

func TestStagingMediaCompat(t *testing.T) {
	Convey("The staging store inherits the instance's docker media compatibility", t, func() {
		service := &BaseService{}
		So(service.stagingMediaCompat(), ShouldBeNil)

		service.config.SetDockerCompat(true)
		So(service.stagingMediaCompat(), ShouldResemble, []compat.MediaCompatibility{compat.DockerManifestV2SchemaV2})
	})
}

func TestMaterializeTraversesPlatformLessIndex(t *testing.T) {
	Convey("A platform-less nested index is traversed so its allowlisted leaves are staged", t, func() {
		ctx := context.Background()
		repo := "library/nested"

		source := newTestImageStore(t, t.TempDir())
		staging := newTestImageStore(t, t.TempDir())

		indexDigest, amd64Digest, _ := seedIndex(t, source, repo)

		// Wrap the index in an index that carries no platform on the nested entry.
		nested := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageIndex, Digest: indexDigest, Size: 1,
			}},
		}

		body, err := json.Marshal(nested)
		So(err, ShouldBeNil)

		outerDigest, _, err := source.PutImageManifest(ctx, repo, "outer", ispec.MediaTypeImageIndex, body, nil)
		So(err, ShouldBeNil)

		service := &BaseService{log: log.NewTestLogger()}

		_, err = service.materializeTree(ctx, source, staging, repo, outerDigest, ispec.MediaTypeImageIndex,
			[]string{"linux/amd64"})
		So(err, ShouldBeNil)

		for _, digest := range []godigest.Digest{outerDigest, indexDigest, amd64Digest} {
			found, _, _, err := staging.StatBlob(repo, digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
		}
	})
}

func TestPushReferrersOfIndexChildren(t *testing.T) {
	Convey("A referrer attached to an index child is pushed with the tree", t, func() {
		ctx := context.Background()
		repo := "library/attested"

		store := newTestImageStore(t, t.TempDir())
		_, amd64Digest, _ := seedIndex(t, store, repo)

		// One signature whose subject is the amd64 child, not the index.
		emptyConfig := []byte("{}")
		emptyDigest := uploadBlob(t, store, repo, emptyConfig)
		sigContent := []byte("child-signature")
		sigDigest := uploadBlob(t, store, repo, sigContent)

		signature := ispec.Manifest{
			Versioned:    specs.Versioned{SchemaVersion: 2},
			MediaType:    ispec.MediaTypeImageManifest,
			ArtifactType: "application/vnd.example.signature",
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeEmptyJSON, Digest: emptyDigest, Size: int64(len(emptyConfig)),
			},
			Layers: []ispec.Descriptor{
				{MediaType: "application/vnd.example.signature", Digest: sigDigest, Size: int64(len(sigContent))},
			},
			Subject: &ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest, Digest: amd64Digest, Size: 1,
			},
		}

		body, err := json.Marshal(signature)
		So(err, ShouldBeNil)

		sigManifestDigest, _, err := store.PutImageManifest(ctx, repo, "signature", ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		fake := newRecordingDestination()
		storeController := storage.StoreController{DefaultStore: store}

		service := &BaseService{
			log:             log.NewTestLogger(),
			contentManager:  NewContentManager([]syncconf.Content{{Prefix: "**"}}, log.NewTestLogger()),
			storeController: storeController,
			destination:     NewDestinationRegistry(storeController, storeController, nil, log.NewTestLogger()),
			pushTargets:     []pushDestination{fake},
		}

		So(service.pushTag(ctx, store, repo, "1.0"), ShouldBeNil)
		So(fake.copies, ShouldContain, sigManifestDigest)
	})
}
