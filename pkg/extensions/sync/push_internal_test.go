//go:build sync

package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

func newTestImageStore(t *testing.T, dir string) storageTypes.ImageStore {
	t.Helper()

	return local.NewImageStore(dir, false, true, log.NewTestLogger(), monitoring.NewNopMetricServer(),
		nil, nil, nil, nil)
}

func uploadBlob(t *testing.T, imageStore storageTypes.ImageStore, repo string, content []byte) godigest.Digest {
	t.Helper()

	digest := godigest.FromBytes(content)

	_, _, err := imageStore.FullBlobUpload(context.Background(), repo, bytes.NewReader(content), digest)
	So(err, ShouldBeNil)

	return digest
}

func TestPushDestinationGetImageReference(t *testing.T) {
	Convey("A destination turns repo and reference into the host/repo:tag form regclient expects", t, func() {
		destination := &PushDestination{host: "zot.edge:5000"}

		tagRef, err := destination.GetImageReference("library/alpine", "3.20")
		So(err, ShouldBeNil)
		So(tagRef.Registry, ShouldEqual, "zot.edge:5000")
		So(tagRef.Repository, ShouldEqual, "library/alpine")
		So(tagRef.Tag, ShouldEqual, "3.20")

		Convey("A digest reference keeps the digest and drops the tag", func() {
			digest := godigest.FromString("subject")
			digestRef, err := destination.GetImageReference("/library/alpine", digest.String())
			So(err, ShouldBeNil)
			So(digestRef.Repository, ShouldEqual, "library/alpine")
			So(digestRef.Digest, ShouldEqual, digest.String())
			So(digestRef.Tag, ShouldBeEmpty)
		})
	})
}

func TestContentMatchesLocalRepo(t *testing.T) {
	Convey("No content rules select nothing, which is why push requires them", t, func() {
		manager := NewContentManager(nil, log.NewTestLogger())

		So(manager.LocalContentMatches("library/alpine"), ShouldBeEmpty)
	})

	Convey("Content rules are the allowlist and they match local names", t, func() {
		manager := NewContentManager([]syncconf.Content{
			{Prefix: "library/**"},
			{Prefix: "secureblue/*", Destination: "mirror"},
		}, log.NewTestLogger())

		So(manager.LocalContentMatches("library/alpine"), ShouldHaveLength, 1)
		So(manager.LocalContentMatches("mirror/secureblue/securecore"), ShouldHaveLength, 1)
		So(manager.LocalContentMatches("unrelated/repo"), ShouldBeEmpty)
	})
}

func TestMaterializeTree(t *testing.T) {
	Convey("A stored image reaches the staging layout with every blob it references", t, func() {
		ctx := context.Background()
		repo := "library/alpine"

		source := newTestImageStore(t, t.TempDir())
		staging := newTestImageStore(t, t.TempDir())

		configContent := []byte(`{"architecture":"amd64","os":"linux"}`)
		layerContent := []byte("layer-bytes")

		configDigest := uploadBlob(t, source, repo, configContent)
		layerDigest := uploadBlob(t, source, repo, layerContent)

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

		manifestDigest, _, err := source.PutImageManifest(ctx, repo, "3.20", ispec.MediaTypeImageManifest, body, nil)
		So(err, ShouldBeNil)

		service := &BaseService{log: log.NewTestLogger()}

		err = service.materializeTree(ctx, source, staging, repo, manifestDigest, ispec.MediaTypeImageManifest, nil)
		So(err, ShouldBeNil)

		for _, digest := range []godigest.Digest{manifestDigest, configDigest, layerDigest} {
			found, _, _, err := staging.StatBlob(repo, digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)
		}

		Convey("A second pass is a no-op", func() {
			err = service.materializeTree(ctx, source, staging, repo, manifestDigest, ispec.MediaTypeImageManifest, nil)
			So(err, ShouldBeNil)
		})
	})
}

func TestMaterializeIndex(t *testing.T) {
	Convey("An index reaches the staging layout with the children it selects", t, func() {
		ctx := context.Background()
		repo := "library/multiarch"

		source := newTestImageStore(t, t.TempDir())
		staging := newTestImageStore(t, t.TempDir())

		buildChild := func(arch string) ispec.Descriptor {
			configContent := []byte(`{"architecture":"` + arch + `","os":"linux"}`)
			layerContent := []byte("layer-" + arch)

			configDigest := uploadBlob(t, source, repo, configContent)
			layerDigest := uploadBlob(t, source, repo, layerContent)

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

			digest, _, err := source.PutImageManifest(ctx, repo, "child-"+arch, ispec.MediaTypeImageManifest, body, nil)
			So(err, ShouldBeNil)

			return ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    digest,
				Size:      int64(len(body)),
				Platform:  &ispec.Platform{OS: "linux", Architecture: arch},
			}
		}

		amd64 := buildChild("amd64")
		arm64 := buildChild("arm64")

		index := ispec.Index{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{amd64, arm64},
		}

		body, err := json.Marshal(index)
		So(err, ShouldBeNil)

		indexDigest, _, err := source.PutImageManifest(ctx, repo, "3.20", ispec.MediaTypeImageIndex, body, nil)
		So(err, ShouldBeNil)

		service := &BaseService{log: log.NewTestLogger()}

		err = service.materializeTree(ctx, source, staging, repo, indexDigest, ispec.MediaTypeImageIndex,
			[]string{"linux/amd64"})
		So(err, ShouldBeNil)

		found, _, _, err := staging.StatBlob(repo, indexDigest)
		So(err, ShouldBeNil)
		So(found, ShouldBeTrue)

		Convey("The selected child is staged and the filtered one is not", func() {
			found, _, _, err := staging.StatBlob(repo, amd64.Digest)
			So(err, ShouldBeNil)
			So(found, ShouldBeTrue)

			// StatBlob reports a missing blob as an error, not as found=false.
			notFound, _, _, _ := staging.StatBlob(repo, arm64.Digest)
			So(notFound, ShouldBeFalse)
		})
	})
}

// referrerRejectingDestination copies the image but refuses the referrer, which is the failure
// mode the signature guarantee exists for.
type referrerRejectingDestination struct {
	inner  *PushDestination
	failOn godigest.Digest
	copies []ref.Ref
}

func (fake *referrerRejectingDestination) URL() string {
	return "http://destination.test:5000"
}

func (fake *referrerRejectingDestination) GetImageReference(repo, reference string) (ref.Ref, error) {
	return fake.inner.GetImageReference(repo, reference)
}

func (fake *referrerRejectingDestination) CanSkipImage(context.Context, string, string, godigest.Digest) (bool, error) {
	return false, nil
}

func (fake *referrerRejectingDestination) CopyImage(_ context.Context, _ ref.Ref, target ref.Ref) error {
	if target.Digest == fake.failOn.String() {
		return errors.New("destination refused the referrer")
	}

	fake.copies = append(fake.copies, target)

	return nil
}

func (fake *referrerRejectingDestination) PutManifest(context.Context, ref.Ref, manifest.Manifest) error {
	return nil
}

func (fake *referrerRejectingDestination) Close(context.Context, ref.Ref) {}

func TestPushFailsWhenReferrerFails(t *testing.T) {
	Convey("A referrer that cannot be pushed fails the tag instead of leaving an unsigned image", t, func() {
		ctx := context.Background()
		repo := "library/signed"

		store := newTestImageStore(t, t.TempDir())

		configContent := []byte(`{"architecture":"amd64","os":"linux"}`)
		layerContent := []byte("the-layer")
		configDigest := uploadBlob(t, store, repo, configContent)
		layerDigest := uploadBlob(t, store, repo, layerContent)

		image := ispec.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: ispec.MediaTypeImageManifest,
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig, Digest: configDigest, Size: int64(len(configContent)),
			},
			Layers: []ispec.Descriptor{
				{MediaType: ispec.MediaTypeImageLayerGzip, Digest: layerDigest, Size: int64(len(layerContent))},
			},
		}

		imageBody, err := json.Marshal(image)
		So(err, ShouldBeNil)

		imageDigest, _, err := store.PutImageManifest(ctx, repo, "1.0", ispec.MediaTypeImageManifest, imageBody, nil)
		So(err, ShouldBeNil)

		emptyConfig := []byte("{}")
		emptyDigest := uploadBlob(t, store, repo, emptyConfig)
		sigContent := []byte("a-signature")
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
				MediaType: ispec.MediaTypeImageManifest, Digest: imageDigest, Size: int64(len(imageBody)),
			},
		}

		sigBody, err := json.Marshal(signature)
		So(err, ShouldBeNil)

		sigManifestDigest, _, err := store.PutImageManifest(ctx, repo, "signature", ispec.MediaTypeImageManifest, sigBody, nil)
		So(err, ShouldBeNil)

		storeController := storage.StoreController{DefaultStore: store}
		destination := NewDestinationRegistry(storeController, storeController, nil, log.NewTestLogger())
		fake := &referrerRejectingDestination{
			inner:  &PushDestination{host: "destination.test:5000"},
			failOn: sigManifestDigest,
		}

		service := &BaseService{
			log:            log.NewTestLogger(),
			contentManager: NewContentManager(nil, log.NewTestLogger()),
			destination:    destination,
			pushTargets:    []pushDestination{fake},
		}

		err = service.pushTag(ctx, store, repo, "1.0")

		So(err, ShouldNotBeNil)
		So(err.Error(), ShouldContainSubstring, "referrers")

		Convey("The image itself was pushed before the referrer failed", func() {
			So(fake.copies, ShouldHaveLength, 1)
			So(fake.copies[0].Tag, ShouldEqual, "1.0")
		})
	})
}

func TestPushConfigIsEnabled(t *testing.T) {
	Convey("A push block is inert until it is enabled", t, func() {
		So((*syncconf.PushConfig)(nil).IsEnabled(), ShouldBeFalse)

		disabled := false
		So((&syncconf.PushConfig{Enabled: &disabled}).IsEnabled(), ShouldBeFalse)

		enabled := true
		push := &syncconf.PushConfig{Enabled: &enabled, URLs: []string{"https://zot.edge:5000"}}
		So(push.IsEnabled(), ShouldBeTrue)

		registryConfig := syncconf.RegistryConfig{Push: push}
		So(registryConfig.IsPushEnabled(), ShouldBeTrue)
		emptyConfig := syncconf.RegistryConfig{}
		So(emptyConfig.IsPushEnabled(), ShouldBeFalse)
	})
}

// seedImage stores one small image (config + one layer) under repo:tag and returns its digest.
func seedImage(t *testing.T, store storageTypes.ImageStore, repo, tag string) godigest.Digest {
	t.Helper()

	configContent := []byte(`{"architecture":"amd64","os":"linux"}`)
	layerContent := []byte("the-layer-" + tag)
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

	digest, _, err := store.PutImageManifest(context.Background(), repo, tag, ispec.MediaTypeImageManifest, body, nil)
	So(err, ShouldBeNil)

	return digest
}

// recordingDestination remembers which source digests it already holds, so the delta check and
// the second run of a push can be observed without a registry.
type recordingDestination struct {
	inner   *PushDestination
	present map[godigest.Digest]bool
	copies  []godigest.Digest
	puts    []godigest.Digest
}

func newRecordingDestination() *recordingDestination {
	return &recordingDestination{
		inner:   &PushDestination{host: "destination.test:5000"},
		present: map[godigest.Digest]bool{},
	}
}

func (fake *recordingDestination) URL() string {
	return "http://destination.test:5000"
}

func (fake *recordingDestination) GetImageReference(repo, reference string) (ref.Ref, error) {
	return fake.inner.GetImageReference(repo, reference)
}

func (fake *recordingDestination) CanSkipImage(_ context.Context, _ string, _ string,
	digest godigest.Digest,
) (bool, error) {
	return fake.present[digest], nil
}

func (fake *recordingDestination) CopyImage(_ context.Context, sourceRef, _ ref.Ref) error {
	digest, ok := parseReference(sourceRef.Digest)
	if ok {
		fake.present[digest] = true
	}

	fake.copies = append(fake.copies, godigest.Digest(sourceRef.Digest))

	return nil
}

func (fake *recordingDestination) PutManifest(_ context.Context, _ ref.Ref, man manifest.Manifest) error {
	fake.puts = append(fake.puts, godigest.Digest(man.GetDescriptor().Digest))

	return nil
}

func (fake *recordingDestination) Close(context.Context, ref.Ref) {}

func newPushServiceForTest(store storageTypes.ImageStore, targets ...pushDestination) *BaseService {
	storeController := storage.StoreController{DefaultStore: store}

	return &BaseService{
		log:            log.NewTestLogger(),
		contentManager: NewContentManager(nil, log.NewTestLogger()),
		destination:    NewDestinationRegistry(storeController, storeController, nil, log.NewTestLogger()),
		pushTargets:    targets,
	}
}

func TestPushDeltaSkip(t *testing.T) {
	Convey("A destination that already holds the digest costs no copy", t, func() {
		ctx := context.Background()
		repo := "library/alpine"

		store := newTestImageStore(t, t.TempDir())
		imageDigest := seedImage(t, store, repo, "3.20")

		fake := newRecordingDestination()
		fake.present[imageDigest] = true

		service := newPushServiceForTest(store, fake)

		So(service.pushTag(ctx, store, repo, "3.20"), ShouldBeNil)
		So(fake.copies, ShouldBeEmpty)
	})
}

func TestPushIsIdempotent(t *testing.T) {
	Convey("A second run of the same tag copies nothing and reports no error", t, func() {
		ctx := context.Background()
		repo := "library/alpine"

		store := newTestImageStore(t, t.TempDir())
		imageDigest := seedImage(t, store, repo, "3.20")

		fake := newRecordingDestination()
		service := newPushServiceForTest(store, fake)

		So(service.pushTag(ctx, store, repo, "3.20"), ShouldBeNil)
		So(fake.copies, ShouldHaveLength, 1)
		So(fake.copies[0], ShouldEqual, imageDigest)

		Convey("The next cycle is a no-op", func() {
			So(service.pushTag(ctx, store, repo, "3.20"), ShouldBeNil)
			So(fake.copies, ShouldHaveLength, 1)
		})
	})
}

func TestContentFirstMatchWins(t *testing.T) {
	Convey("Overlapping content rules resolve to the first entry in config order", t, func() {
		manager := NewContentManager([]syncconf.Content{
			{Prefix: "library/**", Tags: &syncconf.Tags{Regex: strPtr(`^3\.`)}},
			{Prefix: "library/alpine", Tags: &syncconf.Tags{Regex: strPtr(`^9\.`)}},
		}, log.NewTestLogger())

		matches := manager.LocalContentMatches("library/alpine")
		So(matches, ShouldHaveLength, 2)

		governing := manager.GetContentByLocalRepo("library/alpine")
		So(governing, ShouldNotBeNil)
		So(governing.Prefix, ShouldEqual, "library/**")

		tags, err := manager.FilterLocalTags("library/alpine", []string{"3.20", "9.99"})
		So(err, ShouldBeNil)
		So(tags, ShouldResemble, []string{"3.20"})
	})
}

func strPtr(value string) *string {
	return &value
}

func TestPushDestinationRedactsCredentials(t *testing.T) {
	Convey("A destination url never carries a password into logs or errors", t, func() {
		destination, err := NewPushDestination("https://user:secret@zot.edge:5000",
			&syncconf.PushConfig{}, syncconf.RegistryConfig{}, nil, log.NewTestLogger())
		So(err, ShouldBeNil)

		So(destination.URL(), ShouldContainSubstring, "zot.edge:5000")
		So(strings.Contains(destination.URL(), "secret"), ShouldBeFalse)
		So(destination.URL(), ShouldContainSubstring, "xxxxx")
	})
}
