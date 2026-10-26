//go:build sync

package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
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
	Convey("No content rules select the whole store", t, func() {
		manager := NewContentManager(nil, log.NewTestLogger())

		So(manager.MatchesLocalRepo("library/alpine"), ShouldBeTrue)
		So(manager.MatchesLocalRepo("anything/at/all"), ShouldBeTrue)
	})

	Convey("Content rules are the allowlist and they match local names", t, func() {
		manager := NewContentManager([]syncconf.Content{
			{Prefix: "library/**"},
			{Prefix: "secureblue/*", Destination: "mirror"},
		}, log.NewTestLogger())

		So(manager.MatchesLocalRepo("library/alpine"), ShouldBeTrue)
		So(manager.MatchesLocalRepo("mirror/secureblue/securecore"), ShouldBeTrue)
		So(manager.MatchesLocalRepo("unrelated/repo"), ShouldBeFalse)
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
