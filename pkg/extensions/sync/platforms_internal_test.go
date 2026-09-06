//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/platform"
	"github.com/regclient/regclient/types/ref"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

func TestCopySparseIndexStrategy(t *testing.T) {
	Convey("copySparseIndex is distinct from copyDigestComplete", t, func() {
		So(copySparseIndex, ShouldNotEqual, copyDigestComplete)
	})
}

func TestEffectivePeriodicPlatforms(t *testing.T) {
	Convey("effectivePeriodicPlatforms", t, func() {
		registryDefault := []string{"linux/amd64"}

		Convey("inherits registry default when content is nil", func() {
			So(effectivePeriodicPlatforms(nil, registryDefault), ShouldResemble, registryDefault)
		})

		Convey("inherits registry default when content.platforms is unset", func() {
			So(effectivePeriodicPlatforms(&syncconf.Content{Prefix: "repo"}, registryDefault),
				ShouldResemble, registryDefault)
		})

		Convey("content.platforms overrides registry default", func() {
			override := []string{"linux/arm64", "linux/s390x"}
			content := &syncconf.Content{Prefix: "repo", Platforms: &override}
			So(effectivePeriodicPlatforms(content, registryDefault), ShouldResemble, override)
		})

		Convey("non-nil empty content.platforms means all platforms", func() {
			empty := []string{}
			content := &syncconf.Content{Prefix: "repo", Platforms: &empty}
			So(effectivePeriodicPlatforms(content, registryDefault), ShouldResemble, empty)
		})
	})

	Convey("ContentManager.EffectivePlatforms uses matching prefix", t, func() {
		override := []string{"linux/arm64"}
		cm := NewContentManager([]syncconf.Content{
			{Prefix: "other/**", Platforms: nil},
			{Prefix: "special/**", Platforms: &override},
		}, log.NewTestLogger())

		So(cm.EffectivePlatforms("special/app", []string{"linux/amd64"}), ShouldResemble, override)
		So(cm.EffectivePlatforms("other/app", []string{"linux/amd64"}), ShouldResemble, []string{"linux/amd64"})
		So(cm.EffectivePlatforms("unmatched", []string{"linux/amd64"}), ShouldResemble, []string{"linux/amd64"})
	})
}

func TestDescriptorMatchesPlatforms(t *testing.T) {
	Convey("descriptorMatchesPlatforms", t, func() {
		Convey("empty allowlist matches all", func() {
			match, err := descriptorMatchesPlatforms(&platform.Platform{OS: "linux", Architecture: "arm64"}, nil)
			So(err, ShouldBeNil)
			So(match, ShouldBeTrue)
		})

		Convey("matching allowlist entry", func() {
			match, err := descriptorMatchesPlatforms(
				&platform.Platform{OS: "linux", Architecture: "amd64"},
				[]string{"linux/amd64", "linux/arm64"},
			)
			So(err, ShouldBeNil)
			So(match, ShouldBeTrue)
		})

		Convey("non-matching platform is excluded", func() {
			match, err := descriptorMatchesPlatforms(
				&platform.Platform{OS: "linux", Architecture: "arm64"},
				[]string{"linux/amd64"},
			)
			So(err, ShouldBeNil)
			So(match, ShouldBeFalse)
		})

		Convey("unset platform matches only empty allowlist entry", func() {
			match, err := descriptorMatchesPlatforms(nil, []string{"linux/amd64"})
			So(err, ShouldBeNil)
			So(match, ShouldBeFalse)

			match, err = descriptorMatchesPlatforms(nil, []string{""})
			So(err, ShouldBeNil)
			So(match, ShouldBeTrue)
		})

		Convey("skips empty allowlist entries while matching later ones", func() {
			match, err := descriptorMatchesPlatforms(
				&platform.Platform{OS: "linux", Architecture: "amd64"},
				[]string{"", "linux/amd64"},
			)
			So(err, ShouldBeNil)
			So(match, ShouldBeTrue)
		})

		Convey("invalid allowlist entry returns parse error", func() {
			_, err := descriptorMatchesPlatforms(
				&platform.Platform{OS: "linux", Architecture: "amd64"},
				[]string{"bad!"},
			)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestIncludeChildForPlatformFilter(t *testing.T) {
	Convey("includeChildForPlatformFilter", t, func() {
		Convey("platform-less nested index is always included for traversal", func() {
			include, strategy, err := includeChildForPlatformFilter(descriptor.Descriptor{
				MediaType: mediatype.OCI1ManifestList,
				Digest:    "sha256:nested",
			}, []string{"linux/amd64"})
			So(err, ShouldBeNil)
			So(include, ShouldBeTrue)
			So(strategy, ShouldEqual, copySparseIndex)
		})

		Convey("platform-less leaf still requires empty allowlist entry", func() {
			include, strategy, err := includeChildForPlatformFilter(descriptor.Descriptor{
				MediaType: mediatype.OCI1Manifest,
				Digest:    "sha256:leaf",
			}, []string{"linux/amd64"})
			So(err, ShouldBeNil)
			So(include, ShouldBeFalse)
			So(strategy, ShouldEqual, copyDigestComplete)
		})

		Convey("nested index with non-matching platform is excluded", func() {
			include, _, err := includeChildForPlatformFilter(descriptor.Descriptor{
				MediaType: mediatype.Docker2ManifestList,
				Digest:    "sha256:nested-arm",
				Platform:  &platform.Platform{OS: "linux", Architecture: "arm64"},
			}, []string{"linux/amd64"})
			So(err, ShouldBeNil)
			So(include, ShouldBeFalse)
		})

		Convey("propagates platform allowlist parse errors", func() {
			_, _, err := includeChildForPlatformFilter(descriptor.Descriptor{
				MediaType: mediatype.OCI1Manifest,
				Digest:    "sha256:leaf",
				Platform:  &platform.Platform{OS: "linux", Architecture: "amd64"},
			}, []string{"bad!"})
			So(err, ShouldNotBeNil)
		})
	})
}

func TestCopyStrategyForDescriptor(t *testing.T) {
	Convey("copyStrategyForDescriptor", t, func() {
		So(copyStrategyForDescriptor(descriptor.Descriptor{MediaType: mediatype.OCI1ManifestList}),
			ShouldEqual, copySparseIndex)
		So(copyStrategyForDescriptor(descriptor.Descriptor{MediaType: mediatype.Docker2ManifestList}),
			ShouldEqual, copySparseIndex)
		So(copyStrategyForDescriptor(descriptor.Descriptor{MediaType: mediatype.OCI1Manifest}),
			ShouldEqual, copyDigestComplete)
	})
}

func TestExpandIndexChildren(t *testing.T) {
	Convey("expandIndexChildren BFS", t, func() {
		tree := map[string][]childToSync{
			"latest": {
				{digest: "sha256:nested", strategy: copySparseIndex},
				{digest: "sha256:leaf-top", strategy: copyDigestComplete},
			},
			"sha256:nested": {
				{digest: "sha256:leaf-a", strategy: copyDigestComplete},
				{digest: "sha256:leaf-b", strategy: copyDigestComplete},
				{digest: "sha256:nested", strategy: copySparseIndex}, // cycle
			},
		}

		getChildren := func(ref string) ([]childToSync, error) {
			return tree[ref], nil
		}

		out, err := expandIndexChildren("latest", getChildren)
		So(err, ShouldBeNil)
		So(len(out), ShouldEqual, 4)
		So(out[0].digest, ShouldEqual, "sha256:nested")
		So(out[1].digest, ShouldEqual, "sha256:leaf-top")
		So(out[2].digest, ShouldEqual, "sha256:leaf-a")
		So(out[3].digest, ShouldEqual, "sha256:leaf-b")
	})

	Convey("expandIndexChildren empty / non-index root", t, func() {
		out, err := expandIndexChildren("single", func(string) ([]childToSync, error) {
			return nil, nil
		})
		So(err, ShouldBeNil)
		So(out, ShouldBeEmpty)
	})

	Convey("expandIndexChildren skips missing nested index", t, func() {
		getChildren := func(ref string) ([]childToSync, error) {
			switch ref {
			case "latest":
				return []childToSync{
					{digest: "sha256:missing-nested", strategy: copySparseIndex},
					{digest: "sha256:leaf", strategy: copyDigestComplete},
				}, nil
			case "sha256:missing-nested":
				return nil, zerr.ErrManifestNotFound
			default:
				return nil, nil
			}
		}

		out, err := expandIndexChildren("latest", getChildren)
		So(err, ShouldBeNil)
		So(len(out), ShouldEqual, 2)
		So(out[0].digest, ShouldEqual, "sha256:missing-nested")
		So(out[1].digest, ShouldEqual, "sha256:leaf")
	})

	Convey("expandIndexChildren propagates getChildren error", t, func() {
		want := errors.New("expand test error")
		_, err := expandIndexChildren("latest", func(string) ([]childToSync, error) {
			return nil, want
		})
		So(err, ShouldEqual, want)
	})
}

func TestFilterChildrenToSyncMediaType(t *testing.T) {
	Convey("filterChildrenToSync carries descriptor mediaType", t, func() {
		service := &BaseService{
			config:         syncconf.RegistryConfig{},
			contentManager: NewContentManager(nil, log.NewTestLogger()),
			log:            log.NewTestLogger(),
			remote: &mocks.SyncRemoteMock{
				GetManifestListFn: func(ctx context.Context, repo, reference string) ([]descriptor.Descriptor, error) {
					return []descriptor.Descriptor{
						{
							Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							MediaType: mediatype.OCI1Manifest,
							Platform:  &platform.Platform{OS: "linux", Architecture: "amd64"},
						},
						{
							Digest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
							MediaType: mediatype.OCI1ManifestList,
						},
					}, nil
				},
			},
		}

		children, err := service.filterChildrenToSync(context.Background(), "repo", "latest")
		So(err, ShouldBeNil)
		So(len(children), ShouldEqual, 2)
		So(children[0].digest, ShouldEqual, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		So(children[0].mediaType, ShouldEqual, mediatype.OCI1Manifest)
		So(children[0].strategy, ShouldEqual, copyDigestComplete)
		So(children[1].digest, ShouldEqual, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		So(children[1].mediaType, ShouldEqual, mediatype.OCI1ManifestList)
		So(children[1].strategy, ShouldEqual, copySparseIndex)
	})

	Convey("filterChildrenToSync uses content platforms override", t, func() {
		override := []string{"linux/arm64"}
		service := &BaseService{
			config: syncconf.RegistryConfig{
				Platforms: []string{"linux/amd64"},
				Content: []syncconf.Content{
					{Prefix: "special/**", Platforms: &override},
				},
			},
			contentManager: NewContentManager([]syncconf.Content{
				{Prefix: "special/**", Platforms: &override},
			}, log.NewTestLogger()),
			log: log.NewTestLogger(),
			remote: &mocks.SyncRemoteMock{
				GetManifestListFn: func(ctx context.Context, repo, reference string) ([]descriptor.Descriptor, error) {
					return []descriptor.Descriptor{
						{
							Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							MediaType: mediatype.OCI1Manifest,
							Platform:  &platform.Platform{OS: "linux", Architecture: "amd64"},
						},
						{
							Digest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
							MediaType: mediatype.OCI1Manifest,
							Platform:  &platform.Platform{OS: "linux", Architecture: "arm64"},
						},
					}, nil
				},
			},
		}

		children, err := service.filterChildrenToSync(context.Background(), "special/app", "latest")
		So(err, ShouldBeNil)
		So(len(children), ShouldEqual, 1)
		So(children[0].digest, ShouldEqual, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

		children, err = service.filterChildrenToSync(context.Background(), "other/app", "latest")
		So(err, ShouldBeNil)
		So(len(children), ShouldEqual, 1)
		So(children[0].digest, ShouldEqual, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	})
}

func TestShouldFallbackManifestGet(t *testing.T) {
	Convey("shouldFallbackManifestGet", t, func() {
		So(shouldFallbackManifestGet(errs.ErrNotFound), ShouldBeTrue)
		So(shouldFallbackManifestGet(fmt.Errorf("%w [http 404]", errs.ErrNotFound)), ShouldBeTrue)

		So(shouldFallbackManifestGet(nil), ShouldBeFalse)
		So(shouldFallbackManifestGet(errs.ErrHTTPUnauthorized), ShouldBeFalse)
		So(shouldFallbackManifestGet(&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			ShouldBeFalse)
	})
}

func TestMapRegclientManifestErr(t *testing.T) {
	Convey("mapRegclientManifestErr", t, func() {
		So(mapRegclientManifestErr(nil), ShouldBeNil)
		So(errors.Is(mapRegclientManifestErr(errs.ErrNotFound), zerr.ErrManifestNotFound), ShouldBeTrue)
		So(errors.Is(mapRegclientManifestErr(errs.ErrHTTPUnauthorized), zerr.ErrUnauthorizedAccess), ShouldBeTrue)

		other := errors.New("transport")
		So(mapRegclientManifestErr(other), ShouldEqual, other)
	})
}

func TestIsUnresolvedRemoteManifestErr(t *testing.T) {
	Convey("isUnresolvedRemoteManifestErr expects zot-wrapped errors", t, func() {
		So(isUnresolvedRemoteManifestErr(zerr.ErrManifestNotFound), ShouldBeTrue)
		So(isUnresolvedRemoteManifestErr(zerr.ErrBlobNotFound), ShouldBeTrue)
		So(isUnresolvedRemoteManifestErr(zerr.ErrRepoNotFound), ShouldBeTrue)
		// Raw regclient not-found must be mapped by Remote helpers first.
		So(isUnresolvedRemoteManifestErr(errs.ErrNotFound), ShouldBeFalse)
	})
}

func TestRemoteRegistryGetImageReferenceFailures(t *testing.T) {
	Convey("HeadManifest and GetManifestList propagate GetImageReference errors", t, func() {
		// primaryHost "/tmp" makes ref.New reject the constructed registry path.
		registry := &RemoteRegistry{
			primaryHost: "/tmp",
			log:         log.NewTestLogger(),
		}

		_, _, err := registry.HeadManifest(context.Background(), "repo", "tag")
		So(err, ShouldNotBeNil)

		_, err = registry.GetManifestList(context.Background(), "repo", "tag")
		So(err, ShouldNotBeNil)
	})
}

func TestSyncRefReferenceSelection(t *testing.T) {
	Convey("syncRef picks reference from local tag, remote tag, then digests", t, func() {
		service := &BaseService{log: log.NewTestLogger()}

		var seenRef string

		service.destination = &mocks.SyncDestinationMock{
			CanSkipImageFn: func(repo string, reference string, digest godigest.Digest) (bool, error) {
				seenRef = reference

				return true, nil
			},
		}

		remoteDigest := godigest.FromString("payload")

		Convey("prefers local tag", func() {
			localRef, err := ref.New("local/repo:local-tag")
			So(err, ShouldBeNil)
			remoteRef, err := ref.New("remote/repo:remote-tag")
			So(err, ShouldBeNil)

			err = service.syncRef(context.Background(), "repo", remoteRef, localRef, remoteDigest,
				nil, ispec.MediaTypeImageManifest, copyDigestComplete)
			So(err, ShouldBeNil)
			So(seenRef, ShouldEqual, "local-tag")
		})

		Convey("falls back to remote tag when local tag empty", func() {
			localRef := ref.Ref{Repository: "repo"}
			remoteRef, err := ref.New("remote/repo:remote-tag")
			So(err, ShouldBeNil)

			err = service.syncRef(context.Background(), "repo", remoteRef, localRef, remoteDigest,
				nil, ispec.MediaTypeImageManifest, copyDigestComplete)
			So(err, ShouldBeNil)
			So(seenRef, ShouldEqual, "remote-tag")
		})

		Convey("falls back to local digest", func() {
			dig := godigest.FromString("local-pin").String()
			localRef := ref.Ref{Repository: "repo", Digest: dig}
			remoteRef := ref.Ref{Repository: "repo", Digest: godigest.FromString("remote-pin").String()}

			err := service.syncRef(context.Background(), "repo", remoteRef, localRef, remoteDigest,
				nil, ispec.MediaTypeImageManifest, copyDigestComplete)
			So(err, ShouldBeNil)
			So(seenRef, ShouldEqual, dig)
		})

		Convey("falls back to remote digest", func() {
			dig := godigest.FromString("remote-only").String()
			localRef := ref.Ref{Repository: "repo"}
			remoteRef := ref.Ref{Repository: "repo", Digest: dig}

			err := service.syncRef(context.Background(), "repo", remoteRef, localRef, remoteDigest,
				nil, ispec.MediaTypeImageManifest, copyDigestComplete)
			So(err, ShouldBeNil)
			So(seenRef, ShouldEqual, dig)
		})
	})
}
