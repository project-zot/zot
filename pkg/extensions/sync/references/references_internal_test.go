//go:build sync
// +build sync

package references

import (
	"context"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	client "zotregistry.dev/zot/pkg/extensions/sync/httpclient"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/test/mocks"
)

var errRef = errors.New("err")

func TestCosign(t *testing.T) {
	Convey("trigger errors", t, func() {
		cfg := client.Config{
			URL:       "url",
			TLSVerify: false,
		}

		client, err := client.New(cfg, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		cosign := NewCosignReference(client, storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "", "", errRef
			},
		}}, nil, log.NewLogger("debug", ""))

		ok, err := cosign.canSkipReferences("repo", "tag", nil)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)

		// trigger GetImageManifest err
		ok, err = cosign.canSkipReferences("repo", "tag", &ispec.Manifest{MediaType: ispec.MediaTypeImageManifest})
		So(err, ShouldNotBeNil)
		So(ok, ShouldBeFalse)

		cosign = NewCosignReference(client, storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "digest", "", nil
			},
		}}, nil, log.NewLogger("debug", ""))

		// different digest
		ok, err = cosign.canSkipReferences("repo", "tag", &ispec.Manifest{MediaType: ispec.MediaTypeImageManifest})
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})
}

func TestOci(t *testing.T) {
	Convey("trigger errors", t, func() {
		cfg := client.Config{
			URL:       "url",
			TLSVerify: false,
		}

		client, err := client.New(cfg, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		oci := NewOciReferences(client, storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetReferrersFn: func(repo string, digest godigest.Digest, artifactTypes []string) (ispec.Index, error) {
				return ispec.Index{}, zerr.ErrManifestNotFound
			},
		}}, nil, log.NewLogger("debug", ""))

		ok := oci.IsSigned(context.Background(), "repo", "")
		So(ok, ShouldBeFalse)

		// trigger GetReferrers err
		ok, err = oci.canSkipReferences("repo", "tag", ispec.Index{Manifests: []ispec.Descriptor{{Digest: "digest1"}}})
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})
}

func TestReferrersTag(t *testing.T) {
	Convey("trigger errors", t, func() {
		cfg := client.Config{
			URL:       "url",
			TLSVerify: false,
		}

		client, err := client.New(cfg, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		referrersTag := NewTagReferences(client, storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "", "", errRef
			},
		}}, nil, log.NewLogger("debug", ""))

		ok := referrersTag.IsSigned(context.Background(), "repo", "")
		So(ok, ShouldBeFalse)

		// trigger GetImageManifest err
		ok, err = referrersTag.canSkipReferences("repo", "subjectdigest", "digest")
		So(err, ShouldNotBeNil)
		So(ok, ShouldBeFalse)

		referrersTag = NewTagReferences(client, storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "", "", zerr.ErrManifestNotFound
			},
		}}, nil, log.NewLogger("debug", ""))

		// trigger GetImageManifest err
		ok, err = referrersTag.canSkipReferences("repo", "subjectdigest", "digest")
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)

		referrersTag = NewTagReferences(client, storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetImageManifestFn: func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				return []byte{}, "digest", "", nil
			},
		}}, nil, log.NewLogger("debug", ""))

		// different digest
		ok, err = referrersTag.canSkipReferences("repo", "subjectdigest", "newdigest")
		So(err, ShouldBeNil)
		So(ok, ShouldBeFalse)
	})
}

func TestSyncManifest(t *testing.T) {
	Convey("sync manifest not found err", t, func() {
		cfg := client.Config{
			URL:       "url",
			TLSVerify: false,
		}

		client, err := client.New(cfg, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		digest := godigest.FromString("test")

		buf, refDigest, err := syncManifest(context.Background(), client, mocks.MockedImageStore{},
			"repo", "repo", ispec.Descriptor{
				Digest:    digest,
				Size:      10,
				MediaType: ispec.MediaTypeImageManifest,
			}, digest.String(), log.Logger{})

		So(buf, ShouldBeEmpty)
		So(refDigest, ShouldBeEmpty)
		So(err, ShouldNotBeNil)
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
