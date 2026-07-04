package retention_test

import (
	"context"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/retention"
)

func TestGetCandidatesWithMissingStatistics(t *testing.T) {
	Convey("GetCandidates should handle missing statistics gracefully", t, func() {
		now := time.Now()

		Convey("With complete statistics", func() {
			repoMeta := mTypes.RepoMeta{
				Name: "test-repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:    "sha256:digest1",
						MediaType: "application/vnd.oci.image.manifest.v1+json",
					},
					"tag2": {
						Digest:    "sha256:digest2",
						MediaType: "application/vnd.oci.image.manifest.v1+json",
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{
					"sha256:digest1": {
						PushTimestamp:     now,
						LastPullTimestamp: now,
						DownloadCount:     5,
					},
					"sha256:digest2": {
						PushTimestamp:     now.Add(-24 * time.Hour),
						LastPullTimestamp: now.Add(-12 * time.Hour),
						DownloadCount:     10,
					},
				},
			}

			candidates := retention.GetCandidates(repoMeta)

			So(candidates, ShouldHaveLength, 2)
			So(candidates[0].Tag, ShouldBeIn, "tag1", "tag2")
			So(candidates[1].Tag, ShouldBeIn, "tag1", "tag2")
		})

		Convey("With missing statistics for one tag", func() {
			repoMeta := mTypes.RepoMeta{
				Name: "test-repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:    "sha256:digest1",
						MediaType: "application/vnd.oci.image.manifest.v1+json",
					},
					"tag2": {
						Digest:    "sha256:digest2",
						MediaType: "application/vnd.oci.image.manifest.v1+json",
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{
					"sha256:digest1": {
						PushTimestamp:     now,
						LastPullTimestamp: now,
						DownloadCount:     5,
					},
					// tag2's digest has no statistics - simulates inconsistent metaDB state
				},
			}

			candidates := retention.GetCandidates(repoMeta)

			// Should only return candidate for tag1, skipping tag2 with missing statistics
			So(candidates, ShouldHaveLength, 1)
			So(candidates[0].Tag, ShouldEqual, "tag1")
			So(candidates[0].DigestStr, ShouldEqual, "sha256:digest1")
		})

		Convey("With no statistics at all", func() {
			repoMeta := mTypes.RepoMeta{
				Name: "test-repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:    "sha256:digest1",
						MediaType: "application/vnd.oci.image.manifest.v1+json",
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{},
			}

			candidates := retention.GetCandidates(repoMeta)

			// Should return empty list - no candidates without statistics
			So(candidates, ShouldHaveLength, 0)
		})

		Convey("With nil Statistics map", func() {
			repoMeta := mTypes.RepoMeta{
				Name: "test-repo",
				Tags: map[string]mTypes.Descriptor{
					"tag1": {
						Digest:    "sha256:digest1",
						MediaType: "application/vnd.oci.image.manifest.v1+json",
					},
				},
				Statistics: nil,
			}

			candidates := retention.GetCandidates(repoMeta)

			// Should return empty list and not panic
			So(candidates, ShouldHaveLength, 0)
		})
	})
}

func TestGetUntaggedCandidates(t *testing.T) {
	Convey("GetUntaggedCandidates should use only untagged descriptors with statistics", t, func() {
		now := time.Now()
		untaggedDigest := godigest.FromString("untagged")
		taggedDigest := godigest.FromString("tagged")
		missingStatsDigest := godigest.FromString("missing-stats")

		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					Digest:    untaggedDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
				{
					Digest:    taggedDigest,
					MediaType: ispec.MediaTypeImageManifest,
					Annotations: map[string]string{
						ispec.AnnotationRefName: "latest",
					},
				},
				{
					Digest:    missingStatsDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		repoMeta := mTypes.RepoMeta{
			Name: "test-repo",
			Statistics: map[string]mTypes.DescriptorStatistics{
				untaggedDigest.String(): {
					PushTimestamp:     now.Add(-2 * time.Hour),
					LastPullTimestamp: now.Add(-time.Hour),
					DownloadCount:     3,
				},
				taggedDigest.String(): {
					PushTimestamp:     now,
					LastPullTimestamp: now,
				},
			},
		}

		candidates := retention.GetUntaggedCandidates(repoMeta, index)

		So(candidates, ShouldHaveLength, 1)
		So(candidates[0].DigestStr, ShouldEqual, untaggedDigest.String())
		So(candidates[0].Tag, ShouldBeEmpty)
	})
}

func TestGetRetainedUntaggedFromMetaDB(t *testing.T) {
	Convey("GetRetainedUntaggedFromMetaDB applies untagged retention rules separately", t, func() {
		now := time.Now()
		recentDigest := godigest.FromString("recent")
		oldDigest := godigest.FromString("old")
		pulledWithin := 24 * time.Hour

		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					Digest:    recentDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
				{
					Digest:    oldDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		repoMeta := mTypes.RepoMeta{
			Name: "test-repo",
			Statistics: map[string]mTypes.DescriptorStatistics{
				recentDigest.String(): {
					PushTimestamp:     now.Add(-time.Hour),
					LastPullTimestamp: now.Add(-time.Hour),
				},
				oldDigest.String(): {
					PushTimestamp:     now.Add(-48 * time.Hour),
					LastPullTimestamp: now.Add(-36 * time.Hour),
				},
			},
		}

		policyMgr := retention.NewPolicyManager(config.ImageRetention{
			Policies: []config.RetentionPolicy{
				{
					Repositories: []string{"test-repo"},
					KeepUntagged: &config.KeepUntaggedPolicy{
						PulledWithin:            &pulledWithin,
						MostRecentlyPushedCount: 1,
					},
				},
			},
		}, zlog.NewTestLogger(), nil)

		retained := policyMgr.GetRetainedUntaggedFromMetaDB(context.Background(), repoMeta, index)

		So(retained, ShouldHaveLength, 1)
		So(retained[0], ShouldEqual, recentDigest.String())
	})

	Convey("GetRetainedUntaggedFromMetaDB keeps untagged manifests missing statistics", t, func() {
		now := time.Now()
		recentDigest := godigest.FromString("recent")
		missingStatsDigest := godigest.FromString("missing-stats")
		oldDigest := godigest.FromString("old")
		pulledWithin := 24 * time.Hour

		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					Digest:    recentDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
				{
					Digest:    missingStatsDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
				{
					Digest:    oldDigest,
					MediaType: ispec.MediaTypeImageManifest,
				},
			},
		}

		repoMeta := mTypes.RepoMeta{
			Name: "test-repo",
			Statistics: map[string]mTypes.DescriptorStatistics{
				recentDigest.String(): {
					PushTimestamp:     now.Add(-time.Hour),
					LastPullTimestamp: now.Add(-time.Hour),
				},
				oldDigest.String(): {
					PushTimestamp:     now.Add(-48 * time.Hour),
					LastPullTimestamp: now.Add(-36 * time.Hour),
				},
			},
		}

		policyMgr := retention.NewPolicyManager(config.ImageRetention{
			Policies: []config.RetentionPolicy{
				{
					Repositories: []string{"test-repo"},
					KeepUntagged: &config.KeepUntaggedPolicy{
						PulledWithin: &pulledWithin,
					},
				},
			},
		}, zlog.NewTestLogger(), nil)

		retained := policyMgr.GetRetainedUntaggedFromMetaDB(context.Background(), repoMeta, index)

		So(retained, ShouldContain, recentDigest.String())
		So(retained, ShouldContain, missingStatsDigest.String())
		So(retained, ShouldNotContain, oldDigest.String())
	})
}
