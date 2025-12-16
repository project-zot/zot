package retention_test

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

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
