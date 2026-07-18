package imagestore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

// TestGetReferrers covers ImageStore.GetReferrers (a thin WithRepoReadLock wrapper
// around common.GetReferrers), previously untested: it pushes a subject manifest and
// an artifact manifest whose Subject points at it, then confirms the artifact is
// returned as a referrer and a manifest with no referrers returns an empty index.
func TestGetReferrers(t *testing.T) {
	Convey("GetReferrers", t, func() {
		log := zlog.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		store := imagestore.NewImageStore(t.TempDir(), "", false, false, log, metrics, nil,
			local.New(true), nil, nil, nil)

		const repo = "test"

		layerContent := []byte("referrers-subject-layer")
		layerDigest := godigest.FromBytes(layerContent)
		_, _, err := store.FullBlobUpload(context.Background(), repo, bytes.NewReader(layerContent), layerDigest)
		So(err, ShouldBeNil)

		subjectManifest := ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Config:    ispec.DescriptorEmptyJSON,
			Layers: []ispec.Descriptor{
				{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: layerDigest, Size: int64(len(layerContent))},
			},
		}
		subjectManifest.SchemaVersion = 2

		_, _, err = store.FullBlobUpload(context.Background(), repo,
			bytes.NewReader(ispec.DescriptorEmptyJSON.Data), ispec.DescriptorEmptyJSON.Digest)
		So(err, ShouldBeNil)

		subjectBuf, err := json.Marshal(subjectManifest)
		So(err, ShouldBeNil)

		subjectDigest, _, err := store.PutImageManifest(context.Background(), repo, "subject",
			ispec.MediaTypeImageManifest, subjectBuf, nil)
		So(err, ShouldBeNil)

		Convey("a subject with no referrers returns an empty index", func() {
			index, err := store.GetReferrers(repo, subjectDigest, nil)
			So(err, ShouldBeNil)
			So(index.Manifests, ShouldBeEmpty)
		})

		Convey("an artifact manifest pointing at the subject is returned as a referrer", func() {
			artifactBlob := []byte("referrer-artifact-blob")
			artifactBlobDigest := godigest.FromBytes(artifactBlob)
			_, _, err := store.FullBlobUpload(context.Background(), repo, bytes.NewReader(artifactBlob), artifactBlobDigest)
			So(err, ShouldBeNil)

			artifactManifest := ispec.Manifest{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: "application/vnd.example.referrer",
				Config:       ispec.DescriptorEmptyJSON,
				Layers: []ispec.Descriptor{
					{MediaType: "application/octet-stream", Digest: artifactBlobDigest, Size: int64(len(artifactBlob))},
				},
				Subject: &ispec.Descriptor{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    subjectDigest,
					Size:      int64(len(subjectBuf)),
				},
			}
			artifactManifest.SchemaVersion = 2

			artifactBuf, err := json.Marshal(artifactManifest)
			So(err, ShouldBeNil)

			artifactDigest := godigest.FromBytes(artifactBuf)

			_, _, err = store.PutImageManifest(context.Background(), repo, artifactDigest.String(),
				ispec.MediaTypeImageManifest, artifactBuf, nil)
			So(err, ShouldBeNil)

			index, err := store.GetReferrers(repo, subjectDigest, nil)
			So(err, ShouldBeNil)
			So(len(index.Manifests), ShouldEqual, 1)
			So(index.Manifests[0].Digest, ShouldEqual, artifactDigest)
			So(index.Manifests[0].ArtifactType, ShouldEqual, "application/vnd.example.referrer")
		})

		Convey("an invalid digest is rejected", func() {
			_, err := store.GetReferrers(repo, godigest.Digest("not-a-digest"), nil)
			So(err, ShouldNotBeNil)
		})
	})
}
