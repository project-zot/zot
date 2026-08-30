package convert_test

import (
	"testing"
	"time"

	dockerList "github.com/distribution/distribution/v3/manifest/manifestlist"
	docker "github.com/distribution/distribution/v3/manifest/schema2"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/meta/convert"
	"zotregistry.dev/zot/v2/pkg/meta/proto/gen"
)

func TestConvertErrors(t *testing.T) {
	Convey("Errors", t, func() {
		Convey("GetImageArtifactType", func() {
			str := convert.GetImageArtifactType(&gen.ImageMeta{MediaType: "bad-media-type"})
			So(str, ShouldResemble, "")
		})
		Convey("GetImageManifestSize", func() {
			size := convert.GetImageManifestSize(&gen.ImageMeta{MediaType: "bad-media-type"})
			So(size, ShouldEqual, 0)
		})
		Convey("GetImageDigest", func() {
			dig := convert.GetImageDigest(&gen.ImageMeta{MediaType: "bad-media-type"})
			So(dig.String(), ShouldResemble, "")
		})
		Convey("GetImageDigestStr", func() {
			digStr := convert.GetImageDigestStr(&gen.ImageMeta{MediaType: "bad-media-type"})
			So(digStr, ShouldResemble, "")
		})
		Convey("GetImageAnnotations", func() {
			annot := convert.GetImageAnnotations(&gen.ImageMeta{MediaType: "bad-media-type"})
			So(annot, ShouldBeEmpty)
		})
		Convey("GetImageSubject", func() {
			subjs := convert.GetImageSubject(&gen.ImageMeta{MediaType: "bad-media-type"})
			So(subjs, ShouldBeNil)
		})
		Convey("GetDescriptorRef", func() {
			ref := convert.GetDescriptorRef(nil)
			So(ref, ShouldBeNil)
		})
		Convey("GetPlatform", func() {
			platf := convert.GetPlatform(nil)
			So(platf, ShouldEqual, ispec.Platform{})
		})
		Convey("GetPlatformRef", func() {
			platf := convert.GetPlatform(&gen.Platform{Architecture: "arch"})
			So(platf.Architecture, ShouldResemble, "arch")
		})
		Convey("GetImageReferrers", func() {
			ref := convert.GetImageReferrers(nil)
			So(ref, ShouldNotBeNil)
		})
		Convey("GetImageSignatures", func() {
			sigs := convert.GetImageSignatures(nil)
			So(sigs, ShouldNotBeNil)
		})
		Convey("GetImageStatistics", func() {
			sigs := convert.GetImageStatistics(nil)
			So(sigs, ShouldNotBeNil)
		})
		Convey("GetFullImageMetaFromProto", func() {
			imageMeta := convert.GetFullImageMetaFromProto("tag", nil, nil)
			So(imageMeta.Digest.String(), ShouldResemble, "")
		})
		Convey("GetFullManifestData", func() {
			imageMeta := convert.GetFullManifestData(nil, nil)
			So(len(imageMeta), ShouldEqual, 0)
		})
	})
}

func TestGetProtoEarlierUpdatedImage(t *testing.T) {
	Convey("GetProtoEarlierUpdatedImage with nil params", t, func() {
		// repoLastImage is nil
		lastImage := gen.RepoLastUpdatedImage{}

		repoLastUpdatedImage := convert.GetProtoEarlierUpdatedImage(nil, &lastImage)
		So(repoLastUpdatedImage, ShouldNotBeNil)
		So(repoLastUpdatedImage.LastUpdated, ShouldBeNil)

		// lastImage is nil
		repoLastImage := gen.RepoLastUpdatedImage{}

		repoLastUpdatedImage = convert.GetProtoEarlierUpdatedImage(&repoLastImage, nil)
		So(repoLastUpdatedImage, ShouldNotBeNil)
		So(repoLastUpdatedImage.LastUpdated, ShouldBeNil)

		// lastImage.LastUpdated is not nil, but repoLastImage.LastUpdated is nil
		lastUpdated := time.Time{}
		lastImage = gen.RepoLastUpdatedImage{
			LastUpdated: convert.GetProtoTime(&lastUpdated),
		}

		repoLastUpdatedImage = convert.GetProtoEarlierUpdatedImage(&repoLastImage, &lastImage)
		So(repoLastUpdatedImage, ShouldNotBeNil)
		So(repoLastUpdatedImage.LastUpdated, ShouldNotBeNil)
	})
}

func TestPreserveCompatMediaTypes(t *testing.T) {
	Convey("Docker schema2 manifest media types are preserved through proto conversion", t, func() {
		digest := godigest.FromString("docker-manifest")
		imageMeta := convert.GetImageManifestMeta(ispec.Manifest{}, ispec.Image{}, 10, digest, docker.MediaTypeManifest)
		So(imageMeta.MediaType, ShouldEqual, docker.MediaTypeManifest)
		So(imageMeta.Manifests[0].Manifest.MediaType, ShouldEqual, "")

		protoMeta := convert.GetProtoImageMeta(imageMeta)
		So(protoMeta, ShouldNotBeNil)
		So(protoMeta.GetMediaType(), ShouldEqual, docker.MediaTypeManifest)

		roundTrip := convert.GetImageMeta(protoMeta)
		So(roundTrip.MediaType, ShouldEqual, docker.MediaTypeManifest)
		So(roundTrip.Manifests[0].Manifest.MediaType, ShouldEqual, docker.MediaTypeManifest)
		So(roundTrip.Digest, ShouldEqual, digest)
		So(roundTrip.Size, ShouldEqual, int64(10))
	})

	Convey("Docker manifest JSON media type is preferred over descriptor when both are set", t, func() {
		digest := godigest.FromString("docker-manifest-json")
		manifest := ispec.Manifest{MediaType: docker.MediaTypeManifest}
		imageMeta := convert.GetImageManifestMeta(manifest, ispec.Image{}, 10, digest, docker.MediaTypeManifest)
		So(imageMeta.Manifests[0].Manifest.MediaType, ShouldEqual, docker.MediaTypeManifest)

		protoMeta := convert.GetProtoImageMeta(imageMeta)
		So(protoMeta.GetManifests()[0].GetManifest().GetMediaType(), ShouldEqual, docker.MediaTypeManifest)
	})

	Convey("Docker manifest list media types are preserved through proto conversion", t, func() {
		digest := godigest.FromString("docker-index")
		index := ispec.Index{MediaType: dockerList.MediaTypeManifestList}
		imageMeta := convert.GetImageIndexMeta(index, 20, digest, dockerList.MediaTypeManifestList)
		So(imageMeta.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)

		protoMeta := convert.GetProtoImageMeta(imageMeta)
		So(protoMeta, ShouldNotBeNil)
		So(protoMeta.GetMediaType(), ShouldEqual, dockerList.MediaTypeManifestList)

		roundTrip := convert.GetImageMeta(protoMeta)
		So(roundTrip.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
		So(roundTrip.Index, ShouldNotBeNil)
		So(roundTrip.Index.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
		So(roundTrip.Digest, ShouldEqual, digest)
		So(roundTrip.Size, ShouldEqual, int64(20))
	})

	Convey("empty nested index media type is filled from descriptor on proto write", t, func() {
		digest := godigest.FromString("docker-index-empty-nested")
		imageMeta := convert.GetImageIndexMeta(ispec.Index{}, 20, digest, dockerList.MediaTypeManifestList)
		So(imageMeta.Index.MediaType, ShouldEqual, "")

		protoMeta := convert.GetProtoImageMeta(imageMeta)
		So(protoMeta.GetIndex().GetIndex().GetMediaType(), ShouldEqual, dockerList.MediaTypeManifestList)

		roundTrip := convert.GetImageMeta(protoMeta)
		So(roundTrip.Index.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
	})

	Convey("nested index media type is preferred over top-level on read", t, func() {
		digest := godigest.FromString("index-nested-prefers-json")
		index := ispec.Index{MediaType: ispec.MediaTypeImageIndex}
		imageMeta := convert.GetImageIndexMeta(index, 20, digest, dockerList.MediaTypeManifestList)
		protoMeta := convert.GetProtoImageMeta(imageMeta)
		So(protoMeta.GetMediaType(), ShouldEqual, dockerList.MediaTypeManifestList)
		So(protoMeta.GetIndex().GetIndex().GetMediaType(), ShouldEqual, ispec.MediaTypeImageIndex)

		roundTrip := convert.GetImageMeta(protoMeta)
		So(roundTrip.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
		So(roundTrip.Index.MediaType, ShouldEqual, ispec.MediaTypeImageIndex)
	})

	Convey("empty nested index media type falls back to top-level on read", t, func() {
		digest := godigest.FromString("index-empty-nested-fallback")
		// Simulate a legacy MetaDB row: top-level descriptor type set, nested JSON media type omitted.
		protoMeta := &gen.ImageMeta{
			MediaType: dockerList.MediaTypeManifestList,
			Index: &gen.IndexMeta{
				Size:   20,
				Digest: digest.String(),
				Index: &gen.Index{
					Versioned: &gen.Versioned{SchemaVersion: 2},
				},
			},
		}

		imageMeta := convert.GetImageMeta(protoMeta)
		So(imageMeta.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
		So(imageMeta.Index, ShouldNotBeNil)
		So(imageMeta.Index.MediaType, ShouldEqual, dockerList.MediaTypeManifestList)
		So(imageMeta.Digest, ShouldEqual, digest)
		So(imageMeta.Size, ShouldEqual, int64(20))
	})

	Convey("empty media type defaults to OCI", t, func() {
		manifestMeta := convert.GetImageManifestMeta(ispec.Manifest{}, ispec.Image{}, 1, godigest.FromString("m"), "")
		So(manifestMeta.MediaType, ShouldEqual, ispec.MediaTypeImageManifest)

		indexMeta := convert.GetImageIndexMeta(ispec.Index{}, 1, godigest.FromString("i"), "")
		So(indexMeta.MediaType, ShouldEqual, ispec.MediaTypeImageIndex)
	})
}
