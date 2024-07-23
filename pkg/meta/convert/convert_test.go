package convert_test

import (
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/meta/convert"
	"zotregistry.dev/zot/pkg/meta/proto/gen"
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
