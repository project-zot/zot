package storage_test

// CheckIsImageSignature is a pure function used by pkg/meta/hooks.go to classify a
// pushed/deleted manifest as a signature or not; it was previously untested despite
// sitting on the metadata indexing path for every manifest push.

import (
	"encoding/json"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/storage"
)

func TestCheckIsImageSignature(t *testing.T) {
	Convey("CheckIsImageSignature", t, func() {
		Convey("invalid manifest JSON returns an error", func() {
			_, _, _, err := storage.CheckIsImageSignature("repo", []byte("not json"), "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("plain manifest with no subject is not a signature", func() {
			manifest := ispec.Manifest{Config: ispec.DescriptorEmptyJSON}
			manifestBuf, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, "1.0")
			So(err, ShouldBeNil)

			So(isSig, ShouldBeFalse)
			So(sigType, ShouldBeEmpty)
			So(digest, ShouldBeEmpty)
		})

		Convey("notation artifact type with a subject is a notation signature", func() {
			subjectDigest := godigest.FromString("subject-manifest")

			manifest := ispec.Manifest{
				ArtifactType: zcommon.ArtifactTypeNotation,
				Config:       ispec.DescriptorEmptyJSON,
				Subject:      &ispec.Descriptor{Digest: subjectDigest},
			}
			manifestBuf, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, "sha256-abc.sig")
			So(err, ShouldBeNil)

			So(isSig, ShouldBeTrue)
			So(sigType, ShouldEqual, storage.NotationType)
			So(digest, ShouldEqual, subjectDigest)
		})

		Convey("cosign artifact type with a subject is an OCI 1.1 cosign signature", func() {
			subjectDigest := godigest.FromString("subject-manifest")

			manifest := ispec.Manifest{
				ArtifactType: zcommon.ArtifactTypeCosign,
				Config:       ispec.DescriptorEmptyJSON,
				Subject:      &ispec.Descriptor{Digest: subjectDigest},
			}
			manifestBuf, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, "1.0")
			So(err, ShouldBeNil)

			So(isSig, ShouldBeTrue)
			So(sigType, ShouldEqual, storage.CosignType)
			So(digest, ShouldEqual, subjectDigest)
		})

		Convey("legacy cosign tag pattern is a cosign signature keyed off the tag", func() {
			signedDigest := godigest.FromString("legacy-signed-manifest")

			manifest := ispec.Manifest{Config: ispec.DescriptorEmptyJSON}
			manifestBuf, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			reference := "sha256-" + signedDigest.Encoded() + ".sig"

			isSig, sigType, digest, err := storage.CheckIsImageSignature("repo", manifestBuf, reference)
			So(err, ShouldBeNil)

			So(isSig, ShouldBeTrue)
			So(sigType, ShouldEqual, storage.CosignType)
			So(digest, ShouldEqual, signedDigest)
		})
	})
}
