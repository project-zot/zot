package compat_test

import (
	"testing"

	dockerList "github.com/distribution/distribution/v3/manifest/manifestlist"
	docker "github.com/distribution/distribution/v3/manifest/schema2"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/compat"
)

func TestMediaTypeHelpers(t *testing.T) {
	Convey("IsImageManifestMediaType", t, func() {
		So(compat.IsImageManifestMediaType(ispec.MediaTypeImageManifest), ShouldBeTrue)
		So(compat.IsImageManifestMediaType(docker.MediaTypeManifest), ShouldBeTrue)
		So(compat.IsImageManifestMediaType(ispec.MediaTypeImageIndex), ShouldBeFalse)
		So(compat.IsImageManifestMediaType(dockerList.MediaTypeManifestList), ShouldBeFalse)
		So(compat.IsImageManifestMediaType(ispec.MediaTypeImageConfig), ShouldBeFalse)
		So(compat.IsImageManifestMediaType(""), ShouldBeFalse)
	})

	Convey("IsImageIndexMediaType", t, func() {
		So(compat.IsImageIndexMediaType(ispec.MediaTypeImageIndex), ShouldBeTrue)
		So(compat.IsImageIndexMediaType(dockerList.MediaTypeManifestList), ShouldBeTrue)
		So(compat.IsImageIndexMediaType(ispec.MediaTypeImageManifest), ShouldBeFalse)
		So(compat.IsImageIndexMediaType(docker.MediaTypeManifest), ShouldBeFalse)
		So(compat.IsImageIndexMediaType(ispec.MediaTypeImageConfig), ShouldBeFalse)
		So(compat.IsImageIndexMediaType(""), ShouldBeFalse)
	})
}
