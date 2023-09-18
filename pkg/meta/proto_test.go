package meta_test

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"google.golang.org/protobuf/proto"

	"zotregistry.io/zot/pkg/meta/proto_go"
)

func TestProto(t *testing.T) {
	Convey("Basic conversion", t, func() {
		Convey("Manifest", func() {
			mediaType := ispec.MediaTypeImageManifest
			manifest := &proto_go.Manifest{
				Versioned: &proto_go.Versioned{Schemaversion: 2},
				Mediatype: &mediaType,
			}

			buf, err := proto.Marshal(manifest)
			So(err, ShouldBeNil)

			manifest = &proto_go.Manifest{}

			err = proto.Unmarshal(buf, manifest)
			So(err, ShouldBeNil)
			So(*manifest.Mediatype, ShouldEqual, ispec.MediaTypeImageManifest)
		})

		Convey("Index", func() {
			mediaType := ispec.MediaTypeImageIndex
			index := &proto_go.Index{
				Versioned: &proto_go.Versioned{Schemaversion: 2},
				Mediatype: &mediaType,
			}

			out, err := proto.Marshal(index)
			So(err, ShouldBeNil)

			index = &proto_go.Index{}

			err = proto.Unmarshal(out, index)
			So(err, ShouldBeNil)
			So(*index.Mediatype, ShouldEqual, ispec.MediaTypeImageIndex)
		})
	})
}
