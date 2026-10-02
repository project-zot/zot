package imagestore

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

func TestMapStorageErr(t *testing.T) {
	Convey("mapStorageErr preserves classes and wraps ErrBlobNotFound on absence", t, func() {
		Convey("nil → nil", func() {
			So(mapStorageErr(nil), ShouldBeNil)
		})

		Convey("ErrStorageMissing → BlobNotFound + Missing", func() {
			src := errclass.MarkMissing(errors.New("gone")) //nolint:err113 // test
			err := mapStorageErr(src)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeTrue)
		})

		Convey("ErrCacheMiss → BlobNotFound + CacheMiss, not MarkMissing", func() {
			err := mapStorageErr(zerr.ErrCacheMiss)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrStorageMissing), ShouldBeFalse)
		})

		Convey("Transient propagates without BlobNotFound", func() {
			src := errclass.MarkTransient(errors.New("blip")) //nolint:err113 // test
			err := mapStorageErr(src)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)
		})

		Convey("Permanent propagates without BlobNotFound", func() {
			src := errclass.MarkPermanent(errors.New("denied")) //nolint:err113 // test
			err := mapStorageErr(src)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)
		})

		Convey("unclassified → Transient", func() {
			err := mapStorageErr(errors.New("weird")) //nolint:err113 // test
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeFalse)
		})
	})
}
