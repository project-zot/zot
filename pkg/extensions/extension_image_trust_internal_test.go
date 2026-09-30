//go:build imagetrust

package extensions

import (
	"bytes"
	"context"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/local"
)

func TestSignatureBlobGetter(t *testing.T) {
	Convey("signature layers are read from the image store of their repo", t, func() {
		imgStore := local.NewImageStore(t.TempDir(), false, false, log.NewTestLogger(),
			monitoring.NewNopMetricServer(), nil, nil, nil, nil)
		getSignatureBlob := signatureBlobGetter(storage.StoreController{DefaultStore: imgStore})

		upload := func(content []byte) godigest.Digest {
			blobDigest := godigest.FromBytes(content)
			_, _, err := imgStore.FullBlobUpload(context.Background(), "repo", bytes.NewReader(content), blobDigest)
			So(err, ShouldBeNil)

			return blobDigest
		}

		Convey("a signature layer", func() {
			content := []byte("signature")

			blob, err := getSignatureBlob("repo", upload(content))
			So(err, ShouldBeNil)
			So(blob, ShouldResemble, content)
		})

		Convey("a missing layer", func() {
			_, err := getSignatureBlob("repo", godigest.FromString("missing"))
			So(errors.Is(err, zerr.ErrBlobNotFound), ShouldBeTrue)
		})

		Convey("a layer too large to be a signature is not read", func() {
			_, err := getSignatureBlob("repo", upload(make([]byte, maxSignatureLayerSize+1)))
			So(errors.Is(err, zerr.ErrSignatureLayerTooLarge), ShouldBeTrue)
		})
	})
}
