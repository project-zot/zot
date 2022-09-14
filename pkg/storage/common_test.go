package storage_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	storConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

func TestValidateManifest(t *testing.T) {
	Convey("Make manifest", t, func(c C) {
		dir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := local.NewImageStore(dir, true, storConstants.DefaultGCDelay, true,
			true, log, metrics, nil)

		content := []byte("this is a blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		_, blen, err := imgStore.FullBlobUpload("test", bytes.NewReader(content), digest.String())
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		cblob, cdigest := test.GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest.String())
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		Convey("bad manifest schema version", func() {
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}

			manifest.SchemaVersion = 999

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldNotBeNil)
		})

		Convey("bad config blob", func() {
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}

			manifest.SchemaVersion = 2

			configBlobPath := imgStore.BlobPath("test", cdigest)

			err := os.WriteFile(configBlobPath, []byte("bad config blob"), 0o000)
			So(err, ShouldBeNil)

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldNotBeNil)
		})
	})
}
