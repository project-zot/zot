package meta

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/storage"
	testimage "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errParseInternal = errors.New("parse internal test error")

func indexBlobFor(digest godigest.Digest, tag string) []byte {
	blob, err := json.Marshal(ispec.Index{
		MediaType: ispec.MediaTypeImageIndex,
		Manifests: []ispec.Descriptor{{
			MediaType:   ispec.MediaTypeImageManifest,
			Digest:      digest,
			Annotations: map[string]string{ispec.AnnotationRefName: tag},
		}},
	})
	if err != nil {
		panic("image index should always be marshable")
	}

	return blob
}

func TestParseStatsComplete(t *testing.T) {
	Convey("parseStats.complete is true only with no failed or partial repos", t, func() {
		So(parseStats{}.complete(), ShouldBeTrue)
		So(parseStats{failedRepos: 1}.complete(), ShouldBeFalse)
		So(parseStats{partialRepos: 1}.complete(), ShouldBeFalse)
		So(parseStats{failedRepos: 2, partialRepos: 3}.complete(), ShouldBeFalse)
	})
}

func TestFastRestartStamp(t *testing.T) {
	Convey("FastRestartStamp joins the binary version and storage fingerprint", t, func() {
		So(FastRestartStamp("v2.3.4+abc123", "deadbeef"), ShouldEqual, "v2.3.4+abc123|deadbeef")
	})

	Convey("FastRestartStamp returns empty when the binary version is empty", t, func() {
		So(FastRestartStamp("", "deadbeef"), ShouldEqual, "")
	})

	Convey("FastRestartStamp returns empty when the storage fingerprint is empty", t, func() {
		So(FastRestartStamp("v2.3.4+abc123", ""), ShouldEqual, "")
	})
}

func TestParseStorageStats(t *testing.T) {
	logger := log.NewTestLogger()

	// A valid image whose manifest + config blobs parse cleanly through ParseRepo.
	validImage := testimage.CreateRandomImage()

	manifestBlob, err := json.Marshal(validImage.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	configBlob, err := json.Marshal(validImage.Config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	goodDigest := godigest.FromString("good-manifest")
	missingDigest := godigest.FromString("missing-manifest")

	// blobFor maps the descriptor digests our mocked index references back to the
	// valid image blobs, anything else is reported as a missing blob.
	blobFor := func(_ string, digest godigest.Digest) ([]byte, error) {
		switch digest {
		case goodDigest:
			return manifestBlob, nil
		case validImage.ConfigDescriptor.Digest:
			return configBlob, nil
		default:
			return nil, zerr.ErrBlobNotFound
		}
	}

	metaDB := mocks.MetaDBMock{
		SetRepoReferenceFn: func(context.Context, string, string, mTypes.ImageMeta) error { return nil },
	}

	Convey("a fully-parsed repo yields a complete parseStats", t, func() {
		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) { return []string{"goodrepo"}, nil },
			GetIndexContentFn: func(string) ([]byte, error) { return indexBlobFor(goodDigest, "gtag"), nil },
			GetBlobContentFn:  blobFor,
		}}

		stats, err := parseStorage(metaDB, store, logger)
		So(err, ShouldBeNil)
		So(stats.failedRepos, ShouldEqual, 0)
		So(stats.partialRepos, ShouldEqual, 0)
		So(stats.complete(), ShouldBeTrue)
	})

	Convey("failed and partial repos are counted independently", t, func() {
		store := storage.StoreController{DefaultStore: mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{"failrepo", "partialrepo", "goodrepo"}, nil
			},
			StatIndexFn: func(repo string) (bool, int64, time.Time, error) {
				if repo == "failrepo" {
					return false, 0, time.Time{}, errParseInternal
				}

				return true, 0, time.Time{}, nil
			},
			GetIndexContentFn: func(repo string) ([]byte, error) {
				if repo == "partialrepo" {
					return indexBlobFor(missingDigest, "ptag"), nil
				}

				return indexBlobFor(goodDigest, "gtag"), nil
			},
			GetBlobContentFn: blobFor,
		}}

		stats, err := parseStorage(metaDB, store, logger)
		So(err, ShouldBeNil)
		So(stats.failedRepos, ShouldEqual, 1)
		So(stats.partialRepos, ShouldEqual, 1)
		So(stats.complete(), ShouldBeFalse)
	})
}
