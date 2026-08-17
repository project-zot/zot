package imagestore_test

// copyBlob is CheckBlob's cache-miss-but-cache-hit self-heal path: a repo that has
// never seen a digest locally, but the cache (populated by a push to a different
// repo) can resolve it - CheckBlob links/copies the content in on read.

import (
	"bytes"
	"context"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"
)

func TestCheckBlobSelfHealsViaCopyBlob(t *testing.T) {
	Convey("CheckBlob self-heals a repo's missing local copy via the cache", t, func() {
		imgStore := newDedupeStoreForLockTests(t)

		content := []byte("copyblob-selfheal-content")
		digest := godigest.FromBytes(content)

		_, _, err := imgStore.FullBlobUpload(context.Background(), "repoa", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		ok, size, err := imgStore.CheckBlob(context.Background(), "repob", digest)
		So(err, ShouldBeNil)
		So(ok, ShouldBeTrue)
		So(size, ShouldEqual, int64(len(content)))

		blobContent, err := imgStore.GetBlobContent("repob", digest)
		So(err, ShouldBeNil)
		So(blobContent, ShouldResemble, content)
	})
}

func TestCheckBlobSelfHealCopyBlobFailsOnInvalidRepo(t *testing.T) {
	Convey("copyBlob's initRepo call fails fast on an invalid repo name", t, func() {
		imgStore := newDedupeStoreForLockTests(t)

		content := []byte("copyblob-invalid-repo-content")
		digest := godigest.FromBytes(content)

		_, _, err := imgStore.FullBlobUpload(context.Background(), "repoa", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)

		// copyBlob's initRepo call must fail fast on an invalid repo name, surfacing as
		// a not-found result rather than a partial/successful self-heal.
		ok, _, err := imgStore.CheckBlob(context.Background(), "!!!invalid!!!", digest)
		So(err, ShouldNotBeNil)
		So(ok, ShouldBeFalse)
	})
}
