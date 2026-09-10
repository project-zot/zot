package cache_test

// PutBlobRef/GetBlobRefs/DeleteBlobRef are the live blobRefIndexer path for DynamoDB
// deployments. Tests use a dedicated table, separate from TestDynamoDB's "BlobTable".
//
// Each Convey leaf uses its own digest: GoConvey re-runs the ancestor setup for every
// leaf, but state persists in the real DynamoDB table, so leaves sharing a digest
// would contaminate each other.

import (
	"os"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func TestDynamoDBBlobRefs(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("BlobRefs", t, func() {
		log := log.NewTestLogger()

		cacheDriver, err := cache.NewDynamoDBCache(cache.DynamoDBDriverParameters{
			Endpoint:  os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			TableName: "BlobRefTable",
			Region:    "us-east-2",
		}, log)
		So(err, ShouldBeNil)
		So(cacheDriver, ShouldNotBeNil)

		Convey("GetBlobRefs on a digest with no refs is a cache miss", func() {
			refs, err := cacheDriver.GetBlobRefs(godigest.FromString("missing"))
			So(err, ShouldNotBeNil)
			So(refs, ShouldBeEmpty)
		})

		Convey("PutBlobRef establishes the origin, readable via GetBlobRefs", func() {
			digest := godigest.FromString("origin-only")

			err := cacheDriver.PutBlobRef(digest, "/repo1/blob")
			So(err, ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldContain, "/repo1/blob")
		})

		Convey("re-putting the same path is a no-op", func() {
			digest := godigest.FromString("re-put-same-path")

			So(cacheDriver.PutBlobRef(digest, "/repo1/blob"), ShouldBeNil)
			So(cacheDriver.PutBlobRef(digest, "/repo1/blob"), ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(digest)
			So(err, ShouldBeNil)
			So(len(refs), ShouldEqual, 1)
		})

		Convey("a second PutBlobRef adds a duplicate ref", func() {
			digest := godigest.FromString("second-put-adds-duplicate")

			So(cacheDriver.PutBlobRef(digest, "/repo1/blob"), ShouldBeNil)
			So(cacheDriver.PutBlobRef(digest, "/repo2/blob"), ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldContain, "/repo1/blob")
			So(refs, ShouldContain, "/repo2/blob")

			allRefs, err := cacheDriver.GetAllBlobRefs()
			So(err, ShouldBeNil)
			So(allRefs[digest], ShouldContain, "/repo1/blob")
			So(allRefs[digest], ShouldContain, "/repo2/blob")
		})

		Convey("DeleteBlobRef on the only ref removes the whole entry", func() {
			digest := godigest.FromString("delete-only-ref")

			So(cacheDriver.PutBlobRef(digest, "/repo1/blob"), ShouldBeNil)
			So(cacheDriver.DeleteBlobRef(digest, "/repo1/blob"), ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(digest)
			So(err, ShouldNotBeNil)
			So(refs, ShouldBeEmpty)
		})

		Convey("DeleteBlobRef on the origin while a duplicate remains promotes the duplicate to origin", func() {
			digest := godigest.FromString("delete-origin-keep-duplicate")

			So(cacheDriver.PutBlobRef(digest, "/repo1/blob"), ShouldBeNil)
			So(cacheDriver.PutBlobRef(digest, "/repo2/blob"), ShouldBeNil)
			So(cacheDriver.DeleteBlobRef(digest, "/repo1/blob"), ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldContain, "/repo2/blob")
			So(refs, ShouldNotContain, "/repo1/blob")
			So(len(refs), ShouldEqual, 1)
		})

		Convey("DeleteBlobRef on a duplicate leaves the origin intact", func() {
			digest := godigest.FromString("delete-duplicate-keep-origin")

			So(cacheDriver.PutBlobRef(digest, "/repo1/blob"), ShouldBeNil)
			So(cacheDriver.PutBlobRef(digest, "/repo2/blob"), ShouldBeNil)
			So(cacheDriver.DeleteBlobRef(digest, "/repo2/blob"), ShouldBeNil)

			refs, err := cacheDriver.GetBlobRefs(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldContain, "/repo1/blob")
			So(refs, ShouldNotContain, "/repo2/blob")
		})

		Convey("PutBlobRef rejects an empty path", func() {
			err := cacheDriver.PutBlobRef(godigest.FromString("empty-path"), "")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteBlobRef on an unknown digest is a cache miss", func() {
			err := cacheDriver.DeleteBlobRef(godigest.FromString("unknown-digest"), "/repo1/blob")
			So(err, ShouldNotBeNil)
		})
	})
}
