package cache_test

import (
	"errors"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	godigest "github.com/opencontainers/go-digest"
	"github.com/redis/go-redis/v9"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

// newBlobRefIndex returns an empty index whose claims stay live for lease.
type newBlobRefIndex func(t *testing.T, lease time.Duration) storageTypes.BlobRefIndex

func TestBoltDBBlobRefIndex(t *testing.T) {
	testBlobRefIndex(t, func(t *testing.T, lease time.Duration) storageTypes.BlobRefIndex {
		t.Helper()

		cacheDriver, err := cache.NewBoltDBCache(cache.BoltDBDriverParameters{
			RootDir: t.TempDir(),
			Name:    "cache",
		}, zlog.NewTestLogger())
		if err != nil {
			t.Fatal(err)
		}

		cacheDriver.SetReclaimClaimLease(lease)

		return cacheDriver
	})
}

func TestRedisBlobRefIndex(t *testing.T) {
	testBlobRefIndex(t, func(t *testing.T, lease time.Duration) storageTypes.BlobRefIndex {
		t.Helper()

		miniRedis := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: miniRedis.Addr()})
		t.Cleanup(func() { _ = client.Close() })

		cacheDriver, err := cache.NewRedisCache(cache.RedisDriverParameters{
			Client:    client,
			KeyPrefix: "zot",
		}, zlog.NewTestLogger())
		if err != nil {
			t.Fatal(err)
		}

		cacheDriver.SetReclaimClaimLease(lease)

		return cacheDriver
	})
}

func TestDynamoDBBlobRefIndex(t *testing.T) {
	tskip.SkipDynamo(t)

	testBlobRefIndex(t, func(t *testing.T, lease time.Duration) storageTypes.BlobRefIndex {
		t.Helper()

		cacheDriver, err := cache.NewDynamoDBCache(cache.DynamoDBDriverParameters{
			Endpoint:  os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			TableName: uuid.NewString(),
			Region:    "us-east-2",
		}, zlog.NewTestLogger())
		if err != nil {
			t.Fatal(err)
		}

		cacheDriver.SetReclaimClaimLease(lease)

		return cacheDriver
	})
}

// testBlobRefIndex is the contract every BlobRefIndex implementation satisfies.
func testBlobRefIndex(t *testing.T, newIndex newBlobRefIndex) {
	t.Helper()

	digest := godigest.FromString("blob-ref-index")
	repoA := path.Join("/", "repo-a", "blobs", "sha256", digest.Encoded())
	repoB := path.Join("/", "repo-b", "blobs", "sha256", digest.Encoded())

	Convey("References", t, func() {
		index := newIndex(t, time.Minute)

		_, err := index.GetReferences(digest)
		So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)

		So(index.AddReference(digest, repoA), ShouldBeNil)
		So(index.AddReference(digest, repoA), ShouldBeNil)
		So(index.AddReference(digest, repoB), ShouldBeNil)

		refs, err := index.GetReferences(digest)
		So(err, ShouldBeNil)
		So(refs, ShouldHaveLength, 2)
		So(refs, ShouldContain, repoA)
		So(refs, ShouldContain, repoB)

		unowned, err := index.RemoveReference(digest, repoA)
		So(err, ShouldBeNil)
		So(unowned, ShouldBeFalse)

		unowned, err = index.RemoveReference(digest, repoA)
		So(err, ShouldBeNil)
		So(unowned, ShouldBeFalse)

		unowned, err = index.RemoveReference(digest, repoB)
		So(err, ShouldBeNil)
		So(unowned, ShouldBeTrue)

		Convey("a digest with no owners and no recorded payload is forgotten", func() {
			_, err := index.GetReferences(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		})

		Convey("a digest whose payload is recorded is known with no owners", func() {
			So(index.RecordGlobal(digest), ShouldBeNil)

			refs, err := index.GetReferences(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldBeEmpty)
		})

		Convey("an empty path is refused", func() {
			So(errors.Is(index.AddReference(digest, ""), zerr.ErrEmptyValue), ShouldBeTrue)
		})

		Convey("an unknown digest has no owners", func() {
			unowned, err := index.RemoveReference(godigest.FromString("unknown"), repoA)
			So(err, ShouldBeNil)
			So(unowned, ShouldBeTrue)
		})
	})

	Convey("Claiming a digest for reclaim", t, func() {
		index := newIndex(t, time.Minute)

		Convey("an unknown digest cannot be claimed", func() {
			_, err := index.ClaimReclaim(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		})

		Convey("a digest whose payload is not recorded cannot be claimed", func() {
			So(index.AddReference(digest, repoA), ShouldBeNil)
			_, err := index.RemoveReference(digest, repoA)
			So(err, ShouldBeNil)

			_, err = index.ClaimReclaim(digest)
			So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		})

		Convey("a referenced digest cannot be claimed", func() {
			So(index.RecordGlobal(digest), ShouldBeNil)
			So(index.AddReference(digest, repoA), ShouldBeNil)

			_, err := index.ClaimReclaim(digest)
			So(errors.Is(err, zerr.ErrDigestReferenced), ShouldBeTrue)
		})

		Convey("an unowned digest with a recorded payload is claimed once", func() {
			So(index.RecordGlobal(digest), ShouldBeNil)
			So(index.RecordGlobal(digest), ShouldBeNil)
			So(index.AddReference(digest, repoA), ShouldBeNil)
			_, err := index.RemoveReference(digest, repoA)
			So(err, ShouldBeNil)

			claim, err := index.ClaimReclaim(digest)
			So(err, ShouldBeNil)
			So(claim.Digest, ShouldEqual, digest)
			So(claim.ID, ShouldNotBeEmpty)
			So(claim.At, ShouldNotBeZeroValue)

			_, err = index.ClaimReclaim(digest)
			So(errors.Is(err, zerr.ErrDigestClaimed), ShouldBeTrue)

			Convey("while claimed, no reference can be added", func() {
				So(errors.Is(index.AddReference(digest, repoB), zerr.ErrDigestClaimed), ShouldBeTrue)

				_, err := index.GetReferences(digest)
				So(err, ShouldBeNil)
			})

			Convey("finishing forgets the digest", func() {
				So(index.FinishReclaim(claim), ShouldBeNil)

				_, err := index.GetReferences(digest)
				So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)

				_, err = index.ClaimReclaim(digest)
				So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)

				So(errors.Is(index.FinishReclaim(claim), zerr.ErrReclaimClaimLost), ShouldBeTrue)
				So(index.AbandonReclaim(claim), ShouldBeNil)

				// a later push starts the record again
				So(index.AddReference(digest, repoB), ShouldBeNil)

				So(errors.Is(index.FinishReclaim(claim), zerr.ErrReclaimClaimLost), ShouldBeTrue)
			})

			Convey("abandoning keeps the record and lets references in again", func() {
				So(index.AbandonReclaim(claim), ShouldBeNil)
				So(index.AbandonReclaim(claim), ShouldBeNil)

				So(index.AddReference(digest, repoB), ShouldBeNil)
				So(errors.Is(index.FinishReclaim(claim), zerr.ErrReclaimClaimLost), ShouldBeTrue)

				refs, err := index.GetReferences(digest)
				So(err, ShouldBeNil)
				So(refs, ShouldResemble, []string{repoB})
			})
		})
	})

	Convey("A claim older than the lease belongs to a stopped sweep and is broken", t, func() {
		lease := 500 * time.Millisecond
		index := newIndex(t, lease)

		So(index.RecordGlobal(digest), ShouldBeNil)

		claim, err := index.ClaimReclaim(digest)
		So(err, ShouldBeNil)

		time.Sleep(lease + 250*time.Millisecond)

		Convey("by a linker", func() {
			So(index.AddReference(digest, repoA), ShouldBeNil)
			So(errors.Is(index.FinishReclaim(claim), zerr.ErrReclaimClaimLost), ShouldBeTrue)

			refs, err := index.GetReferences(digest)
			So(err, ShouldBeNil)
			So(refs, ShouldResemble, []string{repoA})
		})

		Convey("by another sweep", func() {
			next, err := index.ClaimReclaim(digest)
			So(err, ShouldBeNil)
			So(next.ID, ShouldNotEqual, claim.ID)

			So(errors.Is(index.FinishReclaim(claim), zerr.ErrReclaimClaimLost), ShouldBeTrue)
			So(index.FinishReclaim(next), ShouldBeNil)
		})
	})

	Convey("A linker and a sweep racing on one digest never both succeed", t, func() {
		index := newIndex(t, time.Minute)

		for attempt := range 20 {
			raced := godigest.FromString("race-" + strings.Repeat("x", attempt))
			So(index.RecordGlobal(raced), ShouldBeNil)

			var (
				wait     sync.WaitGroup
				addErr   error
				claimErr error
			)

			wait.Add(2) //nolint:mnd
			go func() {
				defer wait.Done()

				addErr = index.AddReference(raced, repoA)
			}()
			go func() {
				defer wait.Done()

				_, claimErr = index.ClaimReclaim(raced)
			}()
			wait.Wait()

			if addErr == nil {
				So(errors.Is(claimErr, zerr.ErrDigestReferenced), ShouldBeTrue)
			} else {
				So(errors.Is(addErr, zerr.ErrDigestClaimed), ShouldBeTrue)
				So(claimErr, ShouldBeNil)
			}
		}
	})
}

// Every operation reports a cache it cannot reach.
func testBlobRefIndexUnavailable(index storageTypes.BlobRefIndex) {
	digest := godigest.FromString("unavailable")
	claim := storageTypes.ReclaimClaim{Digest: digest, ID: "claim"}

	So(index.AddReference(digest, "/repo/blob"), ShouldNotBeNil)

	_, err := index.RemoveReference(digest, "/repo/blob")
	So(err, ShouldNotBeNil)

	_, err = index.GetReferences(digest)
	So(err, ShouldNotBeNil)
	So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeFalse)

	So(index.RecordGlobal(digest), ShouldNotBeNil)

	_, err = index.ClaimReclaim(digest)
	So(err, ShouldNotBeNil)
	So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeFalse)

	So(index.FinishReclaim(claim), ShouldNotBeNil)
	So(index.AbandonReclaim(claim), ShouldNotBeNil)
}

func TestRedisBlobRefIndexUnavailable(t *testing.T) {
	Convey("The Redis blob reference index reports an unreachable server", t, func() {
		miniRedis := miniredis.RunT(t)
		client := redis.NewClient(&redis.Options{Addr: miniRedis.Addr(), MaxRetries: -1})
		t.Cleanup(func() { _ = client.Close() })

		cacheDriver, err := cache.NewRedisCache(cache.RedisDriverParameters{Client: client}, zlog.NewTestLogger())
		So(err, ShouldBeNil)

		miniRedis.Close()

		testBlobRefIndexUnavailable(cacheDriver)
	})
}

func TestDynamoDBBlobRefIndexUnavailable(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("The DynamoDB blob reference index reports a table it cannot use", t, func() {
		cacheDriver, err := cache.NewDynamoDBCache(cache.DynamoDBDriverParameters{
			Endpoint:  os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			TableName: uuid.NewString(),
			Region:    "us-east-2",
		}, zlog.NewTestLogger())
		So(err, ShouldBeNil)

		cacheDriver.SetTableName("missing-" + uuid.NewString())

		testBlobRefIndexUnavailable(cacheDriver)
	})
}
