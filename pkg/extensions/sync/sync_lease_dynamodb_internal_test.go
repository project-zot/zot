//go:build sync

package sync //nolint:testpackage // white-box test of the DynamoDB sync lease store

import (
	"context"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func newFakeDynamoSyncLeaseStore(transport *fakeDynamoTransport, urls ...string) *dynamoSyncLeaseStore {
	return newDynamoSyncLeaseStore(newFakeDynamoClient(transport), testManifestCheckTable, manifestCheckNamespace(urls))
}

func TestDynamoDBSyncLeaseStore(t *testing.T) {
	ctx := context.Background()
	urls := []string{"https://registry-1.docker.io"}
	key := trackerKey("repo", "latest")

	Convey("A free lease is acquired and the item carries owner and expiry", t, func() {
		transport := newFakeDynamoTransport()
		store := newFakeDynamoSyncLeaseStore(transport, urls...)

		held, err := store.Acquire(ctx, key, "replica-a", time.Minute)
		So(err, ShouldBeNil)
		So(held, ShouldBeTrue)

		item := transport.item(store.keyPrefix + key)
		So(item, ShouldNotBeNil)
		So(item["Owner"], ShouldResemble, map[string]any{"S": "replica-a"})

		expiresAt, ok := item["ExpiresAt"].(map[string]any)
		So(ok, ShouldBeTrue)
		So(expiresAt["N"], ShouldNotBeEmpty)

		Convey("and the holder can acquire it again", func() {
			held, err := store.Acquire(ctx, key, "replica-a", time.Minute)
			So(err, ShouldBeNil)
			So(held, ShouldBeTrue)
		})

		Convey("while another owner is refused until it is released", func() {
			held, err := store.Acquire(ctx, key, "replica-b", time.Minute)
			So(err, ShouldBeNil)
			So(held, ShouldBeFalse)

			So(store.Release(ctx, key, "replica-a"), ShouldBeNil)

			held, err = store.Acquire(ctx, key, "replica-b", time.Minute)
			So(err, ShouldBeNil)
			So(held, ShouldBeTrue)
		})

		Convey("or until it expires", func() {
			store.now = func() time.Time { return time.Now().Add(2 * time.Minute) }

			held, err := store.Acquire(ctx, key, "replica-b", time.Minute)
			So(err, ShouldBeNil)
			So(held, ShouldBeTrue)
			So(transport.item(store.keyPrefix + key)["Owner"], ShouldResemble, map[string]any{"S": "replica-b"})
		})

		Convey("and a lease for another registry does not collide", func() {
			other := newFakeDynamoSyncLeaseStore(transport, "https://fallback.example")

			held, err := other.Acquire(ctx, key, "replica-b", time.Minute)
			So(err, ShouldBeNil)
			So(held, ShouldBeTrue)
		})
	})

	Convey("Renew extends the holder's lease and is refused for anyone else", t, func() {
		transport := newFakeDynamoTransport()
		store := newFakeDynamoSyncLeaseStore(transport, urls...)

		renewed, err := store.Renew(ctx, key, "replica-a", time.Minute)
		So(err, ShouldBeNil)
		So(renewed, ShouldBeFalse)

		_, err = store.Acquire(ctx, key, "replica-a", time.Minute)
		So(err, ShouldBeNil)

		before := transport.item(store.keyPrefix + key)["ExpiresAt"]
		store.now = func() time.Time { return time.Now().Add(30 * time.Second) }

		renewed, err = store.Renew(ctx, key, "replica-a", time.Minute)
		So(err, ShouldBeNil)
		So(renewed, ShouldBeTrue)
		So(transport.item(store.keyPrefix + key)["ExpiresAt"], ShouldNotResemble, before)

		renewed, err = store.Renew(ctx, key, "replica-b", time.Minute)
		So(err, ShouldBeNil)
		So(renewed, ShouldBeFalse)
	})

	Convey("Release by a non-holder leaves the lease in place", t, func() {
		transport := newFakeDynamoTransport()
		store := newFakeDynamoSyncLeaseStore(transport, urls...)

		So(store.Release(ctx, key, "replica-a"), ShouldBeNil)

		_, err := store.Acquire(ctx, key, "replica-a", time.Minute)
		So(err, ShouldBeNil)
		So(store.Release(ctx, key, "replica-b"), ShouldBeNil)
		So(transport.item(store.keyPrefix + key)["Owner"], ShouldResemble, map[string]any{"S": "replica-a"})
	})

	Convey("Transport failures are returned, not mapped to a refused lease", t, func() {
		transport := newFakeDynamoTransport()
		store := newFakeDynamoSyncLeaseStore(transport, urls...)

		transport.setFail("PutItem", true)
		_, err := store.Acquire(ctx, key, "replica-a", time.Minute)
		So(err, ShouldNotBeNil)

		transport.setFail("UpdateItem", true)
		_, err = store.Renew(ctx, key, "replica-a", time.Minute)
		So(err, ShouldNotBeNil)

		transport.setFail("DeleteItem", true)
		So(store.Release(ctx, key, "replica-a"), ShouldNotBeNil)
	})

	Convey("A cancelled context stops every call", t, func() {
		transport := newFakeDynamoTransport()
		store := newFakeDynamoSyncLeaseStore(transport, urls...)
		transport.setBlock(true)

		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		_, err := store.Acquire(cancelled, key, "replica-a", time.Minute)
		So(err, ShouldNotBeNil)
		_, err = store.Renew(cancelled, key, "replica-a", time.Minute)
		So(err, ShouldNotBeNil)
		So(store.Release(cancelled, key, "replica-a"), ShouldNotBeNil)
	})
}
