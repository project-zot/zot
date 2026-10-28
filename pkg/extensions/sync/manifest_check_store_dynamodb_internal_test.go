//go:build sync

package sync //nolint:testpackage // white-box test of the DynamoDB manifest check store

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

const testManifestCheckTable = "ManifestCheckTable"

// fakeDynamoTransport stands in for DynamoDB without an emulator. It keeps items in a map keyed
// by the Digest attribute and answers GetItem, PutItem, UpdateItem and DeleteItem from it,
// evaluating the condition expressions the manifest check and sync lease stores issue. Each
// action can be made to fail with an InternalServerError, and the whole transport can be made
// to block until the request is cancelled.
type fakeDynamoTransport struct {
	mu          sync.Mutex
	items       map[string]map[string]any
	failActions map[string]bool
	block       bool
	calls       []string
}

func newFakeDynamoTransport() *fakeDynamoTransport {
	return &fakeDynamoTransport{
		items:       map[string]map[string]any{},
		failActions: map[string]bool{},
	}
}

func (t *fakeDynamoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	action := req.Header.Get("X-Amz-Target")
	if idx := len("DynamoDB_20120810."); len(action) > idx {
		action = action[idx:]
	}

	var reqBody struct {
		TableName                 string
		Key                       map[string]any
		Item                      map[string]any
		ConditionExpression       string
		ExpressionAttributeValues map[string]map[string]any
	}

	rawBody, _ := io.ReadAll(req.Body)
	_ = json.Unmarshal(rawBody, &reqBody)

	t.mu.Lock()
	t.calls = append(t.calls, action)
	block := t.block
	fail := t.failActions[action]
	t.mu.Unlock()

	if block {
		<-req.Context().Done()

		return nil, req.Context().Err()
	}

	if fail {
		return dynamoResponse(http.StatusInternalServerError,
			`{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"simulated outage"}`), nil
	}

	if reqBody.TableName != testManifestCheckTable {
		return dynamoResponse(http.StatusBadRequest,
			`{"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException","message":"no such table"}`), nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	switch action {
	case "PutItem":
		key := digestAttr(reqBody.Item)
		existing, exists := t.items[key]

		if reqBody.ConditionExpression != "" &&
			exists && !leaseExpired(existing, reqBody.ExpressionAttributeValues) &&
			!ownerMatches(existing, reqBody.ExpressionAttributeValues) {
			return conditionFailed(), nil
		}

		t.items[key] = reqBody.Item

		return dynamoResponse(http.StatusOK, "{}"), nil
	case "UpdateItem":
		existing, exists := t.items[digestAttr(reqBody.Key)]
		if !exists || !ownerMatches(existing, reqBody.ExpressionAttributeValues) {
			return conditionFailed(), nil
		}

		existing["ExpiresAt"] = reqBody.ExpressionAttributeValues[":exp"]

		return dynamoResponse(http.StatusOK, "{}"), nil
	case "DeleteItem":
		key := digestAttr(reqBody.Key)

		existing, exists := t.items[key]
		if !exists || !ownerMatches(existing, reqBody.ExpressionAttributeValues) {
			return conditionFailed(), nil
		}

		delete(t.items, key)

		return dynamoResponse(http.StatusOK, "{}"), nil
	case "GetItem":
		item, ok := t.items[digestAttr(reqBody.Key)]
		if !ok {
			return dynamoResponse(http.StatusOK, "{}"), nil
		}

		body, _ := json.Marshal(map[string]any{"Item": item})

		return dynamoResponse(http.StatusOK, string(body)), nil
	default:
		return dynamoResponse(http.StatusBadRequest,
			`{"__type":"com.amazonaws.dynamodb.v20120810#ValidationException","message":"unexpected action"}`), nil
	}
}

// digestAttr returns the string value of the Digest attribute in a marshaled item or key.
func digestAttr(attrs map[string]any) string {
	digest, _ := attrs["Digest"].(map[string]any)
	value, _ := digest["S"].(string)

	return value
}

// ownerMatches reports whether item's Owner attribute equals the :owner expression value.
func ownerMatches(item map[string]any, values map[string]map[string]any) bool {
	owner, _ := item["Owner"].(map[string]any)

	return owner["S"] == values[":owner"]["S"]
}

// leaseExpired reports whether item's ExpiresAt attribute is before the :now expression value.
func leaseExpired(item map[string]any, values map[string]map[string]any) bool {
	expires, _ := item["ExpiresAt"].(map[string]any)
	expiresAt, _ := expires["N"].(string)
	now, _ := values[":now"]["N"].(string)

	expiresEpoch, _ := strconv.ParseInt(expiresAt, 10, 64)
	nowEpoch, _ := strconv.ParseInt(now, 10, 64)

	return expiresAt != "" && expiresEpoch < nowEpoch
}

func conditionFailed() *http.Response {
	return dynamoResponse(http.StatusBadRequest,
		`{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"condition failed"}`)
}

func dynamoResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func (t *fakeDynamoTransport) setFail(action string, fail bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.failActions[action] = fail
}

func (t *fakeDynamoTransport) setBlock(block bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.block = block
}

func (t *fakeDynamoTransport) callCount(action string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	count := 0

	for _, call := range t.calls {
		if call == action {
			count++
		}
	}

	return count
}

// item returns a copy of the stored item for key, or nil when absent.
func (t *fakeDynamoTransport) item(key string) map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()

	item, ok := t.items[key]
	if !ok {
		return nil
	}

	clone := make(map[string]any, len(item))
	for name, value := range item {
		clone[name] = value
	}

	return clone
}

// lastChecked returns the stored LastChecked attribute of key, or false when absent.
func (t *fakeDynamoTransport) lastChecked(key string) (int64, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	item, ok := t.items[key]
	if !ok {
		return 0, false
	}

	attr, _ := item["LastChecked"].(map[string]any)
	raw, _ := attr["N"].(string)

	nanos, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}

	return nanos, true
}

// setLastChecked overwrites the stored LastChecked attribute of key.
func (t *fakeDynamoTransport) setLastChecked(key string, when time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.items[key]["LastChecked"] = map[string]any{"N": strconv.FormatInt(when.UnixNano(), 10)}
}

// corrupt replaces the stored LastChecked attribute of key with a non-numeric value.
func (t *fakeDynamoTransport) corrupt(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.items[key]["LastChecked"] = map[string]any{"S": "not-a-timestamp"}
}

func newFakeDynamoClient(transport *fakeDynamoTransport) *dynamodb.Client {
	return dynamodb.New(dynamodb.Options{
		Region:           "us-east-2",
		BaseEndpoint:     aws.String("http://dynamodb.invalid"),
		Credentials:      aws.AnonymousCredentials{},
		HTTPClient:       &http.Client{Transport: transport},
		RetryMaxAttempts: 1,
	})
}

func newFakeDynamoManifestCheckTracker(interval time.Duration, transport *fakeDynamoTransport,
	urls ...string,
) *dynamoManifestCheckTracker {
	return &dynamoManifestCheckTracker{
		client:    newFakeDynamoClient(transport),
		tableName: testManifestCheckTable,
		keyPrefix: manifestCheckKeyPrefix + manifestCheckNamespace(syncconf.RegistryConfig{URLs: urls}) + "#",
		interval:  interval,
		log:       log.NewTestLogger(),
	}
}

func TestDynamoDBManifestCheckStore(t *testing.T) {
	ctx := context.Background()
	urls := []string{"https://registry-1.docker.io"}

	Convey("A reference that was never checked is due", t, func() {
		transport := newFakeDynamoTransport()
		tracker := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)

		So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)
		So(transport.callCount("GetItem"), ShouldEqual, 1)
	})

	Convey("MarkChecked stores the check time as Unix nanoseconds under the namespaced key", t, func() {
		transport := newFakeDynamoTransport()
		tracker := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)

		before := time.Now()
		tracker.MarkChecked(ctx, "repo", "latest")

		nanos, ok := transport.lastChecked(tracker.key("repo", "latest"))
		So(ok, ShouldBeTrue)
		So(time.Unix(0, nanos), ShouldHappenOnOrBetween, before, time.Now())

		Convey("and the reference is no longer due", func() {
			So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeFalse)

			Convey("while other references in the same table still are", func() {
				So(tracker.ShouldCheckUpstream(ctx, "repo", "v2"), ShouldBeTrue)
				So(tracker.ShouldCheckUpstream(ctx, "other", "latest"), ShouldBeTrue)
			})
		})

		Convey("and a second store instance for the same registry reads it back", func() {
			replica := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)

			So(replica.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeFalse)
		})

		Convey("but a store for another registry does not see it", func() {
			other := newFakeDynamoManifestCheckTracker(time.Hour, transport, "https://fallback.example")

			So(other.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)
		})

		Convey("and once the interval has elapsed the reference is due again", func() {
			transport.setLastChecked(tracker.key("repo", "latest"), time.Now().Add(-2*time.Hour))

			So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)
		})
	})

	Convey("A read failure counts as due", t, func() {
		transport := newFakeDynamoTransport()
		tracker := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)
		tracker.MarkChecked(ctx, "repo", "latest")

		transport.setFail("GetItem", true)
		So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)

		transport.setFail("GetItem", false)
		So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeFalse)
	})

	Convey("An item that does not decode counts as due", t, func() {
		transport := newFakeDynamoTransport()
		tracker := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)
		tracker.MarkChecked(ctx, "repo", "latest")
		transport.corrupt(tracker.key("repo", "latest"))

		So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)
	})

	Convey("A write failure is dropped and leaves the reference due", t, func() {
		transport := newFakeDynamoTransport()
		tracker := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)
		transport.setFail("PutItem", true)

		tracker.MarkChecked(ctx, "repo", "latest")

		So(transport.callCount("PutItem"), ShouldEqual, 1)
		_, stored := transport.lastChecked(tracker.key("repo", "latest"))
		So(stored, ShouldBeFalse)
		So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)
	})

	Convey("A cancelled caller context stops both calls", t, func() {
		transport := newFakeDynamoTransport()
		tracker := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)
		transport.setBlock(true)

		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		So(tracker.ShouldCheckUpstream(cancelled, "repo", "latest"), ShouldBeTrue)
		tracker.MarkChecked(cancelled, "repo", "latest")

		transport.setBlock(false)
		So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)
	})

	Convey("A stalled store is abandoned after the store timeout", t, func() {
		transport := newFakeDynamoTransport()
		tracker := newFakeDynamoManifestCheckTracker(time.Hour, transport, urls...)
		transport.setBlock(true)

		start := time.Now()
		So(tracker.ShouldCheckUpstream(ctx, "repo", "latest"), ShouldBeTrue)
		So(time.Since(start), ShouldBeBetweenOrEqual, manifestCheckStoreTimeout, manifestCheckStoreTimeout+2*time.Second)
	})

	Convey("newDynamoManifestCheckTracker takes table, interval and namespace from the registry config", t, func() {
		tracker, err := newDynamoManifestCheckTracker(syncconf.RegistryConfig{
			URLs:                  urls,
			ManifestCheckInterval: time.Hour,
			ManifestCheckStore: &syncconf.ManifestCheckStoreConfig{
				Name:      manifestCheckStoreDynamoDB,
				TableName: testManifestCheckTable,
				Region:    "us-east-2",
			},
		}, log.NewTestLogger())
		So(err, ShouldBeNil)
		So(tracker.tableName, ShouldEqual, testManifestCheckTable)
		So(tracker.interval, ShouldEqual, time.Hour)
		So(tracker.keyPrefix, ShouldEqual,
			manifestCheckKeyPrefix+manifestCheckNamespace(syncconf.RegistryConfig{URLs: urls})+"#")
	})
}
