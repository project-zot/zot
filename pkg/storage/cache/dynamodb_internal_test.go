package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

// denyCreateTableTransport simulates an IAM policy that allows DescribeTable/GetItem/etc.
// but denies dynamodb:CreateTable, by intercepting only CreateTable calls and returning
// the same AccessDeniedException shape AWS returns; every other action is forwarded to
// the real (localstack) endpoint.
type denyCreateTableTransport struct {
	base http.RoundTripper
}

func (t *denyCreateTableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("X-Amz-Target") == "DynamoDB_20120810.CreateTable" {
		body := `{"__type":"com.amazon.coral.service#AccessDeniedException",` +
			`"message":"User: arn:aws:iam::123456789012:user/zot is not authorized to perform: ` +
			`dynamodb:CreateTable on resource: arn:aws:dynamodb:us-east-2:123456789012:table/BlobTable"}`

		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Header: http.Header{
				"Content-Type":     []string{"application/x-amz-json-1.0"},
				"X-Amzn-Errortype": []string{"AccessDeniedException"},
			},
			Body:    io.NopCloser(bytes.NewBufferString(body)),
			Request: req,
		}, nil
	}

	return t.base.RoundTrip(req)
}

func TestNewTableWithoutCreateTablePermission(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("NewTable succeeds against a pre-existing table without dynamodb:CreateTable permission", t, func() {
		endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

		httpClient := &http.Client{Transport: &denyCreateTableTransport{base: http.DefaultTransport}}

		cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion("us-east-2"),
			awsconfig.WithHTTPClient(httpClient),
		)
		So(err, ShouldBeNil)

		client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})

		const tableName = "Issue4259PreExistingTable"

		// create the table up front using a plain client (unaffected by the interceptor,
		// since it's not a CreateTable call through the deny-wrapped client)
		plainCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-2"))
		So(err, ShouldBeNil)

		plainClient := dynamodb.NewFromConfig(plainCfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})

		driver := &DynamoDBDriver{client: plainClient, log: log.NewTestLogger()}
		So(driver.NewTable(tableName), ShouldBeNil)

		// now exercise NewTable again through the client that denies CreateTable: since the
		// table already exists, DescribeTable should short-circuit before CreateTable is ever called
		deniedDriver := &DynamoDBDriver{client: client, log: log.NewTestLogger()}
		So(deniedDriver.NewTable(tableName), ShouldBeNil)
		So(deniedDriver.tableName, ShouldEqual, tableName)
	})
}

// denyDescribeTableTransport simulates an IAM policy that allows CreateTable/GetItem/etc.
// but denies dynamodb:DescribeTable, by intercepting only DescribeTable calls and returning
// an AccessDeniedException; every other action is forwarded to the real (localstack) endpoint.
type denyDescribeTableTransport struct {
	base http.RoundTripper
}

func (t *denyDescribeTableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("X-Amz-Target") == "DynamoDB_20120810.DescribeTable" {
		body := `{"__type":"com.amazon.coral.service#AccessDeniedException",` +
			`"message":"User: arn:aws:iam::123456789012:user/zot is not authorized to perform: ` +
			`dynamodb:DescribeTable on resource: arn:aws:dynamodb:us-east-2:123456789012:table/BlobTable"}`

		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Status:     "400 Bad Request",
			Header: http.Header{
				"Content-Type":     []string{"application/x-amz-json-1.0"},
				"X-Amzn-Errortype": []string{"AccessDeniedException"},
			},
			Body:    io.NopCloser(bytes.NewBufferString(body)),
			Request: req,
		}, nil
	}

	return t.base.RoundTrip(req)
}

func newDenyDescribeTableDriver(t *testing.T) *DynamoDBDriver {
	t.Helper()

	endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

	httpClient := &http.Client{Transport: &denyDescribeTableTransport{base: http.DefaultTransport}}

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-2"),
		awsconfig.WithHTTPClient(httpClient),
	)
	So(err, ShouldBeNil)

	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	return &DynamoDBDriver{client: client, log: log.NewTestLogger()}
}

func TestNewTableWithoutDescribeTablePermission(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("NewTable falls back to CreateTable when dynamodb:DescribeTable is denied", t, func() {
		Convey("table does not exist yet", func() {
			const tableName = "Issue4259NewTableNoDescribe"

			deniedDriver := newDenyDescribeTableDriver(t)
			So(deniedDriver.NewTable(tableName), ShouldBeNil)
			So(deniedDriver.tableName, ShouldEqual, tableName)

			// confirm CreateTable actually ran (rather than NewTable returning nil
			// without ever creating the table) via an unwrapped client
			endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

			plainCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-2"))
			So(err, ShouldBeNil)

			plainClient := dynamodb.NewFromConfig(plainCfg, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(endpoint)
			})

			_, err = plainClient.DescribeTable(context.Background(), &dynamodb.DescribeTableInput{
				TableName: aws.String(tableName),
			})
			So(err, ShouldBeNil)
		})

		Convey("table already exists", func() {
			const tableName = "Issue4259ExistingTableNoDescribe"

			endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

			plainCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-2"))
			So(err, ShouldBeNil)

			plainClient := dynamodb.NewFromConfig(plainCfg, func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String(endpoint)
			})

			driver := &DynamoDBDriver{client: plainClient, log: log.NewTestLogger()}
			So(driver.NewTable(tableName), ShouldBeNil)

			// CreateTable will fail with ResourceInUseException; since confirming via DescribeTable
			// is also denied, that should still be tolerated as benign.
			deniedDriver := newDenyDescribeTableDriver(t)
			So(deniedDriver.NewTable(tableName), ShouldBeNil)
			So(deniedDriver.tableName, ShouldEqual, tableName)
		})
	})
}

// failGetItemTransport stands in for DynamoDB without an emulator: every GetItem fails with
// an InternalServerError, every other action succeeds with an empty result, and the actions
// seen are recorded together with their request bodies.
type failGetItemTransport struct {
	mu    sync.Mutex
	calls []string
}

func (t *failGetItemTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	action := strings.TrimPrefix(req.Header.Get("X-Amz-Target"), "DynamoDB_20120810.")

	reqBody, _ := io.ReadAll(req.Body)

	t.mu.Lock()
	t.calls = append(t.calls, action+" "+string(reqBody))
	t.mu.Unlock()

	status, body := http.StatusOK, "{}"
	if action == "GetItem" {
		status = http.StatusInternalServerError
		body = `{"__type":"com.amazonaws.dynamodb.v20120810#InternalServerError","message":"simulated outage"}`
	}

	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}, nil
}

// sent reports whether an action was sent whose request body contains fragment.
func (t *failGetItemTransport) sent(action, fragment string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, call := range t.calls {
		if strings.HasPrefix(call, action+" ") && strings.Contains(call, fragment) {
			return true
		}
	}

	return false
}

func newFailGetItemDriver() (*DynamoDBDriver, *failGetItemTransport) {
	transport := &failGetItemTransport{}

	client := dynamodb.New(dynamodb.Options{
		Region:           "us-east-2",
		BaseEndpoint:     aws.String("http://dynamodb.invalid"),
		Credentials:      aws.AnonymousCredentials{},
		HTTPClient:       &http.Client{Transport: transport},
		RetryMaxAttempts: 1,
	})

	return &DynamoDBDriver{client: client, tableName: "BlobTable", log: log.NewTestLogger()}, transport
}

// A read that fails says nothing about what the cache holds. Treating it as "no origin
// recorded" made PutBlob overwrite the origin and DeleteBlob drop the digest's whole record.
func TestDynamoDBReadFailureDoesNotChangeOrigin(t *testing.T) {
	digest := godigest.FromString("read-failure")

	Convey("PutBlob does not write an origin when it cannot read the current one", t, func() {
		driver, transport := newFailGetItemDriver()

		err := driver.PutBlob(digest, "repo/blobs/sha256/new")
		So(err, ShouldNotBeNil)
		So(transport.sent("GetItem", ""), ShouldBeTrue)
		So(transport.sent("UpdateItem", "OriginalBlobPath"), ShouldBeFalse)
	})

	Convey("DeleteBlob does not drop the record when it cannot read the origin", t, func() {
		driver, transport := newFailGetItemDriver()

		err := driver.DeleteBlob(digest, "repo/blobs/sha256/duplicate")
		So(err, ShouldNotBeNil)
		So(transport.sent("GetItem", ""), ShouldBeTrue)
		So(transport.sent("DeleteItem", ""), ShouldBeFalse)
	})
}

type scriptedDynamoResponse struct {
	status int
	body   string
}

// scriptedDynamoTransport stands in for DynamoDB without an emulator: it answers each request
// with the next scripted response, and records the action and body of every request, so a
// test can play out an interleaving with another writer one step at a time.
type scriptedDynamoTransport struct {
	responses []scriptedDynamoResponse
	targets   []string
	bodies    []string
}

func (t *scriptedDynamoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBody, _ := io.ReadAll(req.Body)

	t.targets = append(t.targets, strings.TrimPrefix(req.Header.Get("X-Amz-Target"), "DynamoDB_20120810."))
	t.bodies = append(t.bodies, string(reqBody))

	// past the end of the script every request fails, so a driver that keeps going is noticed
	response := scriptedDynamoResponse{http.StatusInternalServerError, `{"message":"unscripted request"}`}
	if len(t.targets) <= len(t.responses) {
		response = t.responses[len(t.targets)-1]
	}

	return &http.Response{
		StatusCode: response.status,
		Status:     http.StatusText(response.status),
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
		Body:       io.NopCloser(bytes.NewBufferString(response.body)),
		Request:    req,
	}, nil
}

func newScriptedDynamoDriver(responses ...scriptedDynamoResponse) (*DynamoDBDriver, *scriptedDynamoTransport) {
	transport := &scriptedDynamoTransport{responses: responses}

	client := dynamodb.New(dynamodb.Options{
		Region:           "us-east-2",
		BaseEndpoint:     aws.String("http://dynamodb.invalid"),
		Credentials:      aws.AnonymousCredentials{},
		HTTPClient:       &http.Client{Transport: transport},
		RetryMaxAttempts: 1,
	})

	return &DynamoDBDriver{client: client, tableName: "BlobTable", log: log.NewTestLogger()}, transport
}

// PutBlob and DeleteBlob read the record, decide, and then write. Another zot instance
// sharing the table can change the record in between, so the writes are conditional on what
// was read. These tests play the other instance through scripted responses.
func TestDynamoDBConcurrentWriters(t *testing.T) {
	const (
		noItem        = `{}`
		withDuplicate = `{"Item":{"OriginalBlobPath":{"S":"/repo/origin"},` +
			`"DuplicateBlobPath":{"SS":["/repo/origin","/repo/duplicate"]}}}`
		originOnly        = `{"Item":{"OriginalBlobPath":{"S":"/repo/origin"}}}`
		conditionalFailed = `{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",` +
			`"message":"The conditional request failed"}`
	)

	digest := godigest.FromString("race")

	Convey("PutBlob keeps the origin another writer recorded first", t, func() {
		driver, transport := newScriptedDynamoDriver(
			// no record yet, but another writer records its origin before ours is written
			scriptedDynamoResponse{http.StatusOK, noItem},
			scriptedDynamoResponse{http.StatusBadRequest, conditionalFailed},
			// our path is still added, as a duplicate of that origin
			scriptedDynamoResponse{http.StatusOK, `{}`},
		)

		So(driver.PutBlob(digest, "/repo/late"), ShouldBeNil)
		So(transport.targets, ShouldResemble, []string{"GetItem", "UpdateItem", "UpdateItem"})
		So(transport.bodies[1], ShouldContainSubstring, "SET OriginalBlobPath = :s")
		So(transport.bodies[1], ShouldContainSubstring, "attribute_not_exists(OriginalBlobPath)")
		So(transport.bodies[2], ShouldContainSubstring, "ADD DuplicateBlobPath :i")
	})

	Convey("DeleteBlob does not promote a duplicate that was deleted meanwhile", t, func() {
		driver, transport := newScriptedDynamoDriver(
			// the path is taken out of the duplicates; the record still shows another duplicate
			scriptedDynamoResponse{http.StatusOK, `{}`},
			scriptedDynamoResponse{http.StatusOK, withDuplicate},
			// ...which another writer deletes before it is promoted to origin
			scriptedDynamoResponse{http.StatusBadRequest, conditionalFailed},
			// the retry sees no duplicate left and deletes the record
			scriptedDynamoResponse{http.StatusOK, originOnly},
			scriptedDynamoResponse{http.StatusOK, `{}`},
		)

		So(driver.DeleteBlob(digest, "/repo/origin"), ShouldBeNil)
		So(transport.targets, ShouldResemble,
			[]string{"UpdateItem", "GetItem", "UpdateItem", "GetItem", "DeleteItem"})
		So(transport.bodies[1], ShouldContainSubstring, `"ConsistentRead":true`)
		So(transport.bodies[2], ShouldContainSubstring, "OriginalBlobPath = :old AND contains(DuplicateBlobPath, :new)")
		So(transport.bodies[2], ShouldContainSubstring, "/repo/duplicate")
		So(transport.bodies[4], ShouldContainSubstring, "OriginalBlobPath = :old")
		So(transport.bodies[4], ShouldContainSubstring, "size(DuplicateBlobPath) = :zero")
	})

	Convey("DeleteBlob does not drop a record that gained a duplicate meanwhile", t, func() {
		driver, transport := newScriptedDynamoDriver(
			// the origin is the last tracked path, so the record is to be deleted
			scriptedDynamoResponse{http.StatusOK, `{}`},
			scriptedDynamoResponse{http.StatusOK, originOnly},
			// ...but another writer adds a duplicate first
			scriptedDynamoResponse{http.StatusBadRequest, conditionalFailed},
			// the retry promotes that duplicate instead
			scriptedDynamoResponse{http.StatusOK, withDuplicate},
			scriptedDynamoResponse{http.StatusOK, `{}`},
		)

		So(driver.DeleteBlob(digest, "/repo/origin"), ShouldBeNil)
		So(transport.targets, ShouldResemble,
			[]string{"UpdateItem", "GetItem", "DeleteItem", "GetItem", "UpdateItem"})
		So(transport.bodies[4], ShouldContainSubstring, "SET OriginalBlobPath = :new")
		So(transport.bodies[4], ShouldContainSubstring, "/repo/duplicate")
	})

	Convey("DeleteBlob leaves alone a record whose origin is another path", t, func() {
		driver, transport := newScriptedDynamoDriver(
			scriptedDynamoResponse{http.StatusOK, `{}`},
			scriptedDynamoResponse{http.StatusOK, withDuplicate},
		)

		So(driver.DeleteBlob(digest, "/repo/duplicate"), ShouldBeNil)
		So(transport.targets, ShouldResemble, []string{"UpdateItem", "GetItem"})
	})

	Convey("DeleteBlob reports a failed write", t, func() {
		driver, transport := newScriptedDynamoDriver(
			scriptedDynamoResponse{http.StatusOK, `{}`},
			scriptedDynamoResponse{http.StatusOK, originOnly},
		)

		So(driver.DeleteBlob(digest, "/repo/origin"), ShouldNotBeNil)
		So(slices.Contains(transport.targets, "DeleteItem"), ShouldBeTrue)
	})
}

// The same conditions, checked against a real DynamoDB engine: the scripted tests above
// cannot tell whether the condition expressions are valid or mean what they are meant to.
func TestDynamoDBConditionalWrites(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("Origin writes and removals are conditional on the record's current state", t, func() {
		cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-2"))
		So(err, ShouldBeNil)

		client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(os.Getenv("DYNAMODBMOCK_ENDPOINT"))
		})

		driver := &DynamoDBDriver{client: client, log: log.NewTestLogger()}
		So(driver.NewTable("ConditionalWritesTable"), ShouldBeNil)

		// a digest of its own per run: the emulator's table outlives the test
		digest := godigest.FromString(t.Name() + t.TempDir())

		So(driver.PutBlob(digest, "/repo/first"), ShouldBeNil)

		Convey("an existing origin is not overwritten", func() {
			err := driver.putOriginBlob(digest, "/repo/second")
			So(isConditionalCheckFailed(err), ShouldBeTrue)

			origin, err := driver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(origin, ShouldEqual, "/repo/first")
		})

		Convey("a path that is not tracked is not promoted to origin", func() {
			err := driver.replaceOrigin(digest, "/repo/first", "/repo/never-added")
			So(isConditionalCheckFailed(err), ShouldBeTrue)

			origin, err := driver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(origin, ShouldEqual, "/repo/first")
		})

		Convey("a record that still tracks a duplicate is not deleted", func() {
			So(driver.PutBlob(digest, "/repo/second"), ShouldBeNil)

			err := driver.replaceOrigin(digest, "/repo/first", "")
			So(isConditionalCheckFailed(err), ShouldBeTrue)

			So(driver.HasBlob(digest, "/repo/second"), ShouldBeTrue)
		})

		Convey("a record with an origin is not deleted as an empty one", func() {
			err := driver.deleteItemWithoutOrigin(digest)
			So(isConditionalCheckFailed(err), ShouldBeTrue)

			origin, err := driver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(origin, ShouldEqual, "/repo/first")
		})

		Convey("deleting the origin promotes a duplicate, and deleting the last path drops the record", func() {
			So(driver.PutBlob(digest, "/repo/second"), ShouldBeNil)
			So(driver.DeleteBlob(digest, "/repo/first"), ShouldBeNil)

			origin, err := driver.GetBlob(digest)
			So(err, ShouldBeNil)
			So(origin, ShouldEqual, "/repo/second")

			So(driver.DeleteBlob(digest, "/repo/second"), ShouldBeNil)

			_, err = driver.GetBlob(digest)
			So(err, ShouldEqual, zerr.ErrCacheMiss)

			// and deleting from a digest that is not tracked leaves no record behind
			So(driver.DeleteBlob(digest, "/repo/second"), ShouldBeNil)

			_, err = driver.GetBlob(digest)
			So(err, ShouldEqual, zerr.ErrCacheMiss)
		})
	})
}
