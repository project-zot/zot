package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

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
