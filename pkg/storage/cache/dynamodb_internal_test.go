package cache

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
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

type captureGetItemTransport struct {
	requestBody []byte
}

func (transport *captureGetItemTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	requestBody, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	transport.requestBody = requestBody

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.0"}},
		Body: io.NopCloser(bytes.NewBufferString(
			`{"Item":{"OriginalBlobPath":{"S":"/repo/blob"},` +
				`"DuplicateBlobPath":{"SS":["/repo/duplicate"]}}}`,
		)),
		Request: req,
	}, nil
}

func TestDynamoOwnershipReadsUseConsistentRead(t *testing.T) {
	transport := &captureGetItemTransport{}
	client := dynamodb.NewFromConfig(aws.Config{
		Region:      "us-east-2",
		Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
		HTTPClient:  &http.Client{Transport: transport},
	}, func(options *dynamodb.Options) {
		options.BaseEndpoint = aws.String("http://dynamodb.test")
	})
	driver := &DynamoDBDriver{client: client, tableName: "BlobRefTable", log: log.NewTestLogger()}
	assertConsistentRead := func() {
		t.Helper()

		request := struct {
			ConsistentRead bool `json:"ConsistentRead"`
		}{}
		if err := json.Unmarshal(transport.requestBody, &request); err != nil {
			t.Fatalf("decode GetItem request: %v", err)
		}

		if !request.ConsistentRead {
			t.Fatal("Dynamo ownership reads must be consistent for global blob reclamation decisions")
		}
	}

	refs, err := driver.GetBlobRefs(godigest.FromString("consistent-read"))
	if err != nil {
		t.Fatalf("GetBlobRefs() error = %v", err)
	}

	if len(refs) != 2 {
		t.Fatalf("GetBlobRefs() refs = %v, want two refs", refs)
	}
	assertConsistentRead()

	origin, err := driver.GetBlob(godigest.FromString("consistent-read"))
	if err != nil || origin != "/repo/blob" {
		t.Fatalf("GetBlob() = %q, %v, want /repo/blob, nil", origin, err)
	}
	assertConsistentRead()

	duplicate, err := driver.GetDuplicateBlob(godigest.FromString("consistent-read"))
	if err != nil || duplicate != "/repo/duplicate" {
		t.Fatalf("GetDuplicateBlob() = %q, %v, want /repo/duplicate, nil", duplicate, err)
	}
	assertConsistentRead()
}

// TestGetBlobRefsPartialItemIsCacheMiss covers a blob_refs item that exists (GetItem
// returns a non-nil Item) but has no OriginalBlobPath/DuplicateBlobPath at all. GetBlobRefs
// must report this as a miss, not ([], nil): callers like isDigestReferencedAcrossRepos
// would otherwise read an empty success as "definitely unreferenced" instead of falling
// back to the authoritative GetAllBlobs scan.
func TestGetBlobRefsPartialItemIsCacheMiss(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("GetBlobRefs on an item with no usable path is a cache miss", t, func() {
		endpoint := os.Getenv("DYNAMODBMOCK_ENDPOINT")

		cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-2"))
		So(err, ShouldBeNil)

		client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})

		const tableName = "BlobRefPartialItemTable"

		driver := &DynamoDBDriver{client: client, tableName: tableName, log: log.NewTestLogger()}
		So(driver.NewTable(tableName), ShouldBeNil)

		digest := godigest.FromString("partial-item")
		refDigest := driver.blobRefDigest(digest)

		key, err := attributevalue.MarshalMap(map[string]any{"Digest": refDigest})
		So(err, ShouldBeNil)

		_, err = client.PutItem(context.Background(), &dynamodb.PutItemInput{
			TableName: aws.String(tableName),
			Item:      key,
		})
		So(err, ShouldBeNil)

		refs, err := driver.GetBlobRefs(digest)
		So(errors.Is(err, zerr.ErrCacheMiss), ShouldBeTrue)
		So(refs, ShouldBeEmpty)
	})
}
