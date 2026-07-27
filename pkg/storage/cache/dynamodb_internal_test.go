package cache

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
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
