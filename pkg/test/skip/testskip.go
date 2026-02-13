package skip

import (
	"os"
	"testing"
)

func SkipS3(t *testing.T) {
	t.Helper()

	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS S3 mock server")
	}
}

func SkipDynamo(t *testing.T) {
	t.Helper()

	if os.Getenv("DYNAMODBMOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS DynamoDB mock server")
	}
}

func SkipGCS(t *testing.T) {
	t.Helper()

	if os.Getenv("GCSMOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without GCS mock server")
	}
}
