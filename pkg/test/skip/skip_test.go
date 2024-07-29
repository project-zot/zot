package skip_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	tskip "zotregistry.dev/zot/pkg/test/skip"
)

// for code coverage.
func TestSkipS3(t *testing.T) {
	envName := "S3MOCK_ENDPOINT"
	envVal := os.Getenv(envName)

	if len(envVal) > 0 {
		defer os.Setenv(envName, envVal)
		err := os.Unsetenv(envName)
		require.NoError(t, err, "Error should be nil")
	}

	tskip.SkipS3(t)
}

func TestSkipDynamo(t *testing.T) {
	envName := "DYNAMODBMOCK_ENDPOINT"
	envVal := os.Getenv(envName)

	if len(envVal) > 0 {
		defer os.Setenv(envName, envVal)
		err := os.Unsetenv(envName)
		require.NoError(t, err, "Error should be nil")
	}

	tskip.SkipDynamo(t)
}
