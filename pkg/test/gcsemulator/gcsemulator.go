// Package gcsemulator provides small helpers for GCS tests against
// storage-testbench when STORAGE_EMULATOR_HOST is set.
package gcsemulator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
)

// HostEnv is the official GCS emulator host variable (host[:port] or URL).
const (
	HostEnv     = "STORAGE_EMULATOR_HOST"
	testProject = "test-project"
)

// ErrHostNotSet is returned when CreateBucket is called without STORAGE_EMULATOR_HOST.
var ErrHostNotSet = errors.New("STORAGE_EMULATOR_HOST is not set")

// CreateBucket creates the bucket on the emulator; an existing bucket is fine.
// Relies on cloud.google.com/go/storage honoring STORAGE_EMULATOR_HOST
// (endpoint rewrite + WithoutAuthentication).
func CreateBucket(bucket string) error {
	if os.Getenv(HostEnv) == "" {
		return ErrHostNotSet
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("storage client: %w", err)
	}
	defer client.Close()

	// Create-first is more portable than Attrs: emulators and real GCS may
	// surface a missing bucket as a googleapi 404 instead of ErrBucketNotExist.
	if err := client.Bucket(bucket).Create(ctx, testProject, nil); err != nil && !bucketAlreadyExists(err) {
		return fmt.Errorf("create bucket %s: %w", bucket, err)
	}

	return nil
}

func bucketAlreadyExists(err error) bool {
	var gerr *googleapi.Error
	if errors.As(err, &gerr) && gerr.Code == http.StatusConflict {
		return true
	}

	// Emulator fallbacks when the error is not a typed googleapi.Error.
	msg := err.Error()

	return strings.Contains(msg, "409") ||
		strings.Contains(msg, "AlreadyExists") ||
		strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "bucketAlreadyOwnedByYou")
}
