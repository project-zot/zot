package gcsemulator_test

import (
	"errors"
	"os"
	"testing"

	"zotregistry.dev/zot/v2/pkg/test/gcsemulator"
)

func TestCreateBucketRequiresHostEnv(t *testing.T) {
	t.Setenv(gcsemulator.HostEnv, "")

	err := gcsemulator.CreateBucket("zot-storage-test")
	if !errors.Is(err, gcsemulator.ErrHostNotSet) {
		t.Fatalf("got %v, want ErrHostNotSet", err)
	}
}

func TestCreateBucketIdempotent(t *testing.T) {
	if os.Getenv(gcsemulator.HostEnv) == "" {
		t.Skip("Skipping testing without GCS emulator (STORAGE_EMULATOR_HOST)")
	}

	if err := gcsemulator.CreateBucket("zot-storage-test"); err != nil {
		t.Fatalf("first CreateBucket: %v", err)
	}

	// Second create must tolerate conflict / already-exists from the emulator.
	if err := gcsemulator.CreateBucket("zot-storage-test"); err != nil {
		t.Fatalf("second CreateBucket: %v", err)
	}
}
