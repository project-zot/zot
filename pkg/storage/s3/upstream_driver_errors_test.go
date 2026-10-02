package s3_test

// Characterization for storage error classification.
// Locks distribution S3 (+ zot pass-through) List/Walk/Stat/Get surfaces from
// the matrix. Requires S3MOCK_ENDPOINT (localstack/minio). See
// pkg/storage/errclass/driver-error-matrix.md.

import (
	"context"
	"errors"
	"path"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	guuid "github.com/gofrs/uuid"
	. "github.com/smartystreets/goconvey/convey"

	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func TestUpstreamDriverErrors(t *testing.T) {
	tskip.SkipS3(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-errclass", uuid.String())
	storeDriver, _, _ := createObjectsStore(testDir, t.TempDir(), false)
	defer cleanupStorage(storeDriver, testDir)

	ctx := context.Background()

	Convey("S3 driver upstream error surfaces (matrix)", t, func() {
		Convey("Stat missing object (no key, no children) → PathNotFound", func() {
			_, err := storeDriver.Stat(ctx, path.Join(testDir, "no-such-object"))
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("Stat existing object → nil, not IsDir", func() {
			obj := path.Join(testDir, "existing", "blob")
			So(storeDriver.PutContent(ctx, obj, []byte("payload")), ShouldBeNil)

			fi, err := storeDriver.Stat(ctx, obj)
			So(err, ShouldBeNil)
			So(fi.IsDir(), ShouldBeFalse)
		})

		Convey("Stat prefix with children → IsDir virtual directory", func() {
			obj := path.Join(testDir, "virtdir", "child", "file")
			So(storeDriver.PutContent(ctx, obj, []byte("x")), ShouldBeNil)

			fi, err := storeDriver.Stat(ctx, path.Join(testDir, "virtdir"))
			So(err, ShouldBeNil)
			So(fi.IsDir(), ShouldBeTrue)
		})

		Convey("GetContent missing key → PathNotFound", func() {
			_, err := storeDriver.GetContent(ctx, path.Join(testDir, "no-such-content"))
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("List empty non-root prefix → PathNotFound", func() {
			_, err := storeDriver.List(ctx, path.Join(testDir, "empty-prefix"))
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("List `/` is never PathNotFound (special-cased vs non-root empty)", func() {
			// Same helper pattern as the rest of this package: createStoreDriver's
			// "rootDir" is ignored by distribution, so List("/") sees the shared
			// MinIO bucket and may be non-empty. Lock only the special-case rule —
			// empty non-root → PathNotFound is covered above.
			keys, err := storeDriver.List(ctx, "/")
			So(err, ShouldBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeFalse)
			So(keys, ShouldNotBeNil)
		})

		Convey("Walk missing / empty non-root prefix → nil (divergent from GCS/Azure)", func() {
			called := false
			err := storeDriver.Walk(ctx, path.Join(testDir, "empty-walk"),
				func(_ storagedriver.FileInfo) error {
					called = true

					return nil
				})
			So(err, ShouldBeNil)
			So(called, ShouldBeFalse)
		})

		Convey("Walk prefix with objects → callbacks invoked, nil", func() {
			obj := path.Join(testDir, "walk-populated", "file")
			So(storeDriver.PutContent(ctx, obj, []byte("y")), ShouldBeNil)

			seen := []string{}
			err := storeDriver.Walk(ctx, path.Join(testDir, "walk-populated"),
				func(fi storagedriver.FileInfo) error {
					seen = append(seen, fi.Path())

					return nil
				})
			So(err, ShouldBeNil)
			So(len(seen), ShouldBeGreaterThan, 0)
		})

		Convey("Delete nothing under prefix → PathNotFound", func() {
			err := storeDriver.Delete(ctx, path.Join(testDir, "no-delete-target"))
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
		})

		Convey("Stat partial prefix IsDir quirk (open distribution bug)", func() {
			obj := path.Join(testDir, "ab", "cd", "file")
			So(storeDriver.PutContent(ctx, obj, []byte("x")), ShouldBeNil)

			fi, err := storeDriver.Stat(ctx, path.Join(testDir, "ab", "c"))
			So(err, ShouldBeNil)
			So(fi.IsDir(), ShouldBeTrue)
		})
	})
}
