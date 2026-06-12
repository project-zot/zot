//go:build sync

package sync_test

import (
	"os"
	"path/filepath"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	pkgsync "zotregistry.dev/zot/v2/pkg/extensions/sync"
	"zotregistry.dev/zot/v2/pkg/log"
)

func TestNewLocalTempStore(t *testing.T) {
	Convey("NewLocalTempStore", t, func() {
		logger := log.NewTestLogger()

		Convey("returns a non-nil store when the root directory already exists", func() {
			dir := t.TempDir()

			store := pkgsync.NewLocalTempStore(dir, logger)
			So(store, ShouldNotBeNil)

			info, err := os.Stat(dir)
			So(err, ShouldBeNil)
			So(info.IsDir(), ShouldBeTrue)
		})

		Convey("creates the root directory when it does not exist", func() {
			dir := filepath.Join(t.TempDir(), "new", "nested", "dir")

			_, err := os.Stat(dir)
			So(os.IsNotExist(err), ShouldBeTrue)

			store := pkgsync.NewLocalTempStore(dir, logger)
			So(store, ShouldNotBeNil)

			info, err := os.Stat(dir)
			So(err, ShouldBeNil)
			So(info.IsDir(), ShouldBeTrue)
		})
	})
}

func TestLocalTempStoreBlobPath(t *testing.T) {
	Convey("LocalTempStore.BlobPath", t, func() {
		dir := t.TempDir()
		store := pkgsync.NewLocalTempStore(dir, log.NewTestLogger())

		data := []byte("blob payload")
		dig := godigest.FromBytes(data)

		Convey("returns a path with the expected format rootDir/algorithm/encoded", func() {
			blobPath := store.BlobPath(dig)
			expectedPath := filepath.Join(dir, dig.Algorithm().String(), dig.Encoded())
			So(blobPath, ShouldEqual, expectedPath)
		})

		Convey("creates the algorithm sub-directory on first call", func() {
			algorithmDir := filepath.Join(dir, dig.Algorithm().String())

			// Sub-directory must not exist yet.
			_, err := os.Stat(algorithmDir)
			So(os.IsNotExist(err), ShouldBeTrue)

			store.BlobPath(dig)

			info, err := os.Stat(algorithmDir)
			So(err, ShouldBeNil)
			So(info.IsDir(), ShouldBeTrue)
		})

		Convey("is idempotent — repeated calls return the same path", func() {
			first := store.BlobPath(dig)
			second := store.BlobPath(dig)
			So(first, ShouldEqual, second)
		})

		Convey("different digests produce different paths under the same root", func() {
			dig2 := godigest.FromBytes([]byte("other payload"))

			path1 := store.BlobPath(dig)
			path2 := store.BlobPath(dig2)
			So(path1, ShouldNotEqual, path2)
		})

		Convey("returned path is writable — a file can be created there", func() {
			blobPath := store.BlobPath(dig)

			err := os.WriteFile(blobPath, data, 0o600)
			So(err, ShouldBeNil)

			got, err := os.ReadFile(blobPath)
			So(err, ShouldBeNil)
			So(got, ShouldResemble, data)
		})
	})
}
