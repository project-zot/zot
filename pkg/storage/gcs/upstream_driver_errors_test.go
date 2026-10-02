package gcs_test

// Characterization of distribution WalkFallback (and related) surfaces used by GCS.
// formatErr / Mark* mapping lives in storage_error_mapping_test.go.
// See pkg/storage/errclass/driver-error-matrix.md.

import (
	"context"
	"errors"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/storage/gcs"
)

func TestUpstreamDriverErrors(t *testing.T) {
	Convey("WalkFallback surfaces (GCS / Azure shared distribution path)", t, func() {
		Convey("nested empty List → PathNotFound aborts walk", func() {
			memStore := &memFS{
				objects: []string{
					"/repo/blobs/sha256/deadbeef",
					"/repo/.uploads/session",
				},
				poisoned: map[string]bool{"/repo/.uploads": true},
			}

			err := gcs.New(newWalkStore(memStore)).Walk("/repo", func(_ storagedriver.FileInfo) error {
				return nil
			})
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
			So(pnf.Path, ShouldEqual, "/repo/.uploads")
		})

		Convey("Stat PathNotFound mid-walk → skip and continue (concurrent delete)", func() {
			memStore := &memFS{
				objects: []string{
					"/repo/keep/file",
					"/repo/ghost/file", // listed as child prefix /repo/ghost
				},
				vanished: map[string]bool{"/repo/ghost": true},
			}

			seen := []string{}
			err := gcs.New(newWalkStore(memStore)).Walk("/repo", func(fi storagedriver.FileInfo) error {
				seen = append(seen, fi.Path())

				return nil
			})
			So(err, ShouldBeNil)
			So(seen, ShouldContain, "/repo/keep")
			So(seen, ShouldNotContain, "/repo/ghost")
		})

		Convey("StartAfterHint on missing base → PathNotFound swallowed, Walk returns nil", func() {
			memStore := &memFS{
				objects: []string{"/repo/alive/file"},
			}
			store := newWalkStore(memStore)

			// Exercise distribution WalkFallback directly: zot's Driver.Walk does not
			// forward WalkOptions.
			err := storagedriver.WalkFallback(context.Background(), store, "/repo",
				func(_ storagedriver.FileInfo) error { return nil },
				func(opts *storagedriver.WalkOptions) {
					opts.StartAfterHint = "/repo/missing/nested"
				})
			So(err, ShouldBeNil)
		})
	})
}
