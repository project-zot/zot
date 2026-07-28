package gcs_test

// Regression test for a GC bug that was observed in production against a GCS
// bucket: the GC task generator stopped after the first few repositories and
// silently skipped all remaining ones.
//
// Chain that was affected (all REAL code):
//   ImageStore.GetNextRepository (pkg/storage/imagestore/imagestore.go)
//     -> zot gcs.Driver.Walk (pkg/storage/gcs/driver.go)
//       -> distribution storagedriver.WalkFallback (v3.1.1 walk.go)
//         -> StorageDriver.List / Stat
//
// The distribution GCS driver returned PathNotFoundError whenever a prefix
// listed empty ("Treat empty response as missing directory",
// registry/storage/driver/gcs/gcs.go). That happened for prefixes whose only
// objects were filtered out client-side (in-flight upload sessions in
// .uploads/) or whose objects were deleted concurrently by GC between the
// parent List and the child List. doWalkFallback propagated that nested List
// error up, and GetNextRepository mapped ANY PathNotFoundError from the walk to
// "empty rootDir" -> returned "" -> GCTaskGenerator set done. Result: every
// repository sorting after the poisoned one was never garbage collected.
//
// The bug is now fixed by the .uploads/blobs/.sync ErrSkipDir guard in
// GetNextRepository (pkg/storage/imagestore/imagestore.go): those reserved
// sub-directories are never descended into, so a ghost/empty prefix can no
// longer abort repository enumeration. This test guards against a regression by
// asserting that ALL repositories are still enumerated despite a ghost .uploads
// prefix, and that none of the reserved dirs is ever listed during enumeration.

import (
	"context"
	"sort"
	"strings"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// memFS emulates the observable List/Stat behavior of the distribution GCS
// driver on top of a flat object list. Directories don't exist as objects;
// they are prefixes, and listing a prefix with no visible objects yields
// PathNotFoundError exactly like the real driver. Paths in `poisoned` list
// empty even though their parent still shows them as a child prefix — the
// production situation for .uploads/ with only session objects, or a prefix
// concurrently emptied by GC. Every path passed to List is recorded in
// `listed` so the test can prove reserved dirs are never descended into.
type memFS struct {
	objects  []string
	poisoned map[string]bool
	listed   []string
}

func (m *memFS) list(dir string) ([]string, error) {
	m.listed = append(m.listed, dir)

	if m.poisoned[dir] {
		return nil, storagedriver.PathNotFoundError{Path: dir, DriverName: "gcs"}
	}

	prefix := strings.TrimSuffix(dir, "/") + "/"
	seen := map[string]bool{}
	out := []string{}

	for _, obj := range m.objects {
		if !strings.HasPrefix(obj, prefix) {
			continue
		}

		rest := obj[len(prefix):]
		if before, _, found := strings.Cut(rest, "/"); found {
			child := prefix + before
			if !seen[child] {
				seen[child] = true

				out = append(out, child)
			}
		} else {
			out = append(out, obj)
		}
	}

	if len(out) == 0 {
		// like the real GCS driver: empty listing == missing directory
		return nil, storagedriver.PathNotFoundError{Path: dir, DriverName: "gcs"}
	}

	sort.Strings(out)

	return out, nil
}

func (m *memFS) stat(path string) (storagedriver.FileInfo, error) {
	dirPrefix := strings.TrimSuffix(path, "/") + "/"
	for _, obj := range m.objects {
		if obj == path {
			return &fileInfoMock{isDir: false, path: path}, nil
		}

		if strings.HasPrefix(obj, dirPrefix) {
			return &fileInfoMock{isDir: true, path: path}, nil
		}
	}

	return nil, storagedriver.PathNotFoundError{Path: path, DriverName: "gcs"}
}

// newWalkStore wires the memFS into a distribution StorageDriver whose Walk
// uses the REAL storagedriver.WalkFallback — the same code path the real GCS
// driver uses (distribution gcs.go delegates Walk to WalkFallback).
func newWalkStore(memfs *memFS) *mocks.StorageDriverMock {
	storeMock := &mocks.StorageDriverMock{}
	storeMock.NameFn = func() string { return "gcs" }
	storeMock.ListFn = func(_ context.Context, path string) ([]string, error) {
		return memfs.list(path)
	}
	storeMock.StatFn = func(_ context.Context, path string) (storagedriver.FileInfo, error) {
		return memfs.stat(path)
	}
	storeMock.WalkFn = func(ctx context.Context, path string, f storagedriver.WalkFn,
		options ...func(*storagedriver.WalkOptions),
	) error {
		return storagedriver.WalkFallback(ctx, storeMock, path, f, options...)
	}

	return storeMock
}

func TestGetNextRepositoryVisitsAllReposDespiteGhostUploadsPrefix(t *testing.T) {
	rootDir := "/zot"
	// Healthy fixture: three repos, each with a blobs/ dir. repo-b additionally
	// carries a .uploads/ session object and a .sync/ tmp object so that all
	// three reserved dir types actually surface as child prefixes during the
	// walk — otherwise the reserved-dir assertions (AC-4) would be vacuous.
	objects := []string{
		"/zot/repo-a/repo-a/blobs/sha256/aaa",
		"/zot/repo-a/repo-a/index.json",
		"/zot/repo-a/repo-a/oci-layout",
		"/zot/repo-b/repo-b/.sync/tmp",
		"/zot/repo-b/repo-b/.uploads/session-object",
		"/zot/repo-b/repo-b/blobs/sha256/bbb",
		"/zot/repo-b/repo-b/index.json",
		"/zot/repo-b/repo-b/oci-layout",
		"/zot/repo-c/repo-c/blobs/sha256/ccc",
		"/zot/repo-c/repo-c/index.json",
		"/zot/repo-c/repo-c/oci-layout",
	}

	log := zlog.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	// iterate exactly like GCTaskGenerator.Next: stop on repo == "" (done)
	collectRepos := func(memfs *memFS) []string {
		imgStore := gcs.NewImageStore(rootDir, t.TempDir(), false, false, log, metrics,
			nil, newWalkStore(memfs), nil, nil, nil)

		processed := map[string]struct{}{}
		got := []string{}

		for range 10 {
			repo, err := imgStore.GetNextRepository(processed)
			So(err, ShouldBeNil)

			if repo == "" {
				break // generator would set done=true here
			}

			processed[repo] = struct{}{}
			got = append(got, repo)
		}

		return got
	}

	wantAll := []string{"repo-a/repo-a", "repo-b/repo-b", "repo-c/repo-c"}

	Convey("GetNextRepository enumerates every repository", t, func() {
		Convey("AC-3: healthy bucket -> all three repos in order", func() {
			got := collectRepos(&memFS{objects: objects})
			So(got, ShouldResemble, wantAll)
		})

		Convey("AC-1: a ghost .uploads under an already-processed repo does not abort the walk", func() {
			// While walking towards repo-c the walk descends into the ALREADY
			// processed repo-b, and List(.uploads) returns PathNotFoundError
			// (empty prefix). All three repos must still be returned.
			got := collectRepos(&memFS{
				objects:  objects,
				poisoned: map[string]bool{"/zot/repo-b/repo-b/.uploads": true},
			})
			So(got, ShouldResemble, wantAll)
		})

		Convey("AC-2: a ghost .uploads under the FIRST repo does not hide the rest", func() {
			// The extra .uploads object under repo-a is mandatory: memFS.list
			// only surfaces a child prefix when an object exists beneath it, so
			// without it the poison would never fire.
			objectsWithFirstUpload := append([]string{
				"/zot/repo-a/repo-a/.uploads/session-object",
			}, objects...)

			got := collectRepos(&memFS{
				objects:  objectsWithFirstUpload,
				poisoned: map[string]bool{"/zot/repo-a/repo-a/.uploads": true},
			})
			So(got, ShouldResemble, wantAll)
		})

		Convey("AC-4: reserved dirs (blobs/.uploads/.sync) are never listed during enumeration", func() {
			memfs := &memFS{objects: objects}

			got := collectRepos(memfs)
			So(got, ShouldResemble, wantAll)

			reserved := map[string]bool{"blobs": true, ".uploads": true, ".sync": true}

			var reservedListed []string

			for _, listed := range memfs.listed {
				last := listed[strings.LastIndex(listed, "/")+1:]
				if reserved[last] {
					reservedListed = append(reservedListed, listed)
				}
			}

			So(reservedListed, ShouldBeEmpty)
		})
	})
}
