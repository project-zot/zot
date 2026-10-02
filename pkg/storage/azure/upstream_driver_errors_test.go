package azure_test

// Characterization of distribution WalkFallback surfaces used by Azure.
// formatErr / Mark* mapping lives in storage_error_mapping_test.go.
// Azurite integration (List/Walk empty) lives in azure_test.go.
// See pkg/storage/errclass/driver-error-matrix.md.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/storage/azure"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

// azureMemFS mirrors distribution Azure/GCS List empty → PathNotFound for WalkFallback tests.
type azureMemFS struct {
	objects  []string
	poisoned map[string]bool
	vanished map[string]bool
}

func (m *azureMemFS) list(dir string) ([]string, error) {
	if m.poisoned[dir] {
		return nil, storagedriver.PathNotFoundError{Path: dir, DriverName: "azure"}
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
		return nil, storagedriver.PathNotFoundError{Path: dir, DriverName: "azure"}
	}

	sort.Strings(out)

	return out, nil
}

func (m *azureMemFS) stat(path string) (storagedriver.FileInfo, error) {
	if m.vanished[path] {
		return nil, storagedriver.PathNotFoundError{Path: path, DriverName: "azure"}
	}

	dirPrefix := strings.TrimSuffix(path, "/") + "/"
	for _, obj := range m.objects {
		if obj == path {
			return &fileInfoMock{path: path, isDir: false}, nil
		}

		if strings.HasPrefix(obj, dirPrefix) {
			return &fileInfoMock{path: path, isDir: true}, nil
		}
	}

	return nil, storagedriver.PathNotFoundError{Path: path, DriverName: "azure"}
}

func newAzureWalkStore(memfs *azureMemFS) *mocks.StorageDriverMock {
	storeMock := &mocks.StorageDriverMock{}
	storeMock.NameFn = func() string { return "azure" }
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

func TestUpstreamDriverErrors(t *testing.T) {
	Convey("WalkFallback surfaces through Azure wrapper", t, func() {
		Convey("nested empty List → PathNotFound aborts walk", func() {
			memStore := &azureMemFS{
				objects: []string{
					"/repo/blobs/sha256/deadbeef",
					"/repo/.uploads/session",
				},
				poisoned: map[string]bool{"/repo/.uploads": true},
			}

			err := azure.New(newAzureWalkStore(memStore)).Walk("/repo", func(_ storagedriver.FileInfo) error {
				return nil
			})
			So(err, ShouldNotBeNil)

			var pnf storagedriver.PathNotFoundError
			So(errors.As(err, &pnf), ShouldBeTrue)
			So(pnf.Path, ShouldEqual, "/repo/.uploads")
		})

		Convey("Stat PathNotFound mid-walk → skip and continue", func() {
			memStore := &azureMemFS{
				objects: []string{
					"/repo/keep/file",
					"/repo/ghost/file",
				},
				vanished: map[string]bool{"/repo/ghost": true},
			}

			seen := []string{}
			err := azure.New(newAzureWalkStore(memStore)).Walk("/repo", func(fi storagedriver.FileInfo) error {
				seen = append(seen, fi.Path())

				return nil
			})
			So(err, ShouldBeNil)
			So(seen, ShouldContain, "/repo/keep")
			So(seen, ShouldNotContain, "/repo/ghost")
		})
	})
}
