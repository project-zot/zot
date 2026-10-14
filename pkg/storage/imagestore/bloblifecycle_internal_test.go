package imagestore

import (
	"errors"
	"net/http"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var errLifecycleTest = errors.New("lifecycle test error") //nolint: gochecknoglobals

// lifecycleTestDriver implements the few storageTypes.Driver methods the lifecycles call;
// any other call panics on the nil embedded interface.
type lifecycleTestDriver struct {
	storageTypes.Driver

	name        string
	statFn      func(path string) (driver.FileInfo, error)
	links       [][2]string
	redirectFor string
}

func (d *lifecycleTestDriver) Name() string { return d.name }

func (d *lifecycleTestDriver) Stat(path string) (driver.FileInfo, error) { return d.statFn(path) }

func (d *lifecycleTestDriver) Link(src, dest string) error {
	d.links = append(d.links, [2]string{src, dest})

	return nil
}

func (d *lifecycleTestDriver) RedirectURL(_ *http.Request, path string) (string, error) {
	d.redirectFor = path

	if path == "/fail" {
		return "", errclass.MarkTransient(errLifecycleTest)
	}

	return "https://bucket.example/" + path, nil
}

func TestBlobLifecycle(t *testing.T) {
	digest := godigest.FromString("content")
	emptyDigest := godigest.FromBytes(nil)

	unusedResolver := func(godigest.Digest) (string, error) {
		panic("resolver must not be called")
	}

	newLifecycle := func(name string) (blobLifecycle, *lifecycleTestDriver) {
		storeDriver := &lifecycleTestDriver{name: name}

		return newBlobLifecycle(storeDriver, "/root", monitoring.NewNopMetricServer()), storeDriver
	}

	Convey("The driver picks the lifecycle", t, func() {
		local, _ := newLifecycle(storageConstants.LocalStorageDriverName)
		_, ok := local.(*localHardlinkBlobLifecycle)
		So(ok, ShouldBeTrue)

		for _, name := range []string{storageConstants.S3StorageDriverName, "gcs", "azure"} {
			remote, _ := newLifecycle(name)
			_, ok := remote.(*remoteSharedBlobLifecycle)
			So(ok, ShouldBeTrue)
		}
	})

	Convey("Local storage", t, func() {
		lifecycle, storeDriver := newLifecycle(storageConstants.LocalStorageDriverName)

		Convey("links through the driver", func() {
			So(lifecycle.LinkBlob("/src", "/dst"), ShouldBeNil)
			So(storeDriver.links, ShouldResemble, [][2]string{{"/src", "/dst"}})
		})

		Convey("reads a blob from its own path, even a zero-byte one", func() {
			path, err := lifecycle.ResolveReadPath("/blob", digest, 0, unusedResolver)
			So(err, ShouldBeNil)
			So(path, ShouldEqual, "/blob")
		})

		Convey("needs a blobs directory in each repo", func() {
			storeDriver.statFn = func(path string) (driver.FileInfo, error) {
				So(path, ShouldEqual, "/root/repo/blobs")

				return &mocks.FileInfoMock{IsDirFn: func() bool { return true }}, nil
			}

			ok, err := lifecycle.ValidateBlobsDir("/root/repo")
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)

			storeDriver.statFn = func(string) (driver.FileInfo, error) {
				return &mocks.FileInfoMock{IsDirFn: func() bool { return false }}, nil
			}

			ok, err = lifecycle.ValidateBlobsDir("/root/repo")
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)

			storeDriver.statFn = func(string) (driver.FileInfo, error) {
				return nil, errclass.MarkMissing(errLifecycleTest)
			}

			ok, err = lifecycle.ValidateBlobsDir("/root/repo")
			So(err, ShouldBeNil)
			So(ok, ShouldBeFalse)
		})

		Convey("reports a blobs directory it cannot stat, and does not call it missing", func() {
			storeDriver.statFn = func(string) (driver.FileInfo, error) {
				return nil, errclass.MarkPermanent(errLifecycleTest)
			}

			ok, err := lifecycle.ValidateBlobsDir("/root/repo")
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)

			// an unclassified error is treated as transient
			storeDriver.statFn = func(string) (driver.FileInfo, error) {
				return nil, errLifecycleTest
			}

			ok, err = lifecycle.ValidateBlobsDir("/root/repo")
			So(ok, ShouldBeFalse)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("has no redirect URL, and does not look the blob up for one", func() {
			url, err := lifecycle.RedirectURL(&http.Request{}, func() (string, error) {
				panic("blob path must not be looked up")
			})
			So(err, ShouldBeNil)
			So(url, ShouldBeEmpty)
		})

		Convey("keeps shared content alive across deletes", func() {
			So(lifecycle.DeletesCanDestroySharedContent(), ShouldBeFalse)
		})

		Convey("measures storage usage", func() {
			So(func() { lifecycle.UpdateStorageUsage("repo") }, ShouldNotPanic)
		})
	})

	Convey("Remote storage", t, func() {
		lifecycle, storeDriver := newLifecycle(storageConstants.S3StorageDriverName)

		Convey("links through the driver", func() {
			So(lifecycle.LinkBlob("/src", "/dst"), ShouldBeNil)
			So(storeDriver.links, ShouldResemble, [][2]string{{"/src", "/dst"}})
		})

		Convey("resolves a zero-byte placeholder to the content's path", func() {
			path, err := lifecycle.ResolveReadPath("/blob", digest, 0, func(d godigest.Digest) (string, error) {
				So(d, ShouldEqual, digest)

				return "/origin", nil
			})
			So(err, ShouldBeNil)
			So(path, ShouldEqual, "/origin")

			_, err = lifecycle.ResolveReadPath("/blob", digest, 0, func(godigest.Digest) (string, error) {
				return "", zerr.ErrCacheMiss
			})
			So(err, ShouldEqual, zerr.ErrCacheMiss)
		})

		Convey("reads a blob with content, or an empty blob, from its own path", func() {
			path, err := lifecycle.ResolveReadPath("/blob", digest, 7, unusedResolver)
			So(err, ShouldBeNil)
			So(path, ShouldEqual, "/blob")

			path, err = lifecycle.ResolveReadPath("/empty", emptyDigest, 0, unusedResolver)
			So(err, ShouldBeNil)
			So(path, ShouldEqual, "/empty")
		})

		Convey("needs no blobs directory", func() {
			ok, err := lifecycle.ValidateBlobsDir("/root/repo")
			So(err, ShouldBeNil)
			So(ok, ShouldBeTrue)
		})

		Convey("redirects to the driver's URL for the content's path", func() {
			url, err := lifecycle.RedirectURL(&http.Request{}, func() (string, error) { return "/origin", nil })
			So(err, ShouldBeNil)
			So(url, ShouldEqual, "https://bucket.example//origin")
			So(storeDriver.redirectFor, ShouldEqual, "/origin")

			_, err = lifecycle.RedirectURL(&http.Request{}, func() (string, error) { return "", zerr.ErrBlobNotFound })
			So(err, ShouldEqual, zerr.ErrBlobNotFound)

			_, err = lifecycle.RedirectURL(&http.Request{}, func() (string, error) { return "/fail", nil })
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
		})

		Convey("can lose shared content to a delete", func() {
			So(lifecycle.DeletesCanDestroySharedContent(), ShouldBeTrue)
		})

		Convey("does not measure storage usage", func() {
			So(func() { lifecycle.UpdateStorageUsage("repo") }, ShouldNotPanic)
		})
	})
}
