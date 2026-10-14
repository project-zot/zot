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
	moves       [][2]string
	redirectFor string
}

func (d *lifecycleTestDriver) Name() string { return d.name }

func (d *lifecycleTestDriver) Stat(path string) (driver.FileInfo, error) { return d.statFn(path) }

func (d *lifecycleTestDriver) Link(src, dest string) error {
	d.links = append(d.links, [2]string{src, dest})

	return nil
}

func (d *lifecycleTestDriver) Move(src, dest string) error {
	d.moves = append(d.moves, [2]string{src, dest})

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

	sized := func(size int64) driver.FileInfo {
		return &mocks.FileInfoMock{SizeFn: func() int64 { return size }}
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

	Convey("IsPlaceholder", t, func() {
		local, _ := newLifecycle(storageConstants.LocalStorageDriverName)
		remote, _ := newLifecycle(storageConstants.S3StorageDriverName)

		for _, testCase := range []struct {
			name      string
			lifecycle blobLifecycle
			digest    godigest.Digest
			size      int64
			expected  bool
		}{
			{"local, zero-byte copy of a non-empty digest", local, digest, 0, false},
			{"local, content copy", local, digest, 7, false},
			{"remote, zero-byte copy of a non-empty digest", remote, digest, 0, true},
			{"remote, zero-byte copy of the empty digest", remote, emptyDigest, 0, false},
			{"remote, content copy", remote, digest, 7, false},
		} {
			Convey(testCase.name, func() {
				So(testCase.lifecycle.IsPlaceholder(testCase.digest, sized(testCase.size)), ShouldEqual, testCase.expected)
			})
		}
	})

	Convey("Linking a blob onto itself does nothing, without calling the driver", t, func() {
		for _, name := range []string{storageConstants.LocalStorageDriverName, storageConstants.S3StorageDriverName} {
			// a nil-embedded driver panics on any call it does not implement, and Link records
			lifecycle, storeDriver := newLifecycle(name)
			So(lifecycle.LinkBlob("/repo/blobs/sha256/abc", "/repo/blobs/sha256/./abc"), ShouldBeNil)
			So(storeDriver.links, ShouldBeEmpty)
		}
	})

	Convey("Local storage", t, func() {
		lifecycle, storeDriver := newLifecycle(storageConstants.LocalStorageDriverName)

		Convey("links through the driver", func() {
			So(lifecycle.LinkBlob("/src", "/dst"), ShouldBeNil)
			So(storeDriver.links, ShouldResemble, [][2]string{{"/src", "/dst"}})
		})

		Convey("hands off content without touching the driver, since a hardlink holds it", func() {
			// statFn is nil and Move records, so any driver call would panic or show up
			So(lifecycle.HandOffContent("/origin", "/next"), ShouldBeNil)
			So(storeDriver.moves, ShouldBeEmpty)
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

		Convey("hands off content into a placeholder", func() {
			storeDriver.statFn = func(path string) (driver.FileInfo, error) {
				So(path, ShouldEqual, "/next")

				return sized(0), nil
			}

			So(lifecycle.HandOffContent("/origin", "/next"), ShouldBeNil)
			So(storeDriver.moves, ShouldResemble, [][2]string{{"/origin", "/next"}})
		})

		Convey("does not hand off content into a copy that already holds it", func() {
			storeDriver.statFn = func(string) (driver.FileInfo, error) { return sized(7), nil }

			So(lifecycle.HandOffContent("/origin", "/next"), ShouldBeNil)
			So(storeDriver.moves, ShouldBeEmpty)
		})

		Convey("fails a hand-off when the next copy cannot be stat'd", func() {
			storeDriver.statFn = func(string) (driver.FileInfo, error) {
				return nil, errclass.MarkTransient(errLifecycleTest)
			}

			So(errors.Is(lifecycle.HandOffContent("/origin", "/next"), zerr.ErrStorageTransient), ShouldBeTrue)
			So(storeDriver.moves, ShouldBeEmpty)
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
