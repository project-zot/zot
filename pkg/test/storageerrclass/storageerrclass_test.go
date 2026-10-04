package storageerrclass_test

import (
	"errors"
	"io"
	"path"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	"zotregistry.dev/zot/v2/pkg/test/storageerrclass"
)

var errInjected = errors.New("injected storage failure")

func TestHookDriverReaderDeleteFaults(t *testing.T) {
	Convey("HookDriver Reader and Delete honor injected faults", t, func() {
		root := t.TempDir()
		base := local.New(false)
		So(base.EnsureDir(root), ShouldBeNil)

		filePath := path.Join(root, "blob")
		_, err := base.WriteFile(filePath, []byte("payload"))
		So(err, ShouldBeNil)

		hooks := &storageerrclass.HookDriver{Driver: base}

		Convey("OpReader fault returns the injected error", func() {
			hooks.AddFault(storageerrclass.Fault{
				Op: storageerrclass.OpReader, Path: filePath, Err: errclass.MarkTransient(errInjected), Times: 1,
			})

			_, err := hooks.Reader(filePath, 0)
			So(errors.Is(err, zerr.ErrStorageTransient), ShouldBeTrue)
			// After Times:1 the next Reader succeeds.
			rc, err := hooks.Reader(filePath, 0)
			So(err, ShouldBeNil)
			defer rc.Close()
			data, err := io.ReadAll(rc)
			So(err, ShouldBeNil)
			So(string(data), ShouldEqual, "payload")
		})

		Convey("OpDelete fault returns the injected error", func() {
			hooks.ClearFaults()
			hooks.AddFault(storageerrclass.Fault{
				Op: storageerrclass.OpDelete, Path: filePath, Err: errclass.MarkPermanent(errInjected), Times: 1,
			})

			err := hooks.Delete(filePath)
			So(errors.Is(err, zerr.ErrStoragePermanent), ShouldBeTrue)
			So(hooks.Delete(filePath), ShouldBeNil)
		})
	})
}
