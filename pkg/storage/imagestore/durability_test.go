package imagestore_test

import (
	"context"
	"errors"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

var errDirSyncFailed = errors.New("directory sync failed") //nolint: gochecknoglobals

// notDurableMoveDriver performs the move and then reports it as a durability
// failure: the destination holds the requested bytes, but the directory entry
// the rename created was not fsynced.
type notDurableMoveDriver struct {
	storageTypes.Driver
}

func (d *notDurableMoveDriver) Move(sourcePath, destPath string) error {
	if err := d.Driver.Move(sourcePath, destPath); err != nil {
		return err
	}

	return errclass.Wrap(zerr.ErrStorageNotDurable, errDirSyncFailed)
}

// TestPutIndexContentNotDurable pins the interaction with writeFileViaStaging's
// read-back recovery: that recovery exists for copy-then-delete object stores,
// so it must not turn a rename whose directory sync failed into a success.
func TestPutIndexContentNotDurable(t *testing.T) {
	Convey("PutIndexContent reports a rename whose directory sync failed", t, func() {
		rootDir := t.TempDir()
		log := zlog.NewTestLogger()

		cacheDriver, err := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     rootDir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		So(err, ShouldBeNil)

		store := imagestore.NewImageStore(rootDir, rootDir, true, true, log,
			monitoring.NewNopMetricServer(), nil,
			&notDurableMoveDriver{Driver: local.New(true)}, cacheDriver, nil, nil)

		So(store.InitRepo(context.Background(), "repo"), ShouldBeNil)

		index := ispec.Index{
			SchemaVersion: 2,
			Manifests: []ispec.Descriptor{{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromString("manifest"),
				Size:      1,
			}},
		}

		err = store.PutIndexContent("repo", index)
		So(err, ShouldNotBeNil)
		So(errclass.IsStorageNotDurable(err), ShouldBeTrue)
	})
}
