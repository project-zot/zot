package update_test

import (
	"encoding/json"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	bolt_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	repoDBUpdate "zotregistry.io/zot/pkg/meta/repodb/update"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
)

func TestOnUpdateManifest(t *testing.T) {
	Convey("On UpdateManifest", t, func() {
		rootDir := t.TempDir()
		storeController := storage.StoreController{}
		log := log.NewLogger("debug", "")
		metrics := monitoring.NewMetricsServer(false, log)
		storeController.DefaultStore = local.NewImageStore(rootDir, true, 1*time.Second,
			true, true, log, metrics, nil, nil,
		)

		repoDB, err := bolt_wrapper.NewBoltDBWrapper(bolt_wrapper.DBParameters{
			RootDir: rootDir,
		})
		So(err, ShouldBeNil)

		config, layers, manifest, err := test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(test.Image{Config: config, Manifest: manifest, Layers: layers, Tag: "tag1"},
			"repo", storeController)
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		digest := godigest.FromBytes(manifestBlob)

		err = repoDBUpdate.OnUpdateManifest("repo", "tag1", digest, manifestBlob, storeController, repoDB, log)
		So(err, ShouldBeNil)

		repoMeta, err := repoDB.GetRepoMeta("repo")
		So(err, ShouldBeNil)

		So(repoMeta.Tags, ShouldContainKey, "tag1")
	})
}
