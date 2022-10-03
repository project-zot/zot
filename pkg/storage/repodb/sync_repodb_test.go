package repodb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/storage/repodb"
	"zotregistry.io/zot/pkg/test"
)

func TestSyncRepoDBWithStorage(t *testing.T) {
	Convey("Simple images", t, func() {
		rootDir := t.TempDir()
		repo := "repo"

		imageStore := local.NewImageStore(rootDir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil)

		storeController := storage.StoreController{DefaultStore: imageStore}

		for i := 0; i < 3; i++ {
			config, layers, manifest, err := test.GetImageComponents(100)
			So(err, ShouldBeNil)

			err = test.WriteImageToFileSystem(
				test.Image{
					Config:   config,
					Layers:   layers,
					Manifest: manifest,
					Tag:      fmt.Sprintf("tag%d", i),
				},
				repo,
				storeController)
			So(err, ShouldBeNil)
		}

		// remove tag3 from index.json
		indexPath := path.Join(rootDir, repo, "index.json")
		indexFile, err := os.Open(indexPath)
		So(err, ShouldBeNil)
		buf, err := io.ReadAll(indexFile)
		So(err, ShouldBeNil)

		var index ispec.Index
		if err = json.Unmarshal(buf, &index); err == nil {
			for _, manifest := range index.Manifests {
				if val, ok := manifest.Annotations[ispec.AnnotationRefName]; ok && val == "tag2" {
					delete(manifest.Annotations, ispec.AnnotationRefName)

					break
				}
			}
		}
		buf, err = json.Marshal(index)
		So(err, ShouldBeNil)

		err = os.WriteFile(indexPath, buf, 0o600)
		So(err, ShouldBeNil)

		repoDB, err := repodb.NewBoltDBWrapper(repodb.BoltDBParameters{
			RootDir: rootDir,
		})
		So(err, ShouldBeNil)

		err = repodb.SyncRepoDB(repoDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repos, err := repoDB.GetMultipleRepoMeta(
			context.Background(),
			func(repoMeta repodb.RepoMetadata) bool { return true },
			repodb.PageInput{},
		)
		So(err, ShouldBeNil)

		So(len(repos), ShouldEqual, 1)
		So(len(repos[0].Tags), ShouldEqual, 2)
	})
}
