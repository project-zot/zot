package repodb_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/test"
)

func TestSyncRepoDBWithStorage(t *testing.T) {
	Convey("Simple images", t, func() {
		rootDir := t.TempDir()
		repo := "repo"

		imageStore := local.NewImageStore(rootDir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		manifests := []ispec.Manifest{}
		for i := 0; i < 3; i++ {
			config, layers, manifest, err := test.GetRandomImageComponents(100)
			So(err, ShouldBeNil)

			manifests = append(manifests, manifest)

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

		// add fake signature for tag1
		signatureTag, err := test.GetCosignSignatureTagForManifest(manifests[1])
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifests[1])
		So(err, ShouldBeNil)

		signedManifestDigest := godigest.FromBytes(manifestBlob)

		config, layers, manifest, err := test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
				Tag:      signatureTag,
			},
			repo,
			storeController)
		So(err, ShouldBeNil)

		// remove tag2 from index.json
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

		for _, digest := range repos[0].Tags {
			manifestMeta, err := repoDB.GetManifestMeta(godigest.Digest(digest))
			So(err, ShouldBeNil)
			So(manifestMeta.ManifestBlob, ShouldNotBeNil)
			So(manifestMeta.ConfigBlob, ShouldNotBeNil)

			if digest == signedManifestDigest.String() {
				So(manifestMeta.Signatures, ShouldNotBeEmpty)
			}
		}
	})

	Convey("Ignore orphan signatures", t, func() {
		rootDir := t.TempDir()
		repo := "repo"

		imageStore := local.NewImageStore(rootDir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		config, layers, manifest, err := test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
				Tag:      "tag1",
			},
			repo,
			storeController)
		So(err, ShouldBeNil)

		// add mock cosign signature without pushing the signed image
		_, _, manifest, err = test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		signatureTag, err := test.GetCosignSignatureTagForManifest(manifest)
		So(err, ShouldBeNil)

		// get the body of the signature
		config, layers, manifest, err = test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
				Tag:      signatureTag,
			},
			repo,
			storeController)
		So(err, ShouldBeNil)

		// test that we have only 1 image inside the repo
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
		So(repos[0].Tags, ShouldContainKey, "tag1")
		So(repos[0].Tags, ShouldNotContainKey, signatureTag)
	})
}
