package azure_test

// GC integration parity with S3/GCS's TestGCSGarbageCollectImageManifest. Doesn't
// replicate the full artifact/subject/orphan-artifact retention matrix those cover
// (generic retention-policy logic, backend-agnostic, already covered there and in
// mock-driver-based gc tests) - what's worth confirming end-to-end against real Azure
// specifically is that gc.CleanRepo's WithBlobstoreAndRepoLock pass (see gc.go's
// cleanRepo) actually reclaims an orphan blob and leaves a referenced one alone
// against a real backend, not just a mock.

import (
	"bytes"
	"context"
	"encoding/json"
	"path"
	"testing"
	"time"

	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage/gc"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

//nolint:gochecknoglobals
var azureGCTrueVal = true

func TestAzureGarbageCollectImageManifest(t *testing.T) {
	tskip.SkipAzure(t)

	testLog := log.NewTestLogger()
	audit := log.NewAuditLogger("debug", "")
	metrics := monitoring.NewMetricsServer(false, testLog)
	defer metrics.Stop()

	ctx := context.Background()

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())
	tdir := t.TempDir()

	storeDriver, imgStore, err := createAzureObjectsStore(testDir, tdir, true)
	if err != nil {
		panic(err)
	}

	defer cleanupAzureStorage(storeDriver, testDir)

	const repoName = "test"

	const tag = "0.0.1"

	Convey("Garbage collect with short delay", t, func() {
		gcDelay := 1 * time.Second

		garbageCollect := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
			Delay: gcDelay,
			ImageRetention: config.ImageRetention{
				Delay: gcDelay,
				Policies: []config.RetentionPolicy{
					{
						Repositories:    []string{"**"},
						DeleteReferrers: true,
						DeleteUntagged:  &azureGCTrueVal,
					},
				},
			},
		}, audit, testLog, metrics)

		// orphan blob: never referenced by any manifest
		orphanContent := []byte("azure-gc-orphan")
		orphanDigest := godigest.FromBytes(orphanContent)
		_, _, err := imgStore.FullBlobUpload(context.Background(), repoName, bytes.NewReader(orphanContent), orphanDigest)
		So(err, ShouldBeNil)

		// sleep past the delay so the orphan blob is eligible for GC
		time.Sleep(gcDelay)

		layerContent := []byte("azure-gc-referenced-layer")
		layerDigest := godigest.FromBytes(layerContent)
		_, _, err = imgStore.FullBlobUpload(context.Background(), repoName, bytes.NewReader(layerContent), layerDigest)
		So(err, ShouldBeNil)

		configContent := []byte("{}")
		configDigest := godigest.FromBytes(configContent)
		_, _, err = imgStore.FullBlobUpload(context.Background(), repoName, bytes.NewReader(configContent), configDigest)
		So(err, ShouldBeNil)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    configDigest,
				Size:      int64(len(configContent)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    layerDigest,
					Size:      int64(len(layerContent)),
				},
			},
		}
		manifest.SchemaVersion = 2

		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest, _, err := imgStore.PutImageManifest(context.Background(), repoName, tag,
			ispec.MediaTypeImageManifest, manifestBuf, nil)
		So(err, ShouldBeNil)

		err = garbageCollect.CleanRepo(ctx, repoName)
		So(err, ShouldBeNil)

		hasBlob, _, err := imgStore.CheckBlob(context.Background(), repoName, orphanDigest)
		So(err, ShouldNotBeNil)
		So(hasBlob, ShouldBeFalse)

		hasBlob, _, err = imgStore.CheckBlob(context.Background(), repoName, layerDigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldBeTrue)

		Convey("Blob becomes eligible for GC once its manifest is removed", func() {
			err := imgStore.DeleteImageManifest(context.Background(), repoName, manifestDigest.String(), false)
			So(err, ShouldBeNil)

			time.Sleep(gcDelay)

			err = garbageCollect.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			hasBlob, _, err := imgStore.CheckBlob(context.Background(), repoName, layerDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldBeFalse)
		})
	})
}
