package gcs_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/gcs"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	tskip "zotregistry.dev/zot/v2/pkg/test/skip"
)

func ensureDummyGCSCreds(t *testing.T) {
	t.Helper()

	if os.Getenv("GCSMOCK_ENDPOINT") != "" && os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") == "" {
		credsFile := path.Join(t.TempDir(), "dummy_creds.json")

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}

		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}

		privPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privBytes,
		})

		content := fmt.Sprintf(`{"type": "service_account", "project_id": "test-project", `+
			`"client_email": "test@test.com", "private_key": %q}`, string(privPEM))
		err = os.WriteFile(credsFile, []byte(content), 0o600)
		if err != nil {
			t.Fatal(err)
		}

		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile)
	}
}

func cleanupStorage(store driver.StorageDriver, name string) {
	_ = store.Delete(context.Background(), name)
}

func createObjectsStore(rootDir string, cacheDir string, dedupe bool) (
	driver.StorageDriver,
	storageTypes.ImageStore,
	error,
) {
	bucket := "zot-storage-test"

	if endpoint := os.Getenv("GCSMOCK_ENDPOINT"); endpoint != "" {
		url := endpoint + "/storage/v1/b?project=test-project"
		body := fmt.Sprintf(`{"name": "%s"}`, bucket)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // G107: Test mock
		if err != nil {
			return nil, nil, err
		}
		resp.Body.Close()
	}

	storageDriverParams := map[string]any{
		"rootDir": rootDir,
		"name":    "gcs",
		"bucket":  bucket,
	}

	storeName := fmt.Sprintf("%v", storageDriverParams["name"])

	store, err := factory.Create(context.Background(), storeName, storageDriverParams)
	if err != nil {
		return nil, nil, err
	}

	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	var cacheDriver storageTypes.Cache

	// from pkg/cli/server/root.go/applyDefaultValues, s3 magic
	s3CacheDBPath := path.Join(cacheDir, storageConstants.BoltdbName+storageConstants.DBExtensionName)

	if _, err := os.Stat(s3CacheDBPath); dedupe || (!dedupe && err == nil) {
		cacheDriver, _ = storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     cacheDir,
			Name:        "cache",
			UseRelPaths: false,
		}, log)
	}

	il := gcs.NewImageStore(rootDir, cacheDir, dedupe, false, log, metrics, nil, store, cacheDriver, nil, nil)

	return store, il, nil
}

func TestGCSDriver(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	uuid, err := guuid.NewV4()
	if err != nil {
		panic(err)
	}

	testDir := path.Join("/oci-repo-test", uuid.String())

	Convey("GCS Driver E2E", t, func() {
		// Create a fresh temp dir for each run to avoid BoltDB lock issues
		tdir := t.TempDir()
		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)

		Convey("Init Repo", func() {
			repoName := "test-repo-init"
			err := imgStore.InitRepo(repoName)
			So(err, ShouldBeNil)

			isValid, err := imgStore.ValidateRepo(repoName)
			So(err, ShouldBeNil)
			So(isValid, ShouldBeTrue)
		})

		Convey("Push and Pull Image", func() {
			repoName := "test-repo-push"
			image := CreateDefaultImage()

			// Upload layers
			for _, content := range image.Layers {
				upload, err := imgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)

				buf := bytes.NewBuffer(content)
				buflen := buf.Len()
				digest := godigest.FromBytes(content)

				blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
				So(err, ShouldBeNil)
			}

			// Upload config
			cblob, err := json.Marshal(image.Config)
			So(err, ShouldBeNil)
			cdigest := godigest.FromBytes(cblob)
			_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewBuffer(cblob), cdigest)
			So(err, ShouldBeNil)

			// Upload manifest
			mblob, err := json.Marshal(image.Manifest)
			So(err, ShouldBeNil)
			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mblob)
			So(err, ShouldBeNil)

			// Verify manifest
			_, _, _, err = imgStore.GetImageManifest(repoName, "1.0")
			So(err, ShouldBeNil)

			// Verify blob
			blobReadCloser, _, err := imgStore.GetBlob(repoName, cdigest, ispec.MediaTypeImageConfig)
			So(err, ShouldBeNil)
			defer blobReadCloser.Close()
			content, err := io.ReadAll(blobReadCloser)
			So(err, ShouldBeNil)
			So(content, ShouldResemble, cblob)
		})

		Convey("Delete Image", func() {
			repoName := "test-repo-delete"
			// Setup image
			image := CreateDefaultImage()
			cblob, _ := json.Marshal(image.Config)
			cdigest := godigest.FromBytes(cblob)
			_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewBuffer(cblob), cdigest)
			So(err, ShouldBeNil)

			mblob, _ := json.Marshal(image.Manifest)
			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, mblob)
			So(err, ShouldBeNil)

			err = imgStore.DeleteImageManifest(repoName, "1.0", false)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, "1.0")
			So(err, ShouldNotBeNil)
			So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
		})
	})
}

func TestGCSDedupe(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	Convey("Dedupe", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)

		// manifest1
		upload, err := imgStore.NewBlobUpload("dedupe1")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("dedupe1", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest1 := digest
		So(blobDigest1, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		ok, checkBlobSize1, err := imgStore.CheckBlob("dedupe1", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		ok, checkBlobSize1, _, err = imgStore.StatBlob("dedupe1", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize1, err := imgStore.GetBlob("dedupe1", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize1, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("dedupe1", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err := imgStore.CheckBlob("dedupe1", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(buflen),
				},
			},
		}

		manifest.SchemaVersion = 2
		manifestBuf, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe1", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe1", manifestDigest.String())
		So(err, ShouldBeNil)

		// manifest2
		upload, err = imgStore.NewBlobUpload("dedupe2")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content = []byte("test-data3")
		buf = bytes.NewBuffer(content)
		buflen = buf.Len()
		digest = godigest.FromBytes(content)

		blob, err = imgStore.PutBlobChunkStreamed("dedupe2", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		blobDigest2 := digest
		So(blobDigest2, ShouldNotBeEmpty)

		err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		ok, checkBlobSize2, err := imgStore.CheckBlob("dedupe2", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		ok, checkBlobSize2, _, err = imgStore.StatBlob("dedupe2", digest)
		So(ok, ShouldBeTrue)
		So(checkBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)

		blobReadCloser, getBlobSize2, err := imgStore.GetBlob("dedupe2", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip")
		So(getBlobSize2, ShouldBeGreaterThan, 0)
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		cblob, cdigest = GetRandomImageConfig()
		_, clen, err = imgStore.FullBlobUpload("dedupe2", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		hasBlob, _, err = imgStore.CheckBlob("dedupe2", cdigest)
		So(err, ShouldBeNil)
		So(hasBlob, ShouldEqual, true)

		manifest = ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: "application/vnd.oci.image.config.v1+json",
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: "application/vnd.oci.image.layer.v1.tar",
					Digest:    digest,
					Size:      int64(buflen),
				},
			},
		}

		manifest.SchemaVersion = 2
		manifestBuf, err = json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest = godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest("dedupe2", manifestDigest.String(),
			ispec.MediaTypeImageManifest, manifestBuf)
		So(err, ShouldBeNil)

		_, _, _, err = imgStore.GetImageManifest("dedupe2", manifestDigest.String())
		So(err, ShouldBeNil)

		So(blobDigest1, ShouldEqual, blobDigest2)
		So(checkBlobSize1, ShouldEqual, checkBlobSize2)
		So(getBlobSize1, ShouldEqual, getBlobSize2)
	})
}

func TestGCSPullRange(t *testing.T) {
	tskip.SkipGCS(t)
	ensureDummyGCSCreds(t)

	Convey("Pull range", t, func(c C) {
		uuid, err := guuid.NewV4()
		if err != nil {
			panic(err)
		}

		testDir := path.Join("/oci-repo-test", uuid.String())

		tdir := t.TempDir()

		storeDriver, imgStore, err := createObjectsStore(testDir, tdir, true)
		So(err, ShouldBeNil)
		defer cleanupStorage(storeDriver, testDir)

		upload, err := imgStore.NewBlobUpload("test")
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		blob, err := imgStore.PutBlobChunkStreamed("test", upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		err = imgStore.FinishBlobUpload("test", upload, buf, digest)
		So(err, ShouldBeNil)

		blobReadCloser, _, err := imgStore.GetBlob("test", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		So(err, ShouldBeNil)
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 0, 4)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "test-")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", 4, 5)
		So(err, ShouldBeNil)
		buf.Reset()
		_, err = buf.ReadFrom(blobReadCloser)
		So(err, ShouldBeNil)
		So(buf.String(), ShouldEqual, "data3")
		err = blobReadCloser.Close()
		So(err, ShouldBeNil)

		// get range from negative offset
		blobReadCloser, _, _, err = imgStore.GetBlobPartial("test", digest,
			"application/vnd.oci.image.layer.v1.tar+gzip", -4, 4)
		So(err, ShouldNotBeNil)
		So(blobReadCloser, ShouldBeNil)
	})
}
