package local_test

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path"
	"strings"
	"syscall"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/config"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/scheduler"
	"zotregistry.dev/zot/pkg/storage"
	"zotregistry.dev/zot/pkg/storage/cache"
	storageConstants "zotregistry.dev/zot/pkg/storage/constants"
	"zotregistry.dev/zot/pkg/storage/gc"
	"zotregistry.dev/zot/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
	. "zotregistry.dev/zot/pkg/test/image-utils"
	"zotregistry.dev/zot/pkg/test/mocks"
	"zotregistry.dev/zot/pkg/test/signature"
)

const (
	tag      = "1.0"
	repoName = "test"
)

var trueVal bool = true //nolint: gochecknoglobals

var DeleteReferrers = config.ImageRetention{ //nolint: gochecknoglobals
	Delay: storageConstants.DefaultRetentionDelay,
	Policies: []config.RetentionPolicy{
		{
			Repositories:    []string{"**"},
			DeleteReferrers: true,
			DeleteUntagged:  &trueVal,
		},
	},
}

var errCache = errors.New("new cache error")

func runAndGetScheduler() *scheduler.Scheduler {
	log := zlog.Logger{}
	metrics := monitoring.NewMetricsServer(true, log)
	taskScheduler := scheduler.NewScheduler(config.New(), metrics, log)
	taskScheduler.RateLimit = 50 * time.Millisecond

	taskScheduler.RunScheduler()

	return taskScheduler
}

func TestStorageFSAPIs(t *testing.T) {
	dir := t.TempDir()

	log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)

	imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

	Convey("Repo layout", t, func(c C) {
		Convey("Bad image manifest", func() {
			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content := []byte("test-data1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			digest := godigest.FromBytes(content)

			blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
			So(err, ShouldBeNil)

			annotationsMap := make(map[string]string)
			annotationsMap[ispec.AnnotationRefName] = tag

			cblob, cdigest := GetRandomImageConfig()
			_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
			So(err, ShouldBeNil)
			So(clen, ShouldEqual, len(cblob))
			hasBlob, _, err := imgStore.CheckBlob(repoName, cdigest)
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
				Annotations: annotationsMap,
			}

			manifest.SchemaVersion = 2
			manifestBuf, err := json.Marshal(manifest)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(manifestBuf)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName, "index.json"), 0o000)
			if err != nil {
				panic(err)
			}

			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName, "index.json"), 0o755)
			if err != nil {
				panic(err)
			}

			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldBeNil)

			manifestPath := path.Join(imgStore.RootDir(), repoName, "blobs", digest.Algorithm().String(), digest.Encoded())

			err = os.Chmod(manifestPath, 0o000)
			if err != nil {
				panic(err)
			}

			_, _, _, err = imgStore.GetImageManifest(repoName, digest.String())
			So(err, ShouldNotBeNil)

			err = os.Remove(manifestPath)
			if err != nil {
				panic(err)
			}

			_, _, _, err = imgStore.GetImageManifest(repoName, digest.String())
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o000)
			if err != nil {
				panic(err)
			}

			_, _, err = imgStore.PutImageManifest(repoName, "2.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldNotBeNil)
			err = os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o755)
			if err != nil {
				panic(err)
			}

			// invalid DeleteImageManifest
			indexPath := path.Join(imgStore.RootDir(), repoName, "index.json")
			err = os.Chmod(indexPath, 0o000)
			if err != nil {
				panic(err)
			}

			err = imgStore.DeleteImageManifest(repoName, digest.String(), false)
			So(err, ShouldNotBeNil)

			err = os.RemoveAll(path.Join(imgStore.RootDir(), repoName))
			if err != nil {
				panic(err)
			}
		})
	})
}

func FuzzNewBlobUpload(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		defer os.RemoveAll(dir)
		t.Logf("Input argument is %s", data)
		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		_, err := imgStore.NewBlobUpload(data)
		if err != nil {
			if isKnownErr(err) {
				return
			}

			t.Error(err)
		}
	})
}

func FuzzPutBlobChunk(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		defer os.RemoveAll(dir)
		t.Logf("Input argument is %s", data)
		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}

		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		repoName := data
		uuid, err := imgStore.NewBlobUpload(repoName)
		if err != nil {
			if isKnownErr(err) {
				return
			}

			t.Error(err)
		}

		buf := bytes.NewBufferString(data)
		buflen := buf.Len()
		_, err = imgStore.PutBlobChunk(repoName, uuid, 0, int64(buflen), buf)
		if err != nil {
			t.Error(err)
		}
	})
}

func FuzzPutBlobChunkStreamed(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		defer os.RemoveAll(dir)
		t.Logf("Input argument is %s", data)
		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		repoName := data

		uuid, err := imgStore.NewBlobUpload(repoName)
		if err != nil {
			if isKnownErr(err) {
				return
			}

			t.Error(err)
		}

		buf := bytes.NewBufferString(data)
		_, err = imgStore.PutBlobChunkStreamed(repoName, uuid, buf)
		if err != nil {
			t.Error(err)
		}
	})
}

func FuzzGetBlobUpload(f *testing.F) {
	f.Fuzz(func(t *testing.T, data1 string, data2 string) {
		dir := t.TempDir()
		defer os.RemoveAll(dir)
		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil,
			cacheDriver)

		_, err := imgStore.GetBlobUpload(data1, data2)
		if err != nil {
			if errors.Is(err, zerr.ErrUploadNotFound) || isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzTestPutGetImageManifest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)

		cblob, cdigest := GetRandomImageConfig()

		ldigest, lblob, err := newRandomBlobForFuzz(data)
		if err != nil {
			t.Errorf("error occurred while generating random blob, %v", err)
		}

		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
		if err != nil {
			t.Error(err)
		}
		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(lblob), ldigest)
		if err != nil {
			t.Error(err)
		}

		manifest, err := NewRandomImgManifest(data, cdigest, ldigest, cblob, lblob)
		if err != nil {
			t.Error(err)
		}
		manifestBuf, err := json.Marshal(manifest)
		if err != nil {
			t.Errorf("Error %v occurred while marshaling manifest", err)
		}
		mdigest := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest(repoName, mdigest.String(), ispec.MediaTypeImageManifest, manifestBuf)
		if err != nil && errors.Is(err, zerr.ErrBadManifest) {
			t.Errorf("the error that occurred is %v \n", err)
		}
		_, _, _, err = imgStore.GetImageManifest(repoName, mdigest.String())
		if err != nil {
			t.Errorf("the error that occurred is %v \n", err)
		}
	})
}

func FuzzTestPutDeleteImageManifest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)

		cblob, cdigest := GetRandomImageConfig()

		ldigest, lblob, err := newRandomBlobForFuzz(data)
		if err != nil {
			t.Errorf("error occurred while generating random blob, %v", err)
		}

		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
		if err != nil {
			t.Error(err)
		}

		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(lblob), ldigest)
		if err != nil {
			t.Error(err)
		}

		manifest, err := NewRandomImgManifest(data, cdigest, ldigest, cblob, lblob)
		if err != nil {
			t.Error(err)
		}

		manifestBuf, err := json.Marshal(manifest)
		if err != nil {
			t.Errorf("Error %v occurred while marshaling manifest", err)
		}
		mdigest := godigest.FromBytes(manifestBuf)
		_, _, err = imgStore.PutImageManifest(repoName, mdigest.String(), ispec.MediaTypeImageManifest, manifestBuf)
		if err != nil && errors.Is(err, zerr.ErrBadManifest) {
			t.Errorf("the error that occurred is %v \n", err)
		}

		err = imgStore.DeleteImageManifest(repoName, mdigest.String(), false)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Errorf("the error that occurred is %v \n", err)
		}
	})
}

// no integration with PutImageManifest, just throw fuzz data.
func FuzzTestDeleteImageManifest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)

		digest, _, err := newRandomBlobForFuzz(data)
		if err != nil {
			return
		}
		err = imgStore.DeleteImageManifest(string(data), digest.String(), false)
		if err != nil {
			if errors.Is(err, zerr.ErrRepoNotFound) || isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzDirExists(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		_ = common.DirExists(data)
	})
}

func FuzzInitRepo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		err := imgStore.InitRepo(data)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzInitValidateRepo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		err := imgStore.InitRepo(data)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
		_, err = imgStore.ValidateRepo(data)
		if err != nil {
			if errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrRepoBadVersion) || isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzGetImageTags(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		_, err := imgStore.GetImageTags(data)
		if err != nil {
			if errors.Is(err, zerr.ErrRepoNotFound) || isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzBlobUploadPath(f *testing.F) {
	f.Fuzz(func(t *testing.T, repo, uuid string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)

		_ = imgStore.BlobUploadPath(repo, uuid)
	})
}

func FuzzBlobUploadInfo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string, uuid string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		repo := data

		_, err := imgStore.BlobUploadInfo(repo, uuid)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzTestGetImageManifest(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		defer os.RemoveAll(dir)

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		repoName := data

		digest := godigest.FromBytes([]byte(data))

		_, _, _, err := imgStore.GetImageManifest(repoName, digest.String())
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzFinishBlobUpload(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		dir := t.TempDir()
		defer os.RemoveAll(dir)

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		repoName := data

		upload, err := imgStore.NewBlobUpload(repoName)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}

		content := []byte(data)
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)

		_, err = imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}

		err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzFullBlobUpload(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := "test"

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)

		ldigest, lblob, err := newRandomBlobForFuzz(data)
		if err != nil {
			t.Errorf("error occurred while generating random blob, %v", err)
		}

		_, _, err = imgStore.FullBlobUpload(repoName, bytes.NewReader(lblob), ldigest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func TestStorageCacheErrors(t *testing.T) {
	Convey("get error in DedupeBlob() when cache.Put() deduped blob", t, func() {
		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		dir := t.TempDir()

		originRepo := "dedupe1"
		dedupedRepo := "dedupe2"

		cblob, cdigest := GetRandomImageConfig()

		getBlobPath := ""

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, &mocks.CacheMock{
			PutBlobFn: func(digest godigest.Digest, path string) error {
				if strings.Contains(path, dedupedRepo) {
					return errCache
				}

				return nil
			},
			GetBlobFn: func(digest godigest.Digest) (string, error) {
				return getBlobPath, nil
			},
		})

		err := imgStore.InitRepo(originRepo)
		So(err, ShouldBeNil)

		err = imgStore.InitRepo(dedupedRepo)
		So(err, ShouldBeNil)

		_, _, err = imgStore.FullBlobUpload(originRepo, bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)

		getBlobPath = imgStore.BlobPath(originRepo, cdigest)
		_, _, err = imgStore.FullBlobUpload(dedupedRepo, bytes.NewReader(cblob), cdigest)
		So(err, ShouldNotBeNil)
	})
}

func FuzzDedupeBlob(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)

		blobDigest := godigest.FromString(data)

		// replacement for .uploads folder, usually retrieved from BlobUploadPath
		src := path.Join(imgStore.RootDir(), "src")
		blob := bytes.NewReader([]byte(data))

		_, _, err := imgStore.FullBlobUpload("repoName", blob, blobDigest)
		if err != nil {
			t.Error(err)
		}

		dst := imgStore.BlobPath("repoName", blobDigest)

		err = os.MkdirAll(src, 0o755)
		if err != nil {
			t.Error(err)
		}

		err = imgStore.DedupeBlob(src, blobDigest, "repoName", dst)
		if err != nil {
			t.Error(err)
		}
	})
}

func FuzzDeleteBlobUpload(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := data

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)

		uuid, err := imgStore.NewBlobUpload(repoName)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}

		err = imgStore.DeleteBlobUpload(repoName, uuid)
		if err != nil {
			t.Error(err)
		}
	})
}

func FuzzBlobPath(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := data

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		digest := godigest.FromString(data)

		_ = imgStore.BlobPath(repoName, digest)
	})
}

func FuzzCheckBlob(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := data

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		digest := godigest.FromString(data)

		_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader([]byte(data)), digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
		_, _, err = imgStore.CheckBlob(repoName, digest)
		if err != nil {
			t.Error(err)
		}
	})
}

func FuzzGetBlob(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := data

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		digest := godigest.FromString(data)

		_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader([]byte(data)), digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}

		blobReadCloser, _, err := imgStore.GetBlob(repoName, digest, "application/vnd.oci.image.layer.v1.tar+gzip")
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
		if err = blobReadCloser.Close(); err != nil {
			t.Error(err)
		}
	})
}

func FuzzDeleteBlob(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := data

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		digest := godigest.FromString(data)

		_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader([]byte(data)), digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}

		err = imgStore.DeleteBlob(repoName, digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzGetIndexContent(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := data

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		digest := godigest.FromString(data)

		_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader([]byte(data)), digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}

		_, err = imgStore.GetIndexContent(repoName)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzGetBlobContent(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := &zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, *log)
		repoName := data

		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, *log)
		imgStore := local.NewImageStore(dir, true, true, *log, metrics, nil, cacheDriver)
		digest := godigest.FromString(data)

		_, _, err := imgStore.FullBlobUpload(repoName, bytes.NewReader([]byte(data)), digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}

		_, err = imgStore.GetBlobContent(repoName, digest)
		if err != nil {
			if isKnownErr(err) {
				return
			}
			t.Error(err)
		}
	})
}

func FuzzRunGCRepo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data string) {
		log := zlog.NewLogger("debug", "")
		audit := zlog.NewAuditLogger("debug", "")

		metrics := monitoring.NewMetricsServer(false, log)
		dir := t.TempDir()
		defer os.RemoveAll(dir)

		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
			Delay:          storageConstants.DefaultGCDelay,
			ImageRetention: DeleteReferrers,
		}, audit, log)

		if err := gc.CleanRepo(context.Background(), data); err != nil {
			t.Error(err)
		}
	})
}

func TestDedupeLinks(t *testing.T) {
	testCases := []struct {
		dedupe   bool
		expected bool
	}{
		{
			dedupe:   true,
			expected: true,
		},
		{
			dedupe:   false,
			expected: false,
		},
	}

	log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)

	for _, testCase := range testCases {
		Convey(fmt.Sprintf("Dedupe %t", testCase.dedupe), t, func(c C) {
			dir := t.TempDir()

			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)

			var imgStore storageTypes.ImageStore

			if testCase.dedupe {
				imgStore = local.NewImageStore(dir, testCase.dedupe, true, log, metrics, nil, cacheDriver)
			} else {
				imgStore = local.NewImageStore(dir, testCase.dedupe, true, log, metrics, nil, nil)
			}

			// run on empty image store
			// switch dedupe to true from false
			taskScheduler := runAndGetScheduler()
			defer taskScheduler.Shutdown()

			// rebuild with dedupe true
			imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
			// wait until rebuild finishes
			time.Sleep(1 * time.Second)

			taskScheduler.Shutdown()

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
			blobDigest1 := strings.Split(digest.String(), ":")[1]
			So(blobDigest1, ShouldNotBeEmpty)

			err = imgStore.FinishBlobUpload("dedupe1", upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			_, _, err = imgStore.CheckBlob("dedupe1", digest)
			So(err, ShouldBeNil)

			blobrc, _, err := imgStore.GetBlob("dedupe1", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)
			err = blobrc.Close()
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
			blobDigest2 := strings.Split(digest.String(), ":")[1]
			So(blobDigest2, ShouldNotBeEmpty)

			err = imgStore.FinishBlobUpload("dedupe2", upload, buf, digest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			_, _, err = imgStore.CheckBlob("dedupe2", digest)
			So(err, ShouldBeNil)

			blobrc, _, err = imgStore.GetBlob("dedupe2", digest, "application/vnd.oci.image.layer.v1.tar+gzip")
			So(err, ShouldBeNil)
			err = blobrc.Close()
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
			digest = godigest.FromBytes(manifestBuf)
			_, _, err = imgStore.PutImageManifest("dedupe2", "1.0", ispec.MediaTypeImageManifest, manifestBuf)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest("dedupe2", digest.String())
			So(err, ShouldBeNil)

			// verify that dedupe with hard links happened
			fi1, err := os.Stat(path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1))
			So(err, ShouldBeNil)
			fi2, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
			So(err, ShouldBeNil)
			So(os.SameFile(fi1, fi2), ShouldEqual, testCase.expected)

			if !testCase.dedupe {
				Convey("delete blobs from storage/cache should work when dedupe is false", func() {
					So(blobDigest1, ShouldEqual, blobDigest2)

					// to not trigger BlobInUse err, delete manifest first
					err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
					So(err, ShouldBeNil)

					err = imgStore.DeleteImageManifest("dedupe2", "1.0", false)
					So(err, ShouldBeNil)

					err = imgStore.DeleteBlob("dedupe1", godigest.NewDigestFromEncoded(godigest.SHA256, blobDigest1))
					So(err, ShouldBeNil)

					err = imgStore.DeleteBlob("dedupe2", godigest.NewDigestFromEncoded(godigest.SHA256, blobDigest2))
					So(err, ShouldBeNil)
				})

				Convey("test RunDedupeForDigest directly, trigger stat error on original blob", func() {
					// rebuild with dedupe true
					imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

					duplicateBlobs := []string{
						path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1),
						path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest2),
					}

					// remove original blob so that it can not be statted
					err := os.Remove(path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1))
					So(err, ShouldBeNil)

					err = imgStore.RunDedupeForDigest(context.TODO(), godigest.Digest(blobDigest1), true, duplicateBlobs)
					So(err, ShouldNotBeNil)
				})

				Convey("Intrerrupt rebuilding and restart, checking idempotency", func() {
					for i := 0; i < 10; i++ {
						taskScheduler := runAndGetScheduler()
						defer taskScheduler.Shutdown()

						// rebuild with dedupe true
						imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

						imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
						sleepValue := i * 5
						time.Sleep(time.Duration(sleepValue) * time.Millisecond)

						taskScheduler.Shutdown()
					}

					taskScheduler := runAndGetScheduler()
					defer taskScheduler.Shutdown()

					// rebuild with dedupe true
					imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
					imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)

					// wait until rebuild finishes
					time.Sleep(10 * time.Second)

					taskScheduler.Shutdown()

					fi1, err := os.Stat(path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1))
					So(err, ShouldBeNil)
					fi2, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
					So(err, ShouldBeNil)
					So(os.SameFile(fi1, fi2), ShouldEqual, true)
				})

				Convey("rebuild dedupe index error cache nil", func() {
					// switch dedupe to true from false
					taskScheduler := runAndGetScheduler()
					defer taskScheduler.Shutdown()

					imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, nil)

					// rebuild with dedupe true
					imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
					// wait until rebuild finishes

					time.Sleep(3 * time.Second)

					taskScheduler.Shutdown()

					fi1, err := os.Stat(path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1))
					So(err, ShouldBeNil)
					fi2, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
					So(err, ShouldBeNil)

					So(os.SameFile(fi1, fi2), ShouldEqual, false)
				})

				Convey("rebuild dedupe index cache error on original blob", func() {
					// switch dedupe to true from false
					taskScheduler := runAndGetScheduler()
					defer taskScheduler.Shutdown()

					imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, &mocks.CacheMock{
						HasBlobFn: func(digest godigest.Digest, path string) bool {
							return false
						},
						PutBlobFn: func(digest godigest.Digest, path string) error {
							return errCache
						},
					})
					// rebuild with dedupe true, should have samefile blobs
					imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
					// wait until rebuild finishes

					time.Sleep(10 * time.Second)

					taskScheduler.Shutdown()

					fi1, err := os.Stat(path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1))
					So(err, ShouldBeNil)
					fi2, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
					So(err, ShouldBeNil)

					So(os.SameFile(fi1, fi2), ShouldEqual, false)
				})

				Convey("rebuild dedupe index cache error on duplicate blob", func() {
					// switch dedupe to true from false
					taskScheduler := runAndGetScheduler()
					defer taskScheduler.Shutdown()

					imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, &mocks.CacheMock{
						HasBlobFn: func(digest godigest.Digest, path string) bool {
							return false
						},
						PutBlobFn: func(digest godigest.Digest, path string) error {
							if strings.Contains(path, "dedupe2") {
								return errCache
							}

							return nil
						},
					})
					// rebuild with dedupe true, should have samefile blobs
					imgStore.RunDedupeBlobs(time.Duration(0), taskScheduler)
					// wait until rebuild finishes

					time.Sleep(15 * time.Second)

					taskScheduler.Shutdown()

					fi1, err := os.Stat(path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1))
					So(err, ShouldBeNil)
					fi2, err := os.Stat(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
					So(err, ShouldBeNil)

					So(os.SameFile(fi1, fi2), ShouldEqual, true)
				})
			}

			Convey("delete blobs from storage/cache should work when dedupe is true", func() {
				So(blobDigest1, ShouldEqual, blobDigest2)

				// to not trigger BlobInUse err, delete manifest first
				err = imgStore.DeleteImageManifest("dedupe1", manifestDigest.String(), false)
				So(err, ShouldBeNil)

				err = imgStore.DeleteImageManifest("dedupe2", "1.0", false)
				So(err, ShouldBeNil)

				err = imgStore.DeleteBlob("dedupe1", godigest.NewDigestFromEncoded(godigest.SHA256, blobDigest1))
				So(err, ShouldBeNil)

				err = imgStore.DeleteBlob("dedupe2", godigest.NewDigestFromEncoded(godigest.SHA256, blobDigest2))
				So(err, ShouldBeNil)
			})

			Convey("storage and cache inconsistency", func() {
				// delete blobs
				err = os.Remove(path.Join(dir, "dedupe1", "blobs", "sha256", blobDigest1))
				So(err, ShouldBeNil)

				err := os.Remove(path.Join(dir, "dedupe2", "blobs", "sha256", blobDigest2))
				So(err, ShouldBeNil)

				// now cache is inconsistent with storage (blobs present in cache but not in storage)
				upload, err = imgStore.NewBlobUpload("dedupe3")
				So(err, ShouldBeNil)
				So(upload, ShouldNotBeEmpty)

				content = []byte("test-data3")
				buf = bytes.NewBuffer(content)
				buflen = buf.Len()
				digest = godigest.FromBytes(content)
				blob, err = imgStore.PutBlobChunkStreamed("dedupe3", upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)
				blobDigest2 := strings.Split(digest.String(), ":")[1]
				So(blobDigest2, ShouldNotBeEmpty)

				err = imgStore.FinishBlobUpload("dedupe3", upload, buf, digest)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)
			})
		})
	}
}

func TestDedupe(t *testing.T) {
	Convey("Dedupe", t, func(c C) {
		Convey("Nil ImageStore", func() {
			var is storageTypes.ImageStore
			So(func() { _ = is.DedupeBlob("", "", "", "") }, ShouldPanic)
		})

		Convey("Valid ImageStore", func() {
			dir := t.TempDir()

			log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
			metrics := monitoring.NewMetricsServer(false, log)
			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)

			il := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

			So(il.DedupeBlob("", "", "", ""), ShouldNotBeNil)
		})
	})
}

//nolint:gocyclo
func TestNegativeCases(t *testing.T) {
	Convey("Invalid root dir", t, func(c C) {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		So(local.NewImageStore(dir, true,
			true, log, metrics, nil, cacheDriver), ShouldNotBeNil)
		if os.Geteuid() != 0 {
			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     "/deadBEEF",
				Name:        "cache",
				UseRelPaths: true,
			}, log)
			So(local.NewImageStore("/deadBEEF", true, true, log, metrics, nil, cacheDriver), ShouldBeNil)
		}
	})

	Convey("Invalid init repo", t, func(c C) {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		err := os.Chmod(dir, 0o000) // remove all perms
		if err != nil {
			panic(err)
		}

		if os.Geteuid() != 0 {
			err = imgStore.InitRepo("test")
			So(err, ShouldNotBeNil)
		}

		err = os.Chmod(dir, 0o755)
		if err != nil {
			panic(err)
		}

		// Init repo should fail if repo is a file.
		err = os.WriteFile(path.Join(dir, "file-test"), []byte("this is test file"), 0o755) //nolint:gosec
		So(err, ShouldBeNil)
		err = imgStore.InitRepo("file-test")
		So(err, ShouldNotBeNil)

		err = os.Mkdir(path.Join(dir, "test-dir"), 0o755)
		So(err, ShouldBeNil)

		err = imgStore.InitRepo("test-dir")
		So(err, ShouldBeNil)

		// Init repo should fail if repo is invalid UTF-8
		err = imgStore.InitRepo("hi \255")
		So(err, ShouldNotBeNil)

		// Init repo should fail if repo name does not match spec
		err = imgStore.InitRepo("_trivy")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)
	})

	Convey("Invalid validate repo", t, func(c C) {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)

		err := os.MkdirAll(path.Join(dir, "invalid-test"), 0o755)
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "invalid-test"), 0o000) // remove all perms
		if err != nil {
			panic(err)
		}
		_, err = imgStore.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrRepoNotFound)

		err = os.Chmod(path.Join(dir, "invalid-test"), 0o755) // remove all perms
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(dir, "invalid-test", "blobs"), []byte{}, 0o755) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(dir, "invalid-test", "index.json"), []byte{}, 0o755) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte{}, 0o755) //nolint: gosec
		if err != nil {
			panic(err)
		}

		isValid, err := imgStore.ValidateRepo("invalid-test")
		So(err, ShouldBeNil)
		So(isValid, ShouldEqual, false)

		err = os.Remove(path.Join(dir, "invalid-test", "blobs"))
		if err != nil {
			panic(err)
		}
		err = os.Mkdir(path.Join(dir, "invalid-test", "blobs"), 0o755)
		if err != nil {
			panic(err)
		}
		isValid, err = imgStore.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(isValid, ShouldEqual, false)

		err = os.WriteFile(path.Join(dir, "invalid-test", ispec.ImageLayoutFile), []byte("{}"), 0o755) //nolint: gosec
		if err != nil {
			panic(err)
		}

		isValid, err = imgStore.ValidateRepo("invalid-test")
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrRepoBadVersion)
		So(isValid, ShouldEqual, false)

		files, err := os.ReadDir(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		for _, f := range files {
			os.Remove(path.Join(dir, "test", f.Name()))
		}

		_, err = imgStore.ValidateRepo("test")
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		_, err = imgStore.ValidateRepo("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o000) // remove all perms
		if err != nil {
			panic(err)
		}

		_, err = imgStore.GetRepositories()
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o755) // add perms
		if err != nil {
			panic(err)
		}

		err = os.RemoveAll(dir)
		if err != nil {
			panic(err)
		}
	})

	Convey("Invalid get image tags", t, func(c C) {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)
		So(os.Remove(path.Join(dir, "test", "index.json")), ShouldBeNil)
		_, err := imgStore.GetImageTags("test")
		So(err, ShouldNotBeNil)
		So(os.RemoveAll(path.Join(dir, "test")), ShouldBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)
		So(os.WriteFile(path.Join(dir, "test", "index.json"), []byte{}, 0o600), ShouldBeNil)
		_, err = imgStore.GetImageTags("test")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid get image manifest", t, func(c C) {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)

		err := os.Chmod(path.Join(dir, "test", "index.json"), 0o000)
		if err != nil {
			panic(err)
		}

		_, _, _, err = imgStore.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		err = os.Remove(path.Join(dir, "test", "index.json"))
		if err != nil {
			panic(err)
		}

		_, _, _, err = imgStore.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)

		err = os.RemoveAll(path.Join(dir, "test"))
		if err != nil {
			panic(err)
		}

		So(imgStore.InitRepo("test"), ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "test", "index.json"), []byte{}, 0o600)
		if err != nil {
			panic(err)
		}
		_, _, _, err = imgStore.GetImageManifest("test", "")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid new blob upload", t, func(c C) {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		So(imgStore, ShouldNotBeNil)
		So(imgStore.InitRepo("test"), ShouldBeNil)

		err := os.Chmod(path.Join(dir, "test", ".uploads"), 0o000)
		if err != nil {
			panic(err)
		}
		_, err = imgStore.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test"), 0o000)
		if err != nil {
			panic(err)
		}

		_, err = imgStore.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test"), 0o755)
		if err != nil {
			panic(err)
		}

		So(imgStore.InitRepo("test"), ShouldBeNil)

		_, err = imgStore.NewBlobUpload("test")
		So(err, ShouldNotBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0o755)
		if err != nil {
			panic(err)
		}

		upload, err := imgStore.NewBlobUpload("test")
		So(err, ShouldBeNil)

		err = os.Chmod(path.Join(dir, "test", ".uploads"), 0o000)
		if err != nil {
			panic(err)
		}
		t.Cleanup(func() {
			err = os.Chmod(path.Join(dir, "test", ".uploads"), 0o700)
			if err != nil {
				panic(err)
			}
		})

		content := []byte("test-data3")
		buf := bytes.NewBuffer(content)
		l := buf.Len()
		_, err = imgStore.PutBlobChunkStreamed("test", upload, buf)
		So(err, ShouldNotBeNil)

		_, err = imgStore.PutBlobChunk("test", upload, 0, int64(l), buf)
		So(err, ShouldNotBeNil)
	})

	Convey("DirExists call with a filename as argument", t, func(c C) {
		dir := t.TempDir()

		filePath := path.Join(dir, "file.txt")
		err := os.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		ok := common.DirExists(filePath)
		So(ok, ShouldBeFalse)
	})

	Convey("DirExists call with invalid UTF-8 as argument", t, func(c C) {
		dir := t.TempDir()

		filePath := path.Join(dir, "hi \255")
		ok := common.DirExists(filePath)
		So(ok, ShouldBeFalse)
	})

	Convey("DirExists call with name too long as argument", t, func(c C) {
		var builder strings.Builder
		for i := 0; i < 1025; i++ {
			_, err := builder.WriteString("0")
			if err != nil {
				t.Fatal(err)
			}
		}
		path := builder.String()
		ok := common.DirExists(path)
		So(ok, ShouldBeFalse)
	})
}

func TestHardLink(t *testing.T) {
	Convey("Test that ValidateHardLink creates rootDir if it does not exist", t, func() {
		var randomDir string

		for {
			nBig, err := rand.Int(rand.Reader, big.NewInt(100))
			if err != nil {
				panic(err)
			}
			randomDir = "/tmp/" + randSeq(int(nBig.Int64()))

			if _, err := os.Stat(randomDir); os.IsNotExist(err) {
				break
			}
		}
		defer os.RemoveAll(randomDir)

		err := local.ValidateHardLink(randomDir)
		So(err, ShouldBeNil)
	})
	Convey("Test that ValidateHardLink returns error if rootDir is a file", t, func() {
		dir := t.TempDir()

		filePath := path.Join(dir, "file.txt")
		err := os.WriteFile(filePath, []byte("some dummy file content"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = local.ValidateHardLink(filePath)
		So(err, ShouldNotBeNil)
	})
	Convey("Test if filesystem supports hardlink", t, func() {
		dir := t.TempDir()

		err := local.ValidateHardLink(dir)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "hardtest.txt"), []byte("testing hard link code"), 0o644) //nolint: gosec
		if err != nil {
			panic(err)
		}

		err = os.Chmod(dir, 0o400)
		if err != nil {
			panic(err)
		}
		// Allow hardtest.txt to be cleaned up by t.TempDir()
		t.Cleanup(func() {
			err = os.Chmod(dir, 0o700)
			if err != nil {
				t.Fatal(err)
			}
		})

		err = os.Link(path.Join(dir, "hardtest.txt"), path.Join(dir, "duphardtest.txt"))
		So(err, ShouldNotBeNil)

		err = os.Chmod(dir, 0o644)
		if err != nil {
			panic(err)
		}
	})
}

func TestInjectWriteFile(t *testing.T) {
	Convey("writeFile without commit", t, func() {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, false, log, metrics, nil, cacheDriver)

		Convey("Failure path not reached", func() {
			err := imgStore.InitRepo("repo1")
			So(err, ShouldBeNil)
		})
	})
}

func TestGarbageCollectForImageStore(t *testing.T) {
	//nolint: contextcheck
	Convey("Garbage collect for a specific repo from an ImageStore", t, func(c C) {
		dir := t.TempDir()

		ctx := context.Background()

		Convey("Garbage collect error for repo with config removed", func() {
			logFile, _ := os.CreateTemp("", "zot-log*.txt")

			defer os.Remove(logFile.Name()) // clean up

			log := zlog.NewLogger("debug", logFile.Name())
			audit := zlog.NewAuditLogger("debug", "")

			metrics := monitoring.NewMetricsServer(false, log)
			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)

			imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
			repoName := "gc-all-repos-short"

			gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
				Delay:          1 * time.Second,
				ImageRetention: DeleteReferrers,
			}, audit, log)

			image := CreateDefaultVulnerableImage()
			err := WriteImageToFileSystem(image, repoName, "0.0.1", storage.StoreController{
				DefaultStore: imgStore,
			})
			So(err, ShouldBeNil)

			manifestDigest := image.ManifestDescriptor.Digest
			err = os.Remove(path.Join(dir, repoName, "blobs/sha256", manifestDigest.Encoded()))
			if err != nil {
				panic(err)
			}

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)

			time.Sleep(500 * time.Millisecond)

			data, err := os.ReadFile(logFile.Name())
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring,
				fmt.Sprintf("failed to run GC for %s", path.Join(imgStore.RootDir(), repoName)))
		})

		Convey("Garbage collect error - not enough permissions to access index.json", func() {
			logFile, _ := os.CreateTemp("", "zot-log*.txt")

			defer os.Remove(logFile.Name()) // clean up

			log := zlog.NewLogger("debug", logFile.Name())
			audit := zlog.NewAuditLogger("debug", "")

			metrics := monitoring.NewMetricsServer(false, log)
			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)

			imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
			repoName := "gc-all-repos-short"

			gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
				Delay:          1 * time.Second,
				ImageRetention: DeleteReferrers,
			}, audit, log)

			image := CreateDefaultVulnerableImage()
			err := WriteImageToFileSystem(image, repoName, "0.0.1", storage.StoreController{
				DefaultStore: imgStore,
			})
			So(err, ShouldBeNil)

			So(os.Chmod(path.Join(dir, repoName, "index.json"), 0o000), ShouldBeNil)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)

			time.Sleep(500 * time.Millisecond)

			data, err := os.ReadFile(logFile.Name())
			So(err, ShouldBeNil)
			So(string(data), ShouldContainSubstring,
				fmt.Sprintf("failed to run GC for %s", path.Join(imgStore.RootDir(), repoName)))
			So(os.Chmod(path.Join(dir, repoName, "index.json"), 0o755), ShouldBeNil)
		})

		Convey("Garbage collect - the manifest which the reference points to can be found", func() {
			logFile, _ := os.CreateTemp("", "zot-log*.txt")

			defer os.Remove(logFile.Name()) // clean up

			log := zlog.NewLogger("debug", logFile.Name())
			audit := zlog.NewAuditLogger("debug", "")

			metrics := monitoring.NewMetricsServer(false, log)
			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)
			imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
			repoName := "gc-sig"

			gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
				Delay:          1 * time.Second,
				ImageRetention: DeleteReferrers,
			}, audit, log)

			storeController := storage.StoreController{DefaultStore: imgStore}
			img := CreateRandomImage()

			err := WriteImageToFileSystem(img, repoName, "tag1", storeController)
			So(err, ShouldBeNil)

			// add fake signature for tag1
			cosignTag, err := signature.GetCosignSignatureTagForManifest(img.Manifest)
			So(err, ShouldBeNil)

			cosignSig := CreateRandomImage()
			So(err, ShouldBeNil)

			err = WriteImageToFileSystem(cosignSig, repoName, cosignTag, storeController)
			So(err, ShouldBeNil)

			// add sbom
			manifestBlob, err := json.Marshal(img.Manifest)
			So(err, ShouldBeNil)

			manifestDigest := godigest.FromBytes(manifestBlob)
			sbomTag := fmt.Sprintf("sha256-%s.%s", manifestDigest.Encoded(), "sbom")
			So(err, ShouldBeNil)

			sbomImg := CreateRandomImage()
			So(err, ShouldBeNil)

			err = WriteImageToFileSystem(sbomImg, repoName, sbomTag, storeController)
			So(err, ShouldBeNil)

			// add fake signature for tag1
			notationSig := CreateImageWith().
				RandomLayers(1, 10).
				ArtifactConfig("application/vnd.cncf.notary.signature").
				Subject(img.DescriptorRef()).Build()

			err = WriteImageToFileSystem(notationSig, repoName, "notation", storeController)
			So(err, ShouldBeNil)

			// add fake signature for tag1
			cosignWithReferrersSig := CreateImageWith().
				RandomLayers(1, 10).
				ArtifactConfig(common.ArtifactTypeCosign).
				Subject(img.DescriptorRef()).Build()

			err = WriteImageToFileSystem(cosignWithReferrersSig, repoName, "cosign", storeController)
			So(err, ShouldBeNil)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)
		})
	})
}

func TestGarbageCollectImageUnknownManifest(t *testing.T) {
	Convey("Garbage collect with short delay", t, func() {
		ctx := context.Background()

		dir := t.TempDir()

		log := zlog.NewLogger("debug", "")
		audit := zlog.NewAuditLogger("debug", "")

		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		storeController := storage.StoreController{
			DefaultStore: imgStore,
		}

		gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
			Delay:          1 * time.Second,
			ImageRetention: DeleteReferrers,
		}, audit, log)

		unsupportedMediaType := "application/vnd.oci.artifact.manifest.v1+json"

		img := CreateRandomImage()

		err := WriteImageToFileSystem(img, repoName, "v1", storeController)
		So(err, ShouldBeNil)

		// add image with unsupported media type
		artifact := CreateRandomImage()

		err = WriteImageToFileSystem(artifact, repoName, "artifact", storeController)
		So(err, ShouldBeNil)

		// add referrer with unsupported media type
		subjectDesc := img.Descriptor()
		referrer := CreateRandomImageWith().Subject(&subjectDesc).Build()

		err = WriteImageToFileSystem(referrer, repoName, referrer.Digest().String(), storeController)
		So(err, ShouldBeNil)

		// modify artifact media type
		artifactBuf, err := os.ReadFile(imgStore.BlobPath(repoName, artifact.Digest()))
		So(err, ShouldBeNil)

		var artifactManifest ispec.Manifest
		err = json.Unmarshal(artifactBuf, &artifactManifest)
		So(err, ShouldBeNil)

		artifactManifest.MediaType = unsupportedMediaType
		artifactBuf, err = json.Marshal(artifactManifest)
		So(err, ShouldBeNil)

		artifactDigest := godigest.FromBytes(artifactBuf)
		err = os.WriteFile(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", artifactDigest.Encoded()),
			artifactBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		// modify referrer media type
		referrerBuf, err := os.ReadFile(imgStore.BlobPath(repoName, referrer.Digest()))
		So(err, ShouldBeNil)

		var referrerManifest ispec.Manifest
		err = json.Unmarshal(referrerBuf, &referrerManifest)
		So(err, ShouldBeNil)

		referrerManifest.MediaType = unsupportedMediaType
		referrerBuf, err = json.Marshal(referrerManifest)
		So(err, ShouldBeNil)

		referrerDigest := godigest.FromBytes(referrerBuf)
		err = os.WriteFile(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", referrerDigest.Encoded()),
			referrerBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		indexJSONBuf, err := os.ReadFile(path.Join(imgStore.RootDir(), repoName, "index.json"))
		So(err, ShouldBeNil)

		var indexJSON ispec.Index
		err = json.Unmarshal(indexJSONBuf, &indexJSON)
		So(err, ShouldBeNil)

		for idx, desc := range indexJSON.Manifests {
			if desc.Digest == artifact.Digest() {
				indexJSON.Manifests[idx].Digest = artifactDigest
				indexJSON.Manifests[idx].MediaType = unsupportedMediaType
			} else if desc.Digest == referrer.Digest() {
				indexJSON.Manifests[idx].Digest = referrerDigest
				indexJSON.Manifests[idx].MediaType = unsupportedMediaType
			}
		}

		indexJSONBuf, err = json.Marshal(indexJSON)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(imgStore.RootDir(), repoName, "index.json"),
			indexJSONBuf, storageConstants.DefaultFilePerms)
		So(err, ShouldBeNil)

		// sleep so orphan blob can be GC'ed
		time.Sleep(1 * time.Second)

		Convey("Garbage collect blobs referenced by manifest with unsupported media type", func() {
			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, img.DigestStr())
			So(err, ShouldBeNil)

			hasBlob, _, err := imgStore.CheckBlob(repoName, img.ConfigDescriptor.Digest)
			So(err, ShouldBeNil)
			So(hasBlob, ShouldEqual, true)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, referrerDigest.String())
			So(err, ShouldNotBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, artifactDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, referrerDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, artifact.ConfigDescriptor.Digest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, referrer.ConfigDescriptor.Digest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)
		})

		Convey("Garbage collect - gc repo after manifest delete", func() {
			err = imgStore.DeleteImageManifest(repoName, img.DigestStr(), true)
			So(err, ShouldBeNil)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, img.DigestStr())
			So(err, ShouldNotBeNil)

			hasBlob, _, err := imgStore.CheckBlob(repoName, img.ConfigDescriptor.Digest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			_, _, _, err = imgStore.GetImageManifest(repoName, artifactDigest.String())
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetImageManifest(repoName, referrerDigest.String())
			So(err, ShouldNotBeNil)

			hasBlob, _, err = imgStore.CheckBlob(repoName, artifactDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, referrerDigest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, artifact.ConfigDescriptor.Digest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)

			hasBlob, _, err = imgStore.CheckBlob(repoName, referrer.ConfigDescriptor.Digest)
			So(err, ShouldNotBeNil)
			So(hasBlob, ShouldEqual, false)
		})
	})
}

func TestGarbageCollectErrors(t *testing.T) {
	Convey("Make image store", t, func(c C) {
		ctx := context.Background()

		dir := t.TempDir()

		log := zlog.NewLogger("debug", "")
		audit := zlog.NewAuditLogger("debug", "")

		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
		repoName := "gc-index"

		gc := gc.NewGarbageCollect(imgStore, mocks.MetaDBMock{}, gc.Options{
			Delay:          500 * time.Millisecond,
			ImageRetention: DeleteReferrers,
		}, audit, log)

		// create a blob/layer
		upload, err := imgStore.NewBlobUpload(repoName)
		So(err, ShouldBeNil)
		So(upload, ShouldNotBeEmpty)

		content := []byte("this is a blob1")
		buf := bytes.NewBuffer(content)
		buflen := buf.Len()
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)
		blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)
		bdgst1 := digest
		bsize1 := len(content)

		err = imgStore.FinishBlobUpload(repoName, upload, buf, digest)
		So(err, ShouldBeNil)
		So(blob, ShouldEqual, buflen)

		Convey("Trigger error on GetImageIndex", func() {
			var index ispec.Index
			index.SchemaVersion = 2
			index.MediaType = ispec.MediaTypeImageIndex

			for i := 0; i < 4; i++ {
				// upload image config blob
				upload, err = imgStore.NewBlobUpload(repoName)
				So(err, ShouldBeNil)
				So(upload, ShouldNotBeEmpty)

				cblob, cdigest := GetRandomImageConfig()
				buf = bytes.NewBuffer(cblob)
				buflen = buf.Len()
				blob, err = imgStore.PutBlobChunkStreamed(repoName, upload, buf)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
				So(err, ShouldBeNil)
				So(blob, ShouldEqual, buflen)

				// create a manifest
				manifest := ispec.Manifest{
					Config: ispec.Descriptor{
						MediaType: ispec.MediaTypeImageConfig,
						Digest:    cdigest,
						Size:      int64(len(cblob)),
					},
					Layers: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageLayer,
							Digest:    bdgst1,
							Size:      int64(bsize1),
						},
					},
				}
				manifest.SchemaVersion = 2
				content, err = json.Marshal(manifest)
				So(err, ShouldBeNil)
				digest = godigest.FromBytes(content)
				So(digest, ShouldNotBeNil)
				_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
				So(err, ShouldBeNil)

				index.Manifests = append(index.Manifests, ispec.Descriptor{
					Digest:    digest,
					MediaType: ispec.MediaTypeImageManifest,
					Size:      int64(len(content)),
				})
			}

			// upload index image
			indexContent, err := json.Marshal(index)
			So(err, ShouldBeNil)
			indexDigest := godigest.FromBytes(indexContent)
			So(indexDigest, ShouldNotBeNil)

			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageIndex, indexContent)
			So(err, ShouldBeNil)

			err = os.Chmod(imgStore.BlobPath(repoName, indexDigest), 0o000)
			So(err, ShouldBeNil)

			time.Sleep(500 * time.Millisecond)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger error on GetBlobContent and Unmarshal for untagged manifest", func() {
			// upload image config blob
			upload, err = imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed(repoName, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    bdgst1,
						Size:      int64(bsize1),
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			// trigger GetBlobContent error
			err = os.Remove(imgStore.BlobPath(repoName, digest))
			So(err, ShouldBeNil)

			time.Sleep(500 * time.Millisecond)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)

			// trigger Unmarshal error
			_, err = os.Create(imgStore.BlobPath(repoName, digest))
			So(err, ShouldBeNil)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger manifest conflict error", func() {
			// upload image config blob
			upload, err = imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := GetRandomImageConfig()
			buf = bytes.NewBuffer(cblob)
			buflen = buf.Len()
			blob, err = imgStore.PutBlobChunkStreamed(repoName, upload, buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, cdigest)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			// create a manifest
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayer,
						Digest:    bdgst1,
						Size:      int64(bsize1),
					},
				},
			}
			manifest.SchemaVersion = 2
			content, err = json.Marshal(manifest)
			So(err, ShouldBeNil)
			digest = godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			_, _, err = imgStore.PutImageManifest(repoName, digest.String(), ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)
			// upload again same manifest so that we trigger manifest conflict
			_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, content)
			So(err, ShouldBeNil)

			time.Sleep(500 * time.Millisecond)

			err = gc.CleanRepo(ctx, repoName)
			So(err, ShouldBeNil)

			// blob shouldn't be gc'ed //TODO check this one
			found, _, err := imgStore.CheckBlob(repoName, digest)
			So(err, ShouldBeNil)
			So(found, ShouldEqual, true)
		})
	})
}

func randSeq(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	buf := make([]rune, n)
	for index := range buf {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}

		buf[index] = letters[int(nBig.Int64())]
	}

	return string(buf)
}

func TestInitRepo(t *testing.T) {
	Convey("Get error when creating BlobUploadDir subdir on initRepo", t, func() {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		err := os.Mkdir(path.Join(dir, "test-dir"), 0o000)
		So(err, ShouldBeNil)

		err = imgStore.InitRepo("test-dir")
		So(err, ShouldNotBeNil)
	})
}

func TestValidateRepo(t *testing.T) {
	Convey("Get error when unable to read directory", t, func() {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		err := os.Mkdir(path.Join(dir, "test-dir"), 0o000)
		So(err, ShouldBeNil)

		_, err = imgStore.ValidateRepo("test-dir")
		So(err, ShouldNotBeNil)
	})

	Convey("Get error when repo name is not compliant with repo spec", t, func() {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		_, err := imgStore.ValidateRepo(".")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

		_, err = imgStore.ValidateRepo("..")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

		err = os.Mkdir(path.Join(dir, "_test-dir"), 0o755)
		So(err, ShouldBeNil)

		_, err = imgStore.ValidateRepo("_test-dir")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

		err = os.Mkdir(path.Join(dir, ".test-dir"), 0o755)
		So(err, ShouldBeNil)

		_, err = imgStore.ValidateRepo(".test-dir")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)

		err = os.Mkdir(path.Join(dir, "-test-dir"), 0o755)
		So(err, ShouldBeNil)

		_, err = imgStore.ValidateRepo("-test-dir")
		So(err, ShouldNotBeNil)
		So(errors.Is(err, zerr.ErrInvalidRepositoryName), ShouldBeTrue)
	})
}

func TestGetRepositories(t *testing.T) {
	Convey("Verify errors and repos returned by GetRepositories()", t, func() {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		// Create valid directory with permissions
		err := os.Mkdir(path.Join(dir, "test-dir"), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "test-dir/test-file"), []byte("this is test file"), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		// Folder is not a repo as it is missing the requires files/subfolder
		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(len(repos), ShouldEqual, 0)

		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}
		layoutFileContent, err := json.Marshal(il)
		So(err, ShouldBeNil)

		// Folder becomes a repo after the missing content is added
		err = os.Mkdir(path.Join(dir, "test-dir", "blobs"), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.Mkdir(path.Join(dir, "test-dir", storageConstants.BlobUploadDir), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "test-dir", "index.json"), []byte{}, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "test-dir", ispec.ImageLayoutFile), layoutFileContent, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		// Verify the new repo is turned
		repos, err = imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(len(repos), ShouldEqual, 1)
		So(repos[0], ShouldEqual, "test-dir")

		// create directory starting with underscore, which is not OCI a dist spec compliant repo name
		// [a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*
		err = os.MkdirAll(path.Join(dir, "_trivy", "db"), 0o755)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "_trivy", "db", "trivy.db"), []byte("this is test file"), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		// Folder with invalid name is not a repo as it is missing the requires files/subfolder
		repos, err = imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(len(repos), ShouldEqual, 1)
		So(repos[0], ShouldEqual, "test-dir")

		// Add missing content to folder with invalid name
		err = os.Mkdir(path.Join(dir, "_trivy", "blobs"), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.Mkdir(path.Join(dir, "_trivy", storageConstants.BlobUploadDir), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "_trivy", "index.json"), []byte{}, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "_trivy", ispec.ImageLayoutFile), layoutFileContent, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		// Folder with invalid name doesn't become a repo after the missing content is added
		repos, err = imgStore.GetRepositories()
		So(err, ShouldBeNil)
		t.Logf("repos %v", repos)
		So(len(repos), ShouldEqual, 1)
		So(repos[0], ShouldEqual, "test-dir")

		// Rename folder with invalid name to a valid one
		err = os.Rename(path.Join(dir, "_trivy"), path.Join(dir, "test-dir-2"))
		So(err, ShouldBeNil)

		// Verify both repos are now visible
		repos, err = imgStore.GetRepositories()
		So(err, ShouldBeNil)
		t.Logf("repos %v", repos)
		So(len(repos), ShouldEqual, 2)
		So(repos, ShouldContain, "test-dir")
		So(repos, ShouldContain, "test-dir-2")
	})

	Convey("Verify GetRepositories() doesn't return '.' when having an oci layout as root directory ", t, func() {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		// Root dir does not contain repos
		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(len(repos), ShouldEqual, 0)

		// Configure root directory as an oci layout
		err = os.Mkdir(path.Join(dir, "blobs"), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.Mkdir(path.Join(dir, storageConstants.BlobUploadDir), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "index.json"), []byte{}, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}
		layoutFileContent, err := json.Marshal(il)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, ispec.ImageLayoutFile), layoutFileContent, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		// Verify root directory is not returned as a repo
		repos, err = imgStore.GetRepositories()
		So(err, ShouldBeNil)
		t.Logf("repos %v", repos)
		So(len(repos), ShouldEqual, 0)
	})

	Convey("Verify GetRepositories() doesn't return '..'", t, func() {
		dir := t.TempDir()

		rootDir := path.Join(dir, "rootDir")
		err := os.Mkdir(rootDir, 0o755)
		So(err, ShouldBeNil)

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     rootDir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(rootDir,
			true, true, log, metrics, nil, cacheDriver,
		)

		// Root dir does not contain repos
		repos, err := imgStore.GetRepositories()
		So(err, ShouldBeNil)
		So(len(repos), ShouldEqual, 0)

		// Configure parent of root directory as an oci layout
		err = os.Mkdir(path.Join(dir, "blobs"), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.Mkdir(path.Join(dir, storageConstants.BlobUploadDir), 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, "index.json"), []byte{}, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}
		layoutFileContent, err := json.Marshal(il)
		So(err, ShouldBeNil)

		err = os.WriteFile(path.Join(dir, ispec.ImageLayoutFile), layoutFileContent, 0o755) //nolint: gosec
		So(err, ShouldBeNil)

		// Verify root directory is not returned as a repo
		repos, err = imgStore.GetRepositories()
		So(err, ShouldBeNil)
		t.Logf("repos %v", repos)
		So(len(repos), ShouldEqual, 0)
	})
}

func TestGetNextRepository(t *testing.T) {
	dir := t.TempDir()
	log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)

	imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
	firstRepoName := "repo1"
	secondRepoName := "repo2"

	srcStorageCtlr := storage.StoreController{DefaultStore: imgStore}
	image := CreateDefaultImage()

	err := WriteImageToFileSystem(image, firstRepoName, "0.0.1", srcStorageCtlr)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	err = WriteImageToFileSystem(image, secondRepoName, "0.0.1", srcStorageCtlr)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	Convey("Return first repository", t, func() {
		firstRepo, err := imgStore.GetNextRepository("")
		So(firstRepo, ShouldEqual, firstRepoName)
		So(err, ShouldBeNil)
	})

	Convey("Return second repository", t, func() {
		secondRepo, err := imgStore.GetNextRepository(firstRepoName)
		So(secondRepo, ShouldEqual, secondRepoName)
		So(err, ShouldBeNil)
	})

	Convey("Return error", t, func() {
		err := os.Chmod(imgStore.RootDir(), 0o000)
		So(err, ShouldBeNil)
		_, err = imgStore.GetNextRepository(firstRepoName)
		So(err, ShouldNotBeNil)
		err = os.Chmod(imgStore.RootDir(), 0o755)
		So(err, ShouldBeNil)
	})
}

func TestPutBlobChunkStreamed(t *testing.T) {
	Convey("Get error on opening file", t, func() {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		uuid, err := imgStore.NewBlobUpload("test")
		So(err, ShouldBeNil)

		var reader io.Reader
		blobPath := imgStore.BlobUploadPath("test", uuid)
		err = os.Chmod(blobPath, 0o000)
		So(err, ShouldBeNil)

		_, err = imgStore.PutBlobChunkStreamed("test", uuid, reader)
		So(err, ShouldNotBeNil)
	})
}

func TestPullRange(t *testing.T) {
	Convey("Repo layout", t, func(c C) {
		dir := t.TempDir()

		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)

		Convey("Negative cases", func() {
			cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
				RootDir:     dir,
				Name:        "cache",
				UseRelPaths: true,
			}, log)

			imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)
			repoName := "pull-range"

			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			content := []byte("test-data1")
			buf := bytes.NewBuffer(content)
			buflen := buf.Len()
			bdigest := godigest.FromBytes(content)

			blob, err := imgStore.PutBlobChunk(repoName, upload, 0, int64(buflen), buf)
			So(err, ShouldBeNil)
			So(blob, ShouldEqual, buflen)

			err = imgStore.FinishBlobUpload(repoName, upload, buf, bdigest)
			So(err, ShouldBeNil)

			_, _, _, err = imgStore.GetBlobPartial(repoName, "", "application/octet-stream", 0, 1)
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetBlobPartial(repoName, bdigest, "application/octet-stream", 1, 0)
			So(err, ShouldNotBeNil)

			_, _, _, err = imgStore.GetBlobPartial(repoName, bdigest, "application/octet-stream", 1, 0)
			So(err, ShouldNotBeNil)

			blobPath := path.Join(imgStore.RootDir(), repoName, "blobs", bdigest.Algorithm().String(), bdigest.Encoded())
			err = os.Chmod(blobPath, 0o000)
			So(err, ShouldBeNil)
			_, _, _, err = imgStore.GetBlobPartial(repoName, bdigest, "application/octet-stream", -1, 1)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestStatIndex(t *testing.T) {
	Convey("NewImageStore", t, func() {
		dir := t.TempDir()
		log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, nil)

		err := WriteImageToFileSystem(CreateRandomImage(), "repo", "tag",
			storage.StoreController{DefaultStore: imgStore})
		So(err, ShouldBeNil)

		Convey("StatIndex PathNotFoundError", func() {
			_, _, _, err := imgStore.StatIndex("not-found")
			So(err, ShouldNotBeNil)
		})
	})
}

func TestStorageDriverErr(t *testing.T) {
	dir := t.TempDir()

	log := zlog.Logger{Logger: zerolog.New(os.Stdout)}
	metrics := monitoring.NewMetricsServer(false, log)
	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     dir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)

	imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

	Convey("Init repo", t, func() {
		err := imgStore.InitRepo(repoName)
		So(err, ShouldBeNil)

		Convey("New blob upload error", func() {
			err := os.Chmod(path.Join(imgStore.RootDir(), repoName, storageConstants.BlobUploadDir), 0o000)
			So(err, ShouldBeNil)

			_, err = imgStore.NewBlobUpload(repoName)
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName, storageConstants.BlobUploadDir),
				storageConstants.DefaultDirPerms)
			So(err, ShouldBeNil)

			uuid, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)

			size, err := imgStore.GetBlobUpload(repoName, uuid)
			So(err, ShouldBeNil)
			So(size, ShouldEqual, 0)

			content := []byte("test-blob")
			buf := bytes.NewBuffer(content)
			bufLen := buf.Len()
			digest := godigest.FromBytes(content)

			size, err = imgStore.PutBlobChunkStreamed(repoName, uuid, buf)
			So(err, ShouldBeNil)
			So(size, ShouldEqual, bufLen)

			size, err = imgStore.GetBlobUpload(repoName, uuid)
			So(err, ShouldBeNil)
			So(size, ShouldEqual, bufLen)

			err = imgStore.DeleteBlobUpload(repoName, uuid)
			So(err, ShouldBeNil)

			err = imgStore.DeleteBlobUpload(repoName, uuid)
			So(err, ShouldNotBeNil)

			_, err = imgStore.GetBlobUpload(repoName, uuid)
			So(err, ShouldNotBeNil)

			// push again
			buf = bytes.NewBuffer(content)

			uuid, err = imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)

			size, err = imgStore.PutBlobChunkStreamed(repoName, uuid, buf)
			So(err, ShouldBeNil)
			So(size, ShouldEqual, bufLen)

			// finish blob upload
			err = os.Chmod(path.Join(imgStore.BlobUploadPath(repoName, uuid)), 0o000)
			So(err, ShouldBeNil)

			err = imgStore.FinishBlobUpload(repoName, uuid, &io.LimitedReader{}, digest)
			So(err, ShouldNotBeNil)

			err = os.Chmod(path.Join(imgStore.BlobUploadPath(repoName, uuid)), storageConstants.DefaultFilePerms)
			So(err, ShouldBeNil)

			err = imgStore.FinishBlobUpload(repoName, uuid, &io.LimitedReader{}, digest)
			So(err, ShouldBeNil)

			err = imgStore.FinishBlobUpload(repoName, uuid, &io.LimitedReader{}, digest)
			So(err, ShouldNotBeNil)

			// delete blob
			err = imgStore.DeleteBlob(repoName, digest)
			So(err, ShouldBeNil)

			err = imgStore.DeleteBlob(repoName, digest)
			So(err, ShouldNotBeNil)
		})
	})
}

func NewRandomImgManifest(data []byte, cdigest, ldigest godigest.Digest, cblob, lblob []byte) (*ispec.Manifest, error) {
	annotationsMap := make(map[string]string)

	key := string(data)
	val := string(data)
	annotationsMap[key] = val

	schemaVersion := 2

	manifest := ispec.Manifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Config: ispec.Descriptor{
			MediaType: "application/vnd.oci.image.config.v1+json",
			Digest:    cdigest,
			Size:      int64(len(cblob)),
		},
		Layers: []ispec.Descriptor{
			{
				MediaType: "application/vnd.oci.image.layer.v1.tar",
				Digest:    ldigest,
				Size:      int64(len(lblob)),
			},
		},
		Annotations: annotationsMap,
		Versioned: imeta.Versioned{
			SchemaVersion: schemaVersion,
		},
	}

	return &manifest, nil
}

func newRandomBlobForFuzz(data []byte) (godigest.Digest, []byte, error) { //nolint:unparam
	return godigest.FromBytes(data), data, nil
}

func isKnownErr(err error) bool {
	if errors.Is(err, zerr.ErrInvalidRepositoryName) || errors.Is(err, zerr.ErrManifestNotFound) ||
		errors.Is(err, zerr.ErrRepoNotFound) ||
		errors.Is(err, zerr.ErrBadManifest) {
		return true
	}

	if err, ok := err.(*fs.PathError); ok && errors.Is(err.Err, syscall.EACCES) || //nolint: errorlint
		errors.Is(err.Err, syscall.ENAMETOOLONG) ||
		errors.Is(err.Err, syscall.EINVAL) ||
		errors.Is(err.Err, syscall.ENOENT) {
		return true
	}

	return false
}
