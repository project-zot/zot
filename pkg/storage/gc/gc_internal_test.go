package gc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	artifactspec "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	. "github.com/smartystreets/goconvey/convey"

	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/cache"
	common "zotregistry.io/zot/pkg/storage/common"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

var (
	errGC    = errors.New("gc error")
	repoName = "test" //nolint: gochecknoglobals
)

func TestGarbageCollectManifestErrors(t *testing.T) {
	Convey("Make imagestore and upload manifest", t, func(c C) {
		dir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
			Referrers:      true,
			Delay:          storageConstants.DefaultGCDelay,
			RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
		}, log)

		Convey("trigger repo not found in addImageIndexBlobsToReferences()", func() {
			err := gc.addIndexBlobsToReferences(repoName, ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("miss"),
						MediaType: ispec.MediaTypeImageIndex,
					},
				},
			}, map[string]bool{})
			So(err, ShouldNotBeNil)
		})

		Convey("trigger repo not found in addImageManifestBlobsToReferences()", func() {
			err := gc.addIndexBlobsToReferences(repoName, ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("miss"),
						MediaType: ispec.MediaTypeImageManifest,
					},
				},
			}, map[string]bool{})
			So(err, ShouldNotBeNil)
		})

		Convey("trigger repo not found in addORASImageManifestBlobsToReferences()", func() {
			err := gc.addIndexBlobsToReferences(repoName, ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("miss"),
						MediaType: artifactspec.MediaTypeArtifactManifest,
					},
				},
			}, map[string]bool{})
			So(err, ShouldNotBeNil)
		})

		content := []byte("this is a blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		_, blen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		cblob, cdigest := test.GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		manifest := ispec.Manifest{
			Config: ispec.Descriptor{
				MediaType: ispec.MediaTypeImageConfig,
				Digest:    cdigest,
				Size:      int64(len(cblob)),
			},
			Layers: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageLayer,
					Digest:    digest,
					Size:      int64(len(content)),
				},
			},
		}

		manifest.SchemaVersion = 2

		body, err := json.Marshal(manifest)
		So(err, ShouldBeNil)

		manifestDigest := godigest.FromBytes(body)

		_, _, err = imgStore.PutImageManifest(repoName, "1.0", ispec.MediaTypeImageManifest, body)
		So(err, ShouldBeNil)

		Convey("trigger GetIndex error in GetReferencedBlobs", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(path.Join(imgStore.RootDir(), repoName), 0o755)
				So(err, ShouldBeNil)
			}()

			err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
			So(err, ShouldNotBeNil)
		})

		Convey("trigger GetImageManifest error in AddIndexBlobsToReferences", func() {
			index, err := common.GetIndex(imgStore, repoName, log)
			So(err, ShouldBeNil)

			err = os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", manifestDigest.Encoded()), 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", manifestDigest.Encoded()), 0o755)
				So(err, ShouldBeNil)
			}()

			err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
			So(err, ShouldNotBeNil)
		})
	})
}

func TestGarbageCollectIndexErrors(t *testing.T) {
	Convey("Make imagestore and upload manifest", t, func(c C) {
		dir := t.TempDir()

		log := log.Logger{Logger: zerolog.New(os.Stdout)}
		metrics := monitoring.NewMetricsServer(false, log)
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver)

		gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
			Referrers:      true,
			Delay:          storageConstants.DefaultGCDelay,
			RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
		}, log)

		content := []byte("this is a blob")
		bdgst := godigest.FromBytes(content)
		So(bdgst, ShouldNotBeNil)

		_, bsize, err := imgStore.FullBlobUpload(repoName, bytes.NewReader(content), bdgst)
		So(err, ShouldBeNil)
		So(bsize, ShouldEqual, len(content))

		var index ispec.Index
		index.SchemaVersion = 2
		index.MediaType = ispec.MediaTypeImageIndex

		var digest godigest.Digest
		for i := 0; i < 4; i++ {
			// upload image config blob
			upload, err := imgStore.NewBlobUpload(repoName)
			So(err, ShouldBeNil)
			So(upload, ShouldNotBeEmpty)

			cblob, cdigest := test.GetRandomImageConfig()
			buf := bytes.NewBuffer(cblob)
			buflen := buf.Len()
			blob, err := imgStore.PutBlobChunkStreamed(repoName, upload, buf)
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
						Digest:    bdgst,
						Size:      bsize,
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

		index, err = common.GetIndex(imgStore, repoName, log)
		So(err, ShouldBeNil)

		err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
		So(err, ShouldBeNil)

		Convey("trigger GetImageIndex error in GetReferencedBlobsInImageIndex", func() {
			err := os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", indexDigest.Encoded()), 0o000)
			So(err, ShouldBeNil)

			defer func() {
				err := os.Chmod(path.Join(imgStore.RootDir(), repoName, "blobs", "sha256", indexDigest.Encoded()), 0o755)
				So(err, ShouldBeNil)
			}()

			err = gc.addIndexBlobsToReferences(repoName, index, map[string]bool{})
			So(err, ShouldNotBeNil)
		})
	})
}

func TestGarbageCollectWithMockedImageStore(t *testing.T) {
	Convey("Cover gc error paths", t, func(c C) {
		log := log.Logger{Logger: zerolog.New(os.Stdout)}

		Convey("Error on PutIndexContent in gc.cleanRepo()", func() {
			returnedIndexJSON := ispec.Index{}

			returnedIndexJSONBuf, err := json.Marshal(returnedIndexJSON)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				PutIndexContentFn: func(repo string, index ispec.Index) error {
					return errGC
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexJSONBuf, nil
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
				Referrers:      true,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err = gc.cleanRepo(repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.cleanBlobs() in gc.cleanRepo()", func() {
			returnedIndexJSON := ispec.Index{}

			returnedIndexJSONBuf, err := json.Marshal(returnedIndexJSON)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				PutIndexContentFn: func(repo string, index ispec.Index) error {
					return nil
				},
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return returnedIndexJSONBuf, nil
				},
				GetAllBlobsFn: func(repo string) ([]string, error) {
					return []string{}, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
				Referrers:      true,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err = gc.cleanRepo(repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("False on imgStore.DirExists() in gc.cleanRepo()", func() {
			imgStore := mocks.MockedImageStore{
				DirExistsFn: func(d string) bool {
					return false
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
				Referrers:      true,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err := gc.cleanRepo(repoName)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.identifyManifestsReferencedInIndex in gc.cleanManifests() with multiarch image", func() {
			indexImageDigest := godigest.FromBytes([]byte("digest"))

			returnedIndexImage := ispec.Index{
				Subject: &ispec.DescriptorEmptyJSON,
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    godigest.FromBytes([]byte("digest2")),
					},
				},
			}

			returnedIndexImageBuf, err := json.Marshal(returnedIndexImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					if digest == indexImageDigest {
						return returnedIndexImageBuf, nil
					} else {
						return nil, errGC
					}
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
				Referrers:      false,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err = gc.cleanManifests(repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageIndex,
						Digest:    indexImageDigest,
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.identifyManifestsReferencedInIndex in gc.cleanManifests() with image", func() {
			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return nil, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
				Referrers:      false,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err := gc.cleanManifests(repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("digest")),
					},
				},
			})
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.gcManifest() in gc.cleanManifests() with image", func() {
			returnedImage := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
			}

			returnedImageBuf, err := json.Marshal(returnedImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedImageBuf, nil
				},
			}

			metaDB := mocks.MetaDBMock{
				RemoveRepoReferenceFn: func(repo, reference string, manifestDigest godigest.Digest) error {
					return errGC
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, Options{
				Referrers:      false,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err = gc.cleanManifests(repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    godigest.FromBytes([]byte("digest")),
					},
				},
			})
			So(err, ShouldNotBeNil)
		})
		Convey("Error on gc.gcManifest() in gc.cleanManifests() with signature", func() {
			returnedImage := ispec.Manifest{
				MediaType:    ispec.MediaTypeImageManifest,
				ArtifactType: zcommon.NotationSignature,
			}

			returnedImageBuf, err := json.Marshal(returnedImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedImageBuf, nil
				},
			}

			metaDB := mocks.MetaDBMock{
				DeleteSignatureFn: func(repo string, signedManifestDigest godigest.Digest, sm types.SignatureMetadata) error {
					return errGC
				},
			}

			gc := NewGarbageCollect(imgStore, metaDB, Options{
				Referrers:      false,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			desc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromBytes([]byte("digest")),
			}

			index := &ispec.Index{
				Manifests: []ispec.Descriptor{desc},
			}
			_, err = gc.removeManifest(repoName, index, desc, storage.NotationType,
				godigest.FromBytes([]byte("digest2")))

			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.gcReferrer() in gc.cleanManifests() with image index", func() {
			manifestDesc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    godigest.FromBytes([]byte("digest")),
			}

			returnedIndexImage := ispec.Index{
				MediaType: ispec.MediaTypeImageIndex,
				Subject: &ispec.Descriptor{
					Digest: godigest.FromBytes([]byte("digest2")),
				},
				Manifests: []ispec.Descriptor{
					manifestDesc,
				},
			}

			returnedIndexImageBuf, err := json.Marshal(returnedIndexImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedIndexImageBuf, nil
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
				Referrers:      true,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err = gc.cleanManifests(repoName, &returnedIndexImage)
			So(err, ShouldNotBeNil)
		})

		Convey("Error on gc.gcReferrer() in gc.cleanManifests() with image", func() {
			manifestDesc := ispec.Descriptor{
				MediaType: ispec.MediaTypeImageManifest,
				Digest:    godigest.FromBytes([]byte("digest")),
			}

			returnedImage := ispec.Manifest{
				Subject: &ispec.Descriptor{
					Digest: godigest.FromBytes([]byte("digest2")),
				},
				MediaType: ispec.MediaTypeImageManifest,
			}

			returnedImageBuf, err := json.Marshal(returnedImage)
			So(err, ShouldBeNil)

			imgStore := mocks.MockedImageStore{
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return returnedImageBuf, nil
				},
				StatBlobFn: func(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
					return false, -1, time.Time{}, errGC
				},
			}

			gc := NewGarbageCollect(imgStore, mocks.MetaDBMock{}, Options{
				Referrers:      true,
				Delay:          storageConstants.DefaultGCDelay,
				RetentionDelay: storageConstants.DefaultUntaggedImgeRetentionDelay,
			}, log)

			err = gc.cleanManifests(repoName, &ispec.Index{
				Manifests: []ispec.Descriptor{
					manifestDesc,
				},
			})
			So(err, ShouldNotBeNil)
		})
	})
}
