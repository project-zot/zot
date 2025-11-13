package storage_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/storage"
	"zotregistry.dev/zot/v2/pkg/storage/cache"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/imagestore"
	"zotregistry.dev/zot/v2/pkg/storage/local"
	. "zotregistry.dev/zot/v2/pkg/test/image-utils"
	"zotregistry.dev/zot/v2/pkg/test/mocks"
)

var ErrTestError = errors.New("TestError")

func TestValidateManifest(t *testing.T) {
	Convey("Make manifest", t, func(c C) {
		dir := t.TempDir()

		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)
		imgStore := local.NewImageStore(dir, true, true, log, metrics, nil, cacheDriver, nil, nil)

		content := []byte("this is a blob")
		digest := godigest.FromBytes(content)
		So(digest, ShouldNotBeNil)

		_, blen, err := imgStore.FullBlobUpload("test", bytes.NewReader(content), digest)
		So(err, ShouldBeNil)
		So(blen, ShouldEqual, len(content))

		cblob, cdigest := GetRandomImageConfig()
		_, clen, err := imgStore.FullBlobUpload("test", bytes.NewReader(cblob), cdigest)
		So(err, ShouldBeNil)
		So(clen, ShouldEqual, len(cblob))

		Convey("bad manifest mediatype", func() {
			manifest := ispec.Manifest{}

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageConfig, body)
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrBadManifest)
		})

		Convey("empty manifest with bad media type", func() {
			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageConfig, []byte(""))
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrBadManifest)
		})

		Convey("empty manifest with correct media type", func() {
			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, []byte(""))
			So(err, ShouldNotBeNil)
			So(err, ShouldEqual, zerr.ErrBadManifest)
		})

		Convey("bad manifest schema version", func() {
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

			manifest.SchemaVersion = 999

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldNotBeNil)

			var internalErr *zerr.Error

			So(errors.As(err, &internalErr), ShouldBeTrue)
			So(internalErr.GetDetails(), ShouldContainKey, "jsonSchemaValidation")
			So(internalErr.GetDetails()["jsonSchemaValidation"], ShouldContainSubstring, "must be <= 2 but found 999")
		})

		Convey("bad config blob", func() {
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

			configBlobPath := imgStore.BlobPath("test", cdigest)

			err := os.WriteFile(configBlobPath, []byte("bad config blob"), 0o000)
			So(err, ShouldBeNil)

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			// this was actually an umoci error on config blob
			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldBeNil)
		})

		Convey("manifest with non-distributable layers", func() {
			content := []byte("this blob doesn't exist")
			digest := godigest.FromBytes(content)
			So(digest, ShouldNotBeNil)

			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageLayerNonDistributable, //nolint:staticcheck
						Digest:    digest,
						Size:      int64(len(content)),
					},
				},
			}

			manifest.SchemaVersion = 2

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldBeNil)
		})

		Convey("manifest with empty layers should not error", func() {
			manifest := ispec.Manifest{
				Config: ispec.Descriptor{
					MediaType: ispec.MediaTypeImageConfig,
					Digest:    cdigest,
					Size:      int64(len(cblob)),
				},
				Layers: []ispec.Descriptor{},
			}

			manifest.SchemaVersion = 2

			body, err := json.Marshal(manifest)
			So(err, ShouldBeNil)

			_, _, err = imgStore.PutImageManifest("test", "1.0", ispec.MediaTypeImageManifest, body)
			So(err, ShouldBeNil)
		})
	})
}

func TestGetReferrersErrors(t *testing.T) {
	Convey("make storage", t, func(c C) {
		dir := t.TempDir()

		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, false, true, log, metrics, nil, cacheDriver, nil, nil)

		artifactType := "application/vnd.example.icecream.v1"
		validDigest := godigest.FromBytes([]byte("blob"))

		Convey("Trigger invalid digest error", func(c C) {
			_, err := common.GetReferrers(imgStore, "zot-test", "invalidDigest",
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger repo not found error", func(c C) {
			_, err := common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		storageCtlr := storage.StoreController{DefaultStore: imgStore}
		err := WriteImageToFileSystem(CreateDefaultImage(), "zot-test", "0.0.1", storageCtlr)
		So(err, ShouldBeNil)

		digest := godigest.FromBytes([]byte("{}"))

		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: "application/vnd.example.invalid.v1",
					Digest:    digest,
				},
			},
		}

		indexBuf, err := json.Marshal(index)
		So(err, ShouldBeNil)

		Convey("Trigger GetBlobContent() not found", func(c C) {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, zerr.ErrBlobNotFound
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger GetBlobContent() generic error", func(c C) {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, zerr.ErrBadBlob
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger unmarshal error on manifest image mediaType", func(c C) {
			index = ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
					},
				},
			}

			indexBuf, err = json.Marshal(index)
			So(err, ShouldBeNil)

			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, nil
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Trigger nil subject", func(c C) {
			index = ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						MediaType: ispec.MediaTypeImageManifest,
						Digest:    digest,
					},
				},
			}

			indexBuf, err = json.Marshal(index)
			So(err, ShouldBeNil)

			ociManifest := ispec.Manifest{
				Subject: nil,
			}

			ociManifestBuf, err := json.Marshal(ociManifest)
			So(err, ShouldBeNil)

			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return indexBuf, nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return ociManifestBuf, nil
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{artifactType}, log)
			So(err, ShouldBeNil)
		})

		Convey("Index bad blob", func() {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte(`{
						"manifests": [{
							"digest": "digest",
							"mediaType": "application/vnd.oci.image.index.v1+json"
						}]
					}`), nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte("bad blob"), nil
				},
			}

			_, err = common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{}, log)
			So(err, ShouldNotBeNil)
		})

		Convey("Index bad artifac type", func() {
			imgStore = &mocks.MockedImageStore{
				GetIndexContentFn: func(repo string) ([]byte, error) {
					return []byte(`{
						"manifests": [{
							"digest": "digest",
							"mediaType": "application/vnd.oci.image.index.v1+json"
						}]
					}`), nil
				},
				GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte(`{ 
						"subject": {"digest": "` + validDigest.String() + `"}
						}`), nil
				},
			}

			ref, err := common.GetReferrers(imgStore, "zot-test", validDigest,
				[]string{"art.type"}, log)
			So(err, ShouldBeNil)
			So(len(ref.Manifests), ShouldEqual, 0)
		})
	})
}

func TestGetReferrersDeduplication(t *testing.T) {
	Convey("Test GetReferrers deduplication", t, func(c C) {
		dir := t.TempDir()

		log := log.NewTestLogger()
		metrics := monitoring.NewMetricsServer(false, log)

		defer metrics.Stop() // Clean up metrics server to prevent resource leaks
		cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
			RootDir:     dir,
			Name:        "cache",
			UseRelPaths: true,
		}, log)

		imgStore := local.NewImageStore(dir, false, true, log, metrics, nil, cacheDriver, nil, nil)
		storageCtlr := storage.StoreController{DefaultStore: imgStore}

		// Create subject image
		subjectImage := CreateDefaultImage()
		err := WriteImageToFileSystem(subjectImage, "test-repo", "subject-tag", storageCtlr)
		So(err, ShouldBeNil)

		subjectDigest := subjectImage.Digest()

		// Create referrer image using builder pattern
		referrerImage := CreateImageWith().
			DefaultLayers().
			DefaultConfig().
			Subject(subjectImage.DescriptorRef()).
			Annotations(map[string]string{
				"test": "referrer",
			}).
			Build()

		// Write referrer image to filesystem (this will add it to index once)
		err = WriteImageToFileSystem(referrerImage, "test-repo", referrerImage.DigestStr(), storageCtlr)
		So(err, ShouldBeNil)

		referrerDigest := referrerImage.Digest()

		// Add referrer manifest to index multiple times (simulating tagging)
		index, err := common.GetIndex(imgStore, "test-repo", log)
		So(err, ShouldBeNil)

		// Add same referrer with different tags (simulating duplicates)
		desc1 := ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    referrerDigest,
			Size:      referrerImage.ManifestDescriptor.Size,
			Annotations: map[string]string{
				ispec.AnnotationRefName: "tag1",
			},
		}
		desc2 := ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    referrerDigest,
			Size:      referrerImage.ManifestDescriptor.Size,
			Annotations: map[string]string{
				ispec.AnnotationRefName: "tag2",
			},
		}
		desc3 := ispec.Descriptor{
			MediaType: ispec.MediaTypeImageManifest,
			Digest:    referrerDigest,
			Size:      referrerImage.ManifestDescriptor.Size,
		}

		index.Manifests = append(index.Manifests, desc1, desc2, desc3)

		err = imgStore.PutIndexContent("test-repo", index)
		So(err, ShouldBeNil)

		// Get referrers - should return only one instance despite multiple entries
		referrers, err := common.GetReferrers(imgStore, "test-repo", subjectDigest, []string{}, log)
		So(err, ShouldBeNil)
		So(len(referrers.Manifests), ShouldEqual, 1)
		So(referrers.Manifests[0].Digest, ShouldEqual, referrerDigest)
	})
}

func TestGetImageIndexErrors(t *testing.T) {
	log := log.NewTestLogger()

	Convey("Trigger invalid digest error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{}

		_, err := common.GetImageIndex(imgStore, "zot-test", "invalidDigest", log)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger GetBlobContent error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, zerr.ErrBlobNotFound
			},
		}

		validDigest := godigest.FromBytes([]byte("blob"))

		_, err := common.GetImageIndex(imgStore, "zot-test", validDigest, log)
		So(err, ShouldNotBeNil)
	})

	Convey("Trigger unmarshal error", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				return []byte{}, nil
			},
		}

		validDigest := godigest.FromBytes([]byte("blob"))

		_, err := common.GetImageIndex(imgStore, "zot-test", validDigest, log)
		So(err, ShouldNotBeNil)
	})
}

func TestGetBlobDescriptorFromRepo(t *testing.T) {
	log := log.NewTestLogger()
	metrics := monitoring.NewMetricsServer(false, log)

	defer metrics.Stop() // Clean up metrics server to prevent resource leaks

	tdir := t.TempDir()
	cacheDriver, _ := storage.Create("boltdb", cache.BoltDBDriverParameters{
		RootDir:     tdir,
		Name:        "cache",
		UseRelPaths: true,
	}, log)

	driver := local.New(true)
	imgStore := imagestore.NewImageStore(tdir, tdir, true,
		true, log, metrics, nil, driver, cacheDriver, nil, nil)

	repoName := "zot-test"

	Convey("Test error paths", t, func() {
		storeController := storage.StoreController{DefaultStore: imgStore}

		image := CreateRandomMultiarch()

		tag := "index"

		err := WriteMultiArchImageToFileSystem(image, repoName, tag, storeController)
		So(err, ShouldBeNil)

		blob := image.Images[0].Layers[0]
		blobDigest := godigest.FromBytes(blob)
		blobSize := len(blob)

		desc, err := common.GetBlobDescriptorFromIndex(imgStore, ispec.Index{Manifests: []ispec.Descriptor{
			{
				Digest:    image.Digest(),
				MediaType: ispec.MediaTypeImageIndex,
			},
		}}, repoName, blobDigest, log)
		So(err, ShouldBeNil)
		So(desc.Digest, ShouldEqual, blobDigest)
		So(desc.Size, ShouldEqual, blobSize)

		desc, err = common.GetBlobDescriptorFromRepo(imgStore, repoName, blobDigest, log)
		So(err, ShouldBeNil)
		So(desc.Digest, ShouldEqual, blobDigest)
		So(desc.Size, ShouldEqual, blobSize)

		indexBlobPath := imgStore.BlobPath(repoName, image.Digest())
		err = os.Chmod(indexBlobPath, 0o000)
		So(err, ShouldBeNil)

		defer func() {
			err = os.Chmod(indexBlobPath, 0o644)
			So(err, ShouldBeNil)
		}()

		_, err = common.GetBlobDescriptorFromIndex(imgStore, ispec.Index{Manifests: []ispec.Descriptor{
			{
				Digest:    image.Digest(),
				MediaType: ispec.MediaTypeImageIndex,
			},
		}}, repoName, blobDigest, log)
		So(err, ShouldNotBeNil)

		manifestDigest := image.Images[0].Digest()
		manifestBlobPath := imgStore.BlobPath(repoName, manifestDigest)
		err = os.Chmod(manifestBlobPath, 0o000)
		So(err, ShouldBeNil)

		defer func() {
			err = os.Chmod(manifestBlobPath, 0o644)
			So(err, ShouldBeNil)
		}()

		_, err = common.GetBlobDescriptorFromRepo(imgStore, repoName, blobDigest, log)
		So(err, ShouldNotBeNil)

		_, err = common.GetBlobDescriptorFromRepo(imgStore, repoName, manifestDigest, log)
		So(err, ShouldBeNil)
	})
}

func TestIsSignature(t *testing.T) {
	Convey("Unknown media type", t, func(c C) {
		isSingature := common.IsSignature(ispec.Descriptor{
			MediaType: "unknown media type",
		})
		So(isSingature, ShouldBeFalse)
	})
}

func TestDedupeGeneratorErrors(t *testing.T) {
	log := log.NewTestLogger()

	// Ideally this would be covered by the end-to-end test,
	// but the coverage for the error is unpredictable, prone to race conditions
	Convey("GetNextDigestWithBlobPaths errors", t, func(c C) {
		imgStore := &mocks.MockedImageStore{
			GetRepositoriesFn: func() ([]string, error) {
				return []string{"repo1", "repo2"}, nil
			},
			GetNextDigestWithBlobPathsFn: func(repos []string, lastDigests []godigest.Digest) (
				godigest.Digest, []string, error,
			) {
				return "sha256:123", []string{}, ErrTestError
			},
		}

		generator := &common.DedupeTaskGenerator{
			ImgStore: imgStore,
			Dedupe:   true,
			Log:      log,
		}

		task, err := generator.Next()
		So(err, ShouldNotBeNil)
		So(task, ShouldBeNil)
	})
}

func TestPruneImageManifestsFromIndexMissingIndex(t *testing.T) {
	log := log.NewTestLogger()

	Convey("Missing nested index blob is skipped gracefully", t, func(c C) {
		// Create a main index
		mainIndexDigest := godigest.FromString("main-index")
		manifest1Digest := godigest.FromString("manifest1")
		mainIndex := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    manifest1Digest,
				},
			},
		}
		mainIndexBlob, err := json.Marshal(mainIndex)
		So(err, ShouldBeNil)

		// Create other indexes list with one missing index
		// The missing index would have referenced manifest1, but since it's missing,
		// manifest1 should still be pruned (removed) if it has no tag
		otherImgIndexes := []ispec.Descriptor{
			{
				MediaType: ispec.MediaTypeImageIndex,
				Digest:    godigest.FromString("missing-index"),
				Size:      100,
			},
		}

		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				if digest == mainIndexDigest {
					return mainIndexBlob, nil
				}
				// Return ErrBlobNotFound for the missing nested index
				return nil, zerr.ErrBlobNotFound
			},
		}

		// PruneImageManifestsFromIndex should skip the missing nested index and continue
		// outIndex contains a manifest without a tag, so it should be pruned
		outIndex := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    manifest1Digest,
					// No tag annotation, so it will be pruned
				},
			},
		}

		prunedManifests, err := common.PruneImageManifestsFromIndex(
			imgStore, "repo", mainIndexDigest, outIndex, otherImgIndexes, log)
		So(err, ShouldBeNil)
		// The manifest should be pruned (removed) since it has no tag and the missing index
		// couldn't be checked to see if it references this manifest
		// The important thing is that the function succeeded (didn't error) despite the missing index
		So(len(prunedManifests), ShouldEqual, 0)
	})
}

func TestIsBlobReferencedInImageManifestMissingManifest(t *testing.T) {
	log := log.NewTestLogger()

	Convey("Missing manifest blob is treated as not referenced", t, func(c C) {
		blobDigest := godigest.FromString("blob-digest")
		missingManifestDigest := godigest.FromString("missing-manifest")

		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				// Return ErrBlobNotFound for the missing manifest
				return nil, zerr.ErrBlobNotFound
			},
		}

		// Create an index with a manifest descriptor pointing to a missing manifest
		// IsBlobReferencedInImageIndex will call isBlobReferencedInImageManifest internally
		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    missingManifestDigest,
					Size:      100,
				},
			},
		}

		// isBlobReferencedInImageManifest should treat missing manifest as not referenced
		referenced, err := common.IsBlobReferencedInImageIndex(imgStore, "repo", blobDigest, index, log)
		So(err, ShouldBeNil)
		So(referenced, ShouldBeFalse)
	})
}

func TestIsBlobReferencedInImageIndexNonMissingError(t *testing.T) {
	log := log.NewTestLogger()

	Convey("Non-missing error when reading nested index returns error", t, func(c C) {
		blobDigest := godigest.FromString("blob-digest")
		nestedIndexDigest := godigest.FromString("nested-index")

		// Create an index with a nested index descriptor
		index := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    nestedIndexDigest,
					Size:      100,
				},
			},
		}

		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				// Return a non-missing error (not ErrBlobNotFound or PathNotFoundError)
				return nil, ErrTestError
			},
		}

		// IsBlobReferencedInImageIndex should return the error (not skip it)
		referenced, err := common.IsBlobReferencedInImageIndex(imgStore, "repo", blobDigest, index, log)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, ErrTestError)
		So(referenced, ShouldBeFalse)
	})
}

func TestGetBlobDescriptorFromIndexMissingNestedIndex(t *testing.T) {
	log := log.NewTestLogger()

	Convey("Missing nested index blob is skipped gracefully", t, func(c C) {
		blobDigest := godigest.FromString("blob-digest")
		missingIndexDigest := godigest.FromString("missing-nested-index")

		// Create an index that contains a nested index (which will be missing)
		topLevelIndex := ispec.Index{
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageIndex,
					Digest:    missingIndexDigest,
					Size:      100,
				},
			},
		}

		imgStore := &mocks.MockedImageStore{
			GetBlobContentFn: func(repo string, digest godigest.Digest) ([]byte, error) {
				// Return ErrBlobNotFound for the missing nested index
				return nil, zerr.ErrBlobNotFound
			},
		}

		// GetBlobDescriptorFromIndex should skip the missing nested index and continue
		// Since the blob is not found, it should return ErrBlobNotFound
		_, err := common.GetBlobDescriptorFromIndex(imgStore, topLevelIndex, "repo", blobDigest, log)
		So(err, ShouldNotBeNil)
		So(err, ShouldEqual, zerr.ErrBlobNotFound)
	})
}
