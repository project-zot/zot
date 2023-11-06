package meta_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta"
	"zotregistry.io/zot/pkg/meta/boltdb"
	"zotregistry.io/zot/pkg/meta/dynamodb"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
	"zotregistry.io/zot/pkg/test/deprecated"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/mocks"
	"zotregistry.io/zot/pkg/test/signature"
	tskip "zotregistry.io/zot/pkg/test/skip"
)

const repo = "repo"

func TestParseStorageErrors(t *testing.T) {
	ctx := context.Background()

	Convey("ParseStorage", t, func() {
		imageStore := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return nil, ErrTestError
			},
			GetRepositoriesFn: func() ([]string, error) {
				return []string{"repo1", "repo2"}, nil
			},
		}
		storeController := storage.StoreController{DefaultStore: imageStore}
		metaDB := mocks.MetaDBMock{}

		// sync repo fail
		err := meta.ParseStorage(metaDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		Convey("getAllRepos errors", func() {
			imageStore1 := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return []string{"repo1", "repo2"}, nil
				},
			}
			imageStore2 := mocks.MockedImageStore{
				GetRepositoriesFn: func() ([]string, error) {
					return nil, ErrTestError
				},
			}
			storeController := storage.StoreController{
				DefaultStore: imageStore1,
				SubStore: map[string]storageTypes.ImageStore{
					"a": imageStore2,
				},
			}

			err := meta.ParseStorage(metaDB, storeController, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Parse Repo", t, func() {
		imageStore := mocks.MockedImageStore{}
		storeController := storage.StoreController{DefaultStore: &imageStore}
		metaDB := mocks.MetaDBMock{}
		log := log.NewLogger("debug", "")

		Convey("imageStore.GetIndexContent errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return nil, ErrTestError
			}

			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("json.Unmarshal errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return []byte("Invalid JSON"), nil
			}

			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("resetRepoReferences errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return []byte("{}"), nil
			}
			metaDB.ResetRepoReferencesFn = func(repo string) error { return ErrTestError }
			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("zcommon.IsReferrersTag", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return getIndexBlob(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromString("digest"),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
							},
						},
					},
				}), nil
			}
			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldBeNil)
		})

		Convey("imageStore.GetImageManifest errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return getIndexBlob(ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							MediaType: ispec.MediaTypeImageManifest,
							Digest:    godigest.FromString("digest"),
							Annotations: map[string]string{
								ispec.AnnotationRefName: "tag",
							},
						},
					},
				}), nil
			}
			imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
				return nil, "", "", ErrTestError
			}
			err := meta.ParseRepo("repo", metaDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("manifestMetaIsPresent true", func() {
			indexContent := ispec.Index{
				Manifests: []ispec.Descriptor{
					{
						Digest:    godigest.FromString("manifest1"),
						MediaType: ispec.MediaTypeImageManifest,
						Annotations: map[string]string{
							ispec.AnnotationRefName: "tag1",
						},
					},
				},
			}
			indexBlob, err := json.Marshal(indexContent)
			So(err, ShouldBeNil)

			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return indexBlob, nil
			}

			Convey("metaDB.SetRepoReference", func() {
				metaDB.SetRepoReferenceFn = func(ctx context.Context, repo, reference string, imageMeta mTypes.ImageMeta) error {
					return ErrTestError
				}

				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
		})
	})

	image := CreateRandomImage()

	Convey("SetImageMetaFromInput errors", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		mockedMetaDB := mocks.MetaDBMock{}
		log := log.NewLogger("debug", "")

		Convey("Image Manifest errors", func() {
			Convey("Get Config blob error", func() {
				mockImageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, ErrTestError
				}

				err := meta.SetImageMetaFromInput(ctx, "repo", "tag", ispec.MediaTypeImageManifest, image.Digest(),
					image.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
				So(err, ShouldNotBeNil)
			})
			Convey("Unmarshal config blob error", func() {
				mockImageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte("bad-blob"), nil
				}

				err := meta.SetImageMetaFromInput(ctx, "repo", "tag", ispec.MediaTypeImageManifest, image.Digest(),
					image.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
				So(err, ShouldNotBeNil)
			})
			Convey("Is Signature", func() {
				image := CreateDefaultImage()
				mediaType := ispec.MediaTypeImageManifest
				// it has more than 1 layer
				badNotationSignature := CreateImageWith().RandomLayers(2, 10).EmptyConfig().Subject(image.DescriptorRef()).
					ArtifactType(zcommon.ArtifactTypeNotation).Build()
				goodNotationSignature := CreateMockNotationSignature(image.DescriptorRef())

				Convey("GetSignatureLayersInfo errors", func() {
					err := meta.SetImageMetaFromInput(ctx, "repo", "tag", mediaType, badNotationSignature.Digest(),
						badNotationSignature.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
					So(err, ShouldNotBeNil)
				})
				Convey("UpdateSignaturesValidity errors", func() {
					mockedMetaDB.UpdateSignaturesValidityFn = func(repo string, manifestDigest godigest.Digest) error {
						return ErrTestError
					}
					err := meta.SetImageMetaFromInput(ctx, "repo", "tag", mediaType, goodNotationSignature.Digest(),
						goodNotationSignature.ManifestDescriptor.Data, mockImageStore, mockedMetaDB, log)
					So(err, ShouldNotBeNil)
				})
			})
		})
		Convey("Image Index errors", func() {
			Convey("Unmarshal error", func() {
				err := meta.SetImageMetaFromInput(ctx, "repo", "tag", ispec.MediaTypeImageIndex, "",
					[]byte("bad-json"), mockImageStore, mockedMetaDB, log)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func getIndexBlob(index ispec.Index) []byte {
	index.MediaType = ispec.MediaTypeImageIndex

	blob, err := json.Marshal(index)
	if err != nil {
		panic("image index should always be marshable")
	}

	return blob
}

func TestParseStorageWithBoltDB(t *testing.T) {
	Convey("Boltdb", t, func() {
		rootDir := t.TempDir()

		boltDB, err := boltdb.GetBoltDriver(boltdb.DBParameters{
			RootDir: rootDir,
		})
		So(err, ShouldBeNil)

		metaDB, err := boltdb.New(boltDB, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		RunParseStorageTests(rootDir, metaDB)
	})
}

func TestParseStorageDynamoWrapper(t *testing.T) {
	tskip.SkipDynamo(t)

	Convey("Dynamodb", t, func() {
		rootDir := t.TempDir()

		params := dynamodb.DBDriverParameters{
			Endpoint:               os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			Region:                 "us-east-2",
			RepoMetaTablename:      "RepoMetadataTable",
			RepoBlobsInfoTablename: "RepoBlobsInfoTablename",
			ImageMetaTablename:     "ImageMetaTablename",
			UserDataTablename:      "UserDataTable",
			APIKeyTablename:        "ApiKeyTable",
			VersionTablename:       "Version",
		}

		dynamoClient, err := dynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := dynamodb.New(dynamoClient, params, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetTable(dynamoWrapper.RepoMetaTablename)
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetTable(dynamoWrapper.RepoBlobsTablename)
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetTable(dynamoWrapper.ImageMetaTablename)
		So(err, ShouldBeNil)

		RunParseStorageTests(rootDir, dynamoWrapper)
	})
}

func RunParseStorageTests(rootDir string, metaDB mTypes.MetaDB) {
	Convey("Test with simple case", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		manifests := []ispec.Manifest{}
		for i := 0; i < 3; i++ {
			config, layers, manifest, err := deprecated.GetRandomImageComponents(100) //nolint:staticcheck
			So(err, ShouldBeNil)

			manifests = append(manifests, manifest)

			err = WriteImageToFileSystem(
				Image{
					Config:   config,
					Layers:   layers,
					Manifest: manifest,
				}, repo, fmt.Sprintf("tag%d", i), storeController)
			So(err, ShouldBeNil)
		}

		// add fake signature for tag1
		signatureTag, err := signature.GetCosignSignatureTagForManifest(manifests[1])
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifests[1])
		So(err, ShouldBeNil)

		signedManifestDigest := godigest.FromBytes(manifestBlob)

		config, layers, manifest, err := deprecated.GetRandomImageComponents(100) //nolint:staticcheck
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(
			Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
			}, repo, signatureTag, storeController)
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

		err = meta.ParseStorage(metaDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repos, err := metaDB.GetMultipleRepoMeta(context.Background(),
			func(repoMeta mTypes.RepoMeta) bool { return true })
		So(err, ShouldBeNil)

		So(len(repos), ShouldEqual, 1)
		So(len(repos[0].Tags), ShouldEqual, 2)

		ctx := context.Background()

		for tag, descriptor := range repos[0].Tags {
			imageManifestData, err := metaDB.GetFullImageMeta(ctx, repo, tag)
			So(err, ShouldBeNil)

			if descriptor.Digest == signedManifestDigest.String() {
				So(imageManifestData.Signatures, ShouldNotBeEmpty)
			}
		}
	})

	Convey("Accept orphan signatures", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		config, layers, manifest, err := deprecated.GetRandomImageComponents(100) //nolint:staticcheck
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(
			Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
			}, repo, "tag1", storeController)
		So(err, ShouldBeNil)

		// add mock cosign signature without pushing the signed image
		image, err := deprecated.GetRandomImage() //nolint:staticcheck
		So(err, ShouldBeNil)

		signatureTag, err := signature.GetCosignSignatureTagForManifest(image.Manifest)
		So(err, ShouldBeNil)

		missingImageDigest := image.Digest()

		// get the body of the signature
		config, layers, manifest, err = deprecated.GetRandomImageComponents(100) //nolint:staticcheck
		So(err, ShouldBeNil)

		err = WriteImageToFileSystem(
			Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
			}, repo, signatureTag, storeController)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repos, err := metaDB.GetMultipleRepoMeta(context.Background(),
			func(repoMeta mTypes.RepoMeta) bool { return true })
		So(err, ShouldBeNil)

		for _, desc := range repos[0].Tags {
			So(desc.Digest, ShouldNotResemble, missingImageDigest.String())
		}

		So(len(repos), ShouldEqual, 1)
		So(repos[0].Tags, ShouldContainKey, "tag1")
		So(repos[0].Tags, ShouldNotContainKey, signatureTag)
		So(repos[0].Signatures, ShouldContainKey, missingImageDigest.String())
	})

	Convey("Check statistics after load", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		image := CreateRandomImage() //nolint:staticcheck

		err := WriteImageToFileSystem(image, repo, "tag", storeController)
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(context.Background(), repo, "tag", image.AsImageMeta())
		So(err, ShouldBeNil)

		err = metaDB.IncrementRepoStars(repo)
		So(err, ShouldBeNil)
		err = metaDB.UpdateStatsOnDownload(repo, "tag")
		So(err, ShouldBeNil)
		err = metaDB.UpdateStatsOnDownload(repo, "tag")
		So(err, ShouldBeNil)
		err = metaDB.UpdateStatsOnDownload(repo, "tag")
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(context.Background(), repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[image.DigestStr()].DownloadCount, ShouldEqual, 3)
		So(repoMeta.StarCount, ShouldEqual, 1)
		So(time.Now(), ShouldHappenAfter, repoMeta.Statistics[image.DigestStr()].LastPullTimestamp)

		err = meta.ParseStorage(metaDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repoMeta, err = metaDB.GetRepoMeta(context.Background(), repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[image.DigestStr()].DownloadCount, ShouldEqual, 3)
		So(repoMeta.StarCount, ShouldEqual, 1)
	})
}

func TestGetSignatureLayersInfo(t *testing.T) {
	Convey("wrong signature type", t, func() {
		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", "wrong signature type", []byte{},
			nil, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("notation index", t, func() {
		notationIndex := ispec.Index{
			MediaType: ispec.MediaTypeImageIndex,
		}

		notationIndexBlob, err := json.Marshal(notationIndex)
		So(err, ShouldBeNil)
		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature, notationIndexBlob,
			nil, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("GetBlobContent errors", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		mockImageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
			return nil, ErrTestError
		}
		image := CreateRandomImage()

		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.CosignSignature,
			image.ManifestDescriptor.Data, mockImageStore, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("notation len(manifestContent.Layers) != 1", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		image := CreateImageWith().RandomLayers(3, 10).RandomConfig().Build()

		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature,
			image.ManifestDescriptor.Data, mockImageStore, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("notation GetBlobContent errors", t, func() {
		mockImageStore := mocks.MockedImageStore{}
		mockImageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
			return nil, ErrTestError
		}
		image := CreateImageWith().RandomLayers(1, 10).RandomConfig().Build()

		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature,
			image.ManifestDescriptor.Data, mockImageStore, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
		So(layers, ShouldBeEmpty)
	})

	Convey("error while unmarshaling manifest content", t, func() {
		_, err := meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.CosignSignature, []byte("bad manifest"),
			nil, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)

		_, err = meta.GetSignatureLayersInfo("repo", "tag", "123", zcommon.NotationSignature, []byte("bad manifest"),
			nil, log.NewLogger("debug", ""))
		So(err, ShouldNotBeNil)
	})
}
