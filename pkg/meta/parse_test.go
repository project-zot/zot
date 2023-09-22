package meta_test

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

	zerr "zotregistry.io/zot/errors"
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
	"zotregistry.io/zot/pkg/test"
	. "zotregistry.io/zot/pkg/test/image-utils"
	"zotregistry.io/zot/pkg/test/mocks"
)

const repo = "repo"

func TestParseStorageErrors(t *testing.T) {
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

		Convey("resetRepoMetaTags errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return []byte("{}"), nil
			}

			Convey("metaDB.GetRepoMeta errors", func() {
				metaDB.GetRepoMetaFn = func(repo string) (mTypes.RepoMetadata, error) {
					return mTypes.RepoMetadata{}, ErrTestError
				}

				err := meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("isManifestMetaPresent errors", func() {
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

			Convey("metaDB.GetManifestMeta errors", func() {
				metaDB.GetManifestMetaFn = func(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
					return mTypes.ManifestMetadata{}, ErrTestError
				}

				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
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
				metaDB.SetRepoReferenceFn = func(repo, tag string, manifestDigest godigest.Digest, mediaType string) error {
					return ErrTestError
				}

				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
		})

		Convey("manifestMetaIsPresent false", func() {
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

			metaDB.GetManifestMetaFn = func(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
				return mTypes.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
			}

			Convey("GetImageManifest errors", func() {
				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", ErrTestError
				}
				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})

			Convey("CheckIsImageSignature errors", func() {
				// CheckIsImageSignature will fail because of a invalid json
				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte("Invalid JSON"), "", "", nil
				}
				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
			Convey("CheckIsImageSignature -> not signature", func() {
				manifestContent := ispec.Manifest{}
				manifestBlob, err := json.Marshal(manifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return manifestBlob, "", "", nil
				}

				Convey("imgStore.GetBlobContent errors", func() {
					imageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
						return nil, ErrTestError
					}

					err = meta.ParseRepo("repo", metaDB, storeController, log)
					So(err, ShouldNotBeNil)
				})
			})

			Convey("CheckIsImageSignature -> is signature", func() {
				manifestContent := ispec.Manifest{
					Subject: &ispec.Descriptor{
						Digest: "123",
					},
					ArtifactType: "application/vnd.cncf.notary.signature",
					Layers:       []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayer}},
				}

				manifestBlob, err := json.Marshal(manifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return manifestBlob, "", "", nil
				}

				metaDB.AddManifestSignatureFn = func(repo string, signedManifestDigest godigest.Digest,
					sm mTypes.SignatureMetadata,
				) error {
					return ErrTestError
				}

				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)

				metaDB.AddManifestSignatureFn = func(repo string, signedManifestDigest godigest.Digest,
					sm mTypes.SignatureMetadata,
				) error {
					return nil
				}

				metaDB.UpdateSignaturesValidityFn = func(repo string, signedManifestDigest godigest.Digest,
				) error {
					return ErrTestError
				}

				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})

			Convey("GetSignatureLayersInfo errors", func() {
				// get notation signature layers info
				badNotationManifestContent := ispec.Manifest{
					Subject: &ispec.Descriptor{
						Digest: "123",
					},
					ArtifactType: "application/vnd.cncf.notary.signature",
				}

				badNotationManifestBlob, err := json.Marshal(badNotationManifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return badNotationManifestBlob, "", "", nil
				}

				// wrong number of layers of notation manifest
				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)

				notationManifestContent := ispec.Manifest{
					Subject: &ispec.Descriptor{
						Digest: "123",
					},
					ArtifactType: "application/vnd.cncf.notary.signature",
					Layers:       []ispec.Descriptor{{MediaType: ispec.MediaTypeImageLayer}},
				}

				notationManifestBlob, err := json.Marshal(notationManifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return notationManifestBlob, "", "", nil
				}

				imageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
					return []byte{}, ErrTestError
				}

				// unable to get layer content
				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)

				_, _, cosignManifestContent, _ := test.GetRandomImageComponents(10) //nolint:staticcheck
				_, _, signedManifest, _ := test.GetRandomImageComponents(10)        //nolint:staticcheck
				signatureTag, err := test.GetCosignSignatureTagForManifest(signedManifest)
				So(err, ShouldBeNil)

				cosignManifestContent.Annotations = map[string]string{ispec.AnnotationRefName: signatureTag}

				cosignManifestBlob, err := json.Marshal(cosignManifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return cosignManifestBlob, "", "", nil
				}

				indexContent := ispec.Index{
					Manifests: []ispec.Descriptor{
						{
							Digest:    godigest.FromString("cosignSig"),
							MediaType: ispec.MediaTypeImageManifest,
							Annotations: map[string]string{
								ispec.AnnotationRefName: signatureTag,
							},
						},
					},
				}
				indexBlob, err := json.Marshal(indexContent)
				So(err, ShouldBeNil)

				imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
					return indexBlob, nil
				}

				// unable to get layer content
				err = meta.ParseRepo("repo", metaDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
		})
	})
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
	skipIt(t)

	Convey("Dynamodb", t, func() {
		rootDir := t.TempDir()

		params := dynamodb.DBDriverParameters{
			Endpoint:              os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			Region:                "us-east-2",
			RepoMetaTablename:     "RepoMetadataTable",
			ManifestDataTablename: "ManifestDataTable",
			IndexDataTablename:    "IndexDataTable",
			UserDataTablename:     "UserDataTable",
			APIKeyTablename:       "ApiKeyTable",
			VersionTablename:      "Version",
		}

		dynamoClient, err := dynamodb.GetDynamoClient(params)
		So(err, ShouldBeNil)

		dynamoWrapper, err := dynamodb.New(dynamoClient, params, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetManifestDataTable()
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetRepoMetaTable()
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
			config, layers, manifest, err := test.GetRandomImageComponents(100) //nolint:staticcheck
			So(err, ShouldBeNil)

			manifests = append(manifests, manifest)

			err = test.WriteImageToFileSystem(
				Image{
					Config:   config,
					Layers:   layers,
					Manifest: manifest,
				}, repo, fmt.Sprintf("tag%d", i), storeController)
			So(err, ShouldBeNil)
		}

		// add fake signature for tag1
		signatureTag, err := test.GetCosignSignatureTagForManifest(manifests[1])
		So(err, ShouldBeNil)

		manifestBlob, err := json.Marshal(manifests[1])
		So(err, ShouldBeNil)

		signedManifestDigest := godigest.FromBytes(manifestBlob)

		config, layers, manifest, err := test.GetRandomImageComponents(100) //nolint:staticcheck
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
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
			func(repoMeta mTypes.RepoMetadata) bool { return true })
		So(err, ShouldBeNil)

		So(len(repos), ShouldEqual, 1)
		So(len(repos[0].Tags), ShouldEqual, 2)

		for _, descriptor := range repos[0].Tags {
			manifestMeta, err := metaDB.GetManifestMeta(repo, godigest.Digest(descriptor.Digest))
			So(err, ShouldBeNil)
			So(manifestMeta.ManifestBlob, ShouldNotBeNil)
			So(manifestMeta.ConfigBlob, ShouldNotBeNil)

			if descriptor.Digest == signedManifestDigest.String() {
				So(manifestMeta.Signatures, ShouldNotBeEmpty)
			}
		}
	})

	Convey("Accept orphan signatures", func() {
		imageStore := local.NewImageStore(rootDir, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		config, layers, manifest, err := test.GetRandomImageComponents(100) //nolint:staticcheck
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
			}, repo, "tag1", storeController)
		So(err, ShouldBeNil)

		// add mock cosign signature without pushing the signed image
		image, err := test.GetRandomImage() //nolint:staticcheck
		So(err, ShouldBeNil)

		signatureTag, err := test.GetCosignSignatureTagForManifest(image.Manifest)
		So(err, ShouldBeNil)

		missingImageDigest := image.Digest()

		// get the body of the signature
		config, layers, manifest, err = test.GetRandomImageComponents(100) //nolint:staticcheck
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			Image{
				Config:   config,
				Layers:   layers,
				Manifest: manifest,
			}, repo, signatureTag, storeController)
		So(err, ShouldBeNil)

		err = meta.ParseStorage(metaDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repos, err := metaDB.GetMultipleRepoMeta(
			context.Background(),
			func(repoMeta mTypes.RepoMetadata) bool { return true },
		)
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
		image, err := test.GetRandomImage() //nolint:staticcheck
		So(err, ShouldBeNil)

		manifestDigest := image.Digest()

		err = test.WriteImageToFileSystem(image, repo, "tag", storeController)
		So(err, ShouldBeNil)

		err = metaDB.SetRepoReference(repo, "tag", manifestDigest, ispec.MediaTypeImageManifest)
		So(err, ShouldBeNil)

		err = metaDB.IncrementRepoStars(repo)
		So(err, ShouldBeNil)
		err = metaDB.IncrementImageDownloads(repo, "tag")
		So(err, ShouldBeNil)
		err = metaDB.IncrementImageDownloads(repo, "tag")
		So(err, ShouldBeNil)
		err = metaDB.IncrementImageDownloads(repo, "tag")
		So(err, ShouldBeNil)

		repoMeta, err := metaDB.GetRepoMeta(repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[manifestDigest.String()].DownloadCount, ShouldEqual, 3)
		So(repoMeta.Stars, ShouldEqual, 1)

		err = meta.ParseStorage(metaDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repoMeta, err = metaDB.GetRepoMeta(repo)
		So(err, ShouldBeNil)

		So(repoMeta.Statistics[manifestDigest.String()].DownloadCount, ShouldEqual, 3)
		So(repoMeta.Stars, ShouldEqual, 1)
	})
}

func TestGetReferredInfo(t *testing.T) {
	Convey("GetReferredInfo error", t, func() {
		_, _, _, err := meta.GetReferredInfo([]byte("bad json"), "digest", ispec.MediaTypeImageManifest)
		So(err, ShouldNotBeNil)

		_, _, _, err = meta.GetReferredInfo([]byte("bad json"), "digest", ispec.MediaTypeImageIndex)
		So(err, ShouldNotBeNil)
	})
}

func skipIt(t *testing.T) {
	t.Helper()

	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS S3 mock server")
	}
}

func TestGetSignatureLayersInfo(t *testing.T) {
	Convey("wrong signature type", t, func() {
		layers, err := meta.GetSignatureLayersInfo("repo", "tag", "123", "wrong signature type", []byte{},
			nil, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)
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
