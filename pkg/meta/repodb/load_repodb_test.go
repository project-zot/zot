package repodb_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	dynamo "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper"
	dynamoParams "zotregistry.io/zot/pkg/meta/repodb/dynamodb-wrapper/params"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/local"
	"zotregistry.io/zot/pkg/test"
	"zotregistry.io/zot/pkg/test/mocks"
)

const repo = "repo"

var ErrTestError = errors.New("test error")

func TestLoadOCILayoutErrors(t *testing.T) {
	Convey("LoadOCILayout", t, func() {
		imageStore := mocks.MockedImageStore{
			GetIndexContentFn: func(repo string) ([]byte, error) {
				return nil, ErrTestError
			},
			GetRepositoriesFn: func() ([]string, error) {
				return []string{"repo1", "repo2"}, nil
			},
		}
		storeController := storage.StoreController{DefaultStore: imageStore}
		repoDB := mocks.RepoDBMock{}

		// sync repo fail
		err := repodb.ParseStorage(repoDB, storeController, log.NewLogger("debug", ""))
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
				SubStore: map[string]storage.ImageStore{
					"a": imageStore2,
				},
			}

			err := repodb.ParseStorage(repoDB, storeController, log.NewLogger("debug", ""))
			So(err, ShouldNotBeNil)
		})
	})

	Convey("LoadRepo", t, func() {
		imageStore := mocks.MockedImageStore{}
		storeController := storage.StoreController{DefaultStore: &imageStore}
		repoDB := mocks.RepoDBMock{}
		log := log.NewLogger("debug", "")

		Convey("imageStore.GetIndexContent errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return nil, ErrTestError
			}

			err := repodb.ParseRepo("repo", repoDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("json.Unmarshal errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return []byte("Invalid JSON"), nil
			}

			err := repodb.ParseRepo("repo", repoDB, storeController, log)
			So(err, ShouldNotBeNil)
		})

		Convey("resetRepoMetaTags errors", func() {
			imageStore.GetIndexContentFn = func(repo string) ([]byte, error) {
				return []byte("{}"), nil
			}

			Convey("repoDB.GetRepoMeta errors", func() {
				repoDB.GetRepoMetaFn = func(repo string) (repodb.RepoMetadata, error) {
					return repodb.RepoMetadata{}, ErrTestError
				}

				err := repodb.ParseRepo("repo", repoDB, storeController, log)
				So(err, ShouldNotBeNil)
			})

			Convey("repoDB.DeleteRepoTag errors", func() {
				repoDB.GetRepoMetaFn = func(repo string) (repodb.RepoMetadata, error) {
					return repodb.RepoMetadata{
						Tags: map[string]repodb.Descriptor{
							"digest1": {
								Digest:    "tag1",
								MediaType: ispec.MediaTypeImageManifest,
							},
						},
					}, nil
				}
				repoDB.DeleteRepoTagFn = func(repo, tag string) error {
					return ErrTestError
				}

				err := repodb.ParseRepo("repo", repoDB, storeController, log)
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

			Convey("repoDB.GetManifestMeta errors", func() {
				repoDB.GetManifestMetaFn = func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
					return repodb.ManifestMetadata{}, ErrTestError
				}

				err = repodb.ParseRepo("repo", repoDB, storeController, log)
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

			Convey("repoDB.SetRepoReference", func() {
				repoDB.SetRepoReferenceFn = func(repo, tag string, manifestDigest godigest.Digest, mediaType string) error {
					return ErrTestError
				}

				err = repodb.ParseRepo("repo", repoDB, storeController, log)
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

			repoDB.GetManifestMetaFn = func(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
				return repodb.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
			}

			Convey("GetImageManifest errors", func() {
				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return nil, "", "", ErrTestError
				}
				err = repodb.ParseRepo("repo", repoDB, storeController, log)
				So(err, ShouldNotBeNil)
			})

			Convey("CheckIsImageSignature errors", func() {
				// CheckIsImageSignature will fail because of a invalid json
				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return []byte("Invalid JSON"), "", "", nil
				}
				err = repodb.ParseRepo("repo", repoDB, storeController, log)
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

					err = repodb.ParseRepo("repo", repoDB, storeController, log)
					So(err, ShouldNotBeNil)
				})

				Convey("json.Unmarshal(configBlob errors", func() {
					imageStore.GetBlobContentFn = func(repo string, digest godigest.Digest) ([]byte, error) {
						return []byte("invalid JSON"), nil
					}

					err = repodb.ParseRepo("repo", repoDB, storeController, log)
					So(err, ShouldNotBeNil)
				})
			})

			Convey("CheckIsImageSignature -> is signature", func() {
				manifestContent := ispec.Artifact{
					Subject: &ispec.Descriptor{
						Digest: "123",
					},
					ArtifactType: "application/vnd.cncf.notary.signature",
				}

				manifestBlob, err := json.Marshal(manifestContent)
				So(err, ShouldBeNil)

				imageStore.GetImageManifestFn = func(repo, reference string) ([]byte, godigest.Digest, string, error) {
					return manifestBlob, "", "", nil
				}

				repoDB.AddManifestSignatureFn = func(repo string, signedManifestDigest godigest.Digest,
					sm repodb.SignatureMetadata,
				) error {
					return ErrTestError
				}

				err = repodb.ParseRepo("repo", repoDB, storeController, log)
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestLoadOCILayoutWithStorage(t *testing.T) {
	Convey("Boltdb", t, func() {
		rootDir := t.TempDir()

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
					Config:    config,
					Layers:    layers,
					Manifest:  manifest,
					Reference: fmt.Sprintf("tag%d", i),
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
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: signatureTag,
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

		repoDB, err := bolt.NewBoltDBWrapper(bolt.DBParameters{
			RootDir: rootDir,
		})
		So(err, ShouldBeNil)

		err = repodb.ParseStorage(repoDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repos, err := repoDB.GetMultipleRepoMeta(
			context.Background(),
			func(repoMeta repodb.RepoMetadata) bool { return true },
			repodb.PageInput{},
		)
		So(err, ShouldBeNil)

		So(len(repos), ShouldEqual, 1)
		So(len(repos[0].Tags), ShouldEqual, 2)

		for _, descriptor := range repos[0].Tags {
			manifestMeta, err := repoDB.GetManifestMeta(repo, godigest.Digest(descriptor.Digest))
			So(err, ShouldBeNil)
			So(manifestMeta.ManifestBlob, ShouldNotBeNil)
			So(manifestMeta.ConfigBlob, ShouldNotBeNil)

			if descriptor.Digest == signedManifestDigest.String() {
				So(repos[0].Signatures[descriptor.Digest], ShouldNotBeEmpty)
				So(manifestMeta.Signatures["cosign"], ShouldNotBeEmpty)
			}
		}
	})

	Convey("Ignore orphan signatures", t, func() {
		rootDir := t.TempDir()

		imageStore := local.NewImageStore(rootDir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		config, layers, manifest, err := test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: "tag1",
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
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: signatureTag,
			},
			repo,
			storeController)
		So(err, ShouldBeNil)

		// test that we have only 1 image inside the repo
		repoDB, err := bolt.NewBoltDBWrapper(bolt.DBParameters{
			RootDir: rootDir,
		})
		So(err, ShouldBeNil)

		err = repodb.ParseStorage(repoDB, storeController, log.NewLogger("debug", ""))
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

func TestLoadOCILayoutDynamoWrapper(t *testing.T) {
	skipIt(t)

	Convey("Dynamodb", t, func() {
		rootDir := t.TempDir()

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
					Config:    config,
					Layers:    layers,
					Manifest:  manifest,
					Reference: fmt.Sprintf("tag%d", i),
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
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: signatureTag,
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

		dynamoWrapper, err := dynamo.NewDynamoDBWrapper(dynamoParams.DBDriverParameters{
			Endpoint:              os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			Region:                "us-east-2",
			RepoMetaTablename:     "RepoMetadataTable",
			ManifestDataTablename: "ManifestDataTable",
			IndexDataTablename:    "IndexDataTable",
			ArtifactDataTablename: "ArtifactDataTable",
			VersionTablename:      "Version",
		})
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetManifestDataTable()
		So(err, ShouldBeNil)

		err = dynamoWrapper.ResetRepoMetaTable()
		So(err, ShouldBeNil)

		err = repodb.ParseStorage(dynamoWrapper, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repos, err := dynamoWrapper.GetMultipleRepoMeta(
			context.Background(),
			func(repoMeta repodb.RepoMetadata) bool { return true },
			repodb.PageInput{},
		)
		t.Logf("%#v", repos)
		So(err, ShouldBeNil)

		So(len(repos), ShouldEqual, 1)
		So(len(repos[0].Tags), ShouldEqual, 2)

		for _, descriptor := range repos[0].Tags {
			manifestMeta, err := dynamoWrapper.GetManifestMeta(repo, godigest.Digest(descriptor.Digest))
			So(err, ShouldBeNil)
			So(manifestMeta.ManifestBlob, ShouldNotBeNil)
			So(manifestMeta.ConfigBlob, ShouldNotBeNil)

			if descriptor.Digest == signedManifestDigest.String() {
				So(manifestMeta.Signatures, ShouldNotBeEmpty)
			}
		}
	})

	Convey("Ignore orphan signatures", t, func() {
		rootDir := t.TempDir()

		imageStore := local.NewImageStore(rootDir, false, 0, false, false,
			log.NewLogger("debug", ""), monitoring.NewMetricsServer(false, log.NewLogger("debug", "")), nil, nil)

		storeController := storage.StoreController{DefaultStore: imageStore}
		// add an image
		config, layers, manifest, err := test.GetRandomImageComponents(100)
		So(err, ShouldBeNil)

		err = test.WriteImageToFileSystem(
			test.Image{
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: "tag1",
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
				Config:    config,
				Layers:    layers,
				Manifest:  manifest,
				Reference: signatureTag,
			},
			repo,
			storeController)
		So(err, ShouldBeNil)

		// test that we have only 1 image inside the repo
		repoDB, err := dynamo.NewDynamoDBWrapper(dynamoParams.DBDriverParameters{
			Endpoint:              os.Getenv("DYNAMODBMOCK_ENDPOINT"),
			Region:                "us-east-2",
			RepoMetaTablename:     "RepoMetadataTable",
			ManifestDataTablename: "ManifestDataTable",
			ArtifactDataTablename: "ArtifactDataTable",
			IndexDataTablename:    "IndexDataTable",
			VersionTablename:      "Version",
		})
		So(err, ShouldBeNil)

		err = repodb.ParseStorage(repoDB, storeController, log.NewLogger("debug", ""))
		So(err, ShouldBeNil)

		repos, err := repoDB.GetMultipleRepoMeta(
			context.Background(),
			func(repoMeta repodb.RepoMetadata) bool { return true },
			repodb.PageInput{},
		)
		So(err, ShouldBeNil)
		t.Logf("%#v", repos)

		So(len(repos), ShouldEqual, 1)
		So(repos[0].Tags, ShouldContainKey, "tag1")
		So(repos[0].Tags, ShouldNotContainKey, signatureTag)
	})
}

func TestGetReferredSubject(t *testing.T) {
	Convey("GetReferredSubject error", t, func() {
		_, _, _, err := repodb.GetReferredSubject([]byte("bad json"), "digest", ispec.MediaTypeArtifactManifest)
		So(err, ShouldNotBeNil)

		_, _, _, err = repodb.GetReferredSubject([]byte("bad json"), "digest", ispec.MediaTypeImageManifest)
		So(err, ShouldNotBeNil)
	})
}

func skipIt(t *testing.T) {
	t.Helper()

	if os.Getenv("S3MOCK_ENDPOINT") == "" {
		t.Skip("Skipping testing without AWS S3 mock server")
	}
}
