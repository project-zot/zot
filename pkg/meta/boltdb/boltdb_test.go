package boltdb_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/signer"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/boltdb"
	"zotregistry.io/zot/pkg/meta/signatures"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/test"
)

func TestWrapperErrors(t *testing.T) {
	Convey("Errors", t, func() {
		ctx := context.Background()
		tmpDir := t.TempDir()
		boltDBParams := boltdb.DBParameters{RootDir: tmpDir}
		boltDriver, err := boltdb.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		boltdbWrapper, err := boltdb.New(boltDriver, log)
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		repoMeta := metaTypes.RepoMetadata{
			Tags:       map[string]metaTypes.Descriptor{},
			Signatures: map[string]metaTypes.ManifestSignatures{},
		}

		repoMetaBlob, err := json.Marshal(repoMeta)
		So(err, ShouldBeNil)

		Convey("GetManifestData", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				return dataBuck.Put([]byte("digest1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetManifestData("digest1")
			So(err, ShouldNotBeNil)

			_, err = boltdbWrapper.GetManifestMeta("repo1", "digest1")
			So(err, ShouldNotBeNil)
		})

		Convey("SetManifestMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				err := dataBuck.Put([]byte("digest1"), repoMetaBlob)
				if err != nil {
					return err
				}

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetManifestMeta("repo1", "digest1", metaTypes.ManifestMetadata{})
			So(err, ShouldNotBeNil)

			_, err = boltdbWrapper.GetManifestMeta("repo1", "digest1")
			So(err, ShouldNotBeNil)
		})

		Convey("FilterRepos", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				buck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				err := buck.Put([]byte("badRepo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.FilterRepos(context.Background(),
				func(repoMeta metaTypes.RepoMetadata) bool { return true }, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SetReferrer", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetReferrer("repo", "ref", metaTypes.ReferrerInfo{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteReferrer", func() {
			Convey("RepoMeta not found", func() {
				err := boltdbWrapper.DeleteReferrer("r", "dig", "dig")
				So(err, ShouldNotBeNil)
			})

			Convey("bad repo meta blob", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

					return repoBuck.Put([]byte("repo"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.DeleteReferrer("repo", "dig", "dig")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SetRepoReference", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetRepoReference("repo1", "tag", "digest", ispec.MediaTypeImageManifest)
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetRepoMeta("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteRepoTag", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteRepoTag("repo1", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("GetReferrersInfo", func() {
			_, err = boltdbWrapper.GetReferrersInfo("repo1", "tag", nil)
			So(err, ShouldNotBeNil)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetReferrersInfo("repo1", "tag", nil)
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementRepoStars("repo2")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.IncrementRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("DecrementRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DecrementRepoStars("repo2")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DecrementRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetMultipleRepoMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetMultipleRepoMeta(context.TODO(), func(repoMeta metaTypes.RepoMetadata) bool {
				return true
			}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementImageDownloads", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo2", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				metaTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			// signatures not found
			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				metaTypes.SignatureMetadata{})
			So(err, ShouldBeNil)

			//
			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				repoMeta := metaTypes.RepoMetadata{
					Tags: map[string]metaTypes.Descriptor{},
					Signatures: map[string]metaTypes.ManifestSignatures{
						"digest1": {
							"cosgin": {{}},
						},
						"digest2": {
							"notation": {{}},
						},
					},
				}

				repoMetaBlob, err := json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				metaTypes.SignatureMetadata{
					SignatureType:   "cosign",
					SignatureDigest: "digest1",
				})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				metaTypes.SignatureMetadata{
					SignatureType:   "cosign",
					SignatureDigest: "digest2",
				})
			So(err, ShouldBeNil)

			repoData, err := boltdbWrapper.GetRepoMeta("repo1")
			So(err, ShouldBeNil)
			So(len(repoData.Signatures[string(digest.FromString("dig"))][signatures.CosignSignature]),
				ShouldEqual, 1)
			So(repoData.Signatures[string(digest.FromString("dig"))][signatures.CosignSignature][0].SignatureManifestDigest,
				ShouldEqual, "digest2")

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				metaTypes.SignatureMetadata{
					SignatureType:   "notation",
					SignatureDigest: "digest2",
				})
			So(err, ShouldBeNil)
		})

		Convey("DeleteSignature", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteSignature("repo2", digest.FromString("dig"),
				metaTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DeleteSignature("repo1", digest.FromString("dig"),
				metaTypes.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				repoMeta := metaTypes.RepoMetadata{
					Tags: map[string]metaTypes.Descriptor{},
					Signatures: map[string]metaTypes.ManifestSignatures{
						"digest1": {
							"cosgin": []metaTypes.SignatureInfo{
								{
									SignatureManifestDigest: "sigDigest1",
								},
								{
									SignatureManifestDigest: "sigDigest2",
								},
							},
						},
						"digest2": {
							"notation": {{}},
						},
					},
				}

				repoMetaBlob, err := json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteSignature("repo1", "digest1",
				metaTypes.SignatureMetadata{
					SignatureType:   "cosgin",
					SignatureDigest: "sigDigest2",
				})
			So(err, ShouldBeNil)
		})

		Convey("SearchRepos", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				err := dataBuck.Put([]byte("dig1"), []byte("wrong json"))
				if err != nil {
					return err
				}

				repoMeta := metaTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]metaTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]metaTypes.ManifestSignatures{},
				}
				repoMetaBlob, err := json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo1"), repoMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = metaTypes.RepoMetadata{
					Name: "repo2",
					Tags: map[string]metaTypes.Descriptor{
						"tag2": {Digest: "dig2", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]metaTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo2"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo2", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				manifestMeta := metaTypes.ManifestMetadata{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("wrong json"),
					Signatures:   metaTypes.ManifestSignatures{},
				}

				manifestMetaBlob, err := json.Marshal(manifestMeta)
				if err != nil {
					return err
				}

				err = dataBuck.Put([]byte("dig1"), manifestMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = metaTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]metaTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]metaTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("Index Errors", func() {
			Convey("Bad index data", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = setBadIndexData(boltdbWrapper.DB, indexDigest.String())
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldNotBeNil)
			})

			Convey("Bad indexBlob in IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, metaTypes.IndexData{
					IndexBlob: []byte("bad json"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldNotBeNil)
			})

			Convey("Good index data, bad manifest inside index", func() {
				var (
					indexDigest              = digest.FromString("indexDigest")
					manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndex1")
					manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndex2")
				)

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
					manifestDigestFromIndex1, manifestDigestFromIndex2,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, metaTypes.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex1, metaTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex2, metaTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", metaTypes.Filter{}, metaTypes.PageInput{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SearchTags", func() {
			ctx := context.Background()

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

				manifestMeta := metaTypes.ManifestMetadata{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("wrong json"),
					Signatures:   metaTypes.ManifestSignatures{},
				}

				manifestMetaBlob, err := json.Marshal(manifestMeta)
				if err != nil {
					return err
				}

				err = dataBuck.Put([]byte("dig1"), manifestMetaBlob)
				if err != nil {
					return err
				}

				err = dataBuck.Put([]byte("wrongManifestData"), []byte("wrong json"))
				if err != nil {
					return err
				}

				// manifest data doesn't exist
				repoMeta = metaTypes.RepoMetadata{
					Name: "repo1",
					Tags: map[string]metaTypes.Descriptor{
						"tag2": {Digest: "dig2", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]metaTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo1"), repoMetaBlob)
				if err != nil {
					return err
				}

				// manifest data is wrong
				repoMeta = metaTypes.RepoMetadata{
					Name: "repo2",
					Tags: map[string]metaTypes.Descriptor{
						"tag2": {Digest: "wrongManifestData", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]metaTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo2"), repoMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = metaTypes.RepoMetadata{
					Name: "repo3",
					Tags: map[string]metaTypes.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]metaTypes.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo3"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo2:", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo3:", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("FilterTags Index errors", func() {
			Convey("FilterTags bad IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = setBadIndexData(boltdbWrapper.DB, indexDigest.String())
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool { return true },
					metaTypes.PageInput{},
				)
				So(err, ShouldNotBeNil)
			})

			Convey("FilterTags bad indexBlob in IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, metaTypes.IndexData{
					IndexBlob: []byte("bad json"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool { return true },
					metaTypes.PageInput{},
				)
				So(err, ShouldNotBeNil)
			})

			Convey("FilterTags didn't match any index manifest", func() {
				var (
					indexDigest              = digest.FromString("indexDigest")
					manifestDigestFromIndex1 = digest.FromString("manifestDigestFromIndex1")
					manifestDigestFromIndex2 = digest.FromString("manifestDigestFromIndex2")
				)

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				indexBlob, err := test.GetIndexBlobWithManifests([]digest.Digest{
					manifestDigestFromIndex1, manifestDigestFromIndex2,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, metaTypes.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex1, metaTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex2, metaTypes.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool { return false },
					metaTypes.PageInput{},
				)
				So(err, ShouldBeNil)
			})
		})

		Convey("ToggleStarRepo bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, getting StarredRepoKey from bucket fails", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				userdb, err := tx.CreateBucketIfNotExists([]byte(boltdb.UserDataBucket))
				So(err, ShouldBeNil)
				userBucket, err := userdb.CreateBucketIfNotExists([]byte(acCtx.Username))
				So(err, ShouldBeNil)

				err = userBucket.Put([]byte(boltdb.StarredReposKey), []byte("bad array"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo, unmarshal error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				userdb, err := tx.CreateBucketIfNotExists([]byte(boltdb.UserDataBucket))
				So(err, ShouldBeNil)
				userBucket, err := userdb.CreateBucketIfNotExists([]byte(acCtx.Username))
				So(err, ShouldBeNil)

				err = userBucket.Put([]byte(boltdb.BookmarkedReposKey), []byte("bad array"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, no repoMeta found", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				err := repoBuck.Put([]byte("repo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleStarRepo, bad repoMeta found", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			_, err = boltdbWrapper.ToggleStarRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("ToggleBookmarkRepo bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.ToggleBookmarkRepo(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("GetStarredRepos bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.GetStarredRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetStarredRepos user data unmarshal error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				userdb, err := tx.CreateBucketIfNotExists([]byte(boltdb.UserDataBucket))
				So(err, ShouldBeNil)
				userBucket, err := userdb.CreateBucketIfNotExists([]byte(acCtx.Username))
				So(err, ShouldBeNil)

				err = userBucket.Put([]byte(boltdb.StarredReposKey), []byte("bad array"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetStarredRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetBookmarkedRepos user data unmarshal error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				userdb, err := tx.CreateBucketIfNotExists([]byte(boltdb.UserDataBucket))
				So(err, ShouldBeNil)
				userBucket, err := userdb.CreateBucketIfNotExists([]byte(acCtx.Username))
				So(err, ShouldBeNil)

				err = userBucket.Put([]byte(boltdb.BookmarkedReposKey), []byte("bad array"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetBookmarkedRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("GetBookmarkedRepos bad context errors", func() {
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, "bad context")

			_, err := boltdbWrapper.GetBookmarkedRepos(ctx)
			So(err, ShouldNotBeNil)
		})

		Convey("Unsuported type", func() {
			digest := digest.FromString("digest")

			err := boltdbWrapper.SetRepoReference("repo", "tag1", digest, "invalid type") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", metaTypes.Filter{}, metaTypes.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.FilterTags(
				ctx,
				func(repoMeta metaTypes.RepoMetadata, manifestMeta metaTypes.ManifestMetadata) bool { return true },
				metaTypes.PageInput{},
			)
			So(err, ShouldBeNil)
		})

		Convey("GetUserRepoMeta unmarshal error", func() {
			acCtx := localCtx.AccessControlContext{
				ReadGlobPatterns: map[string]bool{
					"repo": true,
				},
				Username: "username",
			}
			authzCtxKey := localCtx.GetContextKey()
			ctx := context.WithValue(context.Background(), authzCtxKey, acCtx)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

				err := repoBuck.Put([]byte("repo"), []byte("bad repo"))
				So(err, ShouldBeNil)

				return nil
			})
			So(err, ShouldBeNil)

			_, err := boltdbWrapper.GetUserRepoMeta(ctx, "repo")
			So(err, ShouldNotBeNil)
		})

		Convey("UpdateSignaturesValidity", func() {
			Convey("manifestMeta of signed manifest not found", func() {
				err := boltdbWrapper.UpdateSignaturesValidity("repo", digest.FromString("dig"))
				So(err, ShouldBeNil)
			})

			Convey("repoMeta of signed manifest not found", func() {
				// repo Meta not found
				err := boltdbWrapper.SetManifestData(digest.FromString("dig"), metaTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo", digest.FromString("dig"))
				So(err, ShouldNotBeNil)
			})

			Convey("manifest - bad content", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					dataBuck := tx.Bucket([]byte(boltdb.ManifestDataBucket))

					return dataBuck.Put([]byte("digest1"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo1", "digest1")
				So(err, ShouldNotBeNil)
			})

			Convey("index - bad content", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					dataBuck := tx.Bucket([]byte(boltdb.IndexDataBucket))

					return dataBuck.Put([]byte("digest1"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo1", "digest1")
				So(err, ShouldNotBeNil)
			})

			Convey("repo - bad content", func() {
				// repo Meta not found
				err := boltdbWrapper.SetManifestData(digest.FromString("dig"), metaTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

					return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo1", digest.FromString("dig"))
				So(err, ShouldNotBeNil)
			})

			Convey("VerifySignature -> untrusted signature", func() {
				err := boltdbWrapper.SetManifestData(digest.FromString("dig"), metaTypes.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

					return repoBuck.Put([]byte("repo1"), repoMetaBlob)
				})
				So(err, ShouldBeNil)

				layerInfo := metaTypes.LayerInfo{LayerDigest: "", LayerContent: []byte{}, SignatureKey: ""}

				err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
					metaTypes.SignatureMetadata{
						SignatureType:   signatures.CosignSignature,
						SignatureDigest: string(digest.FromString("signature digest")),
						LayersInfo:      []metaTypes.LayerInfo{layerInfo},
					})
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo1", digest.FromString("dig"))
				So(err, ShouldBeNil)

				repoData, err := boltdbWrapper.GetRepoMeta("repo1")
				So(err, ShouldBeNil)
				So(repoData.Signatures[string(digest.FromString("dig"))][signatures.CosignSignature][0].LayersInfo[0].Signer,
					ShouldBeEmpty)
				So(repoData.Signatures[string(digest.FromString("dig"))][signatures.CosignSignature][0].LayersInfo[0].Date,
					ShouldBeZeroValue)
			})

			Convey("VerifySignature -> trusted signature", func() {
				_, _, manifest, _ := test.GetRandomImageComponents(10)
				manifestContent, _ := json.Marshal(manifest)
				manifestDigest := digest.FromBytes(manifestContent)

				err := boltdbWrapper.SetManifestData(manifestDigest, metaTypes.ManifestData{
					ManifestBlob: manifestContent,
					ConfigBlob:   []byte("configContent"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBuck := tx.Bucket([]byte(boltdb.RepoMetadataBucket))

					return repoBuck.Put([]byte("repo"), repoMetaBlob)
				})
				So(err, ShouldBeNil)

				mediaType := jws.MediaTypeEnvelope

				signOpts := notation.SignerSignOptions{
					SignatureMediaType: mediaType,
					PluginConfig:       map[string]string{},
					ExpiryDuration:     24 * time.Hour,
				}

				tdir := t.TempDir()
				keyName := "notation-sign-test"

				test.NotationPathLock.Lock()
				defer test.NotationPathLock.Unlock()

				test.LoadNotationPath(tdir)

				err = test.GenerateNotationCerts(tdir, keyName)
				So(err, ShouldBeNil)

				// getSigner
				var newSigner notation.Signer

				// ResolveKey
				signingKeys, err := test.LoadNotationSigningkeys(tdir)
				So(err, ShouldBeNil)

				idx := test.Index(signingKeys.Keys, keyName)
				So(idx, ShouldBeGreaterThanOrEqualTo, 0)

				key := signingKeys.Keys[idx]

				if key.X509KeyPair != nil {
					newSigner, err = signer.NewFromFiles(key.X509KeyPair.KeyPath, key.X509KeyPair.CertificatePath)
					So(err, ShouldBeNil)
				}

				descToSign := ispec.Descriptor{
					MediaType: manifest.MediaType,
					Digest:    manifestDigest,
					Size:      int64(len(manifestContent)),
				}
				sig, _, err := newSigner.Sign(ctx, descToSign, signOpts)
				So(err, ShouldBeNil)

				layerInfo := metaTypes.LayerInfo{
					LayerDigest:  string(digest.FromBytes(sig)),
					LayerContent: sig, SignatureKey: mediaType,
				}

				err = boltdbWrapper.AddManifestSignature("repo", manifestDigest,
					metaTypes.SignatureMetadata{
						SignatureType:   signatures.NotationSignature,
						SignatureDigest: string(digest.FromString("signature digest")),
						LayersInfo:      []metaTypes.LayerInfo{layerInfo},
					})
				So(err, ShouldBeNil)

				err = signatures.InitNotationDir(tdir)
				So(err, ShouldBeNil)

				trustpolicyPath := path.Join(tdir, "_notation/trustpolicy.json")

				if _, err := os.Stat(trustpolicyPath); errors.Is(err, os.ErrNotExist) {
					trustPolicy := `
						{
							"version": "1.0",
							"trustPolicies": [
								{
									"name": "notation-sign-test",
									"registryScopes": [ "*" ],
									"signatureVerification": {
										"level" : "strict" 
									},
									"trustStores": ["ca:notation-sign-test"],
									"trustedIdentities": [
										"*"
									]
								}
							]
						}`

					file, err := os.Create(trustpolicyPath)
					So(err, ShouldBeNil)

					defer file.Close()

					_, err = file.WriteString(trustPolicy)
					So(err, ShouldBeNil)
				}

				truststore := "_notation/truststore/x509/ca/notation-sign-test"
				truststoreSrc := "notation/truststore/x509/ca/notation-sign-test"
				err = os.MkdirAll(path.Join(tdir, truststore), 0o755)
				So(err, ShouldBeNil)

				err = test.CopyFile(path.Join(tdir, truststoreSrc, "notation-sign-test.crt"),
					path.Join(tdir, truststore, "notation-sign-test.crt"))
				So(err, ShouldBeNil)

				err = boltdbWrapper.UpdateSignaturesValidity("repo", manifestDigest) //nolint:contextcheck
				So(err, ShouldBeNil)

				repoData, err := boltdbWrapper.GetRepoMeta("repo")
				So(err, ShouldBeNil)
				So(repoData.Signatures[string(manifestDigest)][signatures.NotationSignature][0].LayersInfo[0].Signer,
					ShouldNotBeEmpty)
				So(repoData.Signatures[string(manifestDigest)][signatures.NotationSignature][0].LayersInfo[0].Date,
					ShouldNotBeZeroValue)
			})
		})
	})
}

func setBadIndexData(dB *bbolt.DB, digest string) error {
	return dB.Update(func(tx *bbolt.Tx) error {
		indexDataBuck := tx.Bucket([]byte(boltdb.IndexDataBucket))

		return indexDataBuck.Put([]byte(digest), []byte("bad json"))
	})
}
