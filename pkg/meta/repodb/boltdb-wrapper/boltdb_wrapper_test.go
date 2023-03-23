package bolt_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	. "github.com/smartystreets/goconvey/convey"
	"go.etcd.io/bbolt"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/bolt"
	"zotregistry.io/zot/pkg/meta/repodb"
	boltdb_wrapper "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
	"zotregistry.io/zot/pkg/test"
)

func TestWrapperErrors(t *testing.T) {
	Convey("Errors", t, func() {
		ctx := context.Background()
		tmpDir := t.TempDir()
		boltDBParams := bolt.DBParameters{RootDir: tmpDir}
		boltDriver, err := bolt.GetBoltDriver(boltDBParams)
		So(err, ShouldBeNil)

		log := log.NewLogger("debug", "")

		boltdbWrapper, err := boltdb_wrapper.NewBoltDBWrapper(boltDriver, log)
		defer os.Remove("repo.db")
		So(boltdbWrapper, ShouldNotBeNil)
		So(err, ShouldBeNil)

		repoMeta := repodb.RepoMetadata{
			Tags:       map[string]repodb.Descriptor{},
			Signatures: map[string]repodb.ManifestSignatures{},
		}

		repoMetaBlob, err := json.Marshal(repoMeta)
		So(err, ShouldBeNil)

		Convey("GetManifestData", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				dataBuck := tx.Bucket([]byte(bolt.ManifestDataBucket))

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
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(bolt.ManifestDataBucket))

				err := dataBuck.Put([]byte("digest1"), repoMetaBlob)
				if err != nil {
					return err
				}

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetManifestMeta("repo1", "digest1", repodb.ManifestMetadata{})
			So(err, ShouldNotBeNil)

			_, err = boltdbWrapper.GetManifestMeta("repo1", "digest1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetArtifactData", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				artifactBuck := tx.Bucket([]byte(bolt.ArtifactDataBucket))

				return artifactBuck.Put([]byte("artifactDigest"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetArtifactData("artifactDigest")
			So(err, ShouldNotBeNil)
		})

		Convey("SetReferrer", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetReferrer("repo", "ref", repodb.ReferrerInfo{})
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteReferrer", func() {
			Convey("RepoMeta not found", func() {
				err := boltdbWrapper.DeleteReferrer("r", "dig", "dig")
				So(err, ShouldNotBeNil)
			})

			Convey("bad repo meta blob", func() {
				err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
					repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

					return repoBuck.Put([]byte("repo"), []byte("wrong json"))
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.DeleteReferrer("repo", "dig", "dig")
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SetRepoReference", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetRepoReference("repo1", "tag", "digest", ispec.MediaTypeImageManifest)
			So(err, ShouldNotBeNil)
		})

		Convey("GetRepoMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetRepoMeta("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteRepoTag", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetReferrersInfo("repo1", "tag", nil)
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetMultipleRepoMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetMultipleRepoMeta(context.TODO(), func(repoMeta repodb.RepoMetadata) bool {
				return true
			}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementImageDownloads", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo2", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo2", digest.FromString("dig"),
				repodb.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				repodb.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			// signatures not found
			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				repodb.SignatureMetadata{})
			So(err, ShouldBeNil)

			//
			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				repoMeta := repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{},
					Signatures: map[string]repodb.ManifestSignatures{
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
				repodb.SignatureMetadata{
					SignatureType:   "cosign",
					SignatureDigest: "digest1",
				})
			So(err, ShouldBeNil)

			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				repodb.SignatureMetadata{
					SignatureType:   "notation",
					SignatureDigest: "digest2",
				})
			So(err, ShouldBeNil)
		})

		Convey("DeleteSignature", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteSignature("repo2", digest.FromString("dig"),
				repodb.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DeleteSignature("repo1", digest.FromString("dig"),
				repodb.SignatureMetadata{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				repoMeta := repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{},
					Signatures: map[string]repodb.ManifestSignatures{
						"digest1": {
							"cosgin": []repodb.SignatureInfo{
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
				repodb.SignatureMetadata{
					SignatureType:   "cosgin",
					SignatureDigest: "sigDigest2",
				})
			So(err, ShouldBeNil)
		})

		Convey("SearchRepos", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(bolt.ManifestDataBucket))

				err := dataBuck.Put([]byte("dig1"), []byte("wrong json"))
				if err != nil {
					return err
				}

				repoMeta := repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]repodb.ManifestSignatures{},
				}
				repoMetaBlob, err := json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo1"), repoMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tag2": {Digest: "dig2", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]repodb.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo2"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo2", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(bolt.ManifestDataBucket))

				manifestMeta := repodb.ManifestMetadata{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("wrong json"),
					Signatures:   repodb.ManifestSignatures{},
				}

				manifestMetaBlob, err := json.Marshal(manifestMeta)
				if err != nil {
					return err
				}

				err = dataBuck.Put([]byte("dig1"), manifestMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]repodb.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("Index Errors", func() {
			Convey("Bad index data", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = setBadIndexData(boltdbWrapper.DB, indexDigest.String())
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldNotBeNil)
			})

			Convey("Bad indexBlob in IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, repodb.IndexData{
					IndexBlob: []byte("bad json"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
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

				err = boltdbWrapper.SetIndexData(indexDigest, repodb.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex1, repodb.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex2, repodb.ManifestData{
					ManifestBlob: []byte("Bad Manifest"),
					ConfigBlob:   []byte("Bad Manifest"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldNotBeNil)

				_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
				So(err, ShouldNotBeNil)
			})
		})

		Convey("SearchTags", func() {
			ctx := context.Background()

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(bolt.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(bolt.ManifestDataBucket))

				manifestMeta := repodb.ManifestMetadata{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("wrong json"),
					Signatures:   repodb.ManifestSignatures{},
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
				repoMeta = repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tag2": {Digest: "dig2", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]repodb.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo1"), repoMetaBlob)
				if err != nil {
					return err
				}

				// manifest data is wrong
				repoMeta = repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tag2": {Digest: "wrongManifestData", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]repodb.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				err = repoBuck.Put([]byte("repo2"), repoMetaBlob)
				if err != nil {
					return err
				}

				repoMeta = repodb.RepoMetadata{
					Tags: map[string]repodb.Descriptor{
						"tag1": {Digest: "dig1", MediaType: ispec.MediaTypeImageManifest},
					},
					Signatures: map[string]repodb.ManifestSignatures{},
				}
				repoMetaBlob, err = json.Marshal(repoMeta)
				So(err, ShouldBeNil)

				return repoBuck.Put([]byte("repo3"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo2:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo3:", repodb.Filter{}, repodb.PageInput{})
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
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
					repodb.PageInput{},
				)
				So(err, ShouldNotBeNil)
			})

			Convey("FilterTags bad indexBlob in IndexData", func() {
				indexDigest := digest.FromString("indexDigest")

				err := boltdbWrapper.SetRepoReference("repo", "tag1", indexDigest, ispec.MediaTypeImageIndex) //nolint:contextcheck
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetIndexData(indexDigest, repodb.IndexData{
					IndexBlob: []byte("bad json"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
					repodb.PageInput{},
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

				err = boltdbWrapper.SetIndexData(indexDigest, repodb.IndexData{
					IndexBlob: indexBlob,
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex1, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				err = boltdbWrapper.SetManifestData(manifestDigestFromIndex2, repodb.ManifestData{
					ManifestBlob: []byte("{}"),
					ConfigBlob:   []byte("{}"),
				})
				So(err, ShouldBeNil)

				_, _, _, _, err = boltdbWrapper.FilterTags(ctx,
					func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return false },
					repodb.PageInput{},
				)
				So(err, ShouldBeNil)
			})
		})

		Convey("Unsuported type", func() {
			digest := digest.FromString("digest")

			err := boltdbWrapper.SetRepoReference("repo", "tag1", digest, "invalid type") //nolint:contextcheck
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchRepos(ctx, "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.SearchTags(ctx, "repo:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldBeNil)

			_, _, _, _, err = boltdbWrapper.FilterTags(
				ctx,
				func(repoMeta repodb.RepoMetadata, manifestMeta repodb.ManifestMetadata) bool { return true },
				repodb.PageInput{},
			)
			So(err, ShouldBeNil)
		})
	})
}

func setBadIndexData(dB *bbolt.DB, digest string) error {
	return dB.Update(func(tx *bbolt.Tx) error {
		indexDataBuck := tx.Bucket([]byte(bolt.IndexDataBucket))

		return indexDataBuck.Put([]byte(digest), []byte("bad json"))
	})
}
