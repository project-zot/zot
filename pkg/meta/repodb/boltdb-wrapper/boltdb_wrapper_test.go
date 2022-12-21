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

	"zotregistry.io/zot/pkg/meta/repodb"
	bolt "zotregistry.io/zot/pkg/meta/repodb/boltdb-wrapper"
)

func TestWrapperErrors(t *testing.T) {
	Convey("Errors", t, func() {
		boltDBParams := bolt.DBParameters{}
		boltdbWrapper, err := bolt.NewBoltDBWrapper(boltDBParams)
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
				dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))

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

		Convey("SetRepoTag", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.SetRepoTag("repo1", "tag", "digest", ispec.MediaTypeImageManifest)
			So(err, ShouldNotBeNil)
		})

		Convey("DeleteRepoTag", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.DeleteRepoTag("repo1", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("IncrementRepoStars", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, err = boltdbWrapper.GetRepoStars("repo1")
			So(err, ShouldNotBeNil)
		})

		Convey("GetMultipleRepoMeta", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo2", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			err = boltdbWrapper.IncrementImageDownloads("repo1", "tag")
			So(err, ShouldNotBeNil)
		})

		Convey("AddManifestSignature", func() {
			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), repoMetaBlob)
			})
			So(err, ShouldBeNil)

			// signatures not found
			err = boltdbWrapper.AddManifestSignature("repo1", digest.FromString("dig"),
				repodb.SignatureMetadata{})
			So(err, ShouldBeNil)

			//
			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, err = boltdbWrapper.SearchRepos(context.Background(), "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))

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

			_, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo2", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))

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

			_, _, err = boltdbWrapper.SearchRepos(context.Background(), "repo1", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})

		Convey("SearchTags", func() {
			ctx := context.Background()

			err := boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

				return repoBuck.Put([]byte("repo1"), []byte("wrong json"))
			})
			So(err, ShouldBeNil)

			_, _, err = boltdbWrapper.SearchTags(ctx, "", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			err = boltdbWrapper.DB.Update(func(tx *bbolt.Tx) error {
				repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))
				dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))

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

			_, _, err = boltdbWrapper.SearchTags(ctx, "repo1:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, err = boltdbWrapper.SearchTags(ctx, "repo2:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)

			_, _, err = boltdbWrapper.SearchTags(ctx, "repo3:", repodb.Filter{}, repodb.PageInput{})
			So(err, ShouldNotBeNil)
		})
	})
}
