package boltdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/extensions/imagetrust"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/common"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/meta/version"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

type BoltDB struct {
	DB      *bbolt.DB
	Patches []func(DB *bbolt.DB) error
	Log     log.Logger
}

func New(boltDB *bbolt.DB, log log.Logger) (*BoltDB, error) {
	err := boltDB.Update(func(transaction *bbolt.Tx) error {
		versionBuck, err := transaction.CreateBucketIfNotExists([]byte(VersionBucket))
		if err != nil {
			return err
		}

		err = versionBuck.Put([]byte(version.DBVersionKey), []byte(version.CurrentVersion))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(ManifestDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(IndexDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(RepoMetadataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(UserDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(UserAPIKeysBucket))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &BoltDB{
		DB:      boltDB,
		Patches: version.GetBoltDBPatches(),
		Log:     log,
	}, nil
}

func (bdw *BoltDB) SetManifestData(manifestDigest godigest.Digest, manifestData mTypes.ManifestData) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestDataBucket))

		mdBlob, err := json.Marshal(manifestData)
		if err != nil {
			return fmt.Errorf("metadb: error while calculating blob for manifest with digest %s %w", manifestDigest, err)
		}

		err = buck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return fmt.Errorf("metadb: error while setting manifest data with for digest %s %w", manifestDigest, err)
		}

		return nil
	})

	return err
}

func (bdw *BoltDB) GetManifestData(manifestDigest godigest.Digest) (mTypes.ManifestData, error) {
	var manifestData mTypes.ManifestData

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestDataBucket))

		mdBlob := buck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestDataNotFound
		}

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return fmt.Errorf("metadb: error while unmashaling manifest meta for digest %s %w", manifestDigest, err)
		}

		return nil
	})

	return manifestData, err
}

func (bdw *BoltDB) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta mTypes.ManifestMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		dataBuck := tx.Bucket([]byte(ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMeta := mTypes.RepoMetadata{
			Name:       repo,
			Tags:       map[string]mTypes.Descriptor{},
			Statistics: map[string]mTypes.DescriptorStatistics{},
			Signatures: map[string]mTypes.ManifestSignatures{},
			Referrers:  map[string][]mTypes.ReferrerInfo{},
		}

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}
		}

		mdBlob, err := json.Marshal(mTypes.ManifestData{
			ManifestBlob: manifestMeta.ManifestBlob,
			ConfigBlob:   manifestMeta.ConfigBlob,
		})
		if err != nil {
			return fmt.Errorf("metadb: error while calculating blob for manifest with digest %s %w", manifestDigest, err)
		}

		err = dataBuck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return fmt.Errorf("metadb: error while setting manifest meta with for digest %s %w", manifestDigest, err)
		}

		updatedRepoMeta := common.UpdateManifestMeta(repoMeta, manifestDigest, manifestMeta)

		updatedRepoMetaBlob, err := json.Marshal(updatedRepoMeta)
		if err != nil {
			return fmt.Errorf("metadb: error while calculating blob for updated repo meta '%s' %w", repo, err)
		}

		return repoBuck.Put([]byte(repo), updatedRepoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) GetManifestMeta(repo string, manifestDigest godigest.Digest) (mTypes.ManifestMetadata, error) {
	var manifestMetadata mTypes.ManifestMetadata

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		dataBuck := tx.Bucket([]byte(ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		mdBlob := dataBuck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestData mTypes.ManifestData

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return fmt.Errorf("metadb: error while unmashaling manifest meta for digest %s %w", manifestDigest, err)
		}

		var repoMeta mTypes.RepoMetadata

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err = json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return fmt.Errorf("metadb: error while unmashaling manifest meta for digest %s %w", manifestDigest, err)
			}
		}

		manifestMetadata.ManifestBlob = manifestData.ManifestBlob
		manifestMetadata.ConfigBlob = manifestData.ConfigBlob
		manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

		manifestMetadata.Signatures = mTypes.ManifestSignatures{}
		if repoMeta.Signatures[manifestDigest.String()] != nil {
			manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
		}

		return nil
	})

	return manifestMetadata, err
}

func (bdw *BoltDB) SetIndexData(indexDigest godigest.Digest, indexMetadata mTypes.IndexData) error {
	// we make the assumption that the oci layout is consistent and all manifests refferenced inside the
	// index are present
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(IndexDataBucket))

		imBlob, err := json.Marshal(indexMetadata)
		if err != nil {
			return fmt.Errorf("metadb: error while calculating blob for manifest with digest %s %w", indexDigest, err)
		}

		err = buck.Put([]byte(indexDigest), imBlob)
		if err != nil {
			return fmt.Errorf("metadb: error while setting manifest meta with for digest %s %w", indexDigest, err)
		}

		return nil
	})

	return err
}

func (bdw *BoltDB) GetIndexData(indexDigest godigest.Digest) (mTypes.IndexData, error) {
	var indexMetadata mTypes.IndexData

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(IndexDataBucket))

		mmBlob := buck.Get([]byte(indexDigest))

		if len(mmBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		err := json.Unmarshal(mmBlob, &indexMetadata)
		if err != nil {
			return fmt.Errorf("metadb: error while unmashaling manifest meta for digest %s %w", indexDigest, err)
		}

		return nil
	})

	return indexMetadata, err
}

func (bdw BoltDB) SetReferrer(repo string, referredDigest godigest.Digest, referrer mTypes.ReferrerInfo) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			var err error

			// create a new object
			repoMeta := mTypes.RepoMetadata{
				Name:       repo,
				Tags:       map[string]mTypes.Descriptor{},
				Statistics: map[string]mTypes.DescriptorStatistics{},
				Signatures: map[string]mTypes.ManifestSignatures{},
				Referrers: map[string][]mTypes.ReferrerInfo{
					referredDigest.String(): {
						referrer,
					},
				},
			}

			repoMetaBlob, err = json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}
		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		referrers := repoMeta.Referrers[referredDigest.String()]

		for i := range referrers {
			if referrers[i].Digest == referrer.Digest {
				return nil
			}
		}

		referrers = append(referrers, referrer)

		repoMeta.Referrers[referredDigest.String()] = referrers

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDB) DeleteReferrer(repo string, referredDigest godigest.Digest,
	referrerDigest godigest.Digest,
) error {
	return bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		referrers := repoMeta.Referrers[referredDigest.String()]

		for i := range referrers {
			if referrers[i].Digest == referrerDigest.String() {
				referrers = append(referrers[:i], referrers[i+1:]...)

				break
			}
		}

		repoMeta.Referrers[referredDigest.String()] = referrers

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})
}

func (bdw BoltDB) GetReferrersInfo(repo string, referredDigest godigest.Digest, artifactTypes []string,
) ([]mTypes.ReferrerInfo, error) {
	referrersInfoResult := []mTypes.ReferrerInfo{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		referrersInfo := repoMeta.Referrers[referredDigest.String()]

		for i := range referrersInfo {
			if !common.MatchesArtifactTypes(referrersInfo[i].ArtifactType, artifactTypes) {
				continue
			}

			referrersInfoResult = append(referrersInfoResult, referrersInfo[i])
		}

		return nil
	})

	return referrersInfoResult, err
}

func (bdw *BoltDB) SetRepoReference(repo string, reference string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if err := common.ValidateRepoReferenceInput(repo, reference, manifestDigest); err != nil {
		return err
	}

	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		repoMeta := mTypes.RepoMetadata{
			Name:       repo,
			Tags:       map[string]mTypes.Descriptor{},
			Statistics: map[string]mTypes.DescriptorStatistics{},
			Signatures: map[string]mTypes.ManifestSignatures{},
			Referrers:  map[string][]mTypes.ReferrerInfo{},
		}

		// object not found
		if len(repoMetaBlob) > 0 {
			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}
		}

		if !common.ReferenceIsDigest(reference) {
			repoMeta.Tags[reference] = mTypes.Descriptor{
				Digest:    manifestDigest.String(),
				MediaType: mediaType,
			}
		}

		if _, ok := repoMeta.Statistics[manifestDigest.String()]; !ok {
			repoMeta.Statistics[manifestDigest.String()] = mTypes.DescriptorStatistics{DownloadCount: 0}
		}

		if _, ok := repoMeta.Signatures[manifestDigest.String()]; !ok {
			repoMeta.Signatures[manifestDigest.String()] = mTypes.ManifestSignatures{}
		}

		if _, ok := repoMeta.Referrers[manifestDigest.String()]; !ok {
			repoMeta.Referrers[manifestDigest.String()] = []mTypes.ReferrerInfo{}
		}

		repoMetaBlob, err := json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) GetRepoMeta(repo string) (mTypes.RepoMetadata, error) {
	var repoMeta mTypes.RepoMetadata

	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		// object found
		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		return nil
	})

	return repoMeta, err
}

func (bdw *BoltDB) GetUserRepoMeta(ctx context.Context, repo string) (mTypes.RepoMetadata, error) {
	var repoMeta mTypes.RepoMetadata

	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))
		userBookmarks := getUserBookmarks(ctx, tx)
		userStars := getUserStars(ctx, tx)

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		// object found
		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repo)
		repoMeta.IsStarred = zcommon.Contains(userStars, repo)

		return nil
	})

	return repoMeta, err
}

func (bdw *BoltDB) SetRepoMeta(repo string, repoMeta mTypes.RepoMetadata) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMeta.Name = repo

		repoMetaBlob, err := json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) DeleteRepoTag(repo string, tag string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return nil
		}

		// object found
		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		delete(repoMeta.Tags, tag)

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) IncrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Stars++

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) DecrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		if repoMeta.Stars > 0 {
			repoMeta.Stars--
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) GetRepoStars(repo string) (int, error) {
	stars := 0

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		buck.Get([]byte(repo))
		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		stars = repoMeta.Stars

		return nil
	})

	return stars, err
}

func (bdw *BoltDB) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta mTypes.RepoMetadata) bool,
) ([]mTypes.RepoMetadata, error) {
	foundRepos := []mTypes.RepoMetadata{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := mTypes.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				foundRepos = append(foundRepos, repoMeta)
			}
		}

		return nil
	})

	return foundRepos, err
}

func (bdw *BoltDB) IncrementImageDownloads(repo string, reference string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		manifestDigest := reference

		if !common.ReferenceIsDigest(reference) {
			// search digest for tag
			descriptor, found := repoMeta.Tags[reference]

			if !found {
				return zerr.ErrManifestMetaNotFound
			}

			manifestDigest = descriptor.Digest
		}

		manifestStatistics := repoMeta.Statistics[manifestDigest]
		manifestStatistics.DownloadCount++
		repoMeta.Statistics[manifestDigest] = manifestStatistics

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) UpdateSignaturesValidity(repo string, manifestDigest godigest.Digest) error {
	err := bdw.DB.Update(func(transaction *bbolt.Tx) error {
		// get ManifestData of signed manifest
		manifestBuck := transaction.Bucket([]byte(ManifestDataBucket))
		mdBlob := manifestBuck.Get([]byte(manifestDigest))

		var blob []byte

		if len(mdBlob) != 0 {
			var manifestData mTypes.ManifestData

			err := json.Unmarshal(mdBlob, &manifestData)
			if err != nil {
				return fmt.Errorf("metadb: %w error while unmashaling manifest meta for digest %s", err, manifestDigest)
			}

			blob = manifestData.ManifestBlob
		} else {
			var indexData mTypes.IndexData

			indexBuck := transaction.Bucket([]byte(IndexDataBucket))
			idBlob := indexBuck.Get([]byte(manifestDigest))

			if len(idBlob) == 0 {
				// manifest meta not found, updating signatures with details about validity and author will not be performed
				return nil
			}

			err := json.Unmarshal(idBlob, &indexData)
			if err != nil {
				return fmt.Errorf("metadb: %w error while unmashaling index meta for digest %s", err, manifestDigest)
			}

			blob = indexData.IndexBlob
		}

		// update signatures with details about validity and author
		repoBuck := transaction.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		manifestSignatures := mTypes.ManifestSignatures{}
		for sigType, sigs := range repoMeta.Signatures[manifestDigest.String()] {
			signaturesInfo := []mTypes.SignatureInfo{}

			for _, sigInfo := range sigs {
				layersInfo := []mTypes.LayerInfo{}

				for _, layerInfo := range sigInfo.LayersInfo {
					author, date, isTrusted, _ := imagetrust.VerifySignature(sigType, layerInfo.LayerContent, layerInfo.SignatureKey,
						manifestDigest, blob, repo)

					if isTrusted {
						layerInfo.Signer = author
					}

					if !date.IsZero() {
						layerInfo.Signer = author
						layerInfo.Date = date
					}

					layersInfo = append(layersInfo, layerInfo)
				}

				signaturesInfo = append(signaturesInfo, mTypes.SignatureInfo{
					SignatureManifestDigest: sigInfo.SignatureManifestDigest,
					LayersInfo:              layersInfo,
				})
			}

			manifestSignatures[sigType] = signaturesInfo
		}

		repoMeta.Signatures[manifestDigest.String()] = manifestSignatures

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return repoBuck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta mTypes.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		if len(repoMetaBlob) == 0 {
			var err error
			// create a new object
			repoMeta := mTypes.RepoMetadata{
				Name: repo,
				Tags: map[string]mTypes.Descriptor{},
				Signatures: map[string]mTypes.ManifestSignatures{
					signedManifestDigest.String(): {
						sygMeta.SignatureType: []mTypes.SignatureInfo{
							{
								SignatureManifestDigest: sygMeta.SignatureDigest,
								LayersInfo:              sygMeta.LayersInfo,
							},
						},
					},
				},
				Statistics: map[string]mTypes.DescriptorStatistics{},
				Referrers:  map[string][]mTypes.ReferrerInfo{},
			}

			repoMetaBlob, err = json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		var (
			manifestSignatures mTypes.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			manifestSignatures = mTypes.ManifestSignatures{}
		}

		signatureSlice := manifestSignatures[sygMeta.SignatureType]
		if !common.SignatureAlreadyExists(signatureSlice, sygMeta) {
			if sygMeta.SignatureType == zcommon.NotationSignature {
				signatureSlice = append(signatureSlice, mTypes.SignatureInfo{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				})
			} else if sygMeta.SignatureType == zcommon.CosignSignature {
				signatureSlice = []mTypes.SignatureInfo{{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				}}
			}
		}

		manifestSignatures[sygMeta.SignatureType] = signatureSlice

		repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta mTypes.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		sigType := sigMeta.SignatureType

		var (
			manifestSignatures mTypes.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			return zerr.ErrManifestMetaNotFound
		}

		signatureSlice := manifestSignatures[sigType]

		newSignatureSlice := make([]mTypes.SignatureInfo, 0, len(signatureSlice)-1)

		for _, sigDigest := range signatureSlice {
			if sigDigest.SignatureManifestDigest != sigMeta.SignatureDigest {
				newSignatureSlice = append(newSignatureSlice, sigDigest)
			}
		}

		manifestSignatures[sigType] = newSignatureSlice

		repoMeta.Signatures[signedManifestDigest.String()] = manifestSignatures

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *BoltDB) SearchRepos(ctx context.Context, searchText string,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	var (
		foundRepos          = make([]mTypes.RepoMetadata, 0)
		manifestMetadataMap = make(map[string]mTypes.ManifestMetadata)
		indexDataMap        = make(map[string]mTypes.IndexData)
	)

	err := bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			repoBuck      = transaction.Bucket([]byte(RepoMetadataBucket))
			indexBuck     = transaction.Bucket([]byte(IndexDataBucket))
			manifestBuck  = transaction.Bucket([]byte(ManifestDataBucket))
			userBookmarks = getUserBookmarks(ctx, transaction)
			userStars     = getUserStars(ctx, transaction)
		)

		cursor := repoBuck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			var repoMeta mTypes.RepoMetadata

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			rank := common.RankRepoName(searchText, repoMeta.Name)
			if rank == -1 {
				continue
			}

			repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)
			repoMeta.Rank = rank

			for tag, descriptor := range repoMeta.Tags {
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					manifestDigest := descriptor.Digest

					manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest,
						manifestMetadataMap, manifestBuck)
					if err != nil {
						return fmt.Errorf("metadb: error fetching manifest meta for manifest with digest %s %w",
							manifestDigest, err)
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				case ispec.MediaTypeImageIndex:
					indexDigest := descriptor.Digest

					indexData, err := fetchIndexDataWithCheck(indexDigest, indexDataMap, indexBuck)
					if err != nil {
						return fmt.Errorf("metadb: error fetching index data for index with digest %s %w",
							indexDigest, err)
					}

					var indexContent ispec.Index

					err = json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return fmt.Errorf("metadb: error while unmashaling index content for %s:%s %w",
							repoName, tag, err)
					}

					for _, manifest := range indexContent.Manifests {
						manifestDigest := manifest.Digest

						manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest.String(),
							manifestMetadataMap, manifestBuck)
						if err != nil {
							return err
						}

						manifestMetadataMap[manifest.Digest.String()] = manifestMeta
					}

					indexDataMap[indexDigest] = indexData
				default:
					bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

					continue
				}
			}

			foundRepos = append(foundRepos, repoMeta)
		}

		return nil
	})

	return foundRepos, manifestMetadataMap, indexDataMap, err
}

func fetchManifestMetaWithCheck(repoMeta mTypes.RepoMetadata, manifestDigest string,
	manifestMetadataMap map[string]mTypes.ManifestMetadata, manifestBuck *bbolt.Bucket,
) (mTypes.ManifestMetadata, error) {
	manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

	if !manifestDownloaded {
		var manifestData mTypes.ManifestData

		manifestDataBlob := manifestBuck.Get([]byte(manifestDigest))
		if manifestDataBlob == nil {
			return mTypes.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		err := json.Unmarshal(manifestDataBlob, &manifestData)
		if err != nil {
			return mTypes.ManifestMetadata{}, fmt.Errorf("metadb: error while unmarshaling manifest metadata for digest %s %w",
				manifestDigest, err)
		}

		manifestMeta = NewManifestMetadata(manifestDigest, repoMeta, manifestData)
	}

	return manifestMeta, nil
}

func fetchIndexDataWithCheck(indexDigest string, indexDataMap map[string]mTypes.IndexData,
	indexBuck *bbolt.Bucket,
) (mTypes.IndexData, error) {
	var (
		indexData mTypes.IndexData
		err       error
	)

	indexData, indexExists := indexDataMap[indexDigest]

	if !indexExists {
		indexDataBlob := indexBuck.Get([]byte(indexDigest))
		if indexDataBlob == nil {
			return mTypes.IndexData{}, zerr.ErrIndexDataNotFount
		}

		err := json.Unmarshal(indexDataBlob, &indexData)
		if err != nil {
			return mTypes.IndexData{},
				fmt.Errorf("metadb: error while unmashaling index data for digest %s %w", indexDigest, err)
		}
	}

	return indexData, err
}

func NewManifestMetadata(manifestDigest string, repoMeta mTypes.RepoMetadata,
	manifestData mTypes.ManifestData,
) mTypes.ManifestMetadata {
	manifestMeta := mTypes.ManifestMetadata{
		ManifestBlob: manifestData.ManifestBlob,
		ConfigBlob:   manifestData.ConfigBlob,
	}

	manifestMeta.DownloadCount = repoMeta.Statistics[manifestDigest].DownloadCount

	manifestMeta.Signatures = mTypes.ManifestSignatures{}
	if repoMeta.Signatures[manifestDigest] != nil {
		manifestMeta.Signatures = repoMeta.Signatures[manifestDigest]
	}

	return manifestMeta
}

func (bdw *BoltDB) FilterTags(ctx context.Context, filterFunc mTypes.FilterFunc,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error,
) {
	var (
		foundRepos          = make([]mTypes.RepoMetadata, 0)
		manifestMetadataMap = make(map[string]mTypes.ManifestMetadata)
		indexDataMap        = make(map[string]mTypes.IndexData)
	)

	err := bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			repoBuck      = transaction.Bucket([]byte(RepoMetadataBucket))
			indexBuck     = transaction.Bucket([]byte(IndexDataBucket))
			manifestBuck  = transaction.Bucket([]byte(ManifestDataBucket))
			cursor        = repoBuck.Cursor()
			userBookmarks = getUserBookmarks(ctx, transaction)
			userStars     = getUserStars(ctx, transaction)
		)

		repoName, repoMetaBlob := cursor.First()

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := mTypes.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

			matchedTags := make(map[string]mTypes.Descriptor)
			// take all manifestsMeta
			for tag, descriptor := range repoMeta.Tags {
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					manifestDigest := descriptor.Digest

					manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest, manifestMetadataMap, manifestBuck)
					if err != nil {
						return fmt.Errorf("metadb: error while unmashaling manifest metadata for digest %s %w", manifestDigest, err)
					}

					if filterFunc(repoMeta, manifestMeta) {
						matchedTags[tag] = descriptor
						manifestMetadataMap[manifestDigest] = manifestMeta
					}
				case ispec.MediaTypeImageIndex:
					indexDigest := descriptor.Digest

					indexData, err := fetchIndexDataWithCheck(indexDigest, indexDataMap, indexBuck)
					if err != nil {
						return fmt.Errorf("metadb: error while getting index data for digest %s %w", indexDigest, err)
					}

					var indexContent ispec.Index

					err = json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return fmt.Errorf("metadb: error while unmashaling index content for digest %s %w", indexDigest, err)
					}

					matchedManifests := []ispec.Descriptor{}

					for _, manifest := range indexContent.Manifests {
						manifestDigest := manifest.Digest.String()

						manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest, manifestMetadataMap, manifestBuck)
						if err != nil {
							return fmt.Errorf("metadb: error while getting manifest data for digest %s %w", manifestDigest, err)
						}

						if filterFunc(repoMeta, manifestMeta) {
							matchedManifests = append(matchedManifests, manifest)
							manifestMetadataMap[manifestDigest] = manifestMeta
						}
					}

					if len(matchedManifests) > 0 {
						indexContent.Manifests = matchedManifests

						indexBlob, err := json.Marshal(indexContent)
						if err != nil {
							return err
						}

						indexData.IndexBlob = indexBlob

						indexDataMap[indexDigest] = indexData
						matchedTags[tag] = descriptor
					}
				default:
					bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

					continue
				}
			}

			if len(matchedTags) == 0 {
				continue
			}

			repoMeta.Tags = matchedTags

			foundRepos = append(foundRepos, repoMeta)
		}

		return nil
	})

	return foundRepos, manifestMetadataMap, indexDataMap, err
}

func (bdw *BoltDB) FilterRepos(ctx context.Context, filter mTypes.FilterRepoFunc) (
	[]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error,
) {
	foundRepos := make([]mTypes.RepoMetadata, 0)

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		var (
			buck          = tx.Bucket([]byte(RepoMetadataBucket))
			cursor        = buck.Cursor()
			userBookmarks = getUserBookmarks(ctx, tx)
			userStars     = getUserStars(ctx, tx)
		)

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := mTypes.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

			if filter(repoMeta) {
				foundRepos = append(foundRepos, repoMeta)
			}
		}

		return nil
	})
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{}, err
	}

	foundManifestMetadataMap, foundIndexDataMap, err := common.FetchDataForRepos(bdw, foundRepos)

	return foundRepos, foundManifestMetadataMap, foundIndexDataMap, err
}

func (bdw *BoltDB) SearchTags(ctx context.Context, searchText string,
) ([]mTypes.RepoMetadata, map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	var (
		foundRepos          = make([]mTypes.RepoMetadata, 0)
		manifestMetadataMap = make(map[string]mTypes.ManifestMetadata)
		indexDataMap        = make(map[string]mTypes.IndexData)
	)

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []mTypes.RepoMetadata{}, map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
			fmt.Errorf("metadb: error while parsing search text, invalid format %w", err)
	}

	err = bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			repoBuck      = transaction.Bucket([]byte(RepoMetadataBucket))
			indexBuck     = transaction.Bucket([]byte(IndexDataBucket))
			manifestBuck  = transaction.Bucket([]byte(ManifestDataBucket))
			userBookmarks = getUserBookmarks(ctx, transaction)
			userStars     = getUserStars(ctx, transaction)
		)

		repoName, repoMetaBlob := repoBuck.Cursor().Seek([]byte(searchedRepo))

		if string(repoName) != searchedRepo {
			return nil
		}

		if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
			return err
		}

		repoMeta := mTypes.RepoMetadata{}

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
		repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

		matchedTags := make(map[string]mTypes.Descriptor)

		for tag, descriptor := range repoMeta.Tags {
			if !strings.HasPrefix(tag, searchedTag) {
				continue
			}

			matchedTags[tag] = descriptor

			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestDigest := descriptor.Digest

				manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest, manifestMetadataMap, manifestBuck)
				if err != nil {
					return fmt.Errorf("metadb: error fetching manifest meta for manifest with digest %s %w",
						manifestDigest, err)
				}

				manifestMetadataMap[descriptor.Digest] = manifestMeta
			case ispec.MediaTypeImageIndex:
				indexDigest := descriptor.Digest

				indexData, err := fetchIndexDataWithCheck(indexDigest, indexDataMap, indexBuck)
				if err != nil {
					return fmt.Errorf("metadb: error fetching index data for index with digest %s %w",
						indexDigest, err)
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return fmt.Errorf("metadb: error collecting filter data for index with digest %s %w",
						indexDigest, err)
				}

				for _, manifest := range indexContent.Manifests {
					manifestDigest := manifest.Digest.String()

					manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest, manifestMetadataMap, manifestBuck)
					if err != nil {
						return fmt.Errorf("metadb: error fetching from db manifest meta for manifest with digest %s %w",
							manifestDigest, err)
					}

					manifestMetadataMap[manifestDigest] = manifestMeta
				}

				indexDataMap[indexDigest] = indexData
			default:
				bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

				continue
			}
		}

		if len(matchedTags) == 0 {
			return nil
		}

		repoMeta.Tags = matchedTags

		foundRepos = append(foundRepos, repoMeta)

		return nil
	})

	return foundRepos, manifestMetadataMap, indexDataMap, err
}

func (bdw *BoltDB) ToggleStarRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	var res mTypes.ToggleState

	if err := bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		isRepoStarred := zcommon.Contains(userData.StarredRepos, repo)

		if isRepoStarred {
			res = mTypes.Removed
			userData.StarredRepos = zcommon.RemoveFrom(userData.StarredRepos, repo)
		} else {
			res = mTypes.Added
			userData.StarredRepos = append(userData.StarredRepos, repo)
		}

		err = bdw.setUserData(userid, tx, userData)
		if err != nil {
			return err
		}

		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta mTypes.RepoMetadata

		err = json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		switch res {
		case mTypes.Added:
			repoMeta.Stars++
		case mTypes.Removed:
			repoMeta.Stars--
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		err = repoBuck.Put([]byte(repo), repoMetaBlob)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return mTypes.NotChanged, err
	}

	return res, nil
}

func (bdw *BoltDB) GetStarredRepos(ctx context.Context) ([]string, error) {
	userData, err := bdw.GetUserData(ctx)
	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userData.StarredRepos, err
}

func (bdw *BoltDB) ToggleBookmarkRepo(ctx context.Context, repo string) (mTypes.ToggleState, error) {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return mTypes.NotChanged, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		return mTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	var res mTypes.ToggleState

	if err := bdw.DB.Update(func(transaction *bbolt.Tx) error { //nolint:dupl
		var userData mTypes.UserData

		err := bdw.getUserData(userid, transaction, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		isRepoBookmarked := zcommon.Contains(userData.BookmarkedRepos, repo)

		if isRepoBookmarked {
			res = mTypes.Removed
			userData.BookmarkedRepos = zcommon.RemoveFrom(userData.BookmarkedRepos, repo)
		} else {
			res = mTypes.Added
			userData.BookmarkedRepos = append(userData.BookmarkedRepos, repo)
		}

		return bdw.setUserData(userid, transaction, userData)
	}); err != nil {
		return mTypes.NotChanged, err
	}

	return res, nil
}

func (bdw *BoltDB) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	userData, err := bdw.GetUserData(ctx)
	if errors.Is(err, zerr.ErrUserDataNotFound) || errors.Is(err, zerr.ErrUserDataNotAllowed) {
		return []string{}, nil
	}

	return userData.BookmarkedRepos, err
}

func (bdw *BoltDB) PatchDB() error {
	var DBVersion string

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		versionBuck := tx.Bucket([]byte(VersionBucket))
		DBVersion = string(versionBuck.Get([]byte(version.DBVersionKey)))

		return nil
	})
	if err != nil {
		return fmt.Errorf("patching the database failed, can't read db version %w", err)
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return fmt.Errorf("DB has broken format, no version found %w", err)
	}

	for patchIndex, patch := range bdw.Patches {
		if patchIndex < version.GetVersionIndex(DBVersion) {
			continue
		}

		err := patch(bdw.DB)
		if err != nil {
			return err
		}
	}

	return nil
}

func getUserStars(ctx context.Context, transaction *bbolt.Tx) []string {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return []string{}
	}

	var (
		userData mTypes.UserData
		userid   = localCtx.GetUsernameFromContext(acCtx)
		userdb   = transaction.Bucket([]byte(UserDataBucket))
	)

	if userid == "" || userdb == nil {
		return []string{}
	}

	mdata := userdb.Get([]byte(userid))
	if mdata == nil {
		return []string{}
	}

	if err := json.Unmarshal(mdata, &userData); err != nil {
		return []string{}
	}

	return userData.StarredRepos
}

func getUserBookmarks(ctx context.Context, transaction *bbolt.Tx) []string {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return []string{}
	}

	var (
		userData mTypes.UserData
		userid   = localCtx.GetUsernameFromContext(acCtx)
		userdb   = transaction.Bucket([]byte(UserDataBucket))
	)

	if userid == "" || userdb == nil {
		return []string{}
	}

	mdata := userdb.Get([]byte(userid))
	if mdata == nil {
		return []string{}
	}

	if err := json.Unmarshal(mdata, &userData); err != nil {
		return []string{}
	}

	return userData.BookmarkedRepos
}

func (bdw *BoltDB) SetUserGroups(ctx context.Context, groups []string) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		userData.Groups = append(userData.Groups, groups...)

		err = bdw.setUserData(userid, tx, userData)

		return err
	})

	return err
}

func (bdw *BoltDB) GetUserGroups(ctx context.Context) ([]string, error) {
	userData, err := bdw.GetUserData(ctx)

	return userData.Groups, err
}

func (bdw *BoltDB) UpdateUserAPIKeyLastUsed(ctx context.Context, hashedKey string) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil {
			return err
		}

		apiKeyDetails := userData.APIKeys[hashedKey]
		apiKeyDetails.LastUsed = time.Now()

		userData.APIKeys[hashedKey] = apiKeyDetails

		err = bdw.setUserData(userid, tx, userData)

		return err
	})

	return err
}

func (bdw *BoltDB) IsAPIKeyExpired(ctx context.Context, hashedKey string) (bool, error) {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return false, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous
		return false, zerr.ErrUserDataNotAllowed
	}

	var isExpired bool

	err = bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		var userData mTypes.UserData

		err := bdw.getUserData(userid, tx, &userData)
		if err != nil {
			return err
		}

		apiKeyDetails := userData.APIKeys[hashedKey]
		if apiKeyDetails.IsExpired {
			isExpired = true

			return nil
		}

		// if expiresAt is not nil value
		if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
			isExpired = true
			apiKeyDetails.IsExpired = true
		}

		userData.APIKeys[hashedKey] = apiKeyDetails

		err = bdw.setUserData(userid, tx, userData)

		return err
	})

	return isExpired, err
}

func (bdw *BoltDB) GetUserAPIKeys(ctx context.Context) ([]mTypes.APIKeyDetails, error) {
	apiKeys := make([]mTypes.APIKeyDetails, 0)

	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return nil, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return nil, zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.Update(func(transaction *bbolt.Tx) error {
		var userData mTypes.UserData

		err = bdw.getUserData(userid, transaction, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		for hashedKey, apiKeyDetails := range userData.APIKeys {
			// if expiresAt is not nil value
			if !apiKeyDetails.ExpirationDate.Equal(time.Time{}) && time.Now().After(apiKeyDetails.ExpirationDate) {
				apiKeyDetails.IsExpired = true
			}

			userData.APIKeys[hashedKey] = apiKeyDetails

			err = bdw.setUserData(userid, transaction, userData)
			if err != nil {
				return err
			}

			apiKeys = append(apiKeys, apiKeyDetails)
		}

		return nil
	})

	return apiKeys, err
}

func (bdw *BoltDB) AddUserAPIKey(ctx context.Context, hashedKey string, apiKeyDetails *mTypes.APIKeyDetails) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.Update(func(transaction *bbolt.Tx) error {
		var userData mTypes.UserData

		apiKeysbuck := transaction.Bucket([]byte(UserAPIKeysBucket))
		if apiKeysbuck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := apiKeysbuck.Put([]byte(hashedKey), []byte(userid))
		if err != nil {
			return fmt.Errorf("metaDB: error while setting userData for identity %s %w", userid, err)
		}

		err = bdw.getUserData(userid, transaction, &userData)
		if err != nil && !errors.Is(err, zerr.ErrUserDataNotFound) {
			return err
		}

		if userData.APIKeys == nil {
			userData.APIKeys = make(map[string]mTypes.APIKeyDetails)
		}

		userData.APIKeys[hashedKey] = *apiKeyDetails

		err = bdw.setUserData(userid, transaction, userData)

		return err
	})

	return err
}

func (bdw *BoltDB) DeleteUserAPIKey(ctx context.Context, keyID string) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.Update(func(transaction *bbolt.Tx) error {
		var userData mTypes.UserData

		apiKeysbuck := transaction.Bucket([]byte(UserAPIKeysBucket))
		if apiKeysbuck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := bdw.getUserData(userid, transaction, &userData)
		if err != nil {
			return err
		}

		for hash, apiKeyDetails := range userData.APIKeys {
			if apiKeyDetails.UUID == keyID {
				delete(userData.APIKeys, hash)

				err := apiKeysbuck.Delete([]byte(hash))
				if err != nil {
					return fmt.Errorf("userDB: error while deleting userAPIKey entry for hash %s %w", hash, err)
				}
			}
		}

		return bdw.setUserData(userid, transaction, userData)
	})

	return err
}

func (bdw *BoltDB) GetUserAPIKeyInfo(hashedKey string) (string, error) {
	var userid string
	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(UserAPIKeysBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		uiBlob := buck.Get([]byte(hashedKey))
		if len(uiBlob) == 0 {
			return zerr.ErrUserAPIKeyNotFound
		}

		userid = string(uiBlob)

		return nil
	})

	return userid, err
}

func (bdw *BoltDB) GetUserData(ctx context.Context) (mTypes.UserData, error) {
	var userData mTypes.UserData

	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return userData, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return userData, zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.View(func(tx *bbolt.Tx) error {
		return bdw.getUserData(userid, tx, &userData)
	})

	return userData, err
}

func (bdw *BoltDB) getUserData(userid string, transaction *bbolt.Tx, res *mTypes.UserData) error {
	buck := transaction.Bucket([]byte(UserDataBucket))
	if buck == nil {
		return zerr.ErrBucketDoesNotExist
	}

	upBlob := buck.Get([]byte(userid))

	if len(upBlob) == 0 {
		return zerr.ErrUserDataNotFound
	}

	err := json.Unmarshal(upBlob, res)
	if err != nil {
		return err
	}

	return nil
}

func (bdw *BoltDB) SetUserData(ctx context.Context, userData mTypes.UserData) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.Update(func(tx *bbolt.Tx) error {
		return bdw.setUserData(userid, tx, userData)
	})

	return err
}

func (bdw *BoltDB) setUserData(userid string, transaction *bbolt.Tx, userData mTypes.UserData) error {
	buck := transaction.Bucket([]byte(UserDataBucket))
	if buck == nil {
		return zerr.ErrBucketDoesNotExist
	}

	upBlob, err := json.Marshal(userData)
	if err != nil {
		return err
	}

	err = buck.Put([]byte(userid), upBlob)
	if err != nil {
		return fmt.Errorf("metaDB: error while setting userData for identity %s %w", userid, err)
	}

	return nil
}

func (bdw *BoltDB) DeleteUserData(ctx context.Context) error {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return zerr.ErrUserDataNotAllowed
	}

	err = bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(UserDataBucket))
		if buck == nil {
			return zerr.ErrBucketDoesNotExist
		}

		err := buck.Delete([]byte(userid))
		if err != nil {
			return fmt.Errorf("metaDB: error while deleting userData for identity %s %w", userid, err)
		}

		return nil
	})

	return err
}
