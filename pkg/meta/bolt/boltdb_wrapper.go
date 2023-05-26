package bolt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/common"
	"zotregistry.io/zot/pkg/meta/pagination"
	"zotregistry.io/zot/pkg/meta/signatures"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/meta/version"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

type DBWrapper struct {
	DB      *bbolt.DB
	Patches []func(DB *bbolt.DB) error
	Log     log.Logger
}

func NewBoltDBWrapper(boltDB *bbolt.DB, log log.Logger) (*DBWrapper, error) {
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

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &DBWrapper{
		DB:      boltDB,
		Patches: version.GetBoltDBPatches(),
		Log:     log,
	}, nil
}

func (bdw *DBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData metaTypes.ManifestData) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestDataBucket))

		mdBlob, err := json.Marshal(manifestData)
		if err != nil {
			return fmt.Errorf("repodb: error while calculating blob for manifest with digest %s %w", manifestDigest, err)
		}

		err = buck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return fmt.Errorf("repodb: error while setting manifest data with for digest %s %w", manifestDigest, err)
		}

		return nil
	})

	return err
}

func (bdw *DBWrapper) GetManifestData(manifestDigest godigest.Digest) (metaTypes.ManifestData, error) {
	var manifestData metaTypes.ManifestData

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestDataBucket))

		mdBlob := buck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestDataNotFound
		}

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return fmt.Errorf("repodb: error while unmashaling manifest meta for digest %s %w", manifestDigest, err)
		}

		return nil
	})

	return manifestData, err
}

func (bdw *DBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest,
	manifestMeta metaTypes.ManifestMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		dataBuck := tx.Bucket([]byte(ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMeta := metaTypes.RepoMetadata{
			Name:       repo,
			Tags:       map[string]metaTypes.Descriptor{},
			Statistics: map[string]metaTypes.DescriptorStatistics{},
			Signatures: map[string]metaTypes.ManifestSignatures{},
			Referrers:  map[string][]metaTypes.ReferrerInfo{},
		}

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}
		}

		mdBlob, err := json.Marshal(metaTypes.ManifestData{
			ManifestBlob: manifestMeta.ManifestBlob,
			ConfigBlob:   manifestMeta.ConfigBlob,
		})
		if err != nil {
			return fmt.Errorf("repodb: error while calculating blob for manifest with digest %s %w", manifestDigest, err)
		}

		err = dataBuck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return fmt.Errorf("repodb: error while setting manifest meta with for digest %s %w", manifestDigest, err)
		}

		updatedRepoMeta := common.UpdateManifestMeta(repoMeta, manifestDigest, manifestMeta)

		updatedRepoMetaBlob, err := json.Marshal(updatedRepoMeta)
		if err != nil {
			return fmt.Errorf("repodb: error while calculating blob for updated repo meta '%s' %w", repo, err)
		}

		return repoBuck.Put([]byte(repo), updatedRepoMetaBlob)
	})

	return err
}

func (bdw *DBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest) (metaTypes.ManifestMetadata, error) {
	var manifestMetadata metaTypes.ManifestMetadata

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		dataBuck := tx.Bucket([]byte(ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		mdBlob := dataBuck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestData metaTypes.ManifestData

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return fmt.Errorf("repodb: error while unmashaling manifest meta for digest %s %w", manifestDigest, err)
		}

		var repoMeta metaTypes.RepoMetadata

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err = json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return fmt.Errorf("repodb: error while unmashaling manifest meta for digest %s %w", manifestDigest, err)
			}
		}

		manifestMetadata.ManifestBlob = manifestData.ManifestBlob
		manifestMetadata.ConfigBlob = manifestData.ConfigBlob
		manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

		manifestMetadata.Signatures = metaTypes.ManifestSignatures{}
		if repoMeta.Signatures[manifestDigest.String()] != nil {
			manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
		}

		return nil
	})

	return manifestMetadata, err
}

func (bdw *DBWrapper) SetIndexData(indexDigest godigest.Digest, indexMetadata metaTypes.IndexData) error {
	// we make the assumption that the oci layout is consistent and all manifests refferenced inside the
	// index are present
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(IndexDataBucket))

		imBlob, err := json.Marshal(indexMetadata)
		if err != nil {
			return fmt.Errorf("repodb: error while calculating blob for manifest with digest %s %w", indexDigest, err)
		}

		err = buck.Put([]byte(indexDigest), imBlob)
		if err != nil {
			return fmt.Errorf("repodb: error while setting manifest meta with for digest %s %w", indexDigest, err)
		}

		return nil
	})

	return err
}

func (bdw *DBWrapper) GetIndexData(indexDigest godigest.Digest) (metaTypes.IndexData, error) {
	var indexMetadata metaTypes.IndexData

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(IndexDataBucket))

		mmBlob := buck.Get([]byte(indexDigest))

		if len(mmBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		err := json.Unmarshal(mmBlob, &indexMetadata)
		if err != nil {
			return fmt.Errorf("repodb: error while unmashaling manifest meta for digest %s %w", indexDigest, err)
		}

		return nil
	})

	return indexMetadata, err
}

func (bdw DBWrapper) SetReferrer(repo string, referredDigest godigest.Digest, referrer metaTypes.ReferrerInfo) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			var err error

			// create a new object
			repoMeta := metaTypes.RepoMetadata{
				Name:       repo,
				Tags:       map[string]metaTypes.Descriptor{},
				Statistics: map[string]metaTypes.DescriptorStatistics{},
				Signatures: map[string]metaTypes.ManifestSignatures{},
				Referrers: map[string][]metaTypes.ReferrerInfo{
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
		var repoMeta metaTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		refferers := repoMeta.Referrers[referredDigest.String()]

		for i := range refferers {
			if refferers[i].Digest == referrer.Digest {
				return nil
			}
		}

		refferers = append(refferers, referrer)

		repoMeta.Referrers[referredDigest.String()] = refferers

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) DeleteReferrer(repo string, referredDigest godigest.Digest,
	referrerDigest godigest.Digest,
) error {
	return bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

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

func (bdw DBWrapper) GetReferrersInfo(repo string, referredDigest godigest.Digest, artifactTypes []string,
) ([]metaTypes.ReferrerInfo, error) {
	referrersInfoResult := []metaTypes.ReferrerInfo{}

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

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

func (bdw *DBWrapper) SetRepoReference(repo string, reference string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if err := common.ValidateRepoReferenceInput(repo, reference, manifestDigest); err != nil {
		return err
	}

	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		repoMeta := metaTypes.RepoMetadata{
			Name:       repo,
			Tags:       map[string]metaTypes.Descriptor{},
			Statistics: map[string]metaTypes.DescriptorStatistics{},
			Signatures: map[string]metaTypes.ManifestSignatures{},
			Referrers:  map[string][]metaTypes.ReferrerInfo{},
		}

		// object not found
		if len(repoMetaBlob) > 0 {
			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}
		}

		if !common.ReferenceIsDigest(reference) {
			repoMeta.Tags[reference] = metaTypes.Descriptor{
				Digest:    manifestDigest.String(),
				MediaType: mediaType,
			}
		}

		if _, ok := repoMeta.Statistics[manifestDigest.String()]; !ok {
			repoMeta.Statistics[manifestDigest.String()] = metaTypes.DescriptorStatistics{DownloadCount: 0}
		}

		if _, ok := repoMeta.Signatures[manifestDigest.String()]; !ok {
			repoMeta.Signatures[manifestDigest.String()] = metaTypes.ManifestSignatures{}
		}

		if _, ok := repoMeta.Referrers[manifestDigest.String()]; !ok {
			repoMeta.Referrers[manifestDigest.String()] = []metaTypes.ReferrerInfo{}
		}

		repoMetaBlob, err := json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *DBWrapper) GetRepoMeta(repo string) (metaTypes.RepoMetadata, error) {
	var repoMeta metaTypes.RepoMetadata

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

func (bdw *DBWrapper) GetUserRepoMeta(ctx context.Context, repo string) (metaTypes.RepoMetadata, error) {
	var repoMeta metaTypes.RepoMetadata

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

func (bdw *DBWrapper) SetRepoMeta(repo string, repoMeta metaTypes.RepoMetadata) error {
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

func (bdw *DBWrapper) DeleteRepoTag(repo string, tag string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return nil
		}

		// object found
		var repoMeta metaTypes.RepoMetadata

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

func (bdw *DBWrapper) IncrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

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

func (bdw *DBWrapper) DecrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

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

func (bdw *DBWrapper) GetRepoStars(repo string) (int, error) {
	stars := 0

	err := bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		buck.Get([]byte(repo))
		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		stars = repoMeta.Stars

		return nil
	})

	return stars, err
}

func (bdw *DBWrapper) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta metaTypes.RepoMetadata) bool,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, error) {
	var (
		foundRepos = make([]metaTypes.RepoMetadata, 0)
		pageFinder pagination.PageFinder
	)

	pageFinder, err := pagination.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	err = bdw.DB.View(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := metaTypes.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				pageFinder.Add(metaTypes.DetailedRepoMeta{
					RepoMetadata: repoMeta,
				})
			}
		}

		foundRepos, _ = pageFinder.Page()

		return nil
	})

	return foundRepos, err
}

func (bdw *DBWrapper) IncrementImageDownloads(repo string, reference string) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

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

func (bdw *DBWrapper) UpdateSignaturesValidity(repo string, manifestDigest godigest.Digest) error {
	err := bdw.DB.Update(func(transaction *bbolt.Tx) error {
		// get ManifestData of signed manifest
		manifestBuck := transaction.Bucket([]byte(ManifestDataBucket))
		mdBlob := manifestBuck.Get([]byte(manifestDigest))

		var blob []byte

		if len(mdBlob) != 0 {
			var manifestData metaTypes.ManifestData

			err := json.Unmarshal(mdBlob, &manifestData)
			if err != nil {
				return fmt.Errorf("repodb: %w error while unmashaling manifest meta for digest %s", err, manifestDigest)
			}

			blob = manifestData.ManifestBlob
		} else {
			var indexData metaTypes.IndexData

			indexBuck := transaction.Bucket([]byte(IndexDataBucket))
			idBlob := indexBuck.Get([]byte(manifestDigest))

			if len(idBlob) == 0 {
				// manifest meta not found, updating signatures with details about validity and author will not be performed
				return nil
			}

			err := json.Unmarshal(idBlob, &indexData)
			if err != nil {
				return fmt.Errorf("repodb: %w error while unmashaling index meta for digest %s", err, manifestDigest)
			}

			blob = indexData.IndexBlob
		}

		// update signatures with details about validity and author
		repoBuck := transaction.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		manifestSignatures := metaTypes.ManifestSignatures{}
		for sigType, sigs := range repoMeta.Signatures[manifestDigest.String()] {
			signaturesInfo := []metaTypes.SignatureInfo{}

			for _, sigInfo := range sigs {
				layersInfo := []metaTypes.LayerInfo{}

				for _, layerInfo := range sigInfo.LayersInfo {
					author, date, isTrusted, _ := signatures.VerifySignature(sigType, layerInfo.LayerContent, layerInfo.SignatureKey,
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

				signaturesInfo = append(signaturesInfo, metaTypes.SignatureInfo{
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

func (bdw *DBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta metaTypes.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		if len(repoMetaBlob) == 0 {
			var err error
			// create a new object
			repoMeta := metaTypes.RepoMetadata{
				Name: repo,
				Tags: map[string]metaTypes.Descriptor{},
				Signatures: map[string]metaTypes.ManifestSignatures{
					signedManifestDigest.String(): {
						sygMeta.SignatureType: []metaTypes.SignatureInfo{
							{
								SignatureManifestDigest: sygMeta.SignatureDigest,
								LayersInfo:              sygMeta.LayersInfo,
							},
						},
					},
				},
				Statistics: map[string]metaTypes.DescriptorStatistics{},
				Referrers:  map[string][]metaTypes.ReferrerInfo{},
			}

			repoMetaBlob, err = json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}

		var repoMeta metaTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		var (
			manifestSignatures metaTypes.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			manifestSignatures = metaTypes.ManifestSignatures{}
		}

		signatureSlice := manifestSignatures[sygMeta.SignatureType]
		if !common.SignatureAlreadyExists(signatureSlice, sygMeta) {
			if sygMeta.SignatureType == signatures.NotationSignature {
				signatureSlice = append(signatureSlice, metaTypes.SignatureInfo{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				})
			} else if sygMeta.SignatureType == signatures.CosignSignature {
				signatureSlice = []metaTypes.SignatureInfo{{
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

func (bdw *DBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta metaTypes.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bbolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		sigType := sigMeta.SignatureType

		var (
			manifestSignatures metaTypes.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			return zerr.ErrManifestMetaNotFound
		}

		signatureSlice := manifestSignatures[sigType]

		newSignatureSlice := make([]metaTypes.SignatureInfo, 0, len(signatureSlice)-1)

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

func (bdw *DBWrapper) SearchRepos(ctx context.Context, searchText string, filter metaTypes.Filter,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, zcommon.PageInfo,
	error,
) {
	var (
		foundRepos               = make([]metaTypes.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]metaTypes.ManifestMetadata)
		foundindexDataMap        = make(map[string]metaTypes.IndexData)
		pageFinder               pagination.PageFinder
		pageInfo                 zcommon.PageInfo
	)

	pageFinder, err := pagination.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			zcommon.PageInfo{}, err
	}

	err = bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]metaTypes.ManifestMetadata)
			indexDataMap        = make(map[string]metaTypes.IndexData)
			repoBuck            = transaction.Bucket([]byte(RepoMetadataBucket))
			indexBuck           = transaction.Bucket([]byte(IndexDataBucket))
			manifestBuck        = transaction.Bucket([]byte(ManifestDataBucket))
			userBookmarks       = getUserBookmarks(ctx, transaction)
			userStars           = getUserStars(ctx, transaction)
		)

		cursor := repoBuck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			var repoMeta metaTypes.RepoMetadata

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

			rank := common.RankRepoName(searchText, repoMeta.Name)
			if rank == -1 {
				continue
			}

			var (
				repoDownloads   = 0
				repoLastUpdated = time.Time{}
				osSet           = map[string]bool{}
				archSet         = map[string]bool{}
				noImageChecked  = true
				isSigned        = false
			)

			for tag, descriptor := range repoMeta.Tags {
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					manifestDigest := descriptor.Digest

					manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest,
						manifestMetadataMap, manifestBuck)
					if err != nil {
						return fmt.Errorf("repodb: error fetching manifest meta for manifest with digest %s %w",
							manifestDigest, err)
					}

					manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
					if err != nil {
						return fmt.Errorf("repodb: error collecting filter data for manifest with digest %s %w",
							manifestDigest, err)
					}

					repoDownloads += manifestFilterData.DownloadCount

					for _, os := range manifestFilterData.OsList {
						osSet[os] = true
					}
					for _, arch := range manifestFilterData.ArchList {
						archSet[arch] = true
					}

					repoLastUpdated, noImageChecked, isSigned = common.CheckImageLastUpdated(repoLastUpdated, isSigned,
						noImageChecked, manifestFilterData)

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				case ispec.MediaTypeImageIndex:
					indexDigest := descriptor.Digest

					indexData, err := fetchIndexDataWithCheck(indexDigest, indexDataMap, indexBuck)
					if err != nil {
						return fmt.Errorf("repodb: error fetching index data for index with digest %s %w",
							indexDigest, err)
					}

					var indexContent ispec.Index

					err = json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return fmt.Errorf("repodb: error while unmashaling index content for %s:%s %w",
							repoName, tag, err)
					}

					// this also updates manifestMetadataMap
					indexFilterData, err := collectImageIndexFilterInfo(indexDigest, repoMeta, indexData, manifestMetadataMap,
						manifestBuck)
					if err != nil {
						return fmt.Errorf("repodb: error collecting filter data for index with digest %s %w",
							indexDigest, err)
					}

					for _, arch := range indexFilterData.ArchList {
						archSet[arch] = true
					}

					for _, os := range indexFilterData.OsList {
						osSet[os] = true
					}

					repoDownloads += indexFilterData.DownloadCount

					repoLastUpdated, noImageChecked, isSigned = common.CheckImageLastUpdated(repoLastUpdated, isSigned,
						noImageChecked, indexFilterData)

					indexDataMap[indexDigest] = indexData
				default:
					bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

					continue
				}
			}

			repoFilterData := metaTypes.FilterData{
				OsList:        common.GetMapKeys(osSet),
				ArchList:      common.GetMapKeys(archSet),
				LastUpdated:   repoLastUpdated,
				DownloadCount: repoDownloads,
				IsSigned:      isSigned,
				IsBookmarked:  repoMeta.IsBookmarked,
				IsStarred:     repoMeta.IsStarred,
			}

			if !common.AcceptedByFilter(filter, repoFilterData) {
				continue
			}

			pageFinder.Add(metaTypes.DetailedRepoMeta{
				RepoMetadata: repoMeta,
				Rank:         rank,
				Downloads:    repoDownloads,
				UpdateTime:   repoLastUpdated,
			})
		}

		foundRepos, pageInfo = pageFinder.Page()

		foundManifestMetadataMap, foundindexDataMap, err = common.FilterDataByRepo(foundRepos, manifestMetadataMap,
			indexDataMap)

		return err
	})

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func fetchManifestMetaWithCheck(repoMeta metaTypes.RepoMetadata, manifestDigest string,
	manifestMetadataMap map[string]metaTypes.ManifestMetadata, manifestBuck *bbolt.Bucket,
) (metaTypes.ManifestMetadata, error) {
	manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

	if !manifestDownloaded {
		var manifestData metaTypes.ManifestData

		manifestDataBlob := manifestBuck.Get([]byte(manifestDigest))
		if manifestDataBlob == nil {
			return metaTypes.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		err := json.Unmarshal(manifestDataBlob, &manifestData)
		if err != nil {
			return metaTypes.ManifestMetadata{},
				fmt.Errorf("repodb: error while unmarshaling manifest metadata for digest %s %w", manifestDigest, err)
		}

		manifestMeta = NewManifestMetadata(manifestDigest, repoMeta, manifestData)
	}

	return manifestMeta, nil
}

func fetchIndexDataWithCheck(indexDigest string, indexDataMap map[string]metaTypes.IndexData,
	indexBuck *bbolt.Bucket,
) (metaTypes.IndexData, error) {
	var (
		indexData metaTypes.IndexData
		err       error
	)

	indexData, indexExists := indexDataMap[indexDigest]

	if !indexExists {
		indexDataBlob := indexBuck.Get([]byte(indexDigest))
		if indexDataBlob == nil {
			return metaTypes.IndexData{}, zerr.ErrIndexDataNotFount
		}

		err := json.Unmarshal(indexDataBlob, &indexData)
		if err != nil {
			return metaTypes.IndexData{},
				fmt.Errorf("repodb: error while unmashaling index data for digest %s %w", indexDigest, err)
		}
	}

	return indexData, err
}

func collectImageManifestFilterData(digest string, repoMeta metaTypes.RepoMetadata,
	manifestMeta metaTypes.ManifestMetadata,
) (metaTypes.FilterData, error) {
	// get fields related to filtering
	var (
		configContent ispec.Image
		osList        []string
		archList      []string
	)

	err := json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
	if err != nil {
		return metaTypes.FilterData{},
			fmt.Errorf("repodb: error while unmarshaling config content %w", err)
	}

	if configContent.OS != "" {
		osList = append(osList, configContent.OS)
	}

	if configContent.Architecture != "" {
		archList = append(archList, configContent.Architecture)
	}

	return metaTypes.FilterData{
		DownloadCount: repoMeta.Statistics[digest].DownloadCount,
		OsList:        osList,
		ArchList:      archList,
		LastUpdated:   common.GetImageLastUpdatedTimestamp(configContent),
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[digest]),
	}, nil
}

func collectImageIndexFilterInfo(indexDigest string, repoMeta metaTypes.RepoMetadata,
	indexData metaTypes.IndexData, manifestMetadataMap map[string]metaTypes.ManifestMetadata,
	manifestBuck *bbolt.Bucket,
) (metaTypes.FilterData, error) {
	var indexContent ispec.Index

	err := json.Unmarshal(indexData.IndexBlob, &indexContent)
	if err != nil {
		return metaTypes.FilterData{},
			fmt.Errorf("repodb: error while unmarshaling index content for digest %s %w", indexDigest, err)
	}

	var (
		indexLastUpdated     time.Time
		firstManifestChecked = false
		indexOsList          = []string{}
		indexArchList        = []string{}
	)

	for _, manifest := range indexContent.Manifests {
		manifestDigest := manifest.Digest

		manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest.String(),
			manifestMetadataMap, manifestBuck)
		if err != nil {
			return metaTypes.FilterData{},
				fmt.Errorf("%w", err)
		}

		manifestFilterData, err := collectImageManifestFilterData(manifestDigest.String(), repoMeta,
			manifestMeta)
		if err != nil {
			return metaTypes.FilterData{},
				fmt.Errorf("%w", err)
		}

		indexOsList = append(indexOsList, manifestFilterData.OsList...)
		indexArchList = append(indexArchList, manifestFilterData.ArchList...)

		if !firstManifestChecked || indexLastUpdated.Before(manifestFilterData.LastUpdated) {
			indexLastUpdated = manifestFilterData.LastUpdated
			firstManifestChecked = true
		}

		manifestMetadataMap[manifest.Digest.String()] = manifestMeta
	}

	return metaTypes.FilterData{
		DownloadCount: repoMeta.Statistics[indexDigest].DownloadCount,
		LastUpdated:   indexLastUpdated,
		OsList:        indexOsList,
		ArchList:      indexArchList,
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[indexDigest]),
	}, nil
}

func NewManifestMetadata(manifestDigest string, repoMeta metaTypes.RepoMetadata,
	manifestData metaTypes.ManifestData,
) metaTypes.ManifestMetadata {
	manifestMeta := metaTypes.ManifestMetadata{
		ManifestBlob: manifestData.ManifestBlob,
		ConfigBlob:   manifestData.ConfigBlob,
	}

	manifestMeta.DownloadCount = repoMeta.Statistics[manifestDigest].DownloadCount

	manifestMeta.Signatures = metaTypes.ManifestSignatures{}
	if repoMeta.Signatures[manifestDigest] != nil {
		manifestMeta.Signatures = repoMeta.Signatures[manifestDigest]
	}

	return manifestMeta
}

func (bdw *DBWrapper) FilterTags(ctx context.Context, filter metaTypes.FilterFunc,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData,
	zcommon.PageInfo, error,
) {
	var (
		foundRepos               = make([]metaTypes.RepoMetadata, 0)
		manifestMetadataMap      = make(map[string]metaTypes.ManifestMetadata)
		indexDataMap             = make(map[string]metaTypes.IndexData)
		foundManifestMetadataMap = make(map[string]metaTypes.ManifestMetadata)
		foundindexDataMap        = make(map[string]metaTypes.IndexData)
		pageFinder               pagination.PageFinder
		pageInfo                 zcommon.PageInfo
	)

	pageFinder, err := pagination.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			zcommon.PageInfo{}, err
	}

	err = bdw.DB.View(func(transaction *bbolt.Tx) error {
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

			repoMeta := metaTypes.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

			matchedTags := make(map[string]metaTypes.Descriptor)
			// take all manifestMetas
			for tag, descriptor := range repoMeta.Tags {
				matchedTags[tag] = descriptor
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					manifestDigest := descriptor.Digest

					manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest, manifestMetadataMap, manifestBuck)
					if err != nil {
						return fmt.Errorf("repodb: error while unmashaling manifest metadata for digest %s %w", manifestDigest, err)
					}

					if !filter(repoMeta, manifestMeta) {
						delete(matchedTags, tag)

						continue
					}

					manifestMetadataMap[manifestDigest] = manifestMeta
				case ispec.MediaTypeImageIndex:
					indexDigest := descriptor.Digest

					indexData, err := fetchIndexDataWithCheck(indexDigest, indexDataMap, indexBuck)
					if err != nil {
						return fmt.Errorf("repodb: error while getting index data for digest %s %w", indexDigest, err)
					}

					var indexContent ispec.Index

					err = json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return fmt.Errorf("repodb: error while unmashaling index content for digest %s %w", indexDigest, err)
					}

					manifestHasBeenMatched := false

					for _, manifest := range indexContent.Manifests {
						manifestDigest := manifest.Digest.String()

						manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest, manifestMetadataMap, manifestBuck)
						if err != nil {
							return fmt.Errorf("repodb: error while getting manifest data for digest %s %w", manifestDigest, err)
						}

						manifestMetadataMap[manifestDigest] = manifestMeta

						if filter(repoMeta, manifestMeta) {
							manifestHasBeenMatched = true
						}
					}

					if !manifestHasBeenMatched {
						delete(matchedTags, tag)

						for _, manifest := range indexContent.Manifests {
							delete(manifestMetadataMap, manifest.Digest.String())
						}

						continue
					}

					indexDataMap[indexDigest] = indexData
				default:
					bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

					continue
				}
			}

			if len(matchedTags) == 0 {
				continue
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(metaTypes.DetailedRepoMeta{
				RepoMetadata: repoMeta,
			})
		}

		foundRepos, pageInfo = pageFinder.Page()

		foundManifestMetadataMap, foundindexDataMap, err = common.FilterDataByRepo(foundRepos, manifestMetadataMap,
			indexDataMap)

		return err
	})

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (bdw *DBWrapper) FilterRepos(ctx context.Context, filter metaTypes.FilterRepoFunc,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData,
	zcommon.PageInfo, error,
) {
	var (
		foundRepos = make([]metaTypes.RepoMetadata, 0)
		pageFinder pagination.PageFinder
		pageInfo   zcommon.PageInfo
	)

	pageFinder, err := pagination.NewBaseRepoPageFinder(
		requestedPage.Limit,
		requestedPage.Offset,
		requestedPage.SortBy,
	)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo, err
	}

	err = bdw.DB.View(func(tx *bbolt.Tx) error {
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

			repoMeta := metaTypes.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

			if filter(repoMeta) {
				pageFinder.Add(metaTypes.DetailedRepoMeta{
					RepoMetadata: repoMeta,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		return nil
	})
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			pageInfo, err
	}

	foundManifestMetadataMap, foundIndexDataMap, err := common.FetchDataForRepos(bdw, foundRepos)

	return foundRepos, foundManifestMetadataMap, foundIndexDataMap, pageInfo, err
}

func (bdw *DBWrapper) SearchTags(ctx context.Context, searchText string, filter metaTypes.Filter,
	requestedPage metaTypes.PageInput,
) ([]metaTypes.RepoMetadata, map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData,
	zcommon.PageInfo, error,
) {
	var (
		foundRepos               = make([]metaTypes.RepoMetadata, 0)
		manifestMetadataMap      = make(map[string]metaTypes.ManifestMetadata)
		indexDataMap             = make(map[string]metaTypes.IndexData)
		foundManifestMetadataMap = make(map[string]metaTypes.ManifestMetadata)
		foundindexDataMap        = make(map[string]metaTypes.IndexData)
		pageInfo                 zcommon.PageInfo

		pageFinder pagination.PageFinder
	)

	pageFinder, err := pagination.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			zcommon.PageInfo{}, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []metaTypes.RepoMetadata{}, map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
			zcommon.PageInfo{},
			fmt.Errorf("repodb: error while parsing search text, invalid format %w", err)
	}

	err = bdw.DB.View(func(transaction *bbolt.Tx) error {
		var (
			repoBuck      = transaction.Bucket([]byte(RepoMetadataBucket))
			indexBuck     = transaction.Bucket([]byte(IndexDataBucket))
			manifestBuck  = transaction.Bucket([]byte(ManifestDataBucket))
			cursor        = repoBuck.Cursor()
			userBookmarks = getUserBookmarks(ctx, transaction)
			userStars     = getUserStars(ctx, transaction)
		)

		repoName, repoMetaBlob := cursor.Seek([]byte(searchedRepo))

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := metaTypes.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			repoMeta.IsBookmarked = zcommon.Contains(userBookmarks, repoMeta.Name)
			repoMeta.IsStarred = zcommon.Contains(userStars, repoMeta.Name)

			if string(repoName) != searchedRepo {
				continue
			}

			matchedTags := make(map[string]metaTypes.Descriptor)

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
						return fmt.Errorf("repodb: error fetching manifest meta for manifest with digest %s %w",
							manifestDigest, err)
					}

					imageFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
					if err != nil {
						return fmt.Errorf("repodb: error collecting filter data for manifest with digest %s %w",
							manifestDigest, err)
					}

					if !common.AcceptedByFilter(filter, imageFilterData) {
						delete(matchedTags, tag)

						continue
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				case ispec.MediaTypeImageIndex:
					indexDigest := descriptor.Digest

					indexData, err := fetchIndexDataWithCheck(indexDigest, indexDataMap, indexBuck)
					if err != nil {
						return fmt.Errorf("repodb: error fetching index data for index with digest %s %w",
							indexDigest, err)
					}

					var indexContent ispec.Index

					err = json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return fmt.Errorf("repodb: error collecting filter data for index with digest %s %w",
							indexDigest, err)
					}

					manifestHasBeenMatched := false

					for _, manifest := range indexContent.Manifests {
						manifestDigest := manifest.Digest.String()

						manifestMeta, err := fetchManifestMetaWithCheck(repoMeta, manifestDigest, manifestMetadataMap, manifestBuck)
						if err != nil {
							return fmt.Errorf("repodb: error fetching from db manifest meta for manifest with digest %s %w",
								manifestDigest, err)
						}

						manifestFilterData, err := collectImageManifestFilterData(manifestDigest, repoMeta, manifestMeta)
						if err != nil {
							return fmt.Errorf("repodb: error collecting filter data for manifest with digest %s %w",
								manifestDigest, err)
						}

						manifestMetadataMap[manifestDigest] = manifestMeta

						if common.AcceptedByFilter(filter, manifestFilterData) {
							manifestHasBeenMatched = true
						}
					}

					if !manifestHasBeenMatched {
						delete(matchedTags, tag)

						for _, manifest := range indexContent.Manifests {
							delete(manifestMetadataMap, manifest.Digest.String())
						}

						continue
					}

					indexDataMap[indexDigest] = indexData
				default:
					bdw.Log.Error().Str("mediaType", descriptor.MediaType).Msg("Unsupported media type")

					continue
				}
			}

			if len(matchedTags) == 0 {
				continue
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(metaTypes.DetailedRepoMeta{
				RepoMetadata: repoMeta,
			})
		}

		foundRepos, pageInfo = pageFinder.Page()

		foundManifestMetadataMap, foundindexDataMap, err = common.FilterDataByRepo(foundRepos, manifestMetadataMap,
			indexDataMap)

		return nil
	})

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (bdw *DBWrapper) ToggleStarRepo(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return metaTypes.NotChanged, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	if userid == "" {
		// empty user is anonymous
		return metaTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		return metaTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	var res metaTypes.ToggleState

	if err := bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:varnamelen
		userdb := tx.Bucket([]byte(UserDataBucket))
		userBucket, err := userdb.CreateBucketIfNotExists([]byte(userid))
		if err != nil {
			// this is a serious failure
			return zerr.ErrUnableToCreateUserBucket
		}

		mdata := userBucket.Get([]byte(StarredReposKey))
		unpacked := []string{}
		if mdata != nil {
			if err = json.Unmarshal(mdata, &unpacked); err != nil {
				return zerr.ErrInvalidOldUserStarredRepos
			}
		}

		isRepoStarred := zcommon.Contains(unpacked, repo)

		if isRepoStarred {
			res = metaTypes.Removed
			unpacked = zcommon.RemoveFrom(unpacked, repo)
		} else {
			res = metaTypes.Added
			unpacked = append(unpacked, repo)
		}

		var repacked []byte
		if repacked, err = json.Marshal(unpacked); err != nil {
			return zerr.ErrCouldNotMarshalStarredRepos
		}

		err = userBucket.Put([]byte(StarredReposKey), repacked)
		if err != nil {
			return zerr.ErrCouldNotPersistData
		}

		repoBuck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta metaTypes.RepoMetadata

		err = json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		switch res {
		case metaTypes.Added:
			repoMeta.Stars++
		case metaTypes.Removed:
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
		return metaTypes.NotChanged, err
	}

	return res, nil
}

func (bdw *DBWrapper) GetStarredRepos(ctx context.Context) ([]string, error) {
	starredRepos := make([]string, 0)

	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return starredRepos, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	err = bdw.DB.View(func(tx *bbolt.Tx) error { //nolint:dupl
		if userid == "" {
			return nil
		}

		userdb := tx.Bucket([]byte(UserDataBucket))
		userBucket := userdb.Bucket([]byte(userid))

		if userBucket == nil {
			return nil
		}

		mdata := userBucket.Get([]byte(StarredReposKey))
		if mdata == nil {
			return nil
		}

		if err := json.Unmarshal(mdata, &starredRepos); err != nil {
			bdw.Log.Info().Str("user", userid).Err(err).Msg("unmarshal error")

			return zerr.ErrInvalidOldUserStarredRepos
		}

		if starredRepos == nil {
			starredRepos = make([]string, 0)
		}

		return nil
	})

	return starredRepos, err
}

func (bdw *DBWrapper) ToggleBookmarkRepo(ctx context.Context, repo string) (metaTypes.ToggleState, error) {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return metaTypes.NotChanged, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)
	if userid == "" {
		// empty user is anonymous
		return metaTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	if ok, err := localCtx.RepoIsUserAvailable(ctx, repo); !ok || err != nil {
		return metaTypes.NotChanged, zerr.ErrUserDataNotAllowed
	}

	var res metaTypes.ToggleState

	if err := bdw.DB.Update(func(tx *bbolt.Tx) error { //nolint:dupl
		userdb := tx.Bucket([]byte(UserDataBucket))
		userBucket, err := userdb.CreateBucketIfNotExists([]byte(userid))
		if err != nil {
			// this is a serious failure
			return zerr.ErrUnableToCreateUserBucket
		}

		mdata := userBucket.Get([]byte(BookmarkedReposKey))
		unpacked := []string{}
		if mdata != nil {
			if err = json.Unmarshal(mdata, &unpacked); err != nil {
				return zerr.ErrInvalidOldUserBookmarkedRepos
			}
		}

		isRepoBookmarked := zcommon.Contains(unpacked, repo)

		if isRepoBookmarked {
			res = metaTypes.Removed
			unpacked = zcommon.RemoveFrom(unpacked, repo)
		} else {
			res = metaTypes.Added
			unpacked = append(unpacked, repo)
		}

		var repacked []byte
		if repacked, err = json.Marshal(unpacked); err != nil {
			return zerr.ErrCouldNotMarshalBookmarkedRepos
		}

		err = userBucket.Put([]byte(BookmarkedReposKey), repacked)
		if err != nil {
			return zerr.ErrUnableToCreateUserBucket
		}

		return nil
	}); err != nil {
		return metaTypes.NotChanged, err
	}

	return res, nil
}

func (bdw *DBWrapper) GetBookmarkedRepos(ctx context.Context) ([]string, error) {
	bookmarkedRepos := []string{}

	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return bookmarkedRepos, err
	}

	userid := localCtx.GetUsernameFromContext(acCtx)

	err = bdw.DB.View(func(tx *bbolt.Tx) error { //nolint:dupl
		if userid == "" {
			return nil
		}

		userdb := tx.Bucket([]byte(UserDataBucket))
		userBucket := userdb.Bucket([]byte(userid))

		if userBucket == nil {
			return nil
		}

		mdata := userBucket.Get([]byte(BookmarkedReposKey))
		if mdata == nil {
			return nil
		}

		if err := json.Unmarshal(mdata, &bookmarkedRepos); err != nil {
			bdw.Log.Info().Str("user", userid).Err(err).Msg("unmarshal error")

			return zerr.ErrInvalidOldUserBookmarkedRepos
		}

		if bookmarkedRepos == nil {
			bookmarkedRepos = make([]string, 0)
		}

		return nil
	})

	return bookmarkedRepos, err
}

func (bdw *DBWrapper) PatchDB() error {
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
		userid       = localCtx.GetUsernameFromContext(acCtx)
		starredRepos = []string{}
		userdb       = transaction.Bucket([]byte(UserDataBucket))
		userBucket   = userdb.Bucket([]byte(userid))
	)

	if userid == "" {
		return []string{}
	}

	if userBucket == nil {
		return []string{}
	}

	mdata := userBucket.Get([]byte(StarredReposKey))
	if mdata == nil {
		return []string{}
	}

	if err := json.Unmarshal(mdata, &starredRepos); err != nil {
		return []string{}
	}

	return starredRepos
}

func getUserBookmarks(ctx context.Context, transaction *bbolt.Tx) []string {
	acCtx, err := localCtx.GetAccessControlContext(ctx)
	if err != nil {
		return []string{}
	}

	var (
		userid          = localCtx.GetUsernameFromContext(acCtx)
		bookmarkedRepos = []string{}
		userdb          = transaction.Bucket([]byte(UserDataBucket))
		userBucket      = userdb.Bucket([]byte(userid))
	)

	if userid == "" {
		return []string{}
	}

	if userBucket == nil {
		return []string{}
	}

	mdata := userBucket.Get([]byte(BookmarkedReposKey))
	if mdata == nil {
		return []string{}
	}

	if err := json.Unmarshal(mdata, &bookmarkedRepos); err != nil {
		return []string{}
	}

	return bookmarkedRepos
}
