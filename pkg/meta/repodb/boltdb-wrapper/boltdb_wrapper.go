package bolt

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/meta/repodb/common"
	"zotregistry.io/zot/pkg/meta/repodb/version"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

type DBParameters struct {
	RootDir string
}

type DBWrapper struct {
	DB      *bolt.DB
	Patches []func(DB *bolt.DB) error
	Log     log.Logger
}

func NewBoltDBWrapper(params DBParameters) (*DBWrapper, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "repo.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	err = boltDB.Update(func(transaction *bolt.Tx) error {
		versionBuck, err := transaction.CreateBucketIfNotExists([]byte(repodb.VersionBucket))
		if err != nil {
			return err
		}

		err = versionBuck.Put([]byte(version.DBVersionKey), []byte(version.CurrentVersion))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(repodb.ManifestDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(repodb.RepoMetadataBucket))
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
		Log:     log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (bdw DBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData repodb.ManifestData) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestDataBucket))

		mdBlob, err := json.Marshal(manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", manifestDigest)
		}

		err = buck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest data with for digest %s", manifestDigest)
		}

		return nil
	})

	return err
}

func (bdw DBWrapper) GetManifestData(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
	var manifestData repodb.ManifestData

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestDataBucket))

		mdBlob := buck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestDataNotFound
		}

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
		}

		return nil
	})

	return manifestData, err
}

func (bdw DBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta repodb.ManifestMetadata,
) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMeta := repodb.RepoMetadata{
			Name:       repo,
			Tags:       map[string]repodb.Descriptor{},
			Statistics: map[string]repodb.DescriptorStatistics{},
			Signatures: map[string]repodb.ManifestSignatures{},
		}

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}
		}

		mdBlob, err := json.Marshal(repodb.ManifestData{
			ManifestBlob: manifestMeta.ManifestBlob,
			ConfigBlob:   manifestMeta.ConfigBlob,
		})
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", manifestDigest)
		}

		err = dataBuck.Put([]byte(manifestDigest), mdBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest meta with for digest %s", manifestDigest)
		}

		updatedRepoMeta := common.UpdateManifestMeta(repoMeta, manifestDigest, manifestMeta)

		updatedRepoMetaBlob, err := json.Marshal(updatedRepoMeta)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for updated repo meta '%s'", repo)
		}

		return repoBuck.Put([]byte(repo), updatedRepoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
	var manifestMetadata repodb.ManifestMetadata

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		mdBlob := dataBuck.Get([]byte(manifestDigest))

		if len(mdBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestData repodb.ManifestData

		err := json.Unmarshal(mdBlob, &manifestData)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
		}

		var repoMeta repodb.RepoMetadata

		repoMetaBlob := repoBuck.Get([]byte(repo))
		if len(repoMetaBlob) > 0 {
			err = json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
			}
		}

		manifestMetadata.ManifestBlob = manifestData.ManifestBlob
		manifestMetadata.ConfigBlob = manifestData.ConfigBlob
		manifestMetadata.DownloadCount = repoMeta.Statistics[manifestDigest.String()].DownloadCount

		manifestMetadata.Signatures = repodb.ManifestSignatures{}
		if repoMeta.Signatures[manifestDigest.String()] != nil {
			manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
		}

		return nil
	})

	return manifestMetadata, err
}

func (bdw DBWrapper) SetRepoTag(repo string, tag string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if err := common.ValidateRepoTagInput(repo, tag, manifestDigest); err != nil {
		return err
	}

	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			// create a new object
			repoMeta := repodb.RepoMetadata{
				Name: repo,
				Tags: map[string]repodb.Descriptor{
					tag: {
						Digest:    manifestDigest.String(),
						MediaType: mediaType,
					},
				},
				Statistics: map[string]repodb.DescriptorStatistics{
					manifestDigest.String(): {DownloadCount: 0},
				},
				Signatures: map[string]repodb.ManifestSignatures{
					manifestDigest.String(): {},
				},
			}

			repoMetaBlob, err := json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}

		// object found
		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Tags[tag] = repodb.Descriptor{
			Digest:    manifestDigest.String(),
			MediaType: mediaType,
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) GetRepoMeta(repo string) (repodb.RepoMetadata, error) {
	var repoMeta repodb.RepoMetadata

	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

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

func (bdw DBWrapper) DeleteRepoTag(repo string, tag string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return nil
		}

		// object found
		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		delete(repoMeta.Tags, tag)

		if len(repoMeta.Tags) == 0 {
			return buck.Delete([]byte(repo))
		}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) IncrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

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

func (bdw DBWrapper) DecrementRepoStars(repo string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

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

func (bdw DBWrapper) GetRepoStars(repo string) (int, error) {
	stars := 0

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		buck.Get([]byte(repo))
		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		stars = repoMeta.Stars

		return nil
	})

	return stars, err
}

func (bdw DBWrapper) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta repodb.RepoMetadata) bool,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, error) {
	var (
		foundRepos = make([]repodb.RepoMetadata, 0)
		pageFinder repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := repodb.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, _ = pageFinder.Page()

		return nil
	})

	return foundRepos, err
}

func (bdw DBWrapper) IncrementImageDownloads(repo string, reference string) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

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

func (bdw DBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
	sygMeta repodb.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		var (
			manifestSignatures repodb.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			manifestSignatures = repodb.ManifestSignatures{}
		}

		signatureSlice := manifestSignatures[sygMeta.SignatureType]
		if !common.SignatureAlreadyExists(signatureSlice, sygMeta) {
			if sygMeta.SignatureType == repodb.NotationType {
				signatureSlice = append(signatureSlice, repodb.SignatureInfo{
					SignatureManifestDigest: sygMeta.SignatureDigest,
					LayersInfo:              sygMeta.LayersInfo,
				})
			} else if sygMeta.SignatureType == repodb.CosignType {
				signatureSlice = []repodb.SignatureInfo{{
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

func (bdw DBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
	sigMeta repodb.SignatureMetadata,
) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		sigType := sigMeta.SignatureType

		var (
			manifestSignatures repodb.ManifestSignatures
			found              bool
		)

		if manifestSignatures, found = repoMeta.Signatures[signedManifestDigest.String()]; !found {
			return zerr.ErrManifestMetaNotFound
		}

		signatureSlice := manifestSignatures[sigType]

		newSignatureSlice := make([]repodb.SignatureInfo, 0, len(signatureSlice)-1)

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

func (bdw DBWrapper) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		pageFinder               repodb.PageFinder
		pageInfo                 repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, repodb.PageInfo{}, err
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			dataBuck            = tx.Bucket([]byte(repodb.ManifestDataBucket))
		)

		cursor := repoBuck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			var repoMeta repodb.RepoMetadata

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if score := common.ScoreRepoName(searchText, string(repoName)); score != -1 {
				var (
					// specific values used for sorting that need to be calculated based on all manifests from the repo
					repoDownloads     = 0
					repoLastUpdated   time.Time
					firstImageChecked = true
					osSet             = map[string]bool{}
					archSet           = map[string]bool{}
					isSigned          = false
				)

				for _, descriptor := range repoMeta.Tags {
					var manifestMeta repodb.ManifestMetadata

					manifestMeta, manifestDownloaded := manifestMetadataMap[descriptor.Digest]

					if !manifestDownloaded {
						manifestMetaBlob := dataBuck.Get([]byte(descriptor.Digest))
						if manifestMetaBlob == nil {
							return zerr.ErrManifestMetaNotFound
						}

						err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmarshaling manifest metadata for digest %s", descriptor.Digest)
						}
					}

					// get fields related to filtering
					var configContent ispec.Image

					err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmarshaling config content for digest %s", descriptor.Digest)
					}

					osSet[configContent.OS] = true
					archSet[configContent.Architecture] = true

					// get fields related to sorting
					repoDownloads += repoMeta.Statistics[descriptor.Digest].DownloadCount

					imageLastUpdated := common.GetImageLastUpdatedTimestamp(configContent)

					if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
						repoLastUpdated = imageLastUpdated
						firstImageChecked = false

						isSigned = common.CheckIsSigned(repoMeta.Signatures[descriptor.Digest])
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				}

				repoFilterData := repodb.FilterData{
					OsList:   common.GetMapKeys(osSet),
					ArchList: common.GetMapKeys(archSet),
					IsSigned: isSigned,
				}

				if !common.AcceptedByFilter(filter, repoFilterData) {
					continue
				}

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta:   repoMeta,
					Score:      score,
					Downloads:  repoDownloads,
					UpdateTime: repoLastUpdated,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, manifestDigest := range repoMeta.Tags {
				foundManifestMetadataMap[manifestDigest.Digest] = manifestMetadataMap[manifestDigest.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

// TODO: actually implement 2023-01-16
func (bdw DBWrapper) FilterRepos(ctx context.Context,
	filter repodb.FilterRepoFunc,
	requestedPage repodb.PageInput,
) (
	[]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error,
) {
	var (
		foundRepos = make([]repodb.RepoMetadata, 0)
		pageFinder repodb.PageFinder
		pageInfo   repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(
		requestedPage.Limit,
		requestedPage.Offset,
		requestedPage.SortBy,
	)
	if err != nil {
		return nil, nil, pageInfo, err
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := repodb.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		return nil
	})

	foundManifestMetadataMap := make(map[string]repodb.ManifestMetadata)

	for idx := range foundRepos {
		for _, manifestDigest := range foundRepos[idx].Tags {
			manifestMeta, err := bdw.GetManifestMeta(
				foundRepos[idx].Name, godigest.Digest(manifestDigest.Digest))
			if err != nil {
				return nil, nil, pageInfo, err
			}

			foundManifestMetadataMap[manifestDigest.Digest] = manifestMeta
		}
	}

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func (bdw DBWrapper) FilterTags(ctx context.Context, filter repodb.FilterFunc,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		pageFinder               repodb.PageFinder
		pageInfo                 repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, repodb.PageInfo{}, err
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			dataBuck            = tx.Bucket([]byte(repodb.ManifestDataBucket))
			cursor              = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.First()

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := repodb.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			matchedTags := make(map[string]repodb.Descriptor)
			// take all manifestMetas
			for tag, descriptor := range repoMeta.Tags {
				manifestDigest := descriptor.Digest

				matchedTags[tag] = descriptor

				// in case tags reference the same manifest we don't download from DB multiple times
				manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]

				if !manifestExists {
					manifestDataBlob := dataBuck.Get([]byte(manifestDigest))
					if manifestDataBlob == nil {
						return zerr.ErrManifestMetaNotFound
					}

					var manifestData repodb.ManifestData

					err := json.Unmarshal(manifestDataBlob, &manifestData)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
					}

					var configContent ispec.Image

					err = json.Unmarshal(manifestData.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling config for manifest with digest %s", manifestDigest)
					}

					manifestMeta = repodb.ManifestMetadata{
						ConfigBlob:   manifestData.ConfigBlob,
						ManifestBlob: manifestData.ManifestBlob,
					}
				}

				if !filter(repoMeta, manifestMeta) {
					delete(matchedTags, tag)

					continue
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			if len(matchedTags) == 0 {
				continue
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(repodb.DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func (bdw DBWrapper) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, repodb.PageInfo, error) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		pageInfo                 repodb.PageInfo

		pageFinder repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, repodb.PageInfo{}, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, repodb.PageInfo{},
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			dataBuck            = tx.Bucket([]byte(repodb.ManifestDataBucket))
			cursor              = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.Seek([]byte(searchedRepo))

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := localCtx.RepoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := repodb.RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if string(repoName) == searchedRepo {
				matchedTags := make(map[string]repodb.Descriptor)
				// take all manifestMetas
				for tag, descriptor := range repoMeta.Tags {
					if !strings.HasPrefix(tag, searchedTag) {
						continue
					}

					matchedTags[tag] = descriptor

					// in case tags reference the same manifest we don't download from DB multiple times
					if manifestMeta, manifestExists := manifestMetadataMap[descriptor.Digest]; manifestExists {
						manifestMetadataMap[descriptor.Digest] = manifestMeta

						continue
					}

					manifestMetaBlob := dataBuck.Get([]byte(descriptor.Digest))
					if manifestMetaBlob == nil {
						return zerr.ErrManifestMetaNotFound
					}

					var manifestMeta repodb.ManifestMetadata

					err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
					}

					var configContent ispec.Image

					err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling config for manifest with digest %s", descriptor.Digest)
					}

					imageFilterData := repodb.FilterData{
						OsList:   []string{configContent.OS},
						ArchList: []string{configContent.Architecture},
						IsSigned: false,
					}

					if !common.AcceptedByFilter(filter, imageFilterData) {
						delete(matchedTags, tag)
						delete(manifestMetadataMap, descriptor.Digest)

						continue
					}

					manifestMetadataMap[descriptor.Digest] = manifestMeta
				}

				if len(matchedTags) == 0 {
					continue
				}

				repoMeta.Tags = matchedTags

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func (bdw *DBWrapper) PatchDB() error {
	var DBVersion string

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		versionBuck := tx.Bucket([]byte(repodb.VersionBucket))
		DBVersion = string(versionBuck.Get([]byte(version.DBVersionKey)))

		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "patching the database failed, can't read db version")
	}

	if version.GetVersionIndex(DBVersion) == -1 {
		return errors.New("DB has broken format, no version found")
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
