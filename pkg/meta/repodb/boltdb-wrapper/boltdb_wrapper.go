package bolt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
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

		_, err = transaction.CreateBucketIfNotExists([]byte(repodb.IndexDataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(repodb.ArtifactDataBucket))
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

func (bdw *DBWrapper) SetManifestData(manifestDigest godigest.Digest, manifestData repodb.ManifestData) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestDataBucket))

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

func (bdw *DBWrapper) GetManifestData(manifestDigest godigest.Digest) (repodb.ManifestData, error) {
	var manifestData repodb.ManifestData

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestDataBucket))

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

func (bdw *DBWrapper) SetManifestMeta(repo string, manifestDigest godigest.Digest, manifestMeta repodb.ManifestMetadata,
) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		dataBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))
		repoBuck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMeta := repodb.RepoMetadata{
			Name:       repo,
			Tags:       map[string]repodb.Descriptor{},
			Statistics: map[string]repodb.DescriptorStatistics{},
			Signatures: map[string]repodb.ManifestSignatures{},
			Referrers:  map[string][]repodb.Descriptor{},
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

func (bdw *DBWrapper) GetManifestMeta(repo string, manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
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
			return fmt.Errorf("repodb: error while unmashaling manifest meta for digest %s %w", manifestDigest, err)
		}

		var repoMeta repodb.RepoMetadata

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

		manifestMetadata.Signatures = repodb.ManifestSignatures{}
		if repoMeta.Signatures[manifestDigest.String()] != nil {
			manifestMetadata.Signatures = repoMeta.Signatures[manifestDigest.String()]
		}

		return nil
	})

	return manifestMetadata, err
}

func (bdw *DBWrapper) SetIndexData(indexDigest godigest.Digest, indexMetadata repodb.IndexData) error {
	// we make the assumption that the oci layout is consistent and all manifests refferenced inside the
	// index are present
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.IndexDataBucket))

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

func (bdw *DBWrapper) GetIndexData(indexDigest godigest.Digest) (repodb.IndexData, error) {
	var indexMetadata repodb.IndexData

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.IndexDataBucket))

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

func (bdw DBWrapper) SetArtifactData(artifactDigest godigest.Digest, artifactData repodb.ArtifactData) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ArtifactDataBucket))

		imBlob, err := json.Marshal(artifactData)
		if err != nil {
			return fmt.Errorf("repodb: error while calculating blob for artifact with digest %s %w", artifactDigest, err)
		}

		err = buck.Put([]byte(artifactDigest), imBlob)
		if err != nil {
			return fmt.Errorf("repodb: error while setting artifact blob for digest %s %w", artifactDigest, err)
		}

		return nil
	})

	return err
}

func (bdw DBWrapper) GetArtifactData(artifactDigest godigest.Digest) (repodb.ArtifactData, error) {
	var artifactData repodb.ArtifactData

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ArtifactDataBucket))

		blob := buck.Get([]byte(artifactDigest))

		if len(blob) == 0 {
			return zerr.ErrArtifactDataNotFound
		}

		err := json.Unmarshal(blob, &artifactData)
		if err != nil {
			return fmt.Errorf("repodb: error while unmashaling artifact data for digest %s %w", artifactDigest, err)
		}

		return nil
	})

	return artifactData, err
}

func (bdw DBWrapper) SetReferrer(repo string, referredDigest godigest.Digest, referrer repodb.Descriptor) error {
	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			var err error

			// create a new object
			repoMeta := repodb.RepoMetadata{
				Name: repo,
				Tags: map[string]repodb.Descriptor{},
				Statistics: map[string]repodb.DescriptorStatistics{
					referredDigest.String(): {},
				},
				Signatures: map[string]repodb.ManifestSignatures{
					referredDigest.String(): {},
				},
				Referrers: map[string][]repodb.Descriptor{
					referredDigest.String(): {
						{
							Digest:    referrer.Digest,
							MediaType: referrer.MediaType,
						},
					},
				},
			}

			repoMetaBlob, err = json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}
		var repoMeta repodb.RepoMetadata

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

		refferers = append(refferers, repodb.Descriptor{
			Digest:    referrer.Digest,
			MediaType: referrer.MediaType,
		})

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
	return bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

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

func (bdw DBWrapper) GetReferrers(repo string, referredDigest godigest.Digest) ([]repodb.Descriptor, error) {
	var referrers []repodb.Descriptor

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if len(repoMetaBlob) == 0 {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		referrers = repoMeta.Referrers[referredDigest.String()]

		return nil
	})

	return referrers, err
}

func (bdw DBWrapper) GetFilteredReferrersInfo(repo string, referredDigest godigest.Digest,
	artifactTypes []string,
) ([]repodb.ReferrerInfo, error) {
	referrersDescriptors, err := bdw.GetReferrers(repo, referredDigest)
	if err != nil {
		bdw.Log.Error().Msgf("repodb: failed to get referrers for  '%s@%s'", repo, referredDigest.String())

		return nil, err
	}

	referrersInfo := []repodb.ReferrerInfo{}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		artifactBuck := tx.Bucket([]byte(repodb.ArtifactDataBucket))
		manifestBuck := tx.Bucket([]byte(repodb.ManifestDataBucket))

		for _, descriptor := range referrersDescriptors {
			referrerInfo := repodb.ReferrerInfo{}

			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestDataBlob := manifestBuck.Get([]byte(descriptor.Digest))

				if len(manifestDataBlob) == 0 {
					bdw.Log.Error().Msgf("repodb: manifest data not found for digest %s", descriptor.Digest)

					continue
				}

				var manifestData repodb.ManifestData

				err = json.Unmarshal(manifestDataBlob, &manifestData)
				if err != nil {
					bdw.Log.Error().Err(err).Msgf("repodb: can't unmarhsal manifest data for digest %s",
						descriptor.Digest)

					continue
				}

				var manifestContent ispec.Manifest

				err := json.Unmarshal(manifestData.ManifestBlob, &manifestContent)
				if err != nil {
					bdw.Log.Error().Err(err).Msgf("repodb: can't unmarhsal manifest for digest %s",
						descriptor.Digest)

					continue
				}

				referrerInfo = repodb.ReferrerInfo{
					Digest:       descriptor.Digest,
					MediaType:    ispec.MediaTypeImageManifest,
					ArtifactType: manifestContent.Config.MediaType,
					Size:         len(manifestData.ManifestBlob),
					Annotations:  manifestContent.Annotations,
				}
			case ispec.MediaTypeArtifactManifest:
				artifactDataBlob := artifactBuck.Get([]byte(descriptor.Digest))

				if len(artifactDataBlob) == 0 {
					bdw.Log.Error().Msgf("repodb: artifact data not found for digest %s", descriptor.Digest)

					continue
				}

				var artifactData repodb.ArtifactData

				err = json.Unmarshal(artifactDataBlob, &artifactData)
				if err != nil {
					bdw.Log.Error().Err(err).Msgf("repodb: can't unmarhsal artifact data for digest %s", descriptor.Digest)

					continue
				}

				manifestContent := ispec.Artifact{}

				err := json.Unmarshal(artifactData.ManifestBlob, &manifestContent)
				if err != nil {
					bdw.Log.Error().Err(err).Msgf("repodb: can't unmarhsal artifact manifest for digest %s", descriptor.Digest)

					continue
				}

				referrerInfo = repodb.ReferrerInfo{
					Size:         len(artifactData.ManifestBlob),
					Digest:       descriptor.Digest,
					MediaType:    manifestContent.MediaType,
					Annotations:  manifestContent.Annotations,
					ArtifactType: manifestContent.ArtifactType,
				}
			}

			if !common.MatchesArtifactTypes(referrerInfo.ArtifactType, artifactTypes) {
				continue
			}

			referrersInfo = append(referrersInfo, referrerInfo)
		}

		return nil
	})

	return referrersInfo, err
}

func (bdw *DBWrapper) SetRepoReference(repo string, reference string, manifestDigest godigest.Digest,
	mediaType string,
) error {
	if err := common.ValidateRepoReferenceInput(repo, reference, manifestDigest); err != nil {
		return err
	}

	err := bdw.DB.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			var err error
			// create a new object
			repoMeta := repodb.RepoMetadata{
				Name:       repo,
				Tags:       map[string]repodb.Descriptor{},
				Statistics: map[string]repodb.DescriptorStatistics{},
				Signatures: map[string]repodb.ManifestSignatures{},
				Referrers:  map[string][]repodb.Descriptor{},
			}

			repoMetaBlob, err = json.Marshal(repoMeta)
			if err != nil {
				return err
			}
		}

		// object found
		var repoMeta repodb.RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		if !common.ReferenceIsDigest(reference) {
			repoMeta.Tags[reference] = repodb.Descriptor{
				Digest:    manifestDigest.String(),
				MediaType: mediaType,
			}
		}

		repoMeta.Statistics[manifestDigest.String()] = repodb.DescriptorStatistics{DownloadCount: 0}
		repoMeta.Signatures[manifestDigest.String()] = repodb.ManifestSignatures{}
		repoMeta.Referrers[manifestDigest.String()] = []repodb.Descriptor{}

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw *DBWrapper) GetRepoMeta(repo string) (repodb.RepoMetadata, error) {
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

func (bdw *DBWrapper) DeleteRepoTag(repo string, tag string) error {
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

func (bdw *DBWrapper) IncrementRepoStars(repo string) error {
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

func (bdw *DBWrapper) DecrementRepoStars(repo string) error {
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

func (bdw *DBWrapper) GetRepoStars(repo string) (int, error) {
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

func (bdw *DBWrapper) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta repodb.RepoMetadata) bool,
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

func (bdw *DBWrapper) IncrementImageDownloads(repo string, reference string) error {
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

func (bdw *DBWrapper) AddManifestSignature(repo string, signedManifestDigest godigest.Digest,
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

func (bdw *DBWrapper) DeleteSignature(repo string, signedManifestDigest godigest.Digest,
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

func (bdw *DBWrapper) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo,
	error,
) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		foundindexDataMap        = make(map[string]repodb.IndexData)
		pageFinder               repodb.PageFinder
		pageInfo                 repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{}, err
	}

	err = bdw.DB.View(func(transaction *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
			indexDataMap        = make(map[string]repodb.IndexData)
			repoBuck            = transaction.Bucket([]byte(repodb.RepoMetadataBucket))
			indexBuck           = transaction.Bucket([]byte(repodb.IndexDataBucket))
			manifestBuck        = transaction.Bucket([]byte(repodb.ManifestDataBucket))
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

						if firstImageChecked || repoLastUpdated.Before(manifestFilterData.LastUpdated) {
							repoLastUpdated = manifestFilterData.LastUpdated
							firstImageChecked = false

							isSigned = manifestFilterData.IsSigned
						}

						manifestMetadataMap[descriptor.Digest] = manifestMeta
					case ispec.MediaTypeImageIndex:
						var indexLastUpdated time.Time

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
						imageFilterData, err := collectImageIndexFilterInfo(indexDigest, repoMeta, indexData, manifestMetadataMap,
							manifestBuck)
						if err != nil {
							return fmt.Errorf("repodb: error collecting filter data for index with digest %s %w",
								indexDigest, err)
						}

						for _, arch := range imageFilterData.ArchList {
							archSet[arch] = true
						}

						for _, os := range imageFilterData.OsList {
							osSet[os] = true
						}

						repoDownloads += imageFilterData.DownloadCount

						if repoLastUpdated.Before(imageFilterData.LastUpdated) {
							repoLastUpdated = indexLastUpdated

							isSigned = imageFilterData.IsSigned
						}

						indexDataMap[indexDigest] = indexData
					default:
						bdw.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)

						continue
					}
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

		// keep just the manifestMeta and indexData we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
				case ispec.MediaTypeImageIndex:
					indexData := indexDataMap[descriptor.Digest]

					var indexContent ispec.Index

					err := json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return err
					}

					for _, manifestDescriptor := range indexContent.Manifests {
						manifestDigest := manifestDescriptor.Digest.String()

						foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
					}

					foundindexDataMap[descriptor.Digest] = indexData
				default:
					bdw.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)
				}
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func fetchManifestMetaWithCheck(repoMeta repodb.RepoMetadata, manifestDigest string,
	manifestMetadataMap map[string]repodb.ManifestMetadata, manifestBuck *bolt.Bucket,
) (repodb.ManifestMetadata, error) {
	manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

	if !manifestDownloaded {
		var manifestData repodb.ManifestData

		manifestDataBlob := manifestBuck.Get([]byte(manifestDigest))
		if manifestDataBlob == nil {
			return repodb.ManifestMetadata{}, zerr.ErrManifestMetaNotFound
		}

		err := json.Unmarshal(manifestDataBlob, &manifestData)
		if err != nil {
			return repodb.ManifestMetadata{}, fmt.Errorf("repodb: error while unmarshaling manifest metadata for digest %s %w",
				manifestDigest, err)
		}

		manifestMeta = NewManifestMetadata(manifestDigest, repoMeta, manifestData)
	}

	return manifestMeta, nil
}

func fetchIndexDataWithCheck(indexDigest string, indexDataMap map[string]repodb.IndexData,
	indexBuck *bolt.Bucket,
) (repodb.IndexData, error) {
	var (
		indexData repodb.IndexData
		err       error
	)

	indexData, indexExists := indexDataMap[indexDigest]

	if !indexExists {
		indexDataBlob := indexBuck.Get([]byte(indexDigest))
		if indexDataBlob == nil {
			return repodb.IndexData{}, zerr.ErrIndexDataNotFount
		}

		err := json.Unmarshal(indexDataBlob, &indexData)
		if err != nil {
			return repodb.IndexData{},
				fmt.Errorf("repodb: error while unmashaling index data for digest %s %w", indexDigest, err)
		}
	}

	return indexData, err
}

func collectImageManifestFilterData(digest string, repoMeta repodb.RepoMetadata,
	manifestMeta repodb.ManifestMetadata,
) (repodb.FilterData, error) {
	// get fields related to filtering
	var (
		configContent ispec.Image
		osList        []string
		archList      []string
	)

	err := json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
	if err != nil {
		return repodb.FilterData{},
			fmt.Errorf("repodb: error while unmarshaling config content %w", err)
	}

	if configContent.OS != "" {
		osList = append(osList, configContent.OS)
	}

	if configContent.Architecture != "" {
		archList = append(archList, configContent.Architecture)
	}

	return repodb.FilterData{
		DownloadCount: repoMeta.Statistics[digest].DownloadCount,
		OsList:        osList,
		ArchList:      archList,
		LastUpdated:   common.GetImageLastUpdatedTimestamp(configContent),
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[digest]),
	}, nil
}

func collectImageIndexFilterInfo(indexDigest string, repoMeta repodb.RepoMetadata,
	indexData repodb.IndexData, manifestMetadataMap map[string]repodb.ManifestMetadata,
	manifestBuck *bolt.Bucket,
) (repodb.FilterData, error) {
	var indexContent ispec.Index

	err := json.Unmarshal(indexData.IndexBlob, &indexContent)
	if err != nil {
		return repodb.FilterData{},
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
			return repodb.FilterData{},
				fmt.Errorf("%w", err)
		}

		manifestFilterData, err := collectImageManifestFilterData(manifestDigest.String(), repoMeta,
			manifestMeta)
		if err != nil {
			return repodb.FilterData{},
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

	return repodb.FilterData{
		DownloadCount: repoMeta.Statistics[indexDigest].DownloadCount,
		LastUpdated:   indexLastUpdated,
		OsList:        indexOsList,
		ArchList:      indexArchList,
		IsSigned:      common.CheckIsSigned(repoMeta.Signatures[indexDigest]),
	}, nil
}

func NewManifestMetadata(manifestDigest string, repoMeta repodb.RepoMetadata,
	manifestData repodb.ManifestData,
) repodb.ManifestMetadata {
	manifestMeta := repodb.ManifestMetadata{
		ManifestBlob: manifestData.ManifestBlob,
		ConfigBlob:   manifestData.ConfigBlob,
	}

	manifestMeta.DownloadCount = repoMeta.Statistics[manifestDigest].DownloadCount

	manifestMeta.Signatures = repodb.ManifestSignatures{}
	if repoMeta.Signatures[manifestDigest] != nil {
		manifestMeta.Signatures = repoMeta.Signatures[manifestDigest]
	}

	return manifestMeta
}

func (bdw *DBWrapper) FilterTags(ctx context.Context, filter repodb.FilterFunc,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData,
	repodb.PageInfo, error,
) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		manifestMetadataMap      = make(map[string]repodb.ManifestMetadata)
		indexDataMap             = make(map[string]repodb.IndexData)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		foundindexDataMap        = make(map[string]repodb.IndexData)
		pageFinder               repodb.PageFinder
		pageInfo                 repodb.PageInfo
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{}, err
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		var (
			repoBuck     = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			indexBuck    = tx.Bucket([]byte(repodb.IndexDataBucket))
			manifestBuck = tx.Bucket([]byte(repodb.ManifestDataBucket))
			cursor       = repoBuck.Cursor()
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
					bdw.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)

					continue
				}
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

		// keep just the manifestMeta and indexData we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
				case ispec.MediaTypeImageIndex:
					indexData := indexDataMap[descriptor.Digest]

					var indexContent ispec.Index

					err := json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return err
					}

					for _, manifestDescriptor := range indexContent.Manifests {
						manifestDigest := manifestDescriptor.Digest.String()

						foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
					}

					foundindexDataMap[descriptor.Digest] = indexData
				default:
					bdw.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)
				}
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (bdw *DBWrapper) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, map[string]repodb.IndexData, repodb.PageInfo, error) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		manifestMetadataMap      = make(map[string]repodb.ManifestMetadata)
		indexDataMap             = make(map[string]repodb.IndexData)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		foundindexDataMap        = make(map[string]repodb.IndexData)
		pageInfo                 repodb.PageInfo

		pageFinder repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{}, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, map[string]repodb.IndexData{},
			repodb.PageInfo{},
			fmt.Errorf("repodb: error while parsing search text, invalid format %w", err)
	}

	err = bdw.DB.View(func(tx *bolt.Tx) error {
		var (
			repoBuck     = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			indexBuck    = tx.Bucket([]byte(repodb.IndexDataBucket))
			manifestBuck = tx.Bucket([]byte(repodb.ManifestDataBucket))
			cursor       = repoBuck.Cursor()
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
						bdw.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)

						continue
					}
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

		// keep just the manifestMeta and indexData we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				switch descriptor.MediaType {
				case ispec.MediaTypeImageManifest:
					foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
				case ispec.MediaTypeImageIndex:
					indexData := indexDataMap[descriptor.Digest]

					var indexContent ispec.Index

					err := json.Unmarshal(indexData.IndexBlob, &indexContent)
					if err != nil {
						return err
					}

					for _, manifestDescriptor := range indexContent.Manifests {
						manifestDigest := manifestDescriptor.Digest.String()

						foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
					}

					foundindexDataMap[descriptor.Digest] = indexData
				default:
					bdw.Log.Error().Msgf("Unsupported type: %s", descriptor.MediaType)
				}
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, foundindexDataMap, pageInfo, err
}

func (bdw *DBWrapper) PatchDB() error {
	var DBVersion string

	err := bdw.DB.View(func(tx *bolt.Tx) error {
		versionBuck := tx.Bucket([]byte(repodb.VersionBucket))
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
