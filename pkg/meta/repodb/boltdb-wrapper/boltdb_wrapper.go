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
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

type DBParameters struct {
	RootDir string
}

type DBWrapper struct {
	db  *bolt.DB
	log log.Logger
}

func NewBoltDBWrapper(params DBParameters) (*DBWrapper, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "repo.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	err = boltDB.Update(func(transaction *bolt.Tx) error {
		_, err := transaction.CreateBucketIfNotExists([]byte(repodb.ManifestMetadataBucket))
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
		db:  boltDB,
		log: log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (bdw DBWrapper) SetManifestMeta(manifestDigest godigest.Digest, manifestMeta repodb.ManifestMetadata) error {
	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = map[string][]string{}
	}

	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestMetadataBucket))

		mmBlob, err := json.Marshal(manifestMeta)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while calculating blob for manifest with digest %s", manifestDigest)
		}

		err = buck.Put([]byte(manifestDigest), mmBlob)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while setting manifest meta with for digest %s", manifestDigest)
		}

		return nil
	})

	return err
}

func (bdw DBWrapper) GetManifestMeta(manifestDigest godigest.Digest) (repodb.ManifestMetadata, error) {
	var manifestMetadata repodb.ManifestMetadata

	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestMetadataBucket))

		mmBlob := buck.Get([]byte(manifestDigest))

		if len(mmBlob) == 0 {
			return zerr.ErrManifestMetaNotFound
		}

		err := json.Unmarshal(mmBlob, &manifestMetadata)
		if err != nil {
			return errors.Wrapf(err, "repodb: error while unmashaling manifest meta for digest %s", manifestDigest)
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

	err := bdw.db.Update(func(tx *bolt.Tx) error {
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

	err := bdw.db.Update(func(tx *bolt.Tx) error {
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
	err := bdw.db.Update(func(tx *bolt.Tx) error {
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
	err := bdw.db.Update(func(tx *bolt.Tx) error {
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
	err := bdw.db.Update(func(tx *bolt.Tx) error {
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

	err := bdw.db.View(func(tx *bolt.Tx) error {
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

func (bdw DBWrapper) SetRepoDescription(repo, description string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
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

		repoMeta.Description = description

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw DBWrapper) SetRepoLogo(repo string, logoPath string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
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

		repoMeta.LogoPath = logoPath

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
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

	err = bdw.db.View(func(tx *bolt.Tx) error {
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

		foundRepos = pageFinder.Page()

		return nil
	})

	return foundRepos, err
}

func (bdw DBWrapper) IncrementManifestDownloads(manifestDigest godigest.Digest) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestMetadataBucket))

		manifestMetaBlob := buck.Get([]byte(manifestDigest))
		if manifestMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestMeta repodb.ManifestMetadata

		err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
		if err != nil {
			return err
		}

		manifestMeta.DownloadCount++

		manifestMetaBlob, err = json.Marshal(manifestMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(manifestDigest), manifestMetaBlob)
	})

	return err
}

func (bdw DBWrapper) AddManifestSignature(manifestDigest godigest.Digest, sigMeta repodb.SignatureMetadata) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestMetadataBucket))

		manifestMetaBlob := buck.Get([]byte(manifestDigest))
		if manifestMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestMeta repodb.ManifestMetadata

		err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
		if err != nil {
			return err
		}

		manifestMeta.Signatures[sigMeta.SignatureType] = append(manifestMeta.Signatures[sigMeta.SignatureType],
			sigMeta.SignatureDigest.String())

		manifestMetaBlob, err = json.Marshal(manifestMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(manifestDigest), manifestMetaBlob)
	})

	return err
}

func (bdw DBWrapper) DeleteSignature(manifestDigest godigest.Digest, sigMeta repodb.SignatureMetadata) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(repodb.ManifestMetadataBucket))

		manifestMetaBlob := buck.Get([]byte(manifestDigest))
		if manifestMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestMeta repodb.ManifestMetadata

		err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
		if err != nil {
			return err
		}

		sigType := sigMeta.SignatureType

		for i, sig := range manifestMeta.Signatures[sigType] {
			if sig == sigMeta.SignatureDigest.String() {
				signaturesCount := len(manifestMeta.Signatures[sigType])

				// put element to be deleted at the end of the array
				manifestMeta.Signatures[sigType][i] = manifestMeta.Signatures[sigType][signaturesCount-1]

				// trim the last element
				manifestMeta.Signatures[sigType] = manifestMeta.Signatures[sigType][:signaturesCount-1]

				manifestMetaBlob, err = json.Marshal(manifestMeta)
				if err != nil {
					return err
				}

				return buck.Put([]byte(manifestDigest), manifestMetaBlob)
			}
		}

		return nil
	})

	return err
}

func (bdw DBWrapper) SearchRepos(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)
		pageFinder               repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(repodb.ManifestMetadataBucket))
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
						manifestMetaBlob := manifestBuck.Get([]byte(descriptor.Digest))
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
					repoDownloads += manifestMeta.DownloadCount

					imageLastUpdated, err := common.GetImageLastUpdatedTimestamp(manifestMeta.ConfigBlob)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmarshaling image config referenced by digest %s",
							descriptor.Digest)
					}

					if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
						repoLastUpdated = imageLastUpdated
						firstImageChecked = false

						isSigned = common.CheckIsSigned(manifestMeta.Signatures)
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

		foundRepos = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, manifestDigest := range repoMeta.Tags {
				foundManifestMetadataMap[manifestDigest.Digest] = manifestMetadataMap[manifestDigest.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, err
}

func (bdw DBWrapper) SearchTags(ctx context.Context, searchText string, filter repodb.Filter,
	requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	var (
		foundRepos               = make([]repodb.RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]repodb.ManifestMetadata)

		pageFinder repodb.PageFinder
	)

	pageFinder, err := repodb.NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{}, err
	}

	searchedRepo, searchedTag, err := common.GetRepoTag(searchText)
	if err != nil {
		return []repodb.RepoMetadata{}, map[string]repodb.ManifestMetadata{},
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]repodb.ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(repodb.RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(repodb.ManifestMetadataBucket))
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

					manifestMetaBlob := manifestBuck.Get([]byte(descriptor.Digest))
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
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", descriptor.Digest)
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

				repoMeta.Tags = matchedTags

				pageFinder.Add(repodb.DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, descriptor := range repoMeta.Tags {
				foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, err
}

func (bdw DBWrapper) SearchDigests(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw DBWrapper) SearchLayers(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw DBWrapper) SearchForAscendantImages(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw DBWrapper) SearchForDescendantImages(ctx context.Context, searchText string, requestedPage repodb.PageInput,
) ([]repodb.RepoMetadata, map[string]repodb.ManifestMetadata, error) {
	panic("not implemented")
}
