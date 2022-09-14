package repodb

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"strings"
	"time"

	glob "github.com/bmatcuk/doublestar/v4"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/log"
	localCtx "zotregistry.io/zot/pkg/requestcontext"
)

var ErrBadCtxFormat = errors.New("type assertion failed")

type BoltDBParameters struct {
	RootDir string
}

type BoltDBWrapperFactory struct{}

func (bwf BoltDBWrapperFactory) Create(parameters interface{}) (RepoDB, error) {
	properParameters, ok := parameters.(BoltDBParameters)
	if !ok {
		panic("Failed type assertion")
	}

	return NewBoltDBWrapper(properParameters)
}

type BoltDBWrapper struct {
	db  *bolt.DB
	log log.Logger
}

func NewBoltDBWrapper(params BoltDBParameters) (*BoltDBWrapper, error) {
	const perms = 0o600

	boltDB, err := bolt.Open(path.Join(params.RootDir, "repo.db"), perms, &bolt.Options{Timeout: time.Second * 10})
	if err != nil {
		return nil, err
	}

	err = boltDB.Update(func(transaction *bolt.Tx) error {
		_, err := transaction.CreateBucketIfNotExists([]byte(ManifestMetadataBucket))
		if err != nil {
			return err
		}

		_, err = transaction.CreateBucketIfNotExists([]byte(RepoMetadataBucket))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &BoltDBWrapper{
		db:  boltDB,
		log: log.Logger{Logger: zerolog.New(os.Stdout)},
	}, nil
}

func (bdw BoltDBWrapper) SetManifestMeta(manifestDigest godigest.Digest, manifestMeta ManifestMetadata) error {
	// Q: should we check for correct input?
	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = map[string][]string{}
	}

	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestMetadataBucket))

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

func (bdw BoltDBWrapper) GetManifestMeta(manifestDigest godigest.Digest) (ManifestMetadata, error) {
	var manifestMetadata ManifestMetadata

	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestMetadataBucket))

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

func (bdw BoltDBWrapper) SetRepoTag(repo string, tag string, manifestDigest godigest.Digest) error {
	if err := validateRepoTagInput(repo, tag, manifestDigest); err != nil {
		return err
	}

	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if len(repoMetaBlob) == 0 {
			// create a new object
			repoMeta := RepoMetadata{
				Name: repo,
				Tags: map[string]string{
					tag: manifestDigest.String(),
				},
			}

			repoMetaBlob, err := json.Marshal(repoMeta)
			if err != nil {
				return err
			}

			return buck.Put([]byte(repo), repoMetaBlob)
		}

		// object found
		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Tags[tag] = manifestDigest.String()

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func validateRepoTagInput(repo, tag string, manifestDigest godigest.Digest) error {
	if repo == "" {
		return errors.New("repodb: repo name can't be empty string")
	}

	if tag == "" {
		return errors.New("repodb: tag can't be empty string")
	}

	if manifestDigest == "" {
		return errors.New("repodb: manifest digest can't be empty string")
	}

	return nil
}

func (bdw BoltDBWrapper) GetRepoMeta(repo string) (RepoMetadata, error) {
	var repoMeta RepoMetadata

	err := bdw.db.Update(func(tx *bolt.Tx) error {
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

func (bdw BoltDBWrapper) DeleteRepoTag(repo string, tag string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))

		// object not found
		if repoMetaBlob == nil {
			return nil
		}

		// object found
		var repoMeta RepoMetadata

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

func (bdw BoltDBWrapper) IncrementRepoStars(repo string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}
		bdw.log.Info().Int("stars", repoMeta.Stars).Msg("Increment stars")

		repoMeta.Stars++

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDBWrapper) DecrementRepoStars(repo string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

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

func (bdw BoltDBWrapper) GetRepoStars(repo string) (int, error) {
	stars := 0

	err := bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		buck.Get([]byte(repo))
		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		stars = repoMeta.Stars

		return nil
	})

	return stars, err
}

func (bdw BoltDBWrapper) SetRepoDescription(repo, description string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

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

func (bdw BoltDBWrapper) SetRepoLogo(repo string, logoPath string) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

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

func (bdw BoltDBWrapper) SetRepoStars(repo string, starCount int) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		repoMetaBlob := buck.Get([]byte(repo))
		if repoMetaBlob == nil {
			return zerr.ErrRepoMetaNotFound
		}

		var repoMeta RepoMetadata

		err := json.Unmarshal(repoMetaBlob, &repoMeta)
		if err != nil {
			return err
		}

		repoMeta.Stars = starCount

		repoMetaBlob, err = json.Marshal(repoMeta)
		if err != nil {
			return err
		}

		return buck.Put([]byte(repo), repoMetaBlob)
	})

	return err
}

func (bdw BoltDBWrapper) GetMultipleRepoMeta(ctx context.Context, filter func(repoMeta RepoMetadata) bool,
	requestedPage PageInput,
) ([]RepoMetadata, error) {
	var (
		foundRepos = make([]RepoMetadata, 0)
		pageFinder PageFinder
	)

	pageFinder, err := NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return nil, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				pageFinder.Add(DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, _ = pageFinder.Page()

		return nil
	})

	return foundRepos, err
}

func (bdw BoltDBWrapper) IncrementManifestDownloads(manifestDigest godigest.Digest) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestMetadataBucket))

		manifestMetaBlob := buck.Get([]byte(manifestDigest))
		if manifestMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestMeta ManifestMetadata

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

func (bdw BoltDBWrapper) AddManifestSignature(manifestDigest godigest.Digest, sigMeta SignatureMetadata) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestMetadataBucket))

		manifestMetaBlob := buck.Get([]byte(manifestDigest))
		if manifestMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestMeta ManifestMetadata

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

func (bdw BoltDBWrapper) DeleteSignature(manifestDigest godigest.Digest, sigMeta SignatureMetadata) error {
	err := bdw.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(ManifestMetadataBucket))

		manifestMetaBlob := buck.Get([]byte(manifestDigest))
		if manifestMetaBlob == nil {
			return zerr.ErrManifestMetaNotFound
		}

		var manifestMeta ManifestMetadata

		err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
		if err != nil {
			return err
		}

		sigType := sigMeta.SignatureType

		for i, sig := range manifestMeta.Signatures[sigType] {
			if sig == sigMeta.SignatureDigest.String() {
				signaturesCount := len(manifestMeta.Signatures[sigType])

				if signaturesCount < 1 {
					manifestMeta.Signatures[sigType] = []string{}

					return nil
				}

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

func (bdw BoltDBWrapper) SearchRepos(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, PageInfo, error) {
	var (
		foundRepos               = make([]RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]ManifestMetadata)
		pageFinder               PageFinder
		pageInfo                 PageInfo
	)

	pageFinder, err := NewBaseRepoPageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, PageInfo{}, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(ManifestMetadataBucket))
		)

		cursor := repoBuck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			var repoMeta RepoMetadata

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if score := ScoreRepoName(searchText, string(repoName)); score != -1 {
				var (
					// specific values used for sorting that need to be calculated based on all manifests from the repo
					repoDownloads     = 0
					repoLastUpdated   time.Time
					firstImageChecked = true
					osSet             = map[string]bool{}
					archSet           = map[string]bool{}
					isSigned          = false
				)

				for _, manifestDigest := range repoMeta.Tags {
					var manifestMeta ManifestMetadata

					manifestMeta, manifestDownloaded := manifestMetadataMap[manifestDigest]

					if !manifestDownloaded {
						manifestMetaBlob := manifestBuck.Get([]byte(manifestDigest))
						if manifestMetaBlob == nil {
							return zerr.ErrManifestMetaNotFound
						}

						err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
						if err != nil {
							return errors.Wrapf(err, "repodb: error while unmarshaling manifest metadata for digest %s", manifestDigest)
						}
					}

					// get fields related to filtering
					var configContent ispec.Image

					err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmarshaling config content for digest %s", manifestDigest)
					}

					osSet[configContent.OS] = true
					archSet[configContent.Architecture] = true

					// get fields related to sorting
					repoDownloads += manifestMeta.DownloadCount

					imageLastUpdated, err := getImageLastUpdatedTimestamp(manifestMeta.ConfigBlob)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmarshaling image config referenced by digest %s", manifestDigest)
					}

					if firstImageChecked || repoLastUpdated.Before(imageLastUpdated) {
						repoLastUpdated = imageLastUpdated
						firstImageChecked = false

						isSigned = checkIsSigned(manifestMeta.Signatures)
					}

					manifestMetadataMap[manifestDigest] = manifestMeta
				}

				repoFilterData := filterData{
					OsList:   getMapKeys(osSet),
					ArchList: getMapKeys(archSet),
					IsSigned: isSigned,
				}

				if !acceptedByFilter(filter, repoFilterData) {
					continue
				}

				pageFinder.Add(DetailedRepoMeta{
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
				foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func checkIsSigned(signatures map[string][]string) bool {
	for _, signatures := range signatures {
		if len(signatures) > 0 {
			return true
		}
	}

	return false
}

func ScoreRepoName(searchText string, repoName string) int {
	searchTextSlice := strings.Split(searchText, "/")
	repoNameSlice := strings.Split(repoName, "/")

	if len(searchTextSlice) > len(repoNameSlice) {
		return -1
	}

	if len(searchTextSlice) == 1 {
		// check if it maches first or last name in path
		if index := strings.Index(repoNameSlice[len(repoNameSlice)-1], searchTextSlice[0]); index != -1 {
			return index + 1
		}

		// we'll make repos that match the first name in path less important than matching the last name in path
		if index := strings.Index(repoNameSlice[0], searchTextSlice[0]); index != -1 {
			return (index + 1) * 10
		}

		return -1
	}

	if len(searchTextSlice) < len(repoNameSlice) &&
		strings.HasPrefix(repoName, searchText) {
		return 1
	}

	// searchText and repoName match perfectly up until the last name in path
	for i := 0; i < len(searchTextSlice)-1; i++ {
		if searchTextSlice[i] != repoNameSlice[i] {
			return -1
		}
	}

	// check the last
	if index := strings.Index(repoNameSlice[len(repoNameSlice)-1], searchTextSlice[len(searchTextSlice)-1]); index != -1 {
		return (index + 1)
	}

	return -1
}

func (bdw BoltDBWrapper) FilterTags(ctx context.Context, filter FilterFunc,
	requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	var (
		foundRepos               = make([]RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]ManifestMetadata)
		pageFinder               *ImagePageFinder
	)

	pageFinder, err := NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(ManifestMetadataBucket))
			cursor              = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.First()

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			matchedTags := make(map[string]string)
			// take all manifestMetas
			for tag, manifestDigest := range repoMeta.Tags {
				matchedTags[tag] = manifestDigest

				// in case tags reference the same manifest we don't download from DB multiple times
				if manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]; manifestExists {
					manifestMetadataMap[manifestDigest] = manifestMeta

					continue
				}

				manifestMetaBlob := manifestBuck.Get([]byte(manifestDigest))
				if manifestMetaBlob == nil {
					return zerr.ErrManifestMetaNotFound
				}

				var manifestMeta ManifestMetadata

				err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
				if err != nil {
					return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				var configContent ispec.Image

				err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
				if err != nil {
					return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
				}

				if !filter(repoMeta, manifestMeta) {
					delete(matchedTags, tag)
					delete(manifestMetadataMap, manifestDigest)

					continue
				}

				manifestMetadataMap[manifestDigest] = manifestMeta
			}

			repoMeta.Tags = matchedTags

			pageFinder.Add(DetailedRepoMeta{
				RepoMeta: repoMeta,
			})
		}

		foundRepos, _ = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, manifestDigest := range repoMeta.Tags {
				foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, err
}

func (bdw BoltDBWrapper) SearchTags(ctx context.Context, searchText string, filter Filter, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, PageInfo, error) {
	var (
		foundRepos               = make([]RepoMetadata, 0)
		foundManifestMetadataMap = make(map[string]ManifestMetadata)
		pageInfo                 PageInfo

		pageFinder *ImagePageFinder
	)

	pageFinder, err := NewBaseImagePageFinder(requestedPage.Limit, requestedPage.Offset, requestedPage.SortBy)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, PageInfo{}, err
	}

	searchedRepo, searchedTag, err := getRepoTag(searchText)
	if err != nil {
		return []RepoMetadata{}, map[string]ManifestMetadata{}, PageInfo{},
			errors.Wrap(err, "repodb: error while parsing search text, invalid format")
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		var (
			manifestMetadataMap = make(map[string]ManifestMetadata)
			repoBuck            = tx.Bucket([]byte(RepoMetadataBucket))
			manifestBuck        = tx.Bucket([]byte(ManifestMetadataBucket))
			cursor              = repoBuck.Cursor()
		)

		repoName, repoMetaBlob := cursor.Seek([]byte(searchedRepo))

		for ; repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if string(repoName) == searchedRepo {
				matchedTags := make(map[string]string)
				// take all manifestMetas
				for tag, manifestDigest := range repoMeta.Tags {
					if !strings.HasPrefix(tag, searchedTag) {
						continue
					}

					matchedTags[tag] = manifestDigest

					// in case tags reference the same manifest we don't download from DB multiple times
					if manifestMeta, manifestExists := manifestMetadataMap[manifestDigest]; manifestExists {
						manifestMetadataMap[manifestDigest] = manifestMeta

						continue
					}

					manifestMetaBlob := manifestBuck.Get([]byte(manifestDigest))
					if manifestMetaBlob == nil {
						return zerr.ErrManifestMetaNotFound
					}

					var manifestMeta ManifestMetadata

					err := json.Unmarshal(manifestMetaBlob, &manifestMeta)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
					}

					var configContent ispec.Image

					err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
					if err != nil {
						return errors.Wrapf(err, "repodb: error while unmashaling manifest metadata for digest %s", manifestDigest)
					}

					imageFilterData := filterData{
						OsList:   []string{configContent.OS},
						ArchList: []string{configContent.Architecture},
						IsSigned: false,
					}

					if !acceptedByFilter(filter, imageFilterData) {
						delete(matchedTags, tag)
						delete(manifestMetadataMap, manifestDigest)

						continue
					}

					manifestMetadataMap[manifestDigest] = manifestMeta
				}

				if len(matchedTags) == 0 {
					continue
				}

				repoMeta.Tags = matchedTags

				pageFinder.Add(DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		// keep just the manifestMeta we need
		for _, repoMeta := range foundRepos {
			for _, manifestDigest := range repoMeta.Tags {
				foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
			}
		}

		return nil
	})

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

func (bdw BoltDBWrapper) FilterRepos(ctx context.Context,
	filter FilterRepoFunc,
	requestedPage PageInput,
) (
	[]RepoMetadata, map[string]ManifestMetadata, PageInfo, error,
) {
	var (
		foundRepos = make([]RepoMetadata, 0)
		pageFinder PageFinder
		pageInfo   PageInfo
	)

	pageFinder, err := NewBaseRepoPageFinder(
		requestedPage.Limit,
		requestedPage.Offset,
		requestedPage.SortBy,
	)
	if err != nil {
		return nil, nil, pageInfo, err
	}

	err = bdw.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket([]byte(RepoMetadataBucket))

		cursor := buck.Cursor()

		for repoName, repoMetaBlob := cursor.First(); repoName != nil; repoName, repoMetaBlob = cursor.Next() {
			if ok, err := repoIsUserAvailable(ctx, string(repoName)); !ok || err != nil {
				continue
			}

			repoMeta := RepoMetadata{}

			err := json.Unmarshal(repoMetaBlob, &repoMeta)
			if err != nil {
				return err
			}

			if filter(repoMeta) {
				pageFinder.Add(DetailedRepoMeta{
					RepoMeta: repoMeta,
				})
			}
		}

		foundRepos, pageInfo = pageFinder.Page()

		return nil
	})

	foundManifestMetadataMap := make(map[string]ManifestMetadata)

	for idx := range foundRepos {
		for _, manifestDigest := range foundRepos[idx].Tags {
			manifestMeta, err := bdw.GetManifestMeta(godigest.Digest(manifestDigest))
			if err != nil {
				return nil, nil, pageInfo, err
			}

			foundManifestMetadataMap[manifestDigest] = manifestMeta
		}
	}

	return foundRepos, foundManifestMetadataMap, pageInfo, err
}

// acceptedByFilter checks that data contains at least 1 element of each filter
// criteria(os, arch) present in filter.
func acceptedByFilter(filter Filter, data filterData) bool {
	if filter.Arch != nil {
		foundArch := false
		for _, arch := range filter.Arch {
			foundArch = foundArch || containsString(data.ArchList, *arch)
		}

		if !foundArch {
			return false
		}
	}

	if filter.Os != nil {
		foundOs := false
		for _, os := range filter.Os {
			foundOs = foundOs || containsString(data.OsList, *os)
		}

		if !foundOs {
			return false
		}
	}

	if filter.HasToBeSigned != nil && *filter.HasToBeSigned != data.IsSigned {
		return false
	}

	return true
}

func containsString(strSlice []string, str string) bool {
	for _, val := range strSlice {
		if strings.EqualFold(val, str) {
			return true
		}
	}

	return false
}

func (bdw BoltDBWrapper) SearchDigests(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw BoltDBWrapper) SearchLayers(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw BoltDBWrapper) SearchForAscendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func (bdw BoltDBWrapper) SearchForDescendantImages(ctx context.Context, searchText string, requestedPage PageInput,
) ([]RepoMetadata, map[string]ManifestMetadata, error) {
	panic("not implemented")
}

func repoIsUserAvailable(ctx context.Context, repoName string) (bool, error) {
	authzCtxKey := localCtx.GetContextKey()

	if authCtx := ctx.Value(authzCtxKey); authCtx != nil {
		acCtx, ok := authCtx.(localCtx.AccessControlContext)
		if !ok {
			err := ErrBadCtxFormat

			return false, err
		}

		if acCtx.IsAdmin || matchesRepo(acCtx.GlobPatterns, repoName) {
			return true, nil
		}

		return false, nil
	}

	return true, nil
}

// returns either a user has or not rights on 'repository'.
func matchesRepo(globPatterns map[string]bool, repository string) bool {
	var longestMatchedPattern string

	// because of the longest path matching rule, we need to check all patterns from config
	for pattern := range globPatterns {
		matched, err := glob.Match(pattern, repository)
		if err == nil {
			if matched && len(pattern) > len(longestMatchedPattern) {
				longestMatchedPattern = pattern
			}
		}
	}

	allowed := globPatterns[longestMatchedPattern]

	return allowed
}

func getRepoTag(searchText string) (string, string, error) {
	const repoTagCount = 2

	splitSlice := strings.Split(searchText, ":")

	if len(splitSlice) != repoTagCount {
		return "", "", errors.New("invalid format for tag search, not following repo:tag")
	}

	repo := strings.TrimSpace(splitSlice[0])
	tag := strings.TrimSpace(splitSlice[1])

	return repo, tag, nil
}

func getMapKeys[K comparable, V any](genericMap map[K]V) []K {
	keys := make([]K, 0, len(genericMap))

	for k := range genericMap {
		keys = append(keys, k)
	}

	return keys
}

func getImageLastUpdatedTimestamp(configBlob []byte) (time.Time, error) {
	var (
		configContent ispec.Image
		timeStamp     *time.Time
	)

	err := json.Unmarshal(configBlob, &configContent)
	if err != nil {
		return time.Time{}, err
	}

	if configContent.Created != nil && !configContent.Created.IsZero() {
		return *configContent.Created, nil
	}

	if len(configContent.History) != 0 {
		timeStamp = configContent.History[len(configContent.History)-1].Created
	}

	if timeStamp == nil {
		timeStamp = &time.Time{}
	}

	return *timeStamp, nil
}
