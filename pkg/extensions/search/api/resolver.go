package api

//go:generate go run github.com/99designs/gqlgen

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/anuvu/zot/pkg/log"
	godigest "github.com/opencontainers/go-digest"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/storage"
	v1 "github.com/google/go-containerregistry/pkg/v1"
) // THIS CODE IS A STARTING POINT ONLY. IT WILL NOT BE UPDATED WITH SCHEMA CHANGES.

// Resolver ...
type Resolver struct {
	imgStore *storage.ImageStore
	log      log.Logger
	dir      string
}

// Query ...
func (r *Resolver) Query() QueryResolver {
	return &queryResolver{r}
}

type queryResolver struct{ *Resolver }

// GetResolverConfig ...
func GetResolverConfig(dir string, log log.Logger, imgstorage *storage.ImageStore) Config {
	resConfig := &Resolver{imgStore: imgstorage, log: log, dir: dir}

	return Config{
		Resolvers: resConfig, Directives: DirectiveRoot{},
		Complexity: ComplexityRoot{},
	}
}

func (r *queryResolver) ImageListWithLatestTag(ctx context.Context, image string) ([]*ImageInfo, error) {
	var result []*ImageInfo

	repoList, err := r.imgStore.GetRepositories()
	if err != nil {
		r.log.Error().Err(err).Msg("extension api: error extracting repositories list")

		return result, err
	}

	for _, repo := range repoList {
		tagsInfo, err := r.getImageTagsWithTimestamp(r.dir, repo)
		if err != nil {
			r.log.Error().Err(err).Msg("extension api: error getting tag timestamp info")

			return result, nil
		}

		latestTag := getLatestTag(tagsInfo)

		name := repo

		result = append(result, &ImageInfo{Name: &name, Latest: &latestTag.name})
	}
	return result, nil
}

type tagInfo struct {
	name      string
	timestamp time.Time
}

func (r *queryResolver) getImageTagsWithTimestamp(rootDir string, repo string) ([]tagInfo, error) {
	tagsInfo := make([]tagInfo, 0)

	dir := path.Join(rootDir, repo)
	if !dirExists(dir) {
		return nil, errors.ErrRepoNotFound
	}

	manifests, err := r.getImageManifests(dir)
	if err != nil {
		r.log.Error().Err(err).Msg("unable to read image manifests")

		return tagsInfo, err
	}

	for _, manifest := range manifests {
		digest := manifest.Digest

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := r.getImageBlobManifest(dir, digest)
			if err != nil {
				r.log.Error().Err(err).Msg("unable to read image blob manifest")

				return tagsInfo, err
			}

			imageInfo, err := r.getImageInfo(dir, imageBlobManifest.Config.Digest)
			if err != nil {
				r.log.Error().Err(err).Msg("unable to read image info")

				return tagsInfo, err
			}

			timeStamp := *imageInfo.History[0].Created

			tagsInfo = append(tagsInfo, tagInfo{name: v, timestamp: timeStamp})
		}
	}

	return tagsInfo, nil
}

func (r *queryResolver) getImageManifests(imagePath string) ([]ispec.Descriptor, error) {
	buf, err := ioutil.ReadFile(path.Join(imagePath, "index.json"))
	if err != nil {
		if os.IsNotExist(err) {
			r.log.Error().Err(err).Msg("index.json doesn't exist")

			return nil, errors.ErrRepoNotFound
		}

		r.log.Error().Err(err).Msg("unable to open index.json")

		return nil, errors.ErrRepoNotFound
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		r.log.Error().Err(err).Str("dir", imagePath).Msg("invalid JSON")
		return nil, errors.ErrRepoNotFound
	}

	return index.Manifests, nil
}

func (r *queryResolver) getImageBlobManifest(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
	var blobIndex v1.Manifest

	blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", digest.Algorithm().String(), digest.Encoded()))
	if err != nil {
		r.log.Error().Err(err).Msg("unable to open image metadata file")

		return blobIndex, err
	}

	if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
		r.log.Error().Err(err).Msg("unable to marshal blob index")

		return blobIndex, err
	}

	return blobIndex, nil
}

func (r *queryResolver) getImageInfo(imageDir string, hash v1.Hash) (ispec.Image, error) {
	var imageInfo ispec.Image

	blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", hash.Algorithm, hash.Hex))
	if err != nil {
		r.log.Error().Err(err).Msg("unable to open image layers file")

		return imageInfo, err
	}

	if err := json.Unmarshal(blobBuf, &imageInfo); err != nil {
		r.log.Error().Err(err).Msg("unable to marshal blob index")

		return imageInfo, err
	}

	return imageInfo, err
}

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return fi.IsDir()
}

func getLatestTag(allTags []tagInfo) tagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].timestamp.Before(allTags[j].timestamp)
	})

	return allTags[len(allTags)-1]
}
