package cveinfo

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	integration "github.com/aquasecurity/trivy/integration"
	config "github.com/aquasecurity/trivy/integration/config"
	"github.com/aquasecurity/trivy/pkg/report"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// UpdateCVEDb ...
func UpdateCVEDb(dbDir string, log log.Logger) error {
	config, err := config.NewConfig(dbDir)
	if err != nil {
		log.Error().Err(err).Msg("unable to get config")
		return err
	}

	err = integration.RunTrivyDb(config.TrivyConfig)
	if err != nil {
		log.Error().Err(err).Msg("unable to update DB ")
		return err
	}

	return nil
}

func NewTrivyConfig(dir string) (*config.Config, error) {
	return config.NewConfig(dir)
}

func ScanImage(config *config.Config) (report.Results, error) {
	return integration.ScanTrivyImage(config.TrivyConfig)
}

func (cveinfo CveInfo) IsValidImageFormat(imagePath string) (bool, error) {
	imageDir, inputTag := getImageDirAndTag(imagePath)

	if !dirExists(imageDir) {
		cveinfo.Log.Error().Msg("image directory doesn't exist")

		return false, errors.ErrRepoNotFound
	}

	manifests, err := cveinfo.getImageManifests(imageDir)

	if err != nil {
		return false, err
	}

	for _, m := range manifests {
		tag, ok := m.Annotations[ispec.AnnotationRefName]

		if ok && inputTag != "" && tag != inputTag {
			continue
		}

		blobManifest, err := cveinfo.getImageBlobManifest(imageDir, m.Digest)
		if err != nil {
			return false, err
		}

		imageLayers := blobManifest.Layers

		for _, imageLayer := range imageLayers {
			switch imageLayer.MediaType {
			case types.OCILayer, types.DockerLayer:
				return true, nil

			default:
				cveinfo.Log.Debug().Msg("image media type not supported for scanning")
				return false, errors.ErrScanNotSupported
			}
		}
	}

	return false, nil
}

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return fi.IsDir()
}

func getImageDirAndTag(imageName string) (string, string) {
	var imageDir string

	var imageTag string

	if strings.Contains(imageName, ":") {
		splitImageName := strings.Split(imageName, ":")
		imageDir = splitImageName[0]
		imageTag = splitImageName[1]
	} else {
		imageDir = imageName
	}

	return imageDir, imageTag
}

// GetImageTagsWithTimestamp returns a list of image tags with timestamp available in the specified repository.
func (cveinfo CveInfo) GetImageTagsWithTimestamp(rootDir string, repo string) ([]TagInfo, error) {
	tagsInfo := make([]TagInfo, 0)

	dir := path.Join(rootDir, repo)
	if !dirExists(dir) {
		return nil, errors.ErrRepoNotFound
	}

	manifests, err := cveinfo.getImageManifests(dir)

	if err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to read image manifests")

		return tagsInfo, err
	}

	for _, manifest := range manifests {
		digest := manifest.Digest

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := cveinfo.getImageBlobManifest(dir, digest)

			if err != nil {
				cveinfo.Log.Error().Err(err).Msg("unable to read image blob manifest")

				return tagsInfo, err
			}

			imageInfo, err := cveinfo.getImageInfo(dir, imageBlobManifest.Config.Digest)
			if err != nil {
				cveinfo.Log.Error().Err(err).Msg("unable to read image info")

				return tagsInfo, err
			}

			timeStamp := *imageInfo.History[0].Created

			tagsInfo = append(tagsInfo, TagInfo{Name: v, Timestamp: timeStamp})
		}
	}

	return tagsInfo, nil
}

func GetFixedTags(allTags []TagInfo, infectedTags []TagInfo) []TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(allTags[j].Timestamp)
	})

	latestInfected := TagInfo{}

	for _, tag := range infectedTags {
		if !tag.Timestamp.Before(latestInfected.Timestamp) {
			latestInfected = tag
		}
	}

	var fixedTags []TagInfo

	for _, tag := range allTags {
		if tag.Timestamp.After(latestInfected.Timestamp) {
			fixedTags = append(fixedTags, tag)
		}
	}

	return fixedTags
}

func (cveinfo CveInfo) getImageManifests(imagePath string) ([]ispec.Descriptor, error) {
	buf, err := ioutil.ReadFile(path.Join(imagePath, "index.json"))

	if err != nil {
		if os.IsNotExist(err) {
			cveinfo.Log.Error().Err(err).Msg("index.json doesn't exist")

			return nil, errors.ErrRepoNotFound
		}

		cveinfo.Log.Error().Err(err).Msg("unable to open index.json")

		return nil, errors.ErrRepoNotFound
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		cveinfo.Log.Error().Err(err).Str("dir", imagePath).Msg("invalid JSON")
		return nil, errors.ErrRepoNotFound
	}

	return index.Manifests, nil
}

func (cveinfo CveInfo) getImageBlobManifest(imageDir string, digest godigest.Digest) (v1.Manifest, error) {
	var blobIndex v1.Manifest

	blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", digest.Algorithm().String(), digest.Encoded()))
	if err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to open image metadata file")

		return blobIndex, err
	}

	if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to marshal blob index")

		return blobIndex, err
	}

	return blobIndex, nil
}

func (cveinfo CveInfo) getImageInfo(imageDir string, hash v1.Hash) (ispec.Image, error) {
	var imageInfo ispec.Image

	blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", hash.Algorithm, hash.Hex))
	if err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to open image layers file")

		return imageInfo, err
	}

	if err := json.Unmarshal(blobBuf, &imageInfo); err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to marshal blob index")

		return imageInfo, err
	}

	return imageInfo, err
}
