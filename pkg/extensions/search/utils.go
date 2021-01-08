package search

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	AnnotationLabels           = "com.cisco.image.labels"
	LabelAnnotationCreated     = "org.label-schema.build-date"
	LabelAnnotationVendor      = "org.label-schema.vendor"
	LabelAnnotationDescription = "org.label-schema.description"
	LabelAnnotationLicenses    = "org.label-schema.license"
)

// GetImageTagsWithTimestamp returns a list of image tags with timestamp available in the specified repository.
func GetImageTagsWithTimestamp(rootDir string, repo string, log log.Logger) ([]TagInfo, error) {
	tagsInfo := make([]TagInfo, 0)

	dir := path.Join(rootDir, repo)
	if !dirExists(dir) {
		return nil, errors.ErrRepoNotFound
	}

	manifests, err := getImageManifests(dir, log)
	if err != nil {
		log.Error().Err(err).Msg("unable to read image manifests")

		return tagsInfo, err
	}

	for _, manifest := range manifests {
		digest := manifest.Digest

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := getImageBlobManifest(dir, digest, log)
			if err != nil {
				log.Error().Err(err).Msg("unable to read image blob manifest")

				return tagsInfo, err
			}

			imageInfo, err := getManifestConfigBlob(dir, imageBlobManifest.Config.Digest, log)
			if err != nil {
				log.Error().Err(err).Msg("unable to read image info")

				return tagsInfo, err
			}
			timeStamp := imageInfo.History[0].Created
			tagsInfo = append(tagsInfo, TagInfo{Name: &v, Timestamp: timeStamp})

		}
	}

	return tagsInfo, nil
}

func getImageIndex(imagePath string, log log.Logger) (ispec.Index, error) {
	var index ispec.Index

	buf, err := readFile(path.Join(imagePath, "index.json"), log)
	if err != nil {
		log.Error().Err(err).Msg("error reading file")

		return index, errors.ErrRepoNotFound
	}

	if err := json.Unmarshal(buf, &index); err != nil {
		log.Error().Err(err).Str("dir", imagePath).Msg("invalid JSON")
		return index, errors.ErrBadIndex
	}

	return index, err
}

func getImageManifests(imagePath string, log log.Logger) ([]ispec.Descriptor, error) {
	buf, err := readFile(path.Join(imagePath, "index.json"), log)
	if err != nil {
		log.Error().Err(err).Msg("error reading file")

		return nil, errors.ErrRepoNotFound
	}

	var index ispec.Index

	if err := json.Unmarshal(buf, &index); err != nil {
		log.Error().Err(err).Str("dir", imagePath).Msg("invalid JSON")
		return nil, errors.ErrBadIndex
	}

	return index.Manifests, nil
}

func readFile(imagePath string, log log.Logger) ([]byte, error) {
	buf, err := ioutil.ReadFile(imagePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Error().Err(err).Str("file", imagePath).Msg("doesn't exist")

			return nil, errors.ErrRepoNotFound
		}

		log.Error().Err(err).Str("file", imagePath).Msg("doesn't exist")

		return nil, errors.ErrRepoNotFound
	}

	return buf, err
}

func getImageBlobManifest(imageDir string, digest godigest.Digest, log log.Logger) (v1.Manifest, error) {
	var blobIndex v1.Manifest

	blobBuf, err := readFile(path.Join(imageDir, "blobs", digest.Algorithm().String(), digest.Encoded()), log)
	if err != nil {
		log.Error().Err(err).Msg("unable to open image metadata file")

		return blobIndex, err
	}

	if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
		log.Error().Err(err).Msg("unable to marshal blob index")

		return blobIndex, err
	}

	return blobIndex, nil
}

func getManifestConfigBlob(imageDir string, hash v1.Hash, log log.Logger) (ispec.Image, error) {
	var imageInfo ispec.Image

	blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", hash.Algorithm, hash.Hex))
	if err != nil {
		log.Error().Err(err).Msg("unable to open image layers file")

		return imageInfo, err
	}

	if err := json.Unmarshal(blobBuf, &imageInfo); err != nil {
		log.Error().Err(err).Msg("unable to marshal blob index")

		return imageInfo, err
	}

	return imageInfo, err
}

func IsValidImageFormat(imagePath string, log log.Logger) (bool, error) {
	imageDir, inputTag := getImageDirAndTag(imagePath)

	if !dirExists(imageDir) {
		log.Error().Msg("image directory doesn't exist")

		return false, errors.ErrRepoNotFound
	}

	manifests, err := getImageManifests(imageDir, log)
	if err != nil {
		return false, err
	}

	for _, m := range manifests {
		tag, ok := m.Annotations[ispec.AnnotationRefName]

		if ok && inputTag != "" && tag != inputTag {
			continue
		}

		blobManifest, err := getImageBlobManifest(imageDir, m.Digest, log)
		if err != nil {
			return false, err
		}

		imageLayers := blobManifest.Layers

		for _, imageLayer := range imageLayers {
			switch imageLayer.MediaType {
			case types.OCILayer, types.DockerLayer:
				return true, nil

			default:
				log.Debug().Msg("image media type not supported for scanning")
				return false, errors.ErrScanNotSupported
			}
		}
	}

	return false, nil
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

func GetFixedTags(allTags []TagInfo, infectedTags []TagInfo) []TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(*allTags[j].Timestamp)
	})

	var latestInfected TagInfo
	var fixedTags []TagInfo

	if len(infectedTags) != 0 {
		latestInfected = infectedTags[0]
	} else {
		return allTags
	}

	for _, tag := range infectedTags {
		if !tag.Timestamp.Before(*latestInfected.Timestamp) {
			latestInfected = tag
		}
	}

	for _, tag := range allTags {
		if tag.Timestamp.After(*latestInfected.Timestamp) {
			fixedTags = append(fixedTags, tag)
		}
	}

	return fixedTags
}

func getLatestTag(allTags []TagInfo) TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(*allTags[j].Timestamp)
	})

	return allTags[len(allTags)-1]
}

func getGraphqlCompatibleTags(fixedTags []TagInfo) []*TagInfo {
	finalTagList := make([]*TagInfo, 0)

	for _, tag := range fixedTags {
		fmt.Println(tag)
		finalTagList = append(finalTagList, &tag)
	}

	return finalTagList
}

func dirExists(d string) bool {
	fi, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}

	return fi.IsDir()
}

func unmarshalManifest(buf []byte) (v1.Manifest, error) {
	var manifest v1.Manifest
	if err := json.Unmarshal(buf, &manifest); err != nil {
		return manifest, err
	}

	return manifest, nil
}
