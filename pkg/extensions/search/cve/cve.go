package cveinfo

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	integration "github.com/aquasecurity/trivy/integration"
	config "github.com/aquasecurity/trivy/integration/config"
	"github.com/aquasecurity/trivy/pkg/report"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	mediaTypeImageLayerSquashFS = "application/vnd.oci.image.layer.squashfs"
)

// UpdateCVEDb ...
func UpdateCVEDb(dbDir string, log log.Logger, interval time.Duration, isTest bool) error {
	config, err := config.NewConfig(dbDir)
	if err != nil {
		log.Error().Err(err).Msg("Unable to get config")
		return err
	}

	for {
		log.Info().Msg("Updating the CVE database")

		err = integration.RunTrivyDb(config.TrivyConfig)
		if err != nil {
			log.Error().Err(err).Msg("Unable to update DB ")
			return err
		}

		if isTest {
			return nil
		}

		time.Sleep(interval * time.Hour)
	}
}

func NewTrivyConfig(dir string) (*config.Config, error) {
	return config.NewConfig(dir)
}

func ScanImage(config *config.Config) (report.Results, error) {
	return integration.ScanTrivyImage(config.TrivyConfig)
}

func (cveinfo CveInfo) IsSquashFS(imagePath string) (bool, error) {
	imageDir := getImageDir(imagePath)

	if !dirExists(imageDir) {
		cveinfo.Log.Error().Msg("Image Directory not exists")

		return false, errors.ErrRepoNotFound
	}

	buf, err := ioutil.ReadFile(path.Join(imageDir, "index.json"))

	if err != nil {
		if os.IsNotExist(err) {
			cveinfo.Log.Error().Err(err).Msg("Index.json does not exist")

			return false, errors.ErrJSONNotFound
		}

		cveinfo.Log.Error().Err(err).Msg("Unable to open index.json")

		return false, errors.ErrInvalidJSON
	}

	var index ispec.Index

	var blobManifest ispec.Manifest

	var digest godigest.Digest

	if err := json.Unmarshal(buf, &index); err != nil {
		cveinfo.Log.Error().Err(err).Msg("Unable to marshal index.json file")

		return false, err
	}

	for _, m := range index.Manifests {
		digest = m.Digest

		blobBuf, err := ioutil.ReadFile(path.Join(imageDir, "blobs", digest.Algorithm().String(), digest.Encoded()))
		if err != nil {
			cveinfo.Log.Error().Err(err).Msg("Failed to read manifest file")

			return false, err
		}

		if err := json.Unmarshal(blobBuf, &blobManifest); err != nil {
			cveinfo.Log.Error().Err(err).Msg("Invalid manifest json")

			return false, err
		}

		imageLayers := blobManifest.Layers

		for _, imageLayer := range imageLayers {
			return imageLayer.MediaType == mediaTypeImageLayerSquashFS, nil
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

func getImageDir(imageName string) string {
	var imageDir string
	if strings.Contains(imageName, ":") {
		imageDir = strings.Split(imageName, ":")[0]
	} else {
		imageDir = imageName
	}

	return imageDir
}

// GetImageTagsWithTimestamp returns a list of image tags with timestamp available in the specified repository.
func (cveinfo CveInfo) GetImageTagsWithTimestamp(rootDir string, repo string) ([]TagInfo, error) {
	dir := path.Join(rootDir, repo)
	if !dirExists(dir) {
		return nil, errors.ErrRepoNotFound
	}

	var digest godigest.Digest

	buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
		return nil, errors.ErrRepoNotFound
	}

	var index ispec.Index
	if err := json.Unmarshal(buf, &index); err != nil {
		cveinfo.Log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
		return nil, errors.ErrRepoNotFound
	}

	tagsInfo := make([]TagInfo, 0)

	var blobIndex ispec.Manifest

	var layerIndex ispec.Image

	for _, manifest := range index.Manifests {
		digest = manifest.Digest
		v, ok := manifest.Annotations[ispec.AnnotationRefName]

		blobBuf, err := ioutil.ReadFile(path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded()))
		if err != nil {
			cveinfo.Log.Error().Err(err).Msg("Unable to open Image Metadata file")

			return nil, err
		}

		if err := json.Unmarshal(blobBuf, &blobIndex); err != nil {
			cveinfo.Log.Error().Err(err).Msg("Unable to marshal blob index")

			return nil, err
		}

		digest = blobIndex.Config.Digest

		blobBuf, err = ioutil.ReadFile(path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded()))
		if err != nil {
			cveinfo.Log.Error().Err(err).Msg("Unable to open Image Layers file")

			return nil, err
		}

		if err := json.Unmarshal(blobBuf, &layerIndex); err != nil {
			cveinfo.Log.Error().Err(err).Msg("Unable to marshal blob index")

			return nil, err
		}

		timeStamp := *layerIndex.History[0].Created

		if ok {
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
