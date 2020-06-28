package cveinfo

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
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
