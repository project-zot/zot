package cveinfo

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
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
		log.Error().Err(err).Msg("Unable to get config")
		return err
	}

	err = integration.RunTrivyDb(config.TrivyConfig)
	if err != nil {
		log.Error().Err(err).Msg("Unable to update DB ")
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
	imageDir := getImageDir(imagePath)

	if !dirExists(imageDir) {
		cveinfo.Log.Error().Msg("Image Directory not exists")

		return false, errors.ErrRepoNotFound
	}

	buf, err := ioutil.ReadFile(path.Join(imageDir, "index.json"))

	if err != nil {
		if os.IsNotExist(err) {
			cveinfo.Log.Error().Err(err).Msg("Index.json does not exist")

			return false, errors.ErrRepoNotFound
		}

		cveinfo.Log.Error().Err(err).Msg("Unable to open index.json")

		return false, errors.ErrRepoNotFound
	}

	var index ispec.Index

	var blobManifest v1.Manifest

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
			switch imageLayer.MediaType {
			case types.OCILayer, types.DockerLayer:
				return true, nil

			default:
				cveinfo.Log.Debug().Msg("Image media type not supported for scanning")
				return false, nil
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

func getImageDir(imageName string) string {
	var imageDir string
	if strings.Contains(imageName, ":") {
		imageDir = strings.Split(imageName, ":")[0]
	} else {
		imageDir = imageName
	}

	return imageDir
}
