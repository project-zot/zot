package cveinfo

import (
	"fmt"
	"path"
	"strings"

	"github.com/anuvu/zot/pkg/extensions/search/common"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	integration "github.com/aquasecurity/trivy/integration"
	config "github.com/aquasecurity/trivy/integration/config"
	"github.com/aquasecurity/trivy/pkg/report"
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

func GetCVEInfo(storeController storage.StoreController, log log.Logger) (*CveInfo, error) {
	cveController := CveTrivyController{}
	layoutUtils := common.NewOciLayoutUtils(log)

	subCveConfig := make(map[string]*config.Config)

	if storeController.DefaultStore != nil {
		imageStore := storeController.DefaultStore

		rootDir := imageStore.RootDir()

		config, err := NewTrivyConfig(rootDir)
		if err != nil {
			return nil, err
		}

		cveController.DefaultCveConfig = config
	}

	if storeController.SubStore != nil {
		for route, storage := range storeController.SubStore {
			rootDir := storage.RootDir()

			config, err := NewTrivyConfig(rootDir)
			if err != nil {
				return nil, err
			}

			subCveConfig[route] = config
		}
	}

	cveController.SubCveConfig = subCveConfig

	return &CveInfo{Log: log, CveTrivyController: cveController, StoreController: storeController,
		LayoutUtils: layoutUtils}, nil
}

func getRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2)

	if len(names) != 2 { // nolint: gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

func (cveinfo CveInfo) GetTrivyConfig(image string) *config.Config {
	// Split image to get route prefix
	prefixName := getRoutePrefix(image)

	var trivyConfig *config.Config

	var ok bool

	var rootDir string

	// Get corresponding CVE trivy config, if no sub cve config present that means its default
	trivyConfig, ok = cveinfo.CveTrivyController.SubCveConfig[prefixName]
	if ok {
		imgStore := cveinfo.StoreController.SubStore[prefixName]

		rootDir = imgStore.RootDir()
	} else {
		trivyConfig = cveinfo.CveTrivyController.DefaultCveConfig

		imgStore := cveinfo.StoreController.DefaultStore

		rootDir = imgStore.RootDir()
	}

	trivyConfig.TrivyConfig.Input = path.Join(rootDir, image)

	return trivyConfig
}

func (cveinfo CveInfo) GetImageListForCVE(repo string, id string, imgStore *storage.ImageStore,
	trivyConfig *config.Config) ([]*string, error) {
	tags := make([]*string, 0)

	tagList, err := imgStore.GetImageTags(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to get list of image tag")

		return tags, err
	}

	rootDir := imgStore.RootDir()

	for _, tag := range tagList {
		trivyConfig.TrivyConfig.Input = fmt.Sprintf("%s:%s", path.Join(rootDir, repo), tag)

		isValidImage, _ := cveinfo.LayoutUtils.IsValidImageFormat(trivyConfig.TrivyConfig.Input)
		if !isValidImage {
			cveinfo.Log.Debug().Str("image", repo+":"+tag).Msg("image media type not supported for scanning")

			continue
		}

		cveinfo.Log.Info().Str("image", repo+":"+tag).Msg("scanning image")

		results, err := ScanImage(trivyConfig)
		if err != nil {
			cveinfo.Log.Error().Err(err).Str("image", repo+":"+tag).Msg("unable to scan image")

			continue
		}

		for _, result := range results {
			for _, vulnerability := range result.Vulnerabilities {
				if vulnerability.VulnerabilityID == id {
					copyImgTag := tag
					tags = append(tags, &copyImgTag)

					break
				}
			}
		}
	}

	return tags, nil
}
