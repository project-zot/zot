package cveinfo

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/extensions/search/common"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	integration "github.com/aquasecurity/trivy/integration"
	config "github.com/aquasecurity/trivy/integration/config"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/google/go-containerregistry/pkg/v1/types"
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

func GetCVEInfo(storeController storage.StoreController, log log.Logger) (*CveInfo, error) {
	cveController := CveTrivyController{}
	layoutUtils := common.NewOciLayoutUtils(storeController, log)

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

func (cveinfo CveInfo) IsValidImageFormat(image string) (bool, error) {
	imageDir, inputTag := common.GetImageDirAndTag(image)

	manifests, err := cveinfo.LayoutUtils.GetImageManifests(imageDir)
	if err != nil {
		return false, err
	}

	for _, m := range manifests {
		tag, ok := m.Annotations[ispec.AnnotationRefName]

		if ok && inputTag != "" && tag != inputTag {
			continue
		}

		blobManifest, err := cveinfo.LayoutUtils.GetImageBlobManifest(imageDir, m.Digest)
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

func (cveinfo CveInfo) GetImageListForCVE(repo string, id string, imgStore storage.ImageStore,
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

		isValidImage, _ := cveinfo.IsValidImageFormat(fmt.Sprintf("%s:%s", repo, tag))
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

// GetImageTagsWithTimestamp returns a list of image tags with timestamp available in the specified repository.
func (cveinfo CveInfo) GetImageTagsWithTimestamp(repo string) ([]TagInfo, error) {
	tagsInfo := make([]TagInfo, 0)

	imagePath := cveinfo.LayoutUtils.GetImageRepoPath(repo)
	if !cveinfo.LayoutUtils.DirExists(imagePath) {
		return nil, errors.ErrRepoNotFound
	}

	manifests, err := cveinfo.LayoutUtils.GetImageManifests(repo)

	if err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to read image manifests")

		return tagsInfo, err
	}

	for _, manifest := range manifests {
		digest := manifest.Digest

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := cveinfo.LayoutUtils.GetImageBlobManifest(repo, digest)

			if err != nil {
				cveinfo.Log.Error().Err(err).Msg("unable to read image blob manifest")

				return tagsInfo, err
			}

			imageInfo, err := cveinfo.LayoutUtils.GetImageInfo(repo, imageBlobManifest.Config.Digest)
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
