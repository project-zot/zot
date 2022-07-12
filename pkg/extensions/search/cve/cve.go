package cveinfo

import (
	"flag"
	"fmt"
	"path"
	"strings"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

func getRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2) //nolint:gomnd

	if len(names) != 2 { // nolint: gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

// UpdateCVEDb ...
func UpdateCVEDb(dbDir string, log log.Logger) error {
	return operation.DownloadDB("dev", dbDir, false, false, false)
}

// NewTrivyContext set some trivy configuration value and return a context.
func NewTrivyContext(dir string) *TrivyCtx {
	trivyCtx := &TrivyCtx{}

	app := &cli.App{}

	flagSet := &flag.FlagSet{}

	var cacheDir string

	flagSet.StringVar(&cacheDir, "cache-dir", dir, "")

	var vuln string

	flagSet.StringVar(&vuln, "vuln-type", strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","), "")

	var severity string

	flagSet.StringVar(&severity, "severity", strings.Join(dbTypes.SeverityNames, ","), "")

	flagSet.StringVar(&trivyCtx.Input, "input", "", "")

	var securityCheck string

	flagSet.StringVar(&securityCheck, "security-checks", types.SecurityCheckVulnerability, "")

	var reportFormat string

	flagSet.StringVar(&reportFormat, "format", "table", "")

	ctx := cli.NewContext(app, flagSet, nil)

	trivyCtx.Ctx = ctx

	return trivyCtx
}

func ScanImage(ctx *cli.Context) (report.Report, error) {
	return artifact.TrivyImageRun(ctx)
}

func GetCVEInfo(storeController storage.StoreController, log log.Logger) (*CveInfo, error) {
	cveController := CveTrivyController{}
	layoutUtils := common.NewBaseOciLayoutUtils(storeController, log)

	subCveConfig := make(map[string]*TrivyCtx)

	if storeController.DefaultStore != nil {
		imageStore := storeController.DefaultStore

		rootDir := imageStore.RootDir()

		ctx := NewTrivyContext(rootDir)

		cveController.DefaultCveConfig = ctx
	}

	if storeController.SubStore != nil {
		for route, storage := range storeController.SubStore {
			rootDir := storage.RootDir()

			ctx := NewTrivyContext(rootDir)

			subCveConfig[route] = ctx
		}
	}

	cveController.SubCveConfig = subCveConfig

	return &CveInfo{
		Log: log, CveTrivyController: cveController, StoreController: storeController,
		LayoutUtils: layoutUtils,
	}, nil
}

func (cveinfo CveInfo) GetTrivyContext(image string) *TrivyCtx {
	// Split image to get route prefix
	prefixName := getRoutePrefix(image)

	var trivyCtx *TrivyCtx

	var ok bool

	var rootDir string

	// Get corresponding CVE trivy config, if no sub cve config present that means its default
	trivyCtx, ok = cveinfo.CveTrivyController.SubCveConfig[prefixName]
	if ok {
		imgStore := cveinfo.StoreController.SubStore[prefixName]

		rootDir = imgStore.RootDir()
	} else {
		trivyCtx = cveinfo.CveTrivyController.DefaultCveConfig

		imgStore := cveinfo.StoreController.DefaultStore

		rootDir = imgStore.RootDir()
	}

	trivyCtx.Input = path.Join(rootDir, image)

	return trivyCtx
}

func (cveinfo CveInfo) GetImageListForCVE(repo, cvid string, imgStore storage.ImageStore,
	trivyCtx *TrivyCtx,
) ([]*string, error) {
	tags := make([]*string, 0)

	tagList, err := imgStore.GetImageTags(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Msg("unable to get list of image tag")

		return tags, err
	}

	rootDir := imgStore.RootDir()

	for _, tag := range tagList {
		image := fmt.Sprintf("%s:%s", repo, tag)

		trivyCtx.Input = path.Join(rootDir, image)

		isValidImage, _ := cveinfo.LayoutUtils.IsValidImageFormat(image)
		if !isValidImage {
			cveinfo.Log.Debug().Str("image", repo+":"+tag).Msg("image media type not supported for scanning")

			continue
		}

		cveinfo.Log.Info().Str("image", repo+":"+tag).Msg("scanning image")

		report, err := ScanImage(trivyCtx.Ctx)
		if err != nil {
			cveinfo.Log.Error().Err(err).Str("image", repo+":"+tag).Msg("unable to scan image")

			continue
		}

		for _, result := range report.Results {
			for _, vulnerability := range result.Vulnerabilities {
				if vulnerability.VulnerabilityID == cvid {
					copyImgTag := tag
					tags = append(tags, &copyImgTag)

					break
				}
			}
		}
	}

	return tags, nil
}
