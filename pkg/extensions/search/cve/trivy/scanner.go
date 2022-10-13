package trivy

import (
	"flag"
	"path"
	"strings"
	"sync"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/types"
	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli/v2"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

type trivyCtx struct {
	Input string
	Ctx   *cli.Context
}

// newTrivyContext set some trivy configuration value and return a context.
func newTrivyContext(dir string) *trivyCtx {
	tCtx := &trivyCtx{}

	app := &cli.App{}

	flagSet := &flag.FlagSet{}

	var cacheDir string

	flagSet.StringVar(&cacheDir, "cache-dir", dir, "")

	var vuln string

	flagSet.StringVar(&vuln, "vuln-type", strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","), "")

	var severity string

	flagSet.StringVar(&severity, "severity", strings.Join(dbTypes.SeverityNames, ","), "")

	flagSet.StringVar(&tCtx.Input, "input", "", "")

	var securityCheck string

	flagSet.StringVar(&securityCheck, "security-checks", types.SecurityCheckVulnerability, "")

	var reportFormat string

	flagSet.StringVar(&reportFormat, "format", "table", "")

	ctx := cli.NewContext(app, flagSet, nil)

	tCtx.Ctx = ctx

	return tCtx
}

type cveTrivyController struct {
	DefaultCveConfig *trivyCtx
	SubCveConfig     map[string]*trivyCtx
}

type Scanner struct {
	layoutUtils     common.OciLayoutUtils
	cveController   cveTrivyController
	storeController storage.StoreController
	log             log.Logger
	dbLock          *sync.Mutex
	cache           *CveCache
}

func NewScanner(storeController storage.StoreController,
	layoutUtils common.OciLayoutUtils, log log.Logger,
) *Scanner {
	cveController := cveTrivyController{}

	subCveConfig := make(map[string]*trivyCtx)

	if storeController.DefaultStore != nil {
		imageStore := storeController.DefaultStore

		rootDir := imageStore.RootDir()

		ctx := newTrivyContext(rootDir)

		cveController.DefaultCveConfig = ctx
	}

	if storeController.SubStore != nil {
		for route, storage := range storeController.SubStore {
			rootDir := storage.RootDir()

			ctx := newTrivyContext(rootDir)

			subCveConfig[route] = ctx
		}
	}

	cveController.SubCveConfig = subCveConfig

	return &Scanner{
		log:             log,
		layoutUtils:     layoutUtils,
		cveController:   cveController,
		storeController: storeController,
		dbLock:          &sync.Mutex{},
		cache:           NewCveCache(10000, log), //nolint:gomnd
	}
}

func (scanner Scanner) getTrivyContext(image string) *trivyCtx {
	// Split image to get route prefix
	prefixName := common.GetRoutePrefix(image)

	var tCtx *trivyCtx

	var ok bool

	var rootDir string

	// Get corresponding CVE trivy config, if no sub cve config present that means its default
	tCtx, ok = scanner.cveController.SubCveConfig[prefixName]
	if ok {
		imgStore := scanner.storeController.SubStore[prefixName]

		rootDir = imgStore.RootDir()
	} else {
		tCtx = scanner.cveController.DefaultCveConfig

		imgStore := scanner.storeController.DefaultStore

		rootDir = imgStore.RootDir()
	}

	tCtx.Input = path.Join(rootDir, image)

	return tCtx
}

func (scanner Scanner) IsImageFormatScannable(image string) (bool, error) {
	if scanner.cache.Get(image) != nil {
		return true, nil
	}

	imageDir, inputTag := common.GetImageDirAndTag(image)

	manifests, err := scanner.layoutUtils.GetImageManifests(imageDir)
	if err != nil {
		return false, err
	}

	for _, manifest := range manifests {
		tag, ok := manifest.Annotations[ispec.AnnotationRefName]

		if ok && inputTag != "" && tag != inputTag {
			continue
		}

		blobManifest, err := scanner.layoutUtils.GetImageBlobManifest(imageDir, manifest.Digest)
		if err != nil {
			return false, err
		}

		imageLayers := blobManifest.Layers

		for _, imageLayer := range imageLayers {
			switch imageLayer.MediaType {
			case regTypes.OCILayer, regTypes.OCIUncompressedLayer, regTypes.DockerLayer:
				return true, nil

			default:
				scanner.log.Debug().Str("image",
					image).Msgf("image media type %s not supported for scanning", imageLayer.MediaType)

				return false, errors.ErrScanNotSupported
			}
		}
	}

	return false, nil
}

func (scanner Scanner) ScanImage(image string) (map[string]cvemodel.CVE, error) {
	if scanner.cache.Get(image) != nil {
		return scanner.cache.Get(image), nil
	}

	cveidMap := make(map[string]cvemodel.CVE)

	scanner.log.Debug().Str("image", image).Msg("scanning image")

	tCtx := scanner.getTrivyContext(image)

	scanner.dbLock.Lock()
	report, err := artifact.TrivyImageRun(tCtx.Ctx)
	scanner.dbLock.Unlock()

	if err != nil { //nolint: wsl
		scanner.log.Error().Err(err).Str("image", image).Msg("unable to scan image")

		return cveidMap, err
	}

	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			pkgName := vulnerability.PkgName

			installedVersion := vulnerability.InstalledVersion

			var fixedVersion string
			if vulnerability.FixedVersion != "" {
				fixedVersion = vulnerability.FixedVersion
			} else {
				fixedVersion = "Not Specified"
			}

			_, ok := cveidMap[vulnerability.VulnerabilityID]
			if ok {
				cveDetailStruct := cveidMap[vulnerability.VulnerabilityID]

				pkgList := cveDetailStruct.PackageList

				pkgList = append(
					pkgList,
					cvemodel.Package{
						Name:             pkgName,
						InstalledVersion: installedVersion,
						FixedVersion:     fixedVersion,
					},
				)

				cveDetailStruct.PackageList = pkgList

				cveidMap[vulnerability.VulnerabilityID] = cveDetailStruct
			} else {
				newPkgList := make([]cvemodel.Package, 0)

				newPkgList = append(
					newPkgList,
					cvemodel.Package{
						Name:             pkgName,
						InstalledVersion: installedVersion,
						FixedVersion:     fixedVersion,
					},
				)

				cveidMap[vulnerability.VulnerabilityID] = cvemodel.CVE{
					ID:          vulnerability.VulnerabilityID,
					Title:       vulnerability.Title,
					Description: vulnerability.Description,
					Severity:    vulnerability.Severity,
					PackageList: newPkgList,
				}
			}
		}
	}

	scanner.cache.Add(image, cveidMap)

	return cveidMap, nil
}

// UpdateDb download the Trivy DB / Cache under the store root directory.
func (scanner Scanner) UpdateDB() error {
	// We need a lock as using multiple substores each with it's own DB
	// can result in a DATARACE because some varibles in trivy-db are global
	// https://github.com/project-zot/trivy-db/blob/main/pkg/db/db.go#L23
	scanner.dbLock.Lock()
	defer scanner.dbLock.Unlock()

	if scanner.storeController.DefaultStore != nil {
		dbDir := scanner.storeController.DefaultStore.RootDir()

		err := scanner.updateDB(dbDir)
		if err != nil {
			return err
		}
	}

	if scanner.storeController.SubStore != nil {
		for _, storage := range scanner.storeController.SubStore {
			err := scanner.updateDB(storage.RootDir())
			if err != nil {
				return err
			}
		}
	}

	scanner.cache.Purge()

	return nil
}

func (scanner Scanner) updateDB(dbDir string) error {
	scanner.log.Debug().Msgf("Download Trivy DB to destination dir: %s", dbDir)

	err := operation.DownloadDB("dev", dbDir, false, false, false)
	if err != nil {
		scanner.log.Error().Err(err).Msgf("Error downloading Trivy DB to destination dir: %s", dbDir)

		return err
	}

	scanner.log.Debug().Msgf("Finished downloading Trivy DB to destination dir: %s", dbDir)

	return nil
}

func (scanner Scanner) CompareSeverities(severity1, severity2 string) int {
	return dbTypes.CompareSeverityString(severity1, severity2)
}
