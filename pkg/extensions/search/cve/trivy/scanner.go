package trivy

import (
	"context"
	"encoding/json"
	"path"
	"sync"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

const dbRepository = "ghcr.io/aquasecurity/trivy-db"

// getNewScanOptions sets trivy configuration values for our scans and returns them as
// a trivy Options structure.
func getNewScanOptions(dir string) *flag.Options {
	scanOptions := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			CacheDir: dir,
		},
		ScanOptions: flag.ScanOptions{
			SecurityChecks: []string{types.SecurityCheckVulnerability},
			OfflineScan:    true,
		},
		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnType: []string{types.VulnTypeOS, types.VulnTypeLibrary},
		},
		DBOptions: flag.DBOptions{
			DBRepository: dbRepository,
			SkipDBUpdate: true,
		},
		ReportOptions: flag.ReportOptions{
			Format: "table",
			Severities: []dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			},
		},
	}

	return &scanOptions
}

type cveTrivyController struct {
	DefaultCveConfig *flag.Options
	SubCveConfig     map[string]*flag.Options
}

type Scanner struct {
	repoDB          repodb.RepoDB
	cveController   cveTrivyController
	storeController storage.StoreController
	log             log.Logger
	dbLock          *sync.Mutex
	cache           *CveCache
}

func NewScanner(storeController storage.StoreController,
	repoDB repodb.RepoDB, log log.Logger,
) *Scanner {
	cveController := cveTrivyController{}

	subCveConfig := make(map[string]*flag.Options)

	if storeController.DefaultStore != nil {
		imageStore := storeController.DefaultStore

		rootDir := imageStore.RootDir()

		cacheDir := path.Join(rootDir, "_trivy")
		opts := getNewScanOptions(cacheDir)

		cveController.DefaultCveConfig = opts
	}

	if storeController.SubStore != nil {
		for route, storage := range storeController.SubStore {
			rootDir := storage.RootDir()

			cacheDir := path.Join(rootDir, "_trivy")
			opts := getNewScanOptions(cacheDir)

			subCveConfig[route] = opts
		}
	}

	cveController.SubCveConfig = subCveConfig

	return &Scanner{
		log:             log,
		repoDB:          repoDB,
		cveController:   cveController,
		storeController: storeController,
		dbLock:          &sync.Mutex{},
		cache:           NewCveCache(10000, log), //nolint:gomnd
	}
}

func (scanner Scanner) getTrivyOptions(image string) flag.Options {
	// Split image to get route prefix
	prefixName := common.GetRoutePrefix(image)

	var opts flag.Options

	var ok bool

	var rootDir string

	// Get corresponding CVE trivy config, if no sub cve config present that means its default
	_, ok = scanner.cveController.SubCveConfig[prefixName]
	if ok {
		opts = *scanner.cveController.SubCveConfig[prefixName]

		imgStore := scanner.storeController.SubStore[prefixName]

		rootDir = imgStore.RootDir()
	} else {
		opts = *scanner.cveController.DefaultCveConfig

		imgStore := scanner.storeController.DefaultStore

		rootDir = imgStore.RootDir()
	}

	opts.ScanOptions.Target = path.Join(rootDir, image)
	opts.ImageOptions.Input = path.Join(rootDir, image)

	return opts
}

func (scanner Scanner) runTrivy(opts flag.Options) (types.Report, error) {
	ctx := context.Background()

	runner, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		return types.Report{}, err
	}
	defer runner.Close(ctx)

	report, err := runner.ScanImage(ctx, opts)
	if err != nil {
		return types.Report{}, err
	}

	report, err = runner.Filter(ctx, opts, report)
	if err != nil {
		return types.Report{}, err
	}

	return report, nil
}

func (scanner Scanner) IsImageFormatScannable(image string) (bool, error) {
	if scanner.cache.Get(image) != nil {
		return true, nil
	}

	imageDir, inputTag := common.GetImageDirAndTag(image)

	repoMeta, err := scanner.repoDB.GetRepoMeta(imageDir)
	if err != nil {
		return false, err
	}

	manifestDigestStr, ok := repoMeta.Tags[inputTag]
	if !ok {
		return false, zerr.ErrTagMetaNotFound
	}

	manifestDigest, err := godigest.Parse(manifestDigestStr.Digest)
	if err != nil {
		return false, err
	}

	manifestData, err := scanner.repoDB.GetManifestData(manifestDigest)
	if err != nil {
		return false, err
	}

	var manifestContent ispec.Manifest

	err = json.Unmarshal(manifestData.ManifestBlob, &manifestContent)
	if err != nil {
		scanner.log.Error().Err(err).Str("image", image).Msg("unable to unmashal manifest blob")

		return false, zerr.ErrScanNotSupported
	}

	for _, imageLayer := range manifestContent.Layers {
		switch imageLayer.MediaType {
		case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):
			return true, nil
		default:
			scanner.log.Debug().Str("image", image).
				Msgf("image media type %s not supported for scanning", imageLayer.MediaType)

			return false, zerr.ErrScanNotSupported
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

	scanner.dbLock.Lock()
	opts := scanner.getTrivyOptions(image)
	report, err := scanner.runTrivy(opts)
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
		dbDir := path.Join(scanner.storeController.DefaultStore.RootDir(), "_trivy")

		err := scanner.updateDB(dbDir)
		if err != nil {
			return err
		}
	}

	if scanner.storeController.SubStore != nil {
		for _, storage := range scanner.storeController.SubStore {
			dbDir := path.Join(storage.RootDir(), "_trivy")

			err := scanner.updateDB(dbDir)
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

	err := operation.DownloadDB("dev", dbDir, dbRepository, false, false, false)
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
