package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sync"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	fanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/meta/repodb"
	"zotregistry.io/zot/pkg/storage"
)

const defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"

// getNewScanOptions sets trivy configuration values for our scans and returns them as
// a trivy Options structure.
func getNewScanOptions(dir, dbRepository string) *flag.Options {
	scanOptions := flag.Options{
		GlobalOptions: flag.GlobalOptions{
			CacheDir: dir,
		},
		ScanOptions: flag.ScanOptions{
			Scanners:    types.Scanners{types.VulnerabilityScanner},
			OfflineScan: true,
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
	dbRepository    string
}

func NewScanner(storeController storage.StoreController,
	repoDB repodb.RepoDB, dbRepository string, log log.Logger,
) *Scanner {
	cveController := cveTrivyController{}

	subCveConfig := make(map[string]*flag.Options)

	if dbRepository == "" {
		dbRepository = defaultDBRepository
	}

	if storeController.DefaultStore != nil {
		imageStore := storeController.DefaultStore

		rootDir := imageStore.RootDir()

		cacheDir := path.Join(rootDir, "_trivy")
		opts := getNewScanOptions(cacheDir, dbRepository)

		cveController.DefaultCveConfig = opts
	}

	if storeController.SubStore != nil {
		for route, storage := range storeController.SubStore {
			rootDir := storage.RootDir()

			cacheDir := path.Join(rootDir, "_trivy")
			opts := getNewScanOptions(cacheDir, dbRepository)

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
		dbRepository:    dbRepository,
	}
}

func (scanner Scanner) getTrivyOptions(image string) flag.Options {
	// Split image to get route prefix
	prefixName := storage.GetRoutePrefix(image)

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

func (scanner Scanner) IsImageFormatScannable(repo, tag string) (bool, error) {
	image := repo + ":" + tag

	if scanner.cache.Get(image) != nil {
		return true, nil
	}

	repoMeta, err := scanner.repoDB.GetRepoMeta(repo)
	if err != nil {
		return false, err
	}

	var ok bool

	imageDescriptor, ok := repoMeta.Tags[tag]
	if !ok {
		return false, zerr.ErrTagMetaNotFound
	}

	switch imageDescriptor.MediaType {
	case ispec.MediaTypeImageManifest:
		ok, err := scanner.isManifestScanable(imageDescriptor)
		if err != nil {
			return ok, fmt.Errorf("image '%s' %w", image, err)
		}

		return ok, nil
	case ispec.MediaTypeImageIndex:
		ok, err := scanner.isIndexScanable(imageDescriptor)
		if err != nil {
			return ok, fmt.Errorf("image '%s' %w", image, err)
		}

		return ok, nil
	}

	return false, nil
}

func (scanner Scanner) isManifestScanable(descriptor repodb.Descriptor) (bool, error) {
	manifestDigestStr := descriptor.Digest

	manifestDigest, err := godigest.Parse(manifestDigestStr)
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
		scanner.log.Error().Err(err).Msg("unable to unmashal manifest blob")

		return false, zerr.ErrScanNotSupported
	}

	for _, imageLayer := range manifestContent.Layers {
		switch imageLayer.MediaType {
		case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):
			continue
		default:
			scanner.log.Debug().Str("mediaType", imageLayer.MediaType).
				Msg("image media type not supported for scanning")

			return false, zerr.ErrScanNotSupported
		}
	}

	return true, nil
}

func (scanner Scanner) isIndexScanable(descriptor repodb.Descriptor) (bool, error) {
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
	scanner.log.Debug().Str("dbDir", dbDir).Msg("Download Trivy DB to destination dir")

	ctx := context.Background()

	err := operation.DownloadDB(ctx, "dev", dbDir, scanner.dbRepository, false, false,
		fanalTypes.RegistryOptions{Insecure: false})
	if err != nil {
		scanner.log.Error().Err(err).Str("dbDir", dbDir).Msg("Error downloading Trivy DB to destination dir")

		return err
	}

	scanner.log.Debug().Str("dbDir", dbDir).Msg("Finished downloading Trivy DB to destination dir")

	return nil
}

func (scanner Scanner) CompareSeverities(severity1, severity2 string) int {
	return dbTypes.CompareSeverityString(severity1, severity2)
}
