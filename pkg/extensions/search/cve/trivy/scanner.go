package trivy

import (
	"encoding/json"
	"flag"
	"path"
	"strings"
	"sync"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/types"
	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/urfave/cli/v2"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/meta/repodb"
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
	repoDB          repodb.RepoDB
	cveController   cveTrivyController
	storeController storage.StoreController
	log             log.Logger
	dbLock          *sync.Mutex
}

func NewScanner(storeController storage.StoreController,
	repoDB repodb.RepoDB, log log.Logger,
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
		repoDB:          repoDB,
		cveController:   cveController,
		storeController: storeController,
		dbLock:          &sync.Mutex{},
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
	imageDir, inputTag := common.GetImageDirAndTag(image)

	repoMeta, err := scanner.repoDB.GetRepoMeta(imageDir)
	if err != nil {
		return false, err
	}

	manifestDigestStr, ok := repoMeta.Tags[inputTag]
	if !ok {
		return false, zerr.ErrTagMetaNotFound
	}

	manifestDigest, err := godigest.Parse(manifestDigestStr)
	if err != nil {
		return false, err
	}

	manifestMeta, err := scanner.repoDB.GetManifestMeta(manifestDigest)
	if err != nil {
		return false, err
	}

	var manifestContent ispec.Manifest

	err = json.Unmarshal(manifestMeta.ManifestBlob, &manifestContent)
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
