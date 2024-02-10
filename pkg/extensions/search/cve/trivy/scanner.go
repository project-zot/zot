package trivy

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	fanalTypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/types"
	regTypes "github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	_ "modernc.org/sqlite"

	zerr "zotregistry.dev/zot/errors"
	zcommon "zotregistry.dev/zot/pkg/common"
	cvecache "zotregistry.dev/zot/pkg/extensions/search/cve/cache"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
)

const cacheSize = 1000000

// getNewScanOptions sets trivy configuration values for our scans and returns them as
// a trivy Options structure.
func getNewScanOptions(dir, dbRepository, javaDBRepository string) *flag.Options {
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
			DBRepository:     dbRepository,
			JavaDBRepository: javaDBRepository,
			SkipDBUpdate:     true,
			SkipJavaDBUpdate: true,
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
	metaDB           mTypes.MetaDB
	cveController    cveTrivyController
	storeController  storage.StoreController
	log              log.Logger
	dbLock           *sync.Mutex
	cache            *cvecache.CveCache
	dbRepository     string
	javaDBRepository string
}

func NewScanner(storeController storage.StoreController,
	metaDB mTypes.MetaDB, dbRepository, javaDBRepository string, log log.Logger,
) *Scanner {
	cveController := cveTrivyController{}

	subCveConfig := make(map[string]*flag.Options)

	if storeController.DefaultStore != nil {
		imageStore := storeController.DefaultStore

		rootDir := imageStore.RootDir()

		cacheDir := path.Join(rootDir, "_trivy")
		opts := getNewScanOptions(cacheDir, dbRepository, javaDBRepository)

		cveController.DefaultCveConfig = opts
	}

	if storeController.SubStore != nil {
		for route, storage := range storeController.SubStore {
			rootDir := storage.RootDir()

			cacheDir := path.Join(rootDir, "_trivy")
			opts := getNewScanOptions(cacheDir, dbRepository, javaDBRepository)

			subCveConfig[route] = opts
		}
	}

	cveController.SubCveConfig = subCveConfig

	return &Scanner{
		log:              log,
		metaDB:           metaDB,
		cveController:    cveController,
		storeController:  storeController,
		dbLock:           &sync.Mutex{},
		cache:            cvecache.NewCveCache(cacheSize, log),
		dbRepository:     dbRepository,
		javaDBRepository: javaDBRepository,
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

func (scanner Scanner) runTrivy(ctx context.Context, opts flag.Options) (types.Report, error) {
	err := scanner.checkDBPresence()
	if err != nil {
		return types.Report{}, err
	}

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

func (scanner Scanner) IsImageFormatScannable(repo, ref string) (bool, error) {
	var (
		digestStr = ref
		mediaType string
	)

	if zcommon.IsTag(ref) {
		imgDescriptor, err := getImageDescriptor(context.Background(), scanner.metaDB, repo, ref)
		if err != nil {
			return false, err
		}

		digestStr = imgDescriptor.Digest
		mediaType = imgDescriptor.MediaType
	} else {
		var found bool

		found, mediaType = findMediaTypeForDigest(scanner.metaDB, godigest.Digest(ref))
		if !found {
			return false, zerr.ErrManifestNotFound
		}
	}

	return scanner.IsImageMediaScannable(repo, digestStr, mediaType)
}

func (scanner Scanner) IsImageMediaScannable(repo, digestStr, mediaType string) (bool, error) {
	image := repo + "@" + digestStr

	switch mediaType {
	case ispec.MediaTypeImageManifest:
		ok, err := scanner.isManifestScanable(digestStr)
		if err != nil {
			return ok, fmt.Errorf("image '%s' %w", image, err)
		}

		return ok, nil
	case ispec.MediaTypeImageIndex:
		ok, err := scanner.isIndexScannable(digestStr)
		if err != nil {
			return ok, fmt.Errorf("image '%s' %w", image, err)
		}

		return ok, nil
	default:
		return false, nil
	}
}

func (scanner Scanner) isManifestScanable(digestStr string) (bool, error) {
	if scanner.cache.Get(digestStr) != nil {
		return true, nil
	}

	manifestData, err := scanner.metaDB.GetImageMeta(godigest.Digest(digestStr))
	if err != nil {
		return false, err
	}

	for _, imageLayer := range manifestData.Manifests[0].Manifest.Layers {
		switch imageLayer.MediaType {
		case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):
			continue
		default:
			return false, zerr.ErrScanNotSupported
		}
	}

	return true, nil
}

func (scanner Scanner) isManifestDataScannable(manifestData mTypes.ManifestMeta) (bool, error) {
	if scanner.cache.Get(manifestData.Digest.String()) != nil {
		return true, nil
	}

	for _, imageLayer := range manifestData.Manifest.Layers {
		switch imageLayer.MediaType {
		case ispec.MediaTypeImageLayerGzip, ispec.MediaTypeImageLayer, string(regTypes.DockerLayer):
			continue
		default:
			return false, zerr.ErrScanNotSupported
		}
	}

	return true, nil
}

func (scanner Scanner) isIndexScannable(digestStr string) (bool, error) {
	if scanner.cache.Get(digestStr) != nil {
		return true, nil
	}

	indexData, err := scanner.metaDB.GetImageMeta(godigest.Digest(digestStr))
	if err != nil {
		return false, err
	}

	if indexData.Index == nil {
		return false, zerr.ErrUnexpectedMediaType
	}

	indexContent := *indexData.Index

	if len(indexContent.Manifests) == 0 {
		return true, nil
	}

	for _, manifest := range indexData.Manifests {
		isScannable, err := scanner.isManifestDataScannable(manifest)
		if err != nil {
			continue
		}

		// if at least 1 manifest is scannable, the whole index is scannable
		if isScannable {
			return true, nil
		}
	}

	return false, nil
}

func (scanner Scanner) IsResultCached(digest string) bool {
	// Check if the entry exists in cache without updating the recent-ness
	return scanner.cache.Contains(digest)
}

func (scanner Scanner) GetCachedResult(digest string) map[string]cvemodel.CVE {
	return scanner.cache.Get(digest)
}

func (scanner Scanner) ScanImage(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
	var (
		originalImageInput = image
		digest             string
		mediaType          string
	)

	repo, ref, isTag := zcommon.GetImageDirAndReference(image)

	digest = ref

	if isTag {
		imgDescriptor, err := getImageDescriptor(ctx, scanner.metaDB, repo, ref)
		if err != nil {
			return map[string]cvemodel.CVE{}, err
		}

		digest = imgDescriptor.Digest
		mediaType = imgDescriptor.MediaType
	} else {
		var found bool

		found, mediaType = findMediaTypeForDigest(scanner.metaDB, godigest.Digest(ref))
		if !found {
			return map[string]cvemodel.CVE{}, zerr.ErrManifestNotFound
		}
	}

	var (
		cveIDMap map[string]cvemodel.CVE
		err      error
	)

	switch mediaType {
	case ispec.MediaTypeImageIndex:
		cveIDMap, err = scanner.scanIndex(ctx, repo, digest)
	default:
		cveIDMap, err = scanner.scanManifest(ctx, repo, digest)
	}

	if err != nil {
		scanner.log.Error().Err(err).Str("image", originalImageInput).Msg("failed to scan image")

		return map[string]cvemodel.CVE{}, err
	}

	return cveIDMap, nil
}

func (scanner Scanner) scanManifest(ctx context.Context, repo, digest string) (map[string]cvemodel.CVE, error) {
	if cachedMap := scanner.cache.Get(digest); cachedMap != nil {
		return cachedMap, nil
	}

	cveidMap := map[string]cvemodel.CVE{}
	image := repo + "@" + digest

	scanner.dbLock.Lock()
	opts := scanner.getTrivyOptions(image)
	report, err := scanner.runTrivy(ctx, opts)
	scanner.dbLock.Unlock()

	if err != nil { //nolint: wsl
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

			var packagePath string
			if vulnerability.PkgPath != "" {
				packagePath = vulnerability.PkgPath
			} else {
				packagePath = "Not Specified"
			}

			_, ok := cveidMap[vulnerability.VulnerabilityID]
			if ok {
				cveDetailStruct := cveidMap[vulnerability.VulnerabilityID]

				pkgList := cveDetailStruct.PackageList

				pkgList = append(
					pkgList,
					cvemodel.Package{
						Name:             pkgName,
						PackagePath:      packagePath,
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
						PackagePath:      packagePath,
						InstalledVersion: installedVersion,
						FixedVersion:     fixedVersion,
					},
				)

				cveidMap[vulnerability.VulnerabilityID] = cvemodel.CVE{
					ID:          vulnerability.VulnerabilityID,
					Title:       vulnerability.Title,
					Description: vulnerability.Description,
					Reference:   getCVEReference(vulnerability.PrimaryURL, vulnerability.References),
					Severity:    convertSeverity(vulnerability.Severity),
					PackageList: newPkgList,
				}
			}
		}
	}

	scanner.cache.Add(digest, cveidMap)

	return cveidMap, nil
}

func getCVEReference(primaryURL string, references []string) string {
	if primaryURL != "" {
		return primaryURL
	}

	if len(references) > 0 {
		nvdReference, found := getNVDReference(references)

		if found {
			return nvdReference
		}

		return references[0]
	}

	return ""
}

func getNVDReference(references []string) (string, bool) {
	for i := range references {
		if strings.Contains(references[i], "nvd.nist.gov") {
			return references[i], true
		}
	}

	return "", false
}

func (scanner Scanner) scanIndex(ctx context.Context, repo, digest string) (map[string]cvemodel.CVE, error) {
	if cachedMap := scanner.cache.Get(digest); cachedMap != nil {
		return cachedMap, nil
	}

	indexData, err := scanner.metaDB.GetImageMeta(godigest.Digest(digest))
	if err != nil {
		return map[string]cvemodel.CVE{}, err
	}

	if indexData.Index == nil {
		return map[string]cvemodel.CVE{}, zerr.ErrUnexpectedMediaType
	}

	indexCveIDMap := map[string]cvemodel.CVE{}

	for _, manifest := range indexData.Index.Manifests {
		if isScannable, err := scanner.isManifestScanable(manifest.Digest.String()); isScannable && err == nil {
			manifestCveIDMap, err := scanner.scanManifest(ctx, repo, manifest.Digest.String())
			if err != nil {
				return nil, err
			}

			for vulnerabilityID, CVE := range manifestCveIDMap {
				indexCveIDMap[vulnerabilityID] = CVE
			}
		}
	}

	scanner.cache.Add(digest, indexCveIDMap)

	return indexCveIDMap, nil
}

// UpdateDB downloads the Trivy DB / Cache under the store root directory.
func (scanner Scanner) UpdateDB(ctx context.Context) error {
	// We need a lock as using multiple substores each with its own DB
	// can result in a DATARACE because some varibles in trivy-db are global
	// https://github.com/project-zot/trivy-db/blob/main/pkg/db/db.go#L23
	scanner.dbLock.Lock()
	defer scanner.dbLock.Unlock()

	if scanner.storeController.DefaultStore != nil {
		dbDir := path.Join(scanner.storeController.DefaultStore.RootDir(), "_trivy")

		err := scanner.updateDB(ctx, dbDir)
		if err != nil {
			return err
		}
	}

	if scanner.storeController.SubStore != nil {
		for _, storage := range scanner.storeController.SubStore {
			dbDir := path.Join(storage.RootDir(), "_trivy")

			err := scanner.updateDB(ctx, dbDir)
			if err != nil {
				return err
			}
		}
	}

	scanner.cache.Purge()

	return nil
}

func (scanner Scanner) updateDB(ctx context.Context, dbDir string) error {
	scanner.log.Debug().Str("dbDir", dbDir).Msg("download Trivy DB to destination dir")

	registryOpts := fanalTypes.RegistryOptions{Insecure: false}

	scanner.log.Debug().Str("dbDir", dbDir).Msg("started downloading trivy-db to destination dir")

	err := operation.DownloadDB(ctx, "dev", dbDir, scanner.dbRepository, false, false, registryOpts)
	if err != nil {
		scanner.log.Error().Err(err).Str("dbDir", dbDir).
			Str("dbRepository", scanner.dbRepository).Msg("failed to download trivy-db to destination dir")

		return err
	}

	if scanner.javaDBRepository != "" {
		javadb.Init(dbDir, scanner.javaDBRepository, false, false, registryOpts)

		if err := javadb.Update(); err != nil {
			scanner.log.Error().Err(err).Str("dbDir", dbDir).
				Str("javaDBRepository", scanner.javaDBRepository).Msg("failed to download trivy-java-db to destination dir")

			return err
		}
	}

	scanner.log.Debug().Str("dbDir", dbDir).Msg("finished downloading trivy-db to destination dir")

	return nil
}

// checkDBPresence errors if the DB metadata files cannot be accessed.
func (scanner Scanner) checkDBPresence() error {
	result := true

	if scanner.storeController.DefaultStore != nil {
		dbDir := path.Join(scanner.storeController.DefaultStore.RootDir(), "_trivy")
		if _, err := os.Stat(metadata.Path(dbDir)); err != nil {
			result = false
		}
	}

	if scanner.storeController.SubStore != nil {
		for _, storage := range scanner.storeController.SubStore {
			dbDir := path.Join(storage.RootDir(), "_trivy")

			if _, err := os.Stat(metadata.Path(dbDir)); err != nil {
				result = false
			}
		}
	}

	if !result {
		return zerr.ErrCVEDBNotFound
	}

	return nil
}

func getImageDescriptor(ctx context.Context, metaDB mTypes.MetaDB, repo, tag string) (mTypes.Descriptor, error) {
	repoMeta, err := metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		return mTypes.Descriptor{}, err
	}

	imageDescriptor, ok := repoMeta.Tags[tag]
	if !ok {
		return mTypes.Descriptor{}, zerr.ErrTagMetaNotFound
	}

	return imageDescriptor, nil
}

// findMediaTypeForDigest will look into the buckets for a certain digest. Depending on which bucket that
// digest is found the corresponding mediatype is returned.
func findMediaTypeForDigest(metaDB mTypes.MetaDB, digest godigest.Digest) (bool, string) {
	imageMeta, err := metaDB.GetImageMeta(digest)
	if err == nil {
		return true, imageMeta.MediaType
	}

	return false, ""
}

func convertSeverity(detectedSeverity string) string {
	trivySeverity, _ := dbTypes.NewSeverity(detectedSeverity)

	sevMap := map[dbTypes.Severity]string{
		dbTypes.SeverityUnknown:  cvemodel.SeverityUnknown,
		dbTypes.SeverityLow:      cvemodel.SeverityLow,
		dbTypes.SeverityMedium:   cvemodel.SeverityMedium,
		dbTypes.SeverityHigh:     cvemodel.SeverityHigh,
		dbTypes.SeverityCritical: cvemodel.SeverityCritical,
	}

	return sevMap[trivySeverity]
}
