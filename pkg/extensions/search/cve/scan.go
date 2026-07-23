package cveinfo

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"zotregistry.dev/zot/v2/pkg/extensions/events"
	cvemodel "zotregistry.dev/zot/v2/pkg/extensions/search/cve/model"
	"zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/v2/pkg/requestcontext"
	"zotregistry.dev/zot/v2/pkg/scheduler"
)

func NewScanTaskGenerator(
	metaDB mTypes.MetaDB,
	scanner Scanner,
	logC log.Logger,
	eventRecorders ...events.Recorder,
) scheduler.TaskGenerator {
	sublogger := logC.With().Str("component", "cve").Logger()

	var eventRecorder events.Recorder
	if len(eventRecorders) > 0 {
		eventRecorder = eventRecorders[0]
	}

	return &scanTaskGenerator{
		log:           sublogger,
		metaDB:        metaDB,
		scanner:       scanner,
		eventRecorder: eventRecorder,
		lock:          &sync.Mutex{},
		scanErrors:    map[string]error{},
		scheduled:     map[string]bool{},
		done:          false,
	}
}

// scanTaskGenerator takes all manifests from repodb and runs the CVE scanner on them.
// If the scanner already has results cached for a specific manifests, or it cannot be
// scanned, the manifest will be skipped.
// If there are no manifests missing from the cache, the generator finishes.
type scanTaskGenerator struct {
	log           log.Logger
	metaDB        mTypes.MetaDB
	scanner       Scanner
	eventRecorder events.Recorder
	lock          *sync.Mutex
	scanErrors    map[string]error
	scheduled     map[string]bool
	done          bool
}

func (gen *scanTaskGenerator) getMatcherFunc() mTypes.FilterFunc {
	return func(repoMeta mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
		// Note this matcher will return information based on scan status of manifests
		// An index scan aggregates results of manifest scans
		// If at least one of its manifests can be scanned,
		// the index and its tag will be returned by the caller function too
		repoName := repoMeta.Name
		manifestDigest := imageMeta.Digest.String()

		if gen.isScheduled(manifestDigest) {
			// We skip this manifest as it has already scheduled
			return false
		}

		if gen.hasError(manifestDigest) {
			// We skip this manifest as it has already been scanned and errored
			// This is to prevent the generator attempting to run a scan
			// in a loop of the same image which would consistently fail
			return false
		}

		if gen.scanner.IsResultCached(manifestDigest) {
			// We skip this manifest, it was already scanned
			return false
		}

		ok, err := gen.scanner.IsImageFormatScannable(repoName, manifestDigest)
		if !ok || err != nil {
			// We skip this manifest, we cannot scan it
			return false
		}

		return true
	}
}

func (gen *scanTaskGenerator) addError(digest string, err error) {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	gen.scanErrors[digest] = err
}

func (gen *scanTaskGenerator) hasError(digest string) bool {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	_, ok := gen.scanErrors[digest]

	return ok
}

func (gen *scanTaskGenerator) setScheduled(digest string, isScheduled bool) {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	if _, ok := gen.scheduled[digest]; ok && !isScheduled {
		delete(gen.scheduled, digest)
	} else if isScheduled {
		gen.scheduled[digest] = true
	}
}

func (gen *scanTaskGenerator) isScheduled(digest string) bool {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	_, ok := gen.scheduled[digest]

	return ok
}

func (gen *scanTaskGenerator) Name() string {
	return "CVEScanGenerator"
}

func (gen *scanTaskGenerator) Next() (scheduler.Task, error) {
	// metaRB requires us to use a context for authorization
	userAc := reqCtx.NewUserAccessControl()
	userAc.SetUsername("scheduler")
	userAc.SetIsAdmin(true)
	ctx := userAc.DeriveContext(context.Background())

	// Obtain a list of repos with un-scanned scannable manifests
	// We may implement a method to return just 1 match at some point
	imageMeta, err := gen.metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, gen.getMatcherFunc())
	if err != nil {
		// Do not crash the generator for potential metadb inconsistencies
		// as there may be scannable images not yet scanned
		gen.log.Warn().Err(err).Msg("failed to obtain repo metadata during scheduled cve scan")
	}

	// no imageMeta are returned, all results are in already in cache
	// or manifests cannot be scanned
	if len(imageMeta) == 0 {
		gen.log.Info().Msg("finished scanning available images during scheduled cve scan")

		gen.done = true

		return nil, nil //nolint:nilnil
	}

	// Since imageMeta will always contain just un-scanned images we can pick
	// any image out of the resulting matches
	digest := imageMeta[0].Digest.String()

	// Mark the digest as scheduled so it is skipped on next generator run
	gen.setScheduled(digest, true)

	return newScanTask(gen, imageMeta[0].Repo, digest), nil
}

func (gen *scanTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *scanTaskGenerator) IsReady() bool {
	return true
}

func (gen *scanTaskGenerator) Reset() {
	gen.lock.Lock()
	defer gen.lock.Unlock()

	gen.scheduled = map[string]bool{}
	gen.scanErrors = map[string]error{}
	gen.done = false
}

type scanTask struct {
	generator *scanTaskGenerator
	repo      string
	digest    string
}

func newScanTask(generator *scanTaskGenerator, repo string, digest string) *scanTask {
	return &scanTask{generator, repo, digest}
}

func (st *scanTask) DoWork(ctx context.Context) error {
	// When work finished clean this entry from the generator
	defer st.generator.setScheduled(st.digest, false)

	image := st.repo + "@" + st.digest

	// We cache the results internally in the scanner
	// so we can discard the actual results for now
	cveMap, err := st.generator.scanner.ScanImage(ctx, image)
	if err != nil {
		st.generator.log.Error().Err(err).Str("image", image).Msg("failed to perform scheduled cve scan for image")
		st.generator.addError(st.digest, err)

		return err
	}

	st.generator.publishScanEvent(ctx, st.repo, st.digest, cveMap)

	st.generator.log.Debug().Str("image", image).Msg("scheduled cve scan completed successfully for image")

	return nil
}

func (st *scanTask) String() string {
	return fmt.Sprintf("{Name: \"%s\", repo: \"%s\", digest: \"%s\"}",
		st.Name(), st.repo, st.digest)
}

func (st *scanTask) Name() string {
	return "ScanTask"
}

func (gen *scanTaskGenerator) publishScanEvent(ctx context.Context, repo, digest string, cveMap map[string]cvemodel.CVE) {
	if gen.eventRecorder == nil {
		return
	}

	userAc := reqCtx.NewUserAccessControl()
	userAc.SetUsername("scheduler")
	userAc.SetIsAdmin(true)

	repoMeta, err := gen.metaDB.GetRepoMeta(userAc.DeriveContext(ctx), repo)
	if err != nil {
		gen.log.Warn().Err(err).Str("repository", repo).Str("digest", digest).
			Msg("failed to load repo metadata for image scanned event")

		return
	}

	matchingTags := make([]string, 0, len(repoMeta.Tags))
	mediaType := ""

	for tag, descriptor := range repoMeta.Tags {
		if descriptor.Digest != digest {
			continue
		}

		matchingTags = append(matchingTags, tag)
		if mediaType == "" {
			mediaType = descriptor.MediaType
		}
	}

	if len(matchingTags) == 0 {
		gen.log.Warn().Str("repository", repo).Str("digest", digest).
			Msg("skipping image scanned event because no matching tag was found")

		return
	}

	slices.Sort(matchingTags)

	summary := getImageScanSummary(cveMap)
	for _, tag := range matchingTags {
		gen.eventRecorder.ImageScanned(repo, tag, digest, mediaType, summary, nil)
	}
}

func getImageScanSummary(cveMap map[string]cvemodel.CVE) events.ImageScanSummary {
	cveSummary := initCVESummaryFromCVEMap(cveMap)
	summary := events.ImageScanSummary{
		Count:         cveSummary.Count,
		UnknownCount:  cveSummary.UnknownCount,
		LowCount:      cveSummary.LowCount,
		MediumCount:   cveSummary.MediumCount,
		HighCount:     cveSummary.HighCount,
		CriticalCount: cveSummary.CriticalCount,
		MaxSeverity:   cveSummary.MaxSeverity,
	}

	for _, cve := range cveMap {
		if slices.ContainsFunc(cve.PackageList, func(pack cvemodel.Package) bool {
			return pack.FixedVersion != ""
		}) {
			summary.FixableCount++
		}
	}

	return summary
}
