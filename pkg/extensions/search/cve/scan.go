package cveinfo

import (
	"context"
	"fmt"
	"slices"
	"sync"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
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
) scheduler.TaskGenerator {
	sublogger := logC.With().Str("component", "cve").Logger()

	return &scanTaskGenerator{
		log:        sublogger,
		metaDB:     metaDB,
		scanner:    scanner,
		lock:       &sync.Mutex{},
		scanErrors: map[string]error{},
		scheduled:  map[string]bool{},
		done:       false,
	}
}

// scanTaskGenerator takes all manifests from repodb and runs the CVE scanner on them.
// If the scanner already has results cached for a specific manifests, or it cannot be
// scanned, the manifest will be skipped.
// If there are no manifests missing from the cache, the generator finishes.
type scanTaskGenerator struct {
	log        log.Logger
	metaDB     mTypes.MetaDB
	scanner    Scanner
	lock       *sync.Mutex
	scanErrors map[string]error
	scheduled  map[string]bool
	done       bool
}

// getMatcherFunc only uses in-memory state: FilterTags calls it inside a MetaDB read
// transaction, and the scanner checks in needsScan read MetaDB themselves. With BoltDB, a read
// transaction nested in another one deadlocks when a concurrent write grows the database file.
func (gen *scanTaskGenerator) getMatcherFunc() mTypes.FilterFunc {
	return func(_ mTypes.RepoMeta, imageMeta mTypes.ImageMeta) bool {
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

		return true
	}
}

// needsScan reports whether the image still has to be scanned. It reads MetaDB, so it must be
// called outside FilterTags.
func (gen *scanTaskGenerator) needsScan(repoName, digest string) bool {
	// Manifests: digest cache hit. Indexes: all present scannable members cached
	// (index digests are never cache keys; repo is used for presence checks).
	if gen.scanner.IsResultCached(repoName, digest) {
		return false
	}

	ok, err := gen.scanner.IsImageFormatScannable(repoName, digest)
	if !ok || err != nil {
		// We skip this manifest, we cannot scan it
		return false
	}

	return true
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

	// Obtain the images not scheduled and not errored yet
	imageMeta, err := gen.metaDB.FilterTags(ctx, mTypes.AcceptAllRepoTag, gen.getMatcherFunc())
	if err != nil {
		// Do not crash the generator for potential metadb inconsistencies
		// as there may be scannable images not yet scanned
		gen.log.Warn().Err(err).Msg("failed to obtain repo metadata during scheduled cve scan")
	}

	// Pick the first image not already in cache and that can be scanned
	for _, image := range imageMeta {
		digest := image.Digest.String()

		if !gen.needsScan(image.Repo, digest) {
			continue
		}

		// Mark the digest as scheduled so it is skipped on next generator run
		gen.setScheduled(digest, true)

		return newScanTask(gen, image.Repo, digest), nil
	}

	// all results are already in cache or manifests cannot be scanned
	gen.log.Info().Msg("finished scanning available images during scheduled cve scan")

	gen.done = true

	return nil, nil //nolint:nilnil
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
	_, err := st.generator.scanner.ScanImage(ctx, image)
	if err != nil {
		st.generator.log.Error().Err(err).Str("image", image).Msg("failed to perform scheduled cve scan for image")
		st.generator.addError(st.digest, err)

		return err
	}

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

// ScannerOption configures additional features and settings on a scanner.
type ScannerOption func(*scanner)

// WithEventRecorder makes the scanner publish an ImageScanned event via eventRecorder
// after each ScanImage call that wasn't served from cache.
func WithEventRecorder(eventRecorder events.Recorder) ScannerOption {
	return func(s *scanner) {
		s.eventRecorder = eventRecorder
	}
}

// NewDecoratedScanner wraps base with optional cross-cutting behavior
// configured via opts.
func NewDecoratedScanner(base Scanner, log log.Logger, opts ...ScannerOption) Scanner {
	scanner := &scanner{Scanner: base, log: log}

	for _, opt := range opts {
		// a nil option (e.g. from a conditionally-omitted call site) is a no-op, not a panic
		if opt == nil {
			continue
		}

		opt(scanner)
	}

	return scanner
}

type scanner struct {
	Scanner

	eventRecorder events.Recorder
	log           log.Logger
}

func (s *scanner) ScanImage(ctx context.Context, image string) (cvemodel.ScanResult, error) {
	result, err := s.Scanner.ScanImage(ctx, image)
	if err == nil && s.eventRecorder != nil && !result.WasCached {
		// image is whatever reference (tag or digest) the caller passed in; ScanImage is also
		// invoked with the digest of untagged manifests, e.g. the individual manifests inside a
		// multiarch index, so a tag cannot be assumed here. result.Digest/MediaType are what the
		// underlying Scanner already resolved and actually scanned, with no extra metaDB calls.
		repo, ref, _ := zcommon.GetImageDirAndReference(image)
		s.publishScanEvent(ctx, repo, ref, result.Digest, result.MediaType, result.CVEMap)
	}

	return result, err
}

// publishScanEvent emits one ImageScanned event for the given repo/ref/digest/mediaType.
func (s *scanner) publishScanEvent(ctx context.Context, repo, ref, digest, mediaType string,
	cveMap map[string]zcommon.CVE,
) {
	summary := getImageScanSummary(cveMap)
	ectx := events.EventContextFromContext(ctx)

	s.eventRecorder.ImageScanned(repo, ref, digest, mediaType, summary, ectx)
}

func getImageScanSummary(cveMap map[string]zcommon.CVE) events.ImageScanSummary {
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
		if slices.ContainsFunc(cve.PackageList, func(pack zcommon.Package) bool {
			// the scanner uses cvemodel.NotSpecified, never "", when there is no fix
			return pack.FixedVersion != "" && pack.FixedVersion != cvemodel.NotSpecified
		}) {
			summary.FixableCount++
		}
	}

	return summary
}
