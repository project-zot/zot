package cveinfo

import (
	"context"
	"fmt"
	"slices"
	"sync"

	godigest "github.com/opencontainers/go-digest"

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

// WithEventRecorder makes the scanner publish an ImageScanned event via
// eventRecorder after each successful ScanImage call. metaDB is used to
// resolve tags for the scanned digest.
func WithEventRecorder(metaDB mTypes.MetaDB, eventRecorder events.Recorder) ScannerOption {
	return func(s *scanner) {
		s.metaDB = metaDB
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

	metaDB        mTypes.MetaDB
	eventRecorder events.Recorder
	log           log.Logger
}

func (s *scanner) ScanImage(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
	if s.eventRecorder == nil || s.metaDB == nil {
		return s.Scanner.ScanImage(ctx, image)
	}

	repo, ref, digest, ok := s.resolveDigestForEvent(ctx, image)

	// Check the cache before scanning: the trivy scanner's ScanImage returns cached results
	// directly without running a new scan, so checking after would see "cached" even for a
	// scan that just ran, and no event would ever be published for repeated CVE queries.
	wasCached := ok && s.IsResultCached(digest)

	// Scan by the digest resolved above rather than image's original tag, so the digest
	// recorded in the event always matches what was actually scanned even if the tag is
	// moved to point elsewhere between resolution above and the scan below.
	scanTarget := image
	if ok {
		scanTarget = zcommon.GetFullImageName(repo, digest)
	}

	cveMap, err := s.Scanner.ScanImage(ctx, scanTarget)
	if err == nil && ok && !wasCached {
		s.publishScanEvent(ctx, repo, ref, digest, cveMap)
	}

	return cveMap, err
}

// resolveDigestForEvent resolves image (whatever reference, tag or digest, ScanImage was
// called with) to the repo/ref/digest needed to check the cache and publish an event.
// ScanImage is also invoked with the digest of untagged manifests, e.g. the individual
// manifests inside a multiarch index, so a tag cannot be required here. ok is false when
// resolution failed; a warning has already been logged and the caller should skip both the
// cache check and publishing.
func (s *scanner) resolveDigestForEvent(ctx context.Context, image string) (string, string, string, bool) {
	repo, ref, isTag := zcommon.GetImageDirAndReference(image)

	// When isTag is false, ref is already the digest ScanImage was called with.
	if !isTag {
		return repo, ref, ref, true
	}

	// Use the caller's ctx as-is rather than a synthetic elevated identity: GetRepoMeta
	// performs no per-repo access check (unlike the Filter*/Search* methods), so a real
	// request ctx is just as capable here, and this keeps event publishing subject to
	// whatever access control GetRepoMeta may apply in the future.
	repoMeta, err := s.metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		s.log.Warn().Err(err).Str("repository", repo).Str("reference", ref).
			Msg("failed to load repo metadata for image scanned event")

		return repo, ref, "", false
	}

	descriptor, found := repoMeta.Tags[ref]
	if !found {
		s.log.Warn().Str("repository", repo).Str("reference", ref).
			Msg("skipping image scanned event because tag was not found in repo metadata")

		return repo, ref, "", false
	}

	return repo, ref, descriptor.Digest, true
}

// publishScanEvent emits one ImageScanned event for the already-resolved repo/ref/digest.
func (s *scanner) publishScanEvent(ctx context.Context, repo, ref, digest string, cveMap map[string]cvemodel.CVE) {
	imageMeta, err := s.metaDB.GetImageMeta(godigest.Digest(digest))
	if err != nil {
		s.log.Warn().Err(err).Str("repository", repo).Str("digest", digest).
			Msg("failed to load image metadata for image scanned event")

		return
	}

	summary := getImageScanSummary(cveMap)
	ectx := events.EventContextFromContext(ctx)

	s.eventRecorder.ImageScanned(repo, ref, digest, imageMeta.MediaType, summary, ectx)
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
			// the scanner uses cvemodel.NotSpecified, never "", when there is no fix
			return pack.FixedVersion != "" && pack.FixedVersion != cvemodel.NotSpecified
		}) {
			summary.FixableCount++
		}
	}

	return summary
}
