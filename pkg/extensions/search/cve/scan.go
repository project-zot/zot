package cveinfo

import (
	"context"
	"fmt"
	"sync"

	"zotregistry.dev/zot/pkg/log"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	reqCtx "zotregistry.dev/zot/pkg/requestcontext"
	"zotregistry.dev/zot/pkg/scheduler"
)

func NewScanTaskGenerator(
	metaDB mTypes.MetaDB,
	scanner Scanner,
	logC log.Logger,
) scheduler.TaskGenerator {
	sublogger := logC.With().Str("component", "cve").Logger()

	return &scanTaskGenerator{
		log:        log.Logger{Logger: sublogger},
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

		return nil, nil
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
	if _, err := st.generator.scanner.ScanImage(ctx, image); err != nil {
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
