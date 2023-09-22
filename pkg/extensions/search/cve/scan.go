package cveinfo

import (
	"context"
	"sync"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	reqCtx "zotregistry.io/zot/pkg/requestcontext"
	"zotregistry.io/zot/pkg/scheduler"
)

func NewScanTaskGenerator(
	metaDB mTypes.MetaDB,
	scanner Scanner,
	log log.Logger,
) scheduler.TaskGenerator {
	return &scanTaskGenerator{
		log:        log,
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
	return func(repoMeta mTypes.RepoMetadata, manifestMeta mTypes.ManifestMetadata) bool {
		// Note this matcher will return information based on scan status of manifests
		// An index scan aggregates results of manifest scans
		// If at least one of its manifests can be scanned,
		// the index and its tag will be returned by the caller function too
		repoName := repoMeta.Name
		manifestDigest := godigest.FromBytes(manifestMeta.ManifestBlob).String()

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

func (gen *scanTaskGenerator) Next() (scheduler.Task, error) {
	// metaRB requires us to use a context for authorization
	userAc := reqCtx.NewUserAccessControl()
	userAc.SetUsername("scheduler")
	userAc.SetIsAdmin(true)
	ctx := userAc.DeriveContext(context.Background())

	// Obtain a list of repos with unscanned scannable manifests
	// We may implement a method to return just 1 match at some point
	reposMeta, _, _, err := gen.metaDB.FilterTags(ctx, gen.getMatcherFunc())
	if err != nil {
		// Do not crash the generator for potential repodb inconistencies
		// as there may be scannable images not yet scanned
		gen.log.Warn().Err(err).Msg("Scheduled CVE scan: error while obtaining repo metadata")
	}

	// no reposMeta are returned, all results are in already in cache
	// or manifests cannot be scanned
	if len(reposMeta) == 0 {
		gen.log.Info().Msg("Scheduled CVE scan: finished for available images")

		gen.done = true

		return nil, nil
	}

	// Since reposMeta will always contain just unscanned images we can pick
	// any repo and any tag out of the resulting matches
	repoMeta := reposMeta[0]

	var digest string

	// Pick any tag
	for _, descriptor := range repoMeta.Tags {
		digest = descriptor.Digest

		break
	}

	// Mark the digest as scheduled so it is skipped on next generator run
	gen.setScheduled(digest, true)

	return newScanTask(gen, repoMeta.Name, digest), nil
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
	if _, err := st.generator.scanner.ScanImage(image); err != nil {
		st.generator.log.Error().Err(err).Str("image", image).Msg("Scheduled CVE scan errored for image")
		st.generator.addError(st.digest, err)

		return err
	}

	st.generator.log.Debug().Str("image", image).Msg("Scheduled CVE scan completed successfully for image")

	return nil
}
