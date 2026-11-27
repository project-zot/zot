package meta

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/meta/convert"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	stypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

const (
	CosignType   = "cosign"
	NotationType = "notation"

	// parseStorageWorkers bounds how many repos the storage walk parses at once. Parsing a repo
	// is a chain of storage round trips, which a remote storage driver serves slowly but
	// independently, so parsing repos in parallel keeps the walk from paying them one at a time.
	parseStorageWorkers = 8

	// parseChunkSize is how many index.json entries parseRepo reads and writes to the metaDB in one go.
	parseChunkSize = 500

	// parseMemoryBudget is the most manifest and config bytes parseRepo holds for one repo at a time. Half goes
	// to the manifests read ahead of the chunk (their index.json descriptor sizes, written by zot), half to the
	// configs of the chunk (the real blob sizes). Manifest and config sizes declared inside a manifest are
	// pusher-controlled and never trusted.
	parseMemoryBudget   = 64 << 20
	parseManifestBudget = parseMemoryBudget / 2
	parseConfigBudget   = parseMemoryBudget / 2

	// parseReadParallelism bounds the blob reads in flight across all repos that are parsed at once, so
	// that parsing several repos in parallel does not multiply the reads a storage driver has to serve.
	parseReadParallelism = 32
)

//nolint:gochecknoglobals // one bound shared by every parseRepo call is the point
var parseReadSlots = make(chan struct{}, parseReadParallelism)

// concurrentReader is implemented by image stores whose reads are safe to issue from many goroutines.
type concurrentReader interface {
	ConcurrentReadSafe() bool
}

// parseStats tracks per-repo outcomes of a storage walk.
type parseStats struct {
	failedRepos  int // skipped on a StatIndex or ParseRepo error
	partialRepos int // parsed, but a manifest blob was missing
}

// complete reports whether the walk fully populated the metaDB.
func (s parseStats) complete() bool {
	return s.failedRepos == 0 && s.partialRepos == 0
}

// ParseStorage will sync all repos found in the rootdirectory of the oci layout that zot was deployed on with the
// ParseStorage database.
func ParseStorage(metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger) error {
	_, err := parseStorage(metaDB, storeController, log)

	return err
}

// parseStorage runs the storage walk, returning per-repo outcomes in parseStats.
// Repos are parsed in parallel, at most parseStorageWorkers at a time.
// Per-repo failures are logged and skipped. Only enumeration or deletion errors
// abort the walk and return a non-nil error.
func parseStorage(metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger) (parseStats, error) {
	log.Info().Str("component", "metadb").Msg("parsing storage and initializing")

	var stats parseStats

	allStorageRepos, err := getAllRepos(storeController, log)
	if err != nil {
		return parseStats{}, err
	}

	allMetaDBRepos, err := metaDB.GetAllRepoNames()
	if err != nil {
		rootDir := storeController.GetDefaultImageStore().RootDir()
		log.Error().Err(err).Str("component", "metadb").Str("rootDir", rootDir).
			Msg("failed to get all repo names present under rootDir")

		return parseStats{}, err
	}

	for _, repo := range getReposToBeDeleted(allStorageRepos, allMetaDBRepos) {
		err := metaDB.DeleteRepoMeta(repo)
		if err != nil {
			log.Error().Err(err).Str("rootDir", storeController.GetImageStore(repo).RootDir()).Str("component", "metadb").
				Str("repo", repo).Msg("failed to delete repo meta")

			return parseStats{}, err
		}
	}

	var (
		statsMu sync.Mutex
		wg      sync.WaitGroup
	)

	// Take a slot before spawning, so that at most parseStorageWorkers goroutines exist at a time.
	sem := make(chan struct{}, parseStorageWorkers)

	for i, repo := range allStorageRepos {
		sem <- struct{}{}

		wg.Go(func() {
			defer func() { <-sem }()

			log.Info().Int("total", len(allStorageRepos)).Int("progress", i).Str("current-repo", repo).
				Msgf("parsing next repo '%s'", repo)

			partial, err := parseStorageRepo(repo, metaDB, storeController, log)

			statsMu.Lock()
			defer statsMu.Unlock()

			if err != nil {
				stats.failedRepos++
			} else if partial {
				stats.partialRepos++
			}
		})
	}

	wg.Wait()

	log.Info().Str("component", "metadb").Msg("successfully initialized")

	return stats, nil
}

// parseStorageRepo parses repo into the metaDB unless the metaDB is already newer than its
// index.json. Errors are logged here, and partial is reported the same way parseRepo does.
func parseStorageRepo(repo string, metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger,
) (bool, error) {
	imgStore := storeController.GetImageStore(repo)

	_, _, storageLastUpdated, err := imgStore.StatIndex(repo)
	if err != nil {
		log.Error().Err(err).Str("rootDir", imgStore.RootDir()).
			Str("repo", repo).Msg("failed to sync repo")

		return false, err
	}

	metaLastUpdated := metaDB.GetRepoLastUpdated(repo)

	// If repo metadata doesn't exist (zero time), always parse it
	// Otherwise, only parse if storage is newer than metadata
	if !metaLastUpdated.IsZero() && storageLastUpdated.Before(metaLastUpdated) {
		return false, nil
	}

	partial, err := parseRepo(repo, metaDB, storeController, log)
	if err != nil {
		log.Error().Err(err).Str("repo", repo).Str("rootDir", imgStore.RootDir()).Msg("failed to sync repo")

		return false, err
	}

	return partial, nil
}

// FastRestartStamp combines this binary's identity (binaryVersion, from version.CurrentBinaryVersion)
// with a fingerprint of the storage config into the stamp used to gate a fast restart.
func FastRestartStamp(binaryVersion, storageFingerprint string) string {
	if binaryVersion == "" || storageFingerprint == "" {
		return ""
	}

	return binaryVersion + "|" + storageFingerprint
}

// MaybeParseStorage conditionally runs ParseStorage based on a fast-restart stamp stored in metaDB.
// When fastRestart is true and the metaDB carries a stamp matching this binary and storage config,
// the full walk is skipped under the assumption that metaDB is consistent with storage from the
// previous run.
func MaybeParseStorage(metaDB mTypes.MetaDB, storeController stypes.StoreController,
	fastRestart bool, fastRestartStamp string, log log.Logger,
) error {
	if fastRestart {
		if fastRestartStamp == "" {
			log.Info().Str("component", "metadb").
				Msg("fast-restart enabled but no stamp is available; falling back to full parse")
		} else {
			storedStamp, err := metaDB.GetFastRestartStamp()
			switch {
			case err != nil:
				log.Warn().Err(err).Str("component", "metadb").
					Msg("failed to read fast-restart stamp, falling back to full parse")
			case storedStamp == fastRestartStamp:
				log.Info().Str("component", "metadb").Str("fastRestartStamp", storedStamp).
					Msg("metaDB fast-restart stamp matches, skipping full storage parse")

				return nil
			case storedStamp == "":
				log.Info().Str("component", "metadb").
					Msg("metaDB has no fast-restart stamp, running full parse")
			default:
				log.Info().Str("component", "metadb").
					Str("storedStamp", storedStamp).Str("currentStamp", fastRestartStamp).
					Msg("metaDB fast-restart stamp differs, running full parse")
			}
		}
	}

	stats, err := parseStorage(metaDB, storeController, log)
	if err != nil {
		return err
	}

	if fastRestartStamp == "" {
		// go run/go test builds have no stamp, so always reparse.
		return nil
	}

	// Leave the stamp untouched on an incomplete walk so the next restart
	// reparses and can recover.
	if !stats.complete() {
		log.Warn().Str("component", "metadb").
			Int("failedRepos", stats.failedRepos).Int("partialRepos", stats.partialRepos).
			Msg("storage parse incomplete; skipping fast-restart stamp so the next restart reparses")

		return nil
	}

	if err := metaDB.SetFastRestartStamp(fastRestartStamp); err != nil {
		log.Warn().Err(err).Str("component", "metadb").
			Msg("failed to write fast-restart stamp; next restart will reparse")
	}

	return nil
}

// getReposToBeDeleted will return all repos that are found in metaDB but not found in storage anymore.
func getReposToBeDeleted(allStorageRepos []string, allMetaDBRepos []string) []string {
	toBeDeleted := []string{}

	storageRepoNameSet := make(map[string]struct{}, len(allStorageRepos))

	for i := range allStorageRepos {
		storageRepoNameSet[allStorageRepos[i]] = struct{}{}
	}

	for _, metaDBRepo := range allMetaDBRepos {
		if _, found := storageRepoNameSet[metaDBRepo]; !found {
			toBeDeleted = append(toBeDeleted, metaDBRepo)
		}
	}

	return toBeDeleted
}

// ParseRepo reads the contents of a repo and syncs all images and signatures found.
func ParseRepo(repo string, metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger) error {
	_, err := parseRepo(repo, metaDB, storeController, log)

	return err
}

// parseRepo syncs all images and signatures in a repo. It returns partial=true
// when a manifest was skipped because its blob is missing, so the caller knows
// the metaDB is incomplete even though no error was returned.
func parseRepo(repo string, metaDB mTypes.MetaDB, storeController stypes.StoreController, log log.Logger,
) (bool, error) {
	imageStore := storeController.GetImageStore(repo)

	var partial bool

	err := imageStore.WithRepoReadLock(repo, func() error {
		indexBlob, err := imageStore.GetIndexContent(repo)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Msg("failed to read index.json for repo")

			return err
		}

		var indexContent ispec.Index

		err = json.Unmarshal(indexBlob, &indexContent)
		if err != nil {
			log.Error().Err(err).Str("repository", repo).Msg("failed to unmarshal index.json for repo")

			return err
		}

		// Collect tags that exist in storage to preserve them
		tagsToKeep := make(map[string]bool)

		for _, manifest := range indexContent.Manifests {
			tag := manifest.Annotations[ispec.AnnotationRefName]
			if tag != "" && !zcommon.IsReferrersTag(tag) {
				tagsToKeep[tag] = true
			}
		}

		err = metaDB.ResetRepoReferences(repo, tagsToKeep)
		if err != nil && !errors.Is(err, zerr.ErrRepoMetaNotFound) {
			log.Error().Err(err).Str("repository", repo).Msg("failed to reset tag field in RepoMetadata for repo")

			return err
		}

		// Storage has no pull history. Give newly recovered statistics one full
		// pull-retention window, using the same timestamp for every image in the repo.
		initialPullTimestamp := mTypes.WithInitialPullTimestamp(time.Now())

		// Signatures are applied once every reference is written, because they attach to their
		// subject whichever comes first in index.json.
		var signatures []signatureRef

		// manifests read ahead of the chunk that is being cut, keyed like the entries that use them
		reads := map[blobKey]*blobRead{}

		for start := 0; start < len(indexContent.Manifests); {
			chunk := nextChunk(repo, indexContent.Manifests[start:], imageStore, reads, log)
			start += len(chunk)

			parsed, parseErr := parseChunk(repo, chunk, reads, log)

			for i := range parsed.references {
				parsed.references[i].Opts = append(parsed.references[i].Opts, initialPullTimestamp)
			}

			partial = partial || parsed.partial
			signatures = append(signatures, parsed.signatures...)

			if parseErr != nil {
				// what was read before the failing entry is still worth keeping
				flushParsed(repo, metaDB, parsed.references, signatures, imageStore, log)

				return parseErr
			}

			err = setRepoReferences(repo, metaDB, parsed.references, log)
			if err != nil {
				return err
			}
		}

		return applySignatures(repo, metaDB, signatures, imageStore, log)
	})

	return partial, err
}

// flushParsed writes the references and signatures read before a parse error. Errors are logged only,
// the parse error that got us here is the one to report.
func flushParsed(repo string, metaDB mTypes.MetaDB, references []mTypes.RepoReference, signatures []signatureRef,
	imageStore stypes.ImageStore, log log.Logger,
) {
	if err := setRepoReferences(repo, metaDB, references, log); err != nil {
		return
	}

	_ = applySignatures(repo, metaDB, signatures, imageStore, log)
}

func setRepoReferences(repo string, metaDB mTypes.MetaDB, references []mTypes.RepoReference, log log.Logger) error {
	if len(references) == 0 {
		return nil
	}

	err := metaDB.SetRepoReferences(context.Background(), repo, references)
	if err != nil {
		log.Error().Err(err).Str("component", "metadb").Str("repository", repo).Msg("failed to set repo meta")

		return err
	}

	return nil
}

func applySignatures(repo string, metaDB mTypes.MetaDB, signatures []signatureRef, imageStore stypes.ImageStore,
	log log.Logger,
) error {
	for _, sig := range signatures {
		// the blob is read again instead of kept from the chunk read, so that a repo with many
		// signatures does not hold all their manifests in memory until the last chunk is written
		sigBlob, err := imageStore.GetBlobContent(repo, sig.digest)
		if err == nil {
			err = applySignature(context.Background(), repo, sig, sigBlob, imageStore, metaDB, log)
		}

		if err != nil {
			log.Error().Err(err).Str("repository", repo).Str("tag", sig.reference).
				Msg("failed to set metadata for image")

			return err
		}
	}

	return nil
}

// parsedChunk is what parseChunk collected from the entries it consumed, in index.json order.
type parsedChunk struct {
	references []mTypes.RepoReference
	signatures []signatureRef
	partial    bool
}

// blobKey identifies what is read for an index.json entry: entries sharing it share one read.
type blobKey struct {
	digest    godigest.Digest
	mediaType string
}

// blobRead is the outcome of reading one manifest blob of the index. It keeps the decoded results only,
// not the raw manifest and config bytes.
type blobRead struct {
	manifestErr  error
	modTime      time.Time
	hasModTime   bool
	decoded      decodedBlob // until the config is read and the image meta built
	configDigest godigest.Digest
	hasConfig    bool
	configBytes  int64           // real size of the config blob, clamped to the config budget
	built        bool            // the config is read and the image meta built
	manifest     *ispec.Manifest // decoded image manifest, nil for other media types
	imageMeta    mTypes.ImageMeta
	isImage      bool
	buildErr     error // decoding the manifest, or statting, reading and decoding its config failed
}

// errBlobNotRead is returned for an entry whose blob was never scheduled to be read.
var errBlobNotRead = errors.New("manifest blob was not read")

// configCache reads each config blob once per chunk and keeps only the decoded config.
type configCache struct {
	mu      sync.Mutex
	entries map[godigest.Digest]*configEntry
}

type configEntry struct {
	once   sync.Once
	config ispec.Image
	err    error
}

func (c *configCache) get(repo string, digest godigest.Digest, imageStore stypes.ImageStore) (ispec.Image, error) {
	c.mu.Lock()

	entry, found := c.entries[digest]
	if !found {
		entry = &configEntry{}
		c.entries[digest] = entry
	}

	c.mu.Unlock()

	entry.once.Do(func() { entry.config, entry.err = readConfig(repo, digest, imageStore) })

	return entry.config, entry.err
}

// configStats stats each config blob once per window.
type configStats struct {
	mu      sync.Mutex
	entries map[godigest.Digest]*configStatEntry
}

type configStatEntry struct {
	once sync.Once
	size int64
	err  error
}

func (c *configStats) get(repo string, digest godigest.Digest, imageStore stypes.ImageStore) (int64, error) {
	c.mu.Lock()

	entry, found := c.entries[digest]
	if !found {
		entry = &configStatEntry{}
		c.entries[digest] = entry
	}

	c.mu.Unlock()

	entry.once.Do(func() {
		var statFound bool

		statFound, entry.size, _, entry.err = imageStore.StatBlob(repo, digest)
		if entry.err == nil && !statFound {
			entry.err = zerr.ErrBlobNotFound
		}
	})

	return entry.size, entry.err
}

func readConfig(repo string, digest godigest.Digest, imageStore stypes.ImageStore) (ispec.Image, error) {
	config := ispec.Image{}

	configBlob, err := imageStore.GetBlobContent(repo, digest)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal(configBlob, &config)

	return config, err
}

func isMissingBlob(err error) bool {
	var pathNotFoundErr driver.PathNotFoundError

	return errors.Is(err, zerr.ErrBlobNotFound) || errors.As(err, &pathNotFoundErr)
}

// failed reports an error that ends the parse. A missing manifest blob does not: the entry is skipped.
func (r *blobRead) failed() bool {
	if r.manifestErr != nil {
		return !isMissingBlob(r.manifestErr)
	}

	return r.buildErr != nil
}

// readManifest reads, stats and decodes the manifest blob of key and stats its config blob. The config itself
// is read later, for the entries that make it into a chunk.
func readManifest(repo string, key blobKey, imageStore stypes.ImageStore, stats *configStats, log log.Logger,
) *blobRead {
	read := &blobRead{}

	manifestBlob, err := imageStore.GetBlobContent(repo, key.digest)
	if err != nil {
		read.manifestErr = err

		return read
	}

	// The push time only lives in the metaDB; when it is lost, the manifest blob's storage
	// mod time is the closest remaining record of when the image was pushed. Pass it as a
	// hint so a metaDB rebuild doesn't stamp every image with the current time. StatBlob
	// requires the repo lock, which parseRepo already holds.
	if found, _, modTime, err := imageStore.StatBlob(repo, key.digest); err == nil && found {
		read.modTime = modTime
		read.hasModTime = true
	}

	read.decoded, read.buildErr = decodeBlob(key.mediaType, manifestBlob, log)
	if read.buildErr != nil {
		return read
	}

	read.configDigest, read.hasConfig = read.decoded.configDigest()
	if !read.hasConfig {
		return read
	}

	size, err := stats.get(repo, read.configDigest, imageStore)
	if err != nil {
		read.buildErr = err

		return read
	}

	read.configBytes = min(max(size, 0), parseConfigBudget)

	return read
}

// buildImageMeta reads the config of the decoded manifest, once per config digest through configs, and
// converts the result.
func (r *blobRead) buildImageMeta(repo string, key blobKey, configs *configCache, imageStore stypes.ImageStore) {
	config := ispec.Image{}

	if r.hasConfig {
		var err error

		config, err = configs.get(repo, r.configDigest, imageStore)
		if err != nil {
			r.buildErr = err

			return
		}
	}

	r.manifest = r.decoded.manifest
	r.imageMeta, r.isImage = r.decoded.imageMeta(key.digest, config)
	r.decoded = decodedBlob{}
	r.built = true
}

// blobKeyOf returns the key of an entry, false for the referrers tag entries parse skips.
func blobKeyOf(descriptor ispec.Descriptor) (blobKey, bool) {
	if zcommon.IsReferrersTag(descriptor.Annotations[ispec.AnnotationRefName]) {
		return blobKey{}, false
	}

	return blobKey{digest: descriptor.Digest, mediaType: descriptor.MediaType}, true
}

// forEachBounded runs work for every index below count, concurrently when the store allows it. It stops
// scheduling after work reports a failure and waits for the work already started, so the indexes before the
// first failing one have all run.
func forEachBounded(imageStore stypes.ImageStore, count int, work func(i int) (failed bool)) {
	reader, isConcurrentReader := imageStore.(concurrentReader)
	if !isConcurrentReader || !reader.ConcurrentReadSafe() {
		for i := range count {
			if work(i) {
				return
			}
		}

		return
	}

	var (
		wg      sync.WaitGroup
		stopped atomic.Bool
	)

	// Take a slot before spawning, so that no goroutine waits for one.
	for i := range count {
		parseReadSlots <- struct{}{}

		if stopped.Load() {
			<-parseReadSlots

			break
		}

		wg.Go(func() {
			defer func() { <-parseReadSlots }()

			if work(i) {
				stopped.Store(true)
			}
		})
	}

	wg.Wait()
}

// readManifests reads the manifest of every distinct digest in window that reads does not hold yet.
func readManifests(repo string, window []ispec.Descriptor, imageStore stypes.ImageStore,
	reads map[blobKey]*blobRead, log log.Logger,
) {
	seen := map[blobKey]struct{}{}
	keys := make([]blobKey, 0, len(window))

	for _, descriptor := range window {
		key, ok := blobKeyOf(descriptor)
		if !ok {
			continue
		}

		if _, held := reads[key]; held {
			continue
		}

		if _, dup := seen[key]; !dup {
			seen[key] = struct{}{}

			keys = append(keys, key)
		}
	}

	results := make([]*blobRead, len(keys))
	stats := &configStats{entries: map[godigest.Digest]*configStatEntry{}}

	forEachBounded(imageStore, len(keys), func(i int) bool {
		results[i] = readManifest(repo, keys[i], imageStore, stats, log)

		return results[i].failed()
	})

	for i, key := range keys {
		if results[i] != nil {
			reads[key] = results[i]
		}
	}
}

// manifestWindow returns the leading entries whose manifests are read ahead: at most parseChunkSize, while
// their summed descriptor sizes stay within parseManifestBudget, and at least one.
func manifestWindow(entries []ispec.Descriptor) []ispec.Descriptor {
	var bytes int64

	for i, descriptor := range entries {
		size := min(max(descriptor.Size, 0), parseManifestBudget)

		if i == parseChunkSize || (i > 0 && size > parseManifestBudget-bytes) {
			return entries[:i]
		}

		bytes += size
	}

	return entries
}

// cutChunk returns the leading entries of window whose configs stay within parseConfigBudget, and at least
// one. A config shared by several entries is held once, so it is charged once.
func cutChunk(window []ispec.Descriptor, reads map[blobKey]*blobRead) []ispec.Descriptor {
	var bytes int64

	charged := map[godigest.Digest]struct{}{}

	for i, descriptor := range window {
		key, ok := blobKeyOf(descriptor)
		if !ok {
			continue
		}

		read := reads[key]
		if read == nil || !read.hasConfig {
			continue
		}

		if _, done := charged[read.configDigest]; done {
			continue
		}

		if i > 0 && read.configBytes > parseConfigBudget-bytes {
			return window[:i]
		}

		charged[read.configDigest] = struct{}{}
		bytes += read.configBytes
	}

	return window
}

// nextChunk returns the entries that make up the next chunk and leaves their decoded results in reads.
// It reads the manifests of a window of entries and stats their configs, cuts the chunk where the config
// bytes would pass parseConfigBudget, and reads the configs only for the entries inside the cut. Manifests
// read beyond the cut stay in reads and count against the next window.
func nextChunk(repo string, entries []ispec.Descriptor, imageStore stypes.ImageStore, reads map[blobKey]*blobRead,
	log log.Logger,
) []ispec.Descriptor {
	window := manifestWindow(entries)

	readManifests(repo, window, imageStore, reads, log)

	chunk := cutChunk(window, reads)

	readConfigs(repo, chunk, imageStore, reads)

	return chunk
}

// readConfigs reads the configs of the entries in chunk and builds their image meta. It does not go past the
// first entry whose read failed or is missing, as parseChunk returns at that entry.
func readConfigs(repo string, chunk []ispec.Descriptor, imageStore stypes.ImageStore, reads map[blobKey]*blobRead) {
	seen := map[blobKey]struct{}{}
	keys := make([]blobKey, 0, len(chunk))

scan:
	for _, descriptor := range chunk {
		key, ok := blobKeyOf(descriptor)
		if !ok {
			continue
		}

		read := reads[key]

		switch {
		case read == nil || read.failed():
			break scan
		case read.manifestErr != nil: // missing manifest blob, nothing to build
			continue
		}

		if _, dup := seen[key]; !dup {
			seen[key] = struct{}{}

			keys = append(keys, key)
		}
	}

	configs := &configCache{entries: map[godigest.Digest]*configEntry{}}

	forEachBounded(imageStore, len(keys), func(i int) bool {
		read := reads[keys[i]]
		read.buildImageMeta(repo, keys[i], configs, imageStore)

		return read.failed()
	})
}

// parseChunk turns the entries of chunk into references and signatures in index.json order and drops their
// reads. On an error it returns what the entries before the failing one produced.
func parseChunk(repo string, chunk []ispec.Descriptor, reads map[blobKey]*blobRead, log log.Logger,
) (parsedChunk, error) {
	var parsed parsedChunk

	defer func() {
		for _, manifest := range chunk {
			delete(reads, blobKey{digest: manifest.Digest, mediaType: manifest.MediaType})
		}
	}()

	for _, manifest := range chunk {
		tag := manifest.Annotations[ispec.AnnotationRefName]

		if zcommon.IsReferrersTag(tag) {
			continue
		}

		read := reads[blobKey{digest: manifest.Digest, mediaType: manifest.MediaType}]
		if read == nil {
			return parsed, errBlobNotRead
		}

		if read.manifestErr != nil {
			// Handle missing blobs gracefully - log warning and continue with other manifests
			if isMissingBlob(read.manifestErr) {
				log.Warn().Err(read.manifestErr).Str("repository", repo).Str("digest", manifest.Digest.String()).
					Msg("skipping missing manifest blob, continuing repo parse")

				parsed.partial = true

				continue
			}

			log.Error().Err(read.manifestErr).Str("repository", repo).Str("digest", manifest.Digest.String()).
				Msg("failed to get blob for image")

			return parsed, read.manifestErr
		}

		if read.buildErr != nil {
			log.Error().Err(read.buildErr).Str("repository", repo).Str("tag", tag).
				Msg("failed to set metadata for image")

			return parsed, read.buildErr
		}

		if !read.built {
			return parsed, errBlobNotRead
		}

		reference := tag

		if tag == "" {
			reference = manifest.Digest.String()
		}

		if sig, isSig := signatureOf(reference, manifest.Digest, read.manifest); isSig {
			parsed.signatures = append(parsed.signatures, sig)

			continue
		}

		if !read.isImage {
			continue
		}

		setOpts := []mTypes.SetRepoReferenceOption{}
		if read.hasModTime {
			setOpts = append(setOpts, mTypes.WithPushTimestamp(read.modTime))
		}

		parsed.references = append(parsed.references, mTypes.RepoReference{
			Reference: reference,
			ImageMeta: read.imageMeta,
			Opts:      setOpts,
		})
	}

	return parsed, nil
}

func getAllRepos(storeController stypes.StoreController, log log.Logger) ([]string, error) {
	allRepos := make([]string, 0)
	repoSet := make(map[string]struct{})

	// Process substores first
	if storeController.GetImageSubStores() != nil {
		for _, store := range storeController.GetImageSubStores() {
			substoreRepos, err := store.GetRepositories()
			if err != nil {
				log.Error().Err(err).Str("rootDir", store.RootDir()).
					Msg("failed to get all repo names present under rootDir")

				return nil, err
			}

			for _, repo := range substoreRepos {
				if _, exists := repoSet[repo]; !exists {
					allRepos = append(allRepos, repo)
					repoSet[repo] = struct{}{}
				}
			}
		}
	}

	// Process default store, skipping repos already in the set
	defaultRepos, err := storeController.GetDefaultImageStore().GetRepositories()
	if err != nil {
		log.Error().Err(err).Str("rootDir", storeController.GetDefaultImageStore().RootDir()).
			Msg("failed to get all repo names present under rootDir")

		return nil, err
	}

	for _, repo := range defaultRepos {
		if _, exists := repoSet[repo]; !exists {
			allRepos = append(allRepos, repo)
			repoSet[repo] = struct{}{}
		}
	}

	return allRepos, nil
}

func GetSignatureLayersInfo(repo, tag, manifestDigest, signatureType string, manifestBlob []byte,
	imageStore stypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	switch signatureType {
	case zcommon.CosignSignature:
		return getCosignSignatureLayersInfo(repo, tag, manifestDigest, manifestBlob, imageStore, log)
	case zcommon.NotationSignature:
		return getNotationSignatureLayersInfo(repo, manifestDigest, manifestBlob, imageStore, log)
	default:
		return []mTypes.LayerInfo{}, nil
	}
}

func getCosignSignatureLayersInfo(
	repo, tag, manifestDigest string, manifestBlob []byte, imageStore stypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	layers := []mTypes.LayerInfo{}

	var manifestContent ispec.Manifest
	if err := json.Unmarshal(manifestBlob, &manifestContent); err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("digest", manifestDigest).Msg(
			"failed to marshal blob index")

		return layers, err
	}

	err := imageStore.WithRepoReadLock(repo, func() error {
		for _, layer := range manifestContent.Layers {
			// the layer is loaded from storage when the signature is verified, it only has to be there
			if _, _, _, err := imageStore.StatBlob(repo, layer.Digest); err != nil {
				log.Error().Err(err).Str("repository", repo).Str("reference", tag).Str("layerDigest", layer.Digest.String()).Msg(
					"failed to get cosign signature layer")

				return err
			}

			// The legacy cosign annotation is absent on sigstore-bundle referrers (and any other
			// non-legacy cosign format) by design. SignatureKey is simply left
			// empty below in that case.
			layerSigKey, ok := layer.Annotations[zcommon.CosignSigKey]
			if !ok {
				log.Debug().Str("repository", repo).Str("reference", tag).Str("layerDigest", layer.Digest.String()).Msg(
					"cosign signature layer has no legacy signature-key annotation")
			}

			layers = append(layers, mTypes.LayerInfo{
				LayerDigest:  layer.Digest.String(),
				SignatureKey: layerSigKey,
			})
		}

		return nil
	})

	return layers, err
}

func getNotationSignatureLayersInfo(
	repo, manifestDigest string, manifestBlob []byte, imageStore stypes.ImageStore, log log.Logger,
) ([]mTypes.LayerInfo, error) {
	layers := []mTypes.LayerInfo{}

	var manifestContent ispec.Manifest
	if err := json.Unmarshal(manifestBlob, &manifestContent); err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", manifestDigest).Msg(
			"failed to marshal blob index")

		return layers, err
	}

	// skip if is a notation index
	if manifestContent.MediaType == ispec.MediaTypeImageIndex {
		return []mTypes.LayerInfo{}, nil
	}

	if len(manifestContent.Layers) != 1 {
		log.Error().Err(zerr.ErrBadManifest).Str("repository", repo).Str("reference", manifestDigest).
			Msg("notation signature manifest requires exactly one layer but it does not")

		return layers, zerr.ErrBadManifest
	}

	layer := manifestContent.Layers[0].Digest

	err := imageStore.WithRepoReadLock(repo, func() error {
		// the layer is loaded from storage when the signature is verified, it only has to be there
		if _, _, _, err := imageStore.StatBlob(repo, layer); err != nil {
			log.Error().Err(err).Str("repository", repo).Str("reference", manifestDigest).Str("layerDigest", layer.String()).Msg(
				"failed to get notation signature blob")

			return err
		}

		layerSigKey := manifestContent.Layers[0].MediaType

		layers = append(layers, mTypes.LayerInfo{
			LayerDigest:  layer.String(),
			SignatureKey: layerSigKey,
		})

		return nil
	})

	return layers, err
}

// decodedBlob is an image manifest or an image index decoded from its blob, zero for any other media type.
type decodedBlob struct {
	mediaType string
	size      int64
	manifest  *ispec.Manifest
	index     *ispec.Index
}

// signatureRef is a signature manifest that is applied to the image it signs. The manifest blob is not
// part of it: it is read when the signature is applied.
type signatureRef struct {
	reference    string
	digest       godigest.Digest
	sigType      string
	signedDigest godigest.Digest
}

func decodeBlob(mediaType string, blob []byte, log log.Logger) (decodedBlob, error) {
	decoded := decodedBlob{mediaType: mediaType, size: int64(len(blob))}

	if compat.IsImageManifestMediaType(mediaType) { //nolint:gocritic // not converting to switch-case
		manifestContent := ispec.Manifest{}

		err := json.Unmarshal(blob, &manifestContent)
		if err != nil {
			log.Error().Err(err).Str("component", "metadb").Msg("failed to unmarshal image manifest")

			return decodedBlob{}, err
		}

		decoded.manifest = &manifestContent
	} else if compat.IsImageIndexMediaType(mediaType) {
		indexContent := ispec.Index{}

		err := json.Unmarshal(blob, &indexContent)
		if err != nil {
			return decodedBlob{}, err
		}

		decoded.index = &indexContent
	}

	return decoded, nil
}

// configDigest returns the config blob that feeds the image meta of an image manifest, if it has one.
func (d decodedBlob) configDigest() (godigest.Digest, bool) {
	if d.manifest == nil {
		return "", false
	}

	if d.manifest.Config.MediaType == ispec.MediaTypeImageConfig ||
		compat.IsCompatibleConfigMediaType(d.manifest.Config.MediaType) {
		return d.manifest.Config.Digest, true
	}

	return "", false
}

// imageMeta converts the decoded blob, config being the decoded config of an image manifest. ok is false for
// media types that are neither image manifest nor image index.
func (d decodedBlob) imageMeta(digest godigest.Digest, config ispec.Image) (mTypes.ImageMeta, bool) {
	switch {
	case d.manifest != nil:
		return convert.GetImageManifestMeta(*d.manifest, config, d.size, digest, d.mediaType), true
	case d.index != nil:
		return convert.GetImageIndexMeta(*d.index, d.size, digest, d.mediaType), true
	default:
		return mTypes.ImageMeta{}, false
	}
}

// signatureOf reports whether the entry is a signature manifest, and what it signs.
func signatureOf(reference string, digest godigest.Digest, manifest *ispec.Manifest) (signatureRef, bool) {
	if manifest == nil {
		return signatureRef{}, false
	}

	isSig, sigType, signedManifestDigest := isSignature(reference, *manifest)
	if !isSig {
		return signatureRef{}, false
	}

	return signatureRef{reference: reference, digest: digest, sigType: sigType, signedDigest: signedManifestDigest}, true
}

func applySignature(ctx context.Context, repo string, sig signatureRef, sigBlob []byte, imageStore stypes.ImageStore,
	metaDB mTypes.MetaDB, log log.Logger,
) error {
	layers, err := GetSignatureLayersInfo(repo, sig.reference, sig.digest.String(), sig.sigType,
		sigBlob, imageStore, log)
	if err != nil {
		return err
	}

	err = metaDB.AddManifestSignature(repo, sig.signedDigest,
		mTypes.SignatureMetadata{
			SignatureType:   sig.sigType,
			SignatureDigest: sig.digest.String(),
			SignatureTag:    sig.reference,
			LayersInfo:      layers,
		})
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("tag", sig.reference).
			Str("manifestDigest", sig.signedDigest.String()).
			Msg("failed set signature meta for signed image")

		return err
	}

	err = metaDB.UpdateSignaturesValidity(ctx, repo, sig.signedDigest)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("reference", sig.reference).Str("digest",
			sig.signedDigest.String()).Msg("failed to verify signature validity for signed image")

		return err
	}

	return nil
}

// SetImageMetaFromInput tries to set manifest metadata and update repo metadata by adding the current tag
// (in case the reference is a tag). The function expects image manifests and indexes (multi arch images).
func SetImageMetaFromInput(ctx context.Context, repo, reference, mediaType string, digest godigest.Digest, blob []byte,
	imageStore stypes.ImageStore, metaDB mTypes.MetaDB, log log.Logger, setOpts ...mTypes.SetRepoReferenceOption,
) error {
	decoded, err := decodeBlob(mediaType, blob, log)
	if err != nil {
		return err
	}

	config := ispec.Image{}

	if configDigest, hasConfig := decoded.configDigest(); hasConfig {
		config, err = readConfig(repo, configDigest, imageStore)
		if err != nil {
			return err
		}
	}

	if sig, isSig := signatureOf(reference, digest, decoded.manifest); isSig {
		return applySignature(ctx, repo, sig, blob, imageStore, metaDB, log)
	}

	imageMeta, isImage := decoded.imageMeta(digest, config)
	if !isImage {
		return nil
	}

	err = metaDB.SetRepoReference(ctx, repo, reference, imageMeta, setOpts...)
	if err != nil {
		log.Error().Err(err).Str("component", "metadb").Msg("failed to set repo meta")

		return err
	}

	return nil
}

func isSignature(reference string, manifestContent ispec.Manifest) (bool, string, godigest.Digest) {
	manifestArtifactType := zcommon.GetManifestArtifactType(manifestContent)

	// check notation signature
	if manifestArtifactType == zcommon.ArtifactTypeNotation && manifestContent.Subject != nil {
		return true, NotationType, manifestContent.Subject.Digest
	}

	// check cosign signature
	if zcommon.IsCosignSignatureArtifact(manifestArtifactType, manifestContent.Annotations) &&
		manifestContent.Subject != nil {
		return true, CosignType, manifestContent.Subject.Digest
	}

	if tag := reference; zcommon.IsCosignSignature(reference) {
		// IsCosignSignature matches only "sha256-<64 hex>.sig", so the slice below is in bounds and valid.
		prefixLen := len("sha256-")
		digestLen := 64

		signedImageManifestDigestEncoded := tag[prefixLen : prefixLen+digestLen]

		signedImageManifestDigest := godigest.NewDigestFromEncoded(godigest.SHA256,
			signedImageManifestDigestEncoded)

		return true, CosignType, signedImageManifestDigest
	}

	return false, "", ""
}
