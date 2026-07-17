package imagestore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/events"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	syncConstants "zotregistry.dev/zot/v2/pkg/extensions/sync/constants"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
	"zotregistry.dev/zot/v2/pkg/test/inject"
)

const (
	cosignSignatureTagSuffix = "sig"
	SBOMTagSuffix            = "sbom"
)

// ImageStore provides the image storage operations.
type ImageStore struct {
	rootDir     string
	storeDriver storageTypes.Driver
	lock        *sync.RWMutex
	// blobstoreLock protects only GlobalBlobsRepo (_blobstore) state/data mutations.
	// repoLocks holds one *sync.RWMutex per repository name, created lazily on first
	// use. Together these replace the single whole-store lock (see With*Lock helpers
	// below); the mandated acquisition order is blobstoreLock before any repo lock,
	// never the reverse, and never more than one repo's lock held at a time - see
	// WithBlobstoreAndRepoLock/WithBlobstoreReadAndRepoLock, the only sanctioned way
	// to hold both.
	blobstoreLock *sync.RWMutex
	repoLocks     sync.Map
	log           zlog.Logger
	metrics       monitoring.MetricServer
	events        events.Recorder
	cache         storageTypes.Cache
	lifecycle     blobLifecycle
	dedupe        bool
	linter        common.Lint
	commit        bool
	compat        []compat.MediaCompatibility
	// dedupeRebuildDone is set once RunDedupeBlobs has walked all blobs, i.e. the
	// cache accounts for every pre-existing blob; see deleteBlob.
	dedupeRebuildDone atomic.Bool
}

type blobRefIndexer interface {
	PutBlobRef(digest godigest.Digest, path string) error
	DeleteBlobRef(digest godigest.Digest, path string) error
	GetBlobRefs(digest godigest.Digest) ([]string, error)
}

func (is *ImageStore) blobRefs() blobRefIndexer {
	if indexer, ok := is.cache.(blobRefIndexer); ok {
		return indexer
	}

	return nil
}

func (is *ImageStore) putBlobRef(digest godigest.Digest, path string) error {
	if is.cache != nil {
		if err := is.cache.PutBlob(digest, path); err != nil {
			return err
		}
	}

	if indexer := is.blobRefs(); indexer != nil {
		return indexer.PutBlobRef(digest, path)
	}

	return nil
}

func (is *ImageStore) deleteBlobRef(digest godigest.Digest, path string) error {
	if is.cache != nil {
		if err := is.cache.DeleteBlob(digest, path); err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			return err
		}
	}

	if indexer := is.blobRefs(); indexer != nil {
		if err := indexer.DeleteBlobRef(digest, path); err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			return err
		}
	}

	return nil
}

func (is *ImageStore) blobRefsForDigest(digest godigest.Digest) ([]string, error) {
	if indexer := is.blobRefs(); indexer != nil {
		paths, err := indexer.GetBlobRefs(digest)
		if err == nil || !errors.Is(err, zerr.ErrCacheMiss) {
			return paths, err
		}
	}

	if is.cache == nil {
		return nil, zerr.ErrCacheMiss
	}

	return is.cache.GetAllBlobs(digest)
}

func (is *ImageStore) Name() string {
	return is.storeDriver.Name()
}

func (is *ImageStore) RootDir() string {
	return is.rootDir
}

func (is *ImageStore) DirExists(d string) bool {
	return is.storeDriver.DirExists(d)
}

// NewImageStore returns a new image store backed by cloud storages.
// see https://github.com/docker/docker.github.io/tree/master/registry/storage-drivers
// Use the last argument to properly set a cache database, or it will default to boltDB local storage.
func NewImageStore(rootDir string, cacheDir string, dedupe, commit bool, log zlog.Logger,
	metrics monitoring.MetricServer, linter common.Lint, storeDriver storageTypes.Driver,
	cacheDriver storageTypes.Cache, compat []compat.MediaCompatibility, recorder events.Recorder,
) storageTypes.ImageStore {
	if err := storeDriver.EnsureDir(rootDir); err != nil {
		log.Error().Err(err).Str("rootDir", rootDir).Msg("failed to create root dir")

		return nil
	}

	imgStore := &ImageStore{
		rootDir:       rootDir,
		storeDriver:   storeDriver,
		lock:          &sync.RWMutex{},
		blobstoreLock: &sync.RWMutex{},
		log:           log,
		metrics:       metrics,
		dedupe:        dedupe,
		linter:        linter,
		commit:        commit,
		cache:         cacheDriver,
		lifecycle:     newBlobLifecycle(storeDriver),
		compat:        compat,
		events:        recorder,
	}

	if dedupe {
		// create the global blobs repo which will serve as the master copy for all deduped blobs
		if err := imgStore.initRepo(context.Background(), storageConstants.GlobalBlobsRepo); err != nil {
			log.Error().Err(err).Str("rootDir", rootDir).Msg("failed to create global blobs repo")

			return nil
		}

		// upgrade from older releases that did not have _blobstore
		// runs whenever migration marker is absent (checked at top of upgradeToGlobalBlobstore)
		if err := imgStore.upgradeToGlobalBlobstore(); err != nil {
			log.Error().Err(err).Msg("failed to upgrade to global blobstore")

			return nil
		}
	}

	// Deletes are only gated while a dedupe/restore walk is pending; see RunDedupeBlobs.
	imgStore.dedupeRebuildDone.Store(true)

	return imgStore
}

// RLock read-lock.
func (is *ImageStore) RLock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.RLock()
}

// RUnlock read-unlock.
func (is *ImageStore) RUnlock(lockStart *time.Time) {
	is.lock.RUnlock()

	lockEnd := time.Now()
	// includes time spent in acquiring and holding a lock
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RLOCK) // histogram
}

// Lock write-lock.
func (is *ImageStore) Lock(lockStart *time.Time) {
	*lockStart = time.Now()

	is.lock.Lock()
}

// Unlock write-unlock.
func (is *ImageStore) Unlock(lockStart *time.Time) {
	is.lock.Unlock()

	lockEnd := time.Now()
	// includes time spent in acquiring and holding a lock
	latency := lockEnd.Sub(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RWLOCK) // histogram
}

// getRepoLock returns the lazily-created per-repository lock for repo. Entries are
// never evicted (bounded by actual repo count, same tradeoff a prior locking attempt
// made in real cluster deployments without it being the reported problem); revisit
// only if profiling shows unbounded growth matters in practice.
func (is *ImageStore) getRepoLock(repo string) *sync.RWMutex {
	val, _ := is.repoLocks.LoadOrStore(repo, &sync.RWMutex{})

	//nolint:forcetypeassert // only ever stored as *sync.RWMutex via getRepoLock itself
	return val.(*sync.RWMutex)
}

// lockRepo/unlockRepo mirror the pre-refactor Lock/Unlock signature (direct lock,
// deferred unlock, no closure) for the handful of methods with too many early-return
// points to safely wrap in WithRepoLock's closure shape without risking a mistake in
// the rewrite. Internal use only within this package; external callers (and the
// storageTypes.ImageStore interface) use WithRepoLock/WithRepoReadLock.
func (is *ImageStore) lockRepo(repo string, lockStart *time.Time) {
	*lockStart = time.Now()
	is.getRepoLock(repo).Lock()
}

func (is *ImageStore) unlockRepo(repo string, lockStart *time.Time) {
	is.getRepoLock(repo).Unlock()

	latency := time.Since(*lockStart)
	monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RepoRWLock)
}

// WithRepoLock runs wrappedFunc while holding repo's write lock. Callers must not
// call this, or WithRepoReadLock, for a second repo from within wrappedFunc: only one
// repo's lock may be held at a time in a given goroutine (see ImageStore's lock
// ordering doc comment).
func (is *ImageStore) WithRepoLock(repo string, wrappedFunc func() error) error {
	lockStart := time.Now()
	repoLock := is.getRepoLock(repo)

	repoLock.Lock()
	defer func() {
		repoLock.Unlock()

		latency := time.Since(lockStart)
		monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RepoRWLock)
	}()

	return wrappedFunc()
}

// WithRepoReadLock runs wrappedFunc while holding repo's read lock. Same
// one-repo-at-a-time restriction as WithRepoLock.
func (is *ImageStore) WithRepoReadLock(repo string, wrappedFunc func() error) error {
	lockStart := time.Now()
	repoLock := is.getRepoLock(repo)

	repoLock.RLock()
	defer func() {
		repoLock.RUnlock()

		latency := time.Since(lockStart)
		monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.RepoRLock)
	}()

	return wrappedFunc()
}

// WithBlobstoreLock runs wrappedFunc while holding the global blobstore write lock.
// If wrappedFunc also needs a repo lock, it must acquire it via WithRepoLock from
// *inside* wrappedFunc (or, more simply, call WithBlobstoreAndRepoLock) - never take
// a repo lock first and then call WithBlobstoreLock from within it, that inverts the
// mandated order.
func (is *ImageStore) WithBlobstoreLock(wrappedFunc func() error) error {
	lockStart := time.Now()

	is.blobstoreLock.Lock()
	defer func() {
		is.blobstoreLock.Unlock()

		latency := time.Since(lockStart)
		monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.BlobstoreRWLock)
	}()

	return wrappedFunc()
}

// WithBlobstoreReadLock runs wrappedFunc while holding the global blobstore read
// lock. Same ordering rule as WithBlobstoreLock.
func (is *ImageStore) WithBlobstoreReadLock(wrappedFunc func() error) error {
	lockStart := time.Now()

	is.blobstoreLock.RLock()
	defer func() {
		is.blobstoreLock.RUnlock()

		latency := time.Since(lockStart)
		monitoring.ObserveStorageLockLatency(is.metrics, latency, is.RootDir(), storageConstants.BlobstoreRLock)
	}()

	return wrappedFunc()
}

// WithBlobstoreAndRepoLock is the only sanctioned way to hold both the blobstore and
// a repo lock at once: it enforces the mandated order (blobstore, then repo)
// internally so call sites can't get it backwards.
func (is *ImageStore) WithBlobstoreAndRepoLock(repo string, wrappedFunc func() error) error {
	return is.WithBlobstoreLock(func() error {
		return is.WithRepoLock(repo, wrappedFunc)
	})
}

// WithBlobstoreReadAndRepoLock is WithBlobstoreAndRepoLock's read-lock-on-the-
// blobstore counterpart, for operations that only read _blobstore (e.g. resolving a
// dedupe marker) while still writing into a specific repo.
func (is *ImageStore) WithBlobstoreReadAndRepoLock(repo string, wrappedFunc func() error) error {
	return is.WithBlobstoreReadLock(func() error {
		return is.WithRepoLock(repo, wrappedFunc)
	})
}

func (is *ImageStore) initRepo(ctx context.Context, name string) error {
	if name != storageConstants.GlobalBlobsRepo {
		if !utf8.ValidString(name) {
			is.log.Error().Msg("invalid UTF-8 input")

			return zerr.ErrInvalidRepositoryName
		}

		if !zreg.FullNameRegexp.MatchString(name) {
			is.log.Error().Str("repository", name).Msg("invalid repository name")

			return zerr.ErrInvalidRepositoryName
		}
	}

	repoDir := path.Join(is.rootDir, name)

	// create "blobs" subdir
	err := is.storeDriver.EnsureDir(path.Join(repoDir, ispec.ImageBlobsDir))
	if err != nil {
		is.log.Error().Err(err).Str("repository", name).Str("dir", repoDir).Msg("failed to create blobs subdir")

		return err
	}
	// create BlobUploadDir subdir
	err = is.storeDriver.EnsureDir(path.Join(repoDir, storageConstants.BlobUploadDir))
	if err != nil {
		is.log.Error().Err(err).Msg("failed to create blob upload subdir")

		return err
	}

	// "oci-layout" file - create if it doesn't exist
	ilPath := path.Join(repoDir, ispec.ImageLayoutFile)
	if _, err := is.storeDriver.Stat(ilPath); err != nil {
		il := ispec.ImageLayout{Version: ispec.ImageLayoutVersion}

		buf, err := json.Marshal(il)
		if err != nil {
			is.log.Error().Err(err).Msg("failed to marshal JSON")

			return err
		}

		if _, err := is.storeDriver.WriteFile(ilPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("failed to write file")

			return err
		}
	}

	// "index.json" file - create if it doesn't exist
	indexPath := path.Join(repoDir, ispec.ImageIndexFile)
	if _, err := is.storeDriver.Stat(indexPath); err != nil {
		index := ispec.Index{}
		index.SchemaVersion = 2

		buf, err := json.Marshal(index)
		if err != nil {
			is.log.Error().Err(err).Msg("failed to marshal JSON")

			return err
		}

		if _, err := is.storeDriver.WriteFile(indexPath, buf); err != nil {
			is.log.Error().Err(err).Str("file", ilPath).Msg("failed to write file")

			return err
		}

		if is.events != nil {
			is.events.RepositoryCreated(name, events.EventContextFromContext(ctx))
		}
	}

	return nil
}

// promoteBlobCandidate handles the core logic of copying/linking a single blob candidate
// into the global blobstore and registering it in the cache.
//
// blobCandidate holds metadata for a blob selected from the pre-blobstore layout.
type blobCandidate struct {
	repoName string
	blobPath string
	size     int64
}

// repoBlobRef tracks a blob's presence in a specific repo (for cache registration).
type repoBlobRef struct {
	digest   godigest.Digest
	repoName string
	blobPath string
	size     int64
}

func (is *ImageStore) promoteBlobCandidate(
	candidate blobCandidate,
	digest godigest.Digest,
	globalBlobPath string,
) error {
	emptyDigest := digest.Algorithm().FromBytes(nil)
	if candidate.size == 0 && digest != emptyDigest {
		if binfo, err := is.storeDriver.Stat(globalBlobPath); err == nil {
			if binfo.Size() > 0 {
				// Resume safety: candidate can be a repo marker after a partial prior run.
				// If global content already exists, do not overwrite it with marker bytes.
				if err := is.putBlobRef(digest, globalBlobPath); err != nil {
					is.log.Error().Err(err).Str("digest", digest.String()).
						Msg("failed to update blob refs with existing global blob path during upgrade")

					return err
				}

				is.log.Info().Str("digest", digest.String()).Str("repo", candidate.repoName).
					Msg("detected existing global blob, skipping marker-only promotion")

				return nil
			}
		} else {
			var pathNotFoundErr driver.PathNotFoundError
			if !errors.As(err, &pathNotFoundErr) {
				return err
			}
		}
	}

	// ensure algorithm dir exists in _blobstore
	algoDir := path.Join(is.rootDir, storageConstants.GlobalBlobsRepo,
		ispec.ImageBlobsDir, digest.Algorithm().String())
	if err := is.storeDriver.EnsureDir(algoDir); err != nil {
		is.log.Error().Err(err).Str("dir", algoDir).Msg("failed to create algorithm dir")

		return err
	}

	if err := is.lifecycle.PromoteCandidate(candidate.blobPath, globalBlobPath); err != nil {
		is.log.Error().Err(err).Str("src", candidate.blobPath).Str("dst", globalBlobPath).
			Msg("failed to promote blob to global blobstore")

		return err
	}

	// register global blobstore path as the master/original reference first,
	// so that subsequent writes for per-repo paths are tracked alongside it.
	if err := is.putBlobRef(digest, globalBlobPath); err != nil {
		is.log.Error().Err(err).Str("digest", digest.String()).
			Msg("failed to update blob refs with global blobstore path during upgrade")

		return err
	}

	is.log.Info().Str("digest", digest.String()).Str("repo", candidate.repoName).
		Msg("upgraded blob to global blobstore")

	return nil
}

// upgradeToGlobalBlobstore migrates blobs from per-repo directories into the global _blobstore
// for older zot releases that did not have a centralized blobstore.
// For local filesystem it uses hard links (no extra disk space).
// For S3/GCS it copies the blob content to the global blobstore.
func (is *ImageStore) upgradeToGlobalBlobstore() error {
	// Check for the migration-complete marker first; this is more reliable than counting
	// blobs (which would be zero on a fresh install that never pushed anything).
	markerPath := path.Join(is.rootDir, storageConstants.BlobstoreMigratedMarker)
	if _, err := is.storeDriver.Stat(markerPath); err == nil {
		// marker exists — migration already done on a previous startup
		return nil
	} else {
		var pathNotFoundErr driver.PathNotFoundError
		if !errors.As(err, &pathNotFoundErr) {
			return err
		}
	}

	// discover repos using Walk (supports nested repos like org/repo)
	repos := []string{}

	err := is.storeDriver.Walk(is.rootDir, func(fileInfo driver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		// skip internal dirs
		base := filepath.Base(fileInfo.Path())
		if base == syncConstants.SyncBlobUploadDir ||
			base == ispec.ImageBlobsDir ||
			base == storageConstants.BlobUploadDir {
			return driver.ErrSkipDir
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil {
			return nil //nolint:nilerr
		}

		rel = filepath.ToSlash(rel)

		if rel == storageConstants.GlobalBlobsRepo {
			return driver.ErrSkipDir
		}

		if ok, _ := is.ValidateRepo(rel); !ok {
			return nil //nolint:nilerr
		}

		repos = append(repos, rel)

		return nil
	})
	if err != nil && !errors.As(err, &driver.PathNotFoundError{}) {
		return err
	}

	if len(repos) == 0 {
		is.writeBlobstoreMigrationMarker(markerPath)

		return nil
	}

	is.log.Info().Msg("upgrading storage: populating global blobstore from existing repos")

	candidates := map[string]blobCandidate{}
	repoBlobRefs := []repoBlobRef{}
	promotedDigests := map[string]bool{}
	verifiedPromotedDigests := map[string]bool{}
	skippedRepoListFailures := 0
	markerOnlyDigests := 0

	for _, repoName := range repos {
		repoBlobs, err := is.GetAllBlobs(repoName)
		if err != nil {
			skippedRepoListFailures++
			is.log.Warn().Err(err).Str("repo", repoName).Msg("failed to list blobs during upgrade, skipping repo")

			continue
		}

		for _, digest := range repoBlobs {
			repoBlobPath := is.BlobPath(repoName, digest)
			blobSize := int64(0)

			candidate, found := candidates[digest.String()]
			if !found {
				candidate = blobCandidate{repoName: repoName, blobPath: repoBlobPath}
			}

			if binfo, err := is.storeDriver.Stat(repoBlobPath); err == nil {
				blobSize = binfo.Size()

				if binfo.Size() > 0 && candidate.size == 0 {
					candidate.repoName = repoName
					candidate.blobPath = repoBlobPath
					candidate.size = binfo.Size()
				}
			}

			repoBlobRefs = append(repoBlobRefs, repoBlobRef{
				digest:   digest,
				repoName: repoName,
				blobPath: repoBlobPath,
				size:     blobSize,
			})

			candidates[digest.String()] = candidate
		}
	}

	for digestStr, candidate := range candidates {
		digest := godigest.Digest(digestStr)
		globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)

		if candidate.size == 0 {
			markerOnlyDigests++
			is.log.Warn().Str("digest", digestStr).Str("repo", candidate.repoName).
				Msg("upgrading digest with only empty marker blobs found")
		}

		if err := is.promoteBlobCandidate(candidate, digest, globalBlobPath); err != nil {
			return err
		}

		promotedDigests[digest.String()] = true
	}

	for _, repoBlobRef := range repoBlobRefs {
		if !promotedDigests[repoBlobRef.digest.String()] {
			continue
		}

		if repoBlobRef.size > 0 {
			if err := is.verifyPromotedGlobalBlobForMigration(repoBlobRef, verifiedPromotedDigests); err != nil {
				return err
			}

			globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, repoBlobRef.digest)

			if err := is.lifecycle.ConvertMigratedRepoBlobToMarker(globalBlobPath, repoBlobRef.blobPath); err != nil {
				is.log.Error().Err(err).Str("digest", repoBlobRef.digest.String()).Str("repo", repoBlobRef.repoName).
					Str("repoBlobPath", repoBlobRef.blobPath).Msg("failed to convert repo blob to marker")

				return err
			}
		}

		// always register each repo's blob path in the cache as a duplicate,
		// so GetAllDedupeReposCandidates returns all repos that own this blob
		if err := is.putBlobRef(repoBlobRef.digest, repoBlobRef.blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", repoBlobRef.digest.String()).Str("repo", repoBlobRef.repoName).
				Msg("failed to register repo blob path in blob refs during upgrade")

			return err
		}
	}

	return is.completeBlobstoreUpgrade(markerPath, skippedRepoListFailures, promotedDigests, candidates, markerOnlyDigests)
}

func (is *ImageStore) completeBlobstoreUpgrade(markerPath string, skippedRepoListFailures int,
	promotedDigests map[string]bool, candidates map[string]blobCandidate, markerOnlyDigests int,
) error {
	is.log.Info().
		Int("blobCount", len(promotedDigests)).
		Int("candidateCount", len(candidates)).
		Int("markerOnlyDigestCount", markerOnlyDigests).
		Msg("global blobstore upgrade completed")

	if skippedRepoListFailures > 0 {
		is.log.Warn().Int("skippedRepoCount", skippedRepoListFailures).
			Msg("blobstore upgrade incomplete: migration marker not written because some repos were skipped")

		return nil
	}

	if len(promotedDigests) == 0 {
		is.log.Warn().Int("candidateCount", len(candidates)).
			Msg("blobstore upgrade incomplete: migration marker not written because no digests were promoted")

		return nil
	}

	is.writeBlobstoreMigrationMarker(markerPath)

	return nil
}

func (is *ImageStore) verifyPromotedGlobalBlobForMigration(ref repoBlobRef, verified map[string]bool) error {
	// Local filesystem migration uses hardlinks and keeps per-repo blobs as content files.
	if !is.lifecycle.ShouldGateDeleteUntilRebuild() || verified[ref.digest.String()] {
		return nil
	}

	globalDigestPath := is.BlobPath(storageConstants.GlobalBlobsRepo, ref.digest)

	// For remote marker backends, verify promoted global content before replacing
	// per-repo content blobs with zero-byte markers.
	if err := is.VerifyBlobDigestValue(storageConstants.GlobalBlobsRepo, ref.digest); err != nil {
		is.log.Error().Err(err).Str("digest", ref.digest.String()).Str("repo", ref.repoName).
			Str("globalBlobPath", globalDigestPath).Msg("failed to verify promoted global blob during upgrade")

		return err
	}

	verified[ref.digest.String()] = true

	return nil
}

func (is *ImageStore) writeBlobstoreMigrationMarker(markerPath string) {
	// Write the migration-complete marker (at the store root, is.rootDir already exists)
	// so this scan is skipped on future startups.
	if _, err := is.storeDriver.WriteFile(markerPath, []byte("1")); err != nil {
		is.log.Warn().Err(err).Msg("failed to write blobstore migration marker")
	}
}

// InitRepo creates an image repository under this store.
func (is *ImageStore) InitRepo(ctx context.Context, name string) error {
	if !utf8.ValidString(name) {
		is.log.Error().Msg("invalid UTF-8 input")

		return zerr.ErrInvalidRepositoryName
	}

	if !zreg.FullNameRegexp.MatchString(name) {
		is.log.Error().Str("repository", name).Msg("invalid repository name")

		return zerr.ErrInvalidRepositoryName
	}

	return is.WithRepoLock(name, func() error {
		return is.initRepo(ctx, name)
	})
}

// ValidateRepo validates that the repository layout is complaint with the OCI repo layout.
func (is *ImageStore) ValidateRepo(name string) (bool, error) {
	if !zreg.FullNameRegexp.MatchString(name) {
		return false, zerr.ErrInvalidRepositoryName
	}

	// https://github.com/opencontainers/image-spec/blob/master/image-layout.md#content
	// at least, expect at least 3 entries - ["blobs", "oci-layout", "index.json"]
	// and an additional/optional BlobUploadDir in each image store
	// for s3 we can not create empty dirs, so we check only against index.json and oci-layout
	dir := path.Join(is.rootDir, name)

	files, err := is.storeDriver.List(dir)
	if err != nil {
		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read directory")

		return false, zerr.ErrRepoNotFound
	}

	//nolint:mnd
	if len(files) < 2 {
		return false, zerr.ErrRepoBadVersion
	}

	found := map[string]bool{
		ispec.ImageLayoutFile: false,
		ispec.ImageIndexFile:  false,
	}

	for _, file := range files {
		if path.Base(file) == ispec.ImageIndexFile {
			found[ispec.ImageIndexFile] = true
		}

		if strings.HasSuffix(file, ispec.ImageLayoutFile) {
			found[ispec.ImageLayoutFile] = true
		}
	}

	// check blobs dir exists only for filesystem, in s3 we can't have empty dirs
	if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
		if !is.storeDriver.DirExists(path.Join(dir, ispec.ImageBlobsDir)) {
			return false, nil
		}
	}

	for _, v := range found {
		if !v {
			return false, nil
		}
	}

	return true, nil
}

// GetNextRepositories does not take a lock: it's a read-only, whole-tree Walk that
// already tolerates a concurrently-changing repo set (e.g. InitRepo creating a repo
// mid-walk) the same way it does today - no backend offers an atomic multi-key
// listing, so a whole-store lock never made this walk atomic, it only serialized
// unrelated writes against it for no consistency benefit.
func (is *ImageStore) GetNextRepositories(lastRepo string, maxEntries int, filterFn storageTypes.FilterRepoFunc,
) ([]string, bool, error) {
	dir := is.rootDir

	stores := make([]string, 0)

	moreEntries := false
	entries := 0
	found := false
	err := is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if entries == maxEntries {
			moreEntries = true

			return io.EOF
		}

		if !fileInfo.IsDir() {
			return nil
		}

		// skip .sync and .uploads dirs no need to try to validate them
		if strings.HasSuffix(fileInfo.Path(), syncConstants.SyncBlobUploadDir) ||
			strings.HasSuffix(fileInfo.Path(), ispec.ImageBlobsDir) ||
			strings.HasSuffix(fileInfo.Path(), storageConstants.BlobUploadDir) {
			return driver.ErrSkipDir
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil {
			return nil //nolint:nilerr // ignore paths that are not under root dir
		}

		rel = filepath.ToSlash(rel)

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

		if lastRepo == rel {
			found = true

			return nil
		}

		if lastRepo == "" {
			found = true
		}

		ok, err := filterFn(rel)
		if err != nil {
			return err
		}

		if found && ok {
			entries++

			stores = append(stores, rel)
		}

		return nil
	})

	// if the root directory is not yet created then return an empty slice of repositories

	driverErr := &driver.Error{}

	if errors.As(err, &driver.PathNotFoundError{}) {
		is.log.Debug().Msg("empty rootDir")

		return stores, false, nil
	}

	if errors.Is(err, io.EOF) ||
		(errors.As(err, driverErr) && errors.Is(driverErr.Detail, io.EOF)) {
		return stores, moreEntries, nil
	}

	return stores, moreEntries, err
}

// GetRepositories returns a list of all the repositories under this store. Does not
// take a lock - see GetNextRepositories' doc comment.
func (is *ImageStore) GetRepositories() ([]string, error) {
	dir := is.rootDir

	stores := make([]string, 0)

	err := is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		// skip .sync and .uploads dirs no need to try to validate them
		if strings.HasSuffix(fileInfo.Path(), syncConstants.SyncBlobUploadDir) ||
			strings.HasSuffix(fileInfo.Path(), ispec.ImageBlobsDir) ||
			strings.HasSuffix(fileInfo.Path(), storageConstants.BlobUploadDir) {
			return driver.ErrSkipDir
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil {
			return nil //nolint:nilerr // ignore paths that are not under root dir
		}

		rel = filepath.ToSlash(rel)

		if ok, err := is.ValidateRepo(rel); !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

		stores = append(stores, rel)

		return nil
	})

	// if the root directory is not yet created then return an empty slice of repositories
	var perr driver.PathNotFoundError
	if errors.As(err, &perr) {
		return stores, nil
	}

	return stores, err
}

// isDigestReferencedAcrossRepos reports whether any repo other than the global
// blobstore still holds a physical blob path for this digest. It relies on the
// blob-ref cache (kept in sync by putBlobRef/deleteBlobRef on every dedupe link
// and delete) rather than scanning manifests: a blob can legitimately exist
// without yet being referenced by any manifest (e.g. mid-upload, or a raw
// dedupe'd blob) while still being the last physical copy backing other repos'
// dedupe markers, so a manifest-only scan can miss live references and cause
// the shared global copy to be reclaimed while still in use.
func (is *ImageStore) isDigestReferencedAcrossRepos(digest godigest.Digest) (bool, error) {
	blobPaths, err := is.blobRefsForDigest(digest)
	if err != nil {
		if errors.Is(err, zerr.ErrCacheMiss) {
			return false, nil
		}

		return false, err
	}

	rootPrefix := filepath.ToSlash(is.rootDir)

	for _, blobPath := range blobPaths {
		normalizedPath := filepath.ToSlash(blobPath)
		normalizedPath = strings.TrimPrefix(normalizedPath, "./")

		if relativePath, ok := strings.CutPrefix(normalizedPath, rootPrefix+"/"); ok {
			normalizedPath = relativePath
		}

		normalizedPath = strings.TrimPrefix(normalizedPath, "/")

		if strings.HasPrefix(normalizedPath, storageConstants.GlobalBlobsRepo+"/") {
			continue
		}

		return true, nil
	}

	return false, nil
}

// GetNextRepository returns next repository under this store.
// GetNextRepository does not take a lock - see GetNextRepositories' doc comment.
func (is *ImageStore) GetNextRepository(processedRepos map[string]struct{}) (string, error) {
	dir := is.rootDir

	_, err := is.storeDriver.List(dir)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Debug().Msg("empty rootDir")

			return "", nil
		}

		is.log.Error().Err(err).Str("root-dir", dir).Msg("failed to walk storage root-dir")

		return "", err
	}

	store := ""
	err = is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		if !fileInfo.IsDir() {
			return nil
		}

		// skip .sync and .uploads dirs no need to try to validate them
		if strings.HasSuffix(fileInfo.Path(), syncConstants.SyncBlobUploadDir) ||
			strings.HasSuffix(fileInfo.Path(), ispec.ImageBlobsDir) ||
			strings.HasSuffix(fileInfo.Path(), storageConstants.BlobUploadDir) {
			return driver.ErrSkipDir
		}

		rel, err := filepath.Rel(is.rootDir, fileInfo.Path())
		if err != nil {
			return nil //nolint:nilerr // ignore paths not relative to root dir
		}

		rel = filepath.ToSlash(rel)

		// ValidateRepo already rejects this, but skip descending into it outright -
		// it can hold one entry per digest ever deduped, so walking its full blob
		// tree on every call (this runs once per repo, in a loop, from GC/scrub/
		// dedupe generators) is wasted work for a directory that's never a repo.
		if rel == storageConstants.GlobalBlobsRepo {
			return driver.ErrSkipDir
		}

		if _, ok := processedRepos[rel]; ok {
			return nil // repo already processed
		}

		ok, err := is.ValidateRepo(rel)
		if !ok || err != nil {
			return nil //nolint:nilerr // ignore invalid repos
		}

		store = rel

		return io.EOF
	})

	driverErr := &driver.Error{}

	// some s3 implementations (eg, digitalocean spaces) will return pathnotfounderror for walk but not list
	// therefore, we must also catch that error here.
	if errors.As(err, &driver.PathNotFoundError{}) {
		is.log.Debug().Msg("empty rootDir")

		return "", nil
	}

	if errors.Is(err, io.EOF) ||
		(errors.As(err, driverErr) && errors.Is(driverErr.Detail, io.EOF)) {
		return store, nil
	}

	return store, err
}

// GetImageTags returns a list of image tags available in the specified repository.
func (is *ImageStore) GetImageTags(repo string) ([]string, error) {
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.storeDriver.Stat(dir); err != nil || !fi.IsDir() {
		return nil, zerr.ErrRepoNotFound
	}

	var tags []string

	err := is.WithRepoReadLock(repo, func() error {
		index, err := common.GetIndex(is, repo, is.log)
		if err != nil {
			return err
		}

		tags = common.GetTagsByIndex(index)

		return nil
	})

	return tags, err
}

// GetImageManifest returns the image manifest of an image in the specific repository.
func (is *ImageStore) GetImageManifest(repo, reference string) ([]byte, godigest.Digest, string, error) {
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.storeDriver.Stat(dir); err != nil || !fi.IsDir() {
		return nil, "", "", zerr.ErrRepoNotFound
	}

	var (
		buf       []byte
		digest    godigest.Digest
		mediaType string
	)

	err := is.WithRepoReadLock(repo, func() error {
		index, err := common.GetIndex(is, repo, is.log)
		if err != nil {
			return err
		}

		manifestDesc, found := common.GetManifestDescByReference(index, reference)
		if !found {
			return zerr.ErrManifestNotFound
		}

		content, err := is.GetBlobContent(repo, manifestDesc.Digest)
		if err != nil {
			if errors.Is(err, zerr.ErrBlobNotFound) {
				return zerr.ErrManifestNotFound
			}

			return err
		}

		var manifest ispec.Manifest
		if err := json.Unmarshal(content, &manifest); err != nil {
			is.log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")

			return err
		}

		buf = content
		digest = manifestDesc.Digest
		mediaType = manifestDesc.MediaType

		return nil
	})
	if err == nil {
		monitoring.IncDownloadCounter(is.metrics, repo)
	}

	return buf, digest, mediaType, err
}

// PutImageManifest adds an image manifest to the repository.
// When extraTags is non-empty, the reference must be a digest; each entry becomes an
// org.opencontainers.image.ref.name on a separate index descriptor (distribution-spec
// digest push with tag query params).
func (is *ImageStore) PutImageManifest(ctx context.Context, repo, reference, mediaType string, //nolint: gocyclo,cyclop
	body []byte, extraTags []string,
) (godigest.Digest, godigest.Digest, error) {
	if err := is.InitRepo(ctx, repo); err != nil {
		is.log.Debug().Err(err).Msg("init repo")

		return "", "", err
	}

	// This function has many early returns, which don't fit cleanly into
	// WithRepoLock's closure shape without risking a mistake in the rewrite -
	// lock the repo directly instead via lockRepo/unlockRepo.
	var lockLatency time.Time

	var err error

	is.lockRepo(repo, &lockLatency)
	defer func() {
		is.unlockRepo(repo, &lockLatency)

		if err == nil {
			if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
				monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
			}

			monitoring.IncUploadCounter(is.metrics, repo)
		}
	}()

	refIsDigest := true

	mDigest, err := common.GetAndValidateRequestDigest(body, reference, is.log)
	if err != nil {
		if errors.Is(err, zerr.ErrBadManifest) {
			return mDigest, "", err
		}

		// Tag query parameters apply only to digest-addressed pushes (?tag= on PUT .../manifests/<digest>).
		// If the path reference is not a digest, extraTags must be empty; otherwise the request is invalid.
		if len(extraTags) > 0 {
			return "", "", zerr.ErrBadManifest
		}

		refIsDigest = false
	}

	err = common.ValidateManifest(is, repo, reference, mediaType, body, is.compat, is.log)
	if err != nil {
		return mDigest, "", err
	}

	index, err := common.GetIndex(is, repo, is.log)
	if err != nil {
		return "", "", err
	}

	// create a new descriptor
	desc := ispec.Descriptor{
		MediaType: mediaType, Size: int64(len(body)), Digest: mDigest,
	}

	if !refIsDigest {
		desc.Annotations = map[string]string{ispec.AnnotationRefName: reference}
	}

	var subjectDigest godigest.Digest

	artifactType := ""

	if mediaType == ispec.MediaTypeImageManifest {
		var manifest ispec.Manifest

		err := json.Unmarshal(body, &manifest)
		if err != nil {
			return "", "", err
		}

		if manifest.Subject != nil {
			subjectDigest = manifest.Subject.Digest
		}

		artifactType = zcommon.GetManifestArtifactType(manifest)
	} else if mediaType == ispec.MediaTypeImageIndex {
		var imgIndex ispec.Index

		err := json.Unmarshal(body, &imgIndex)
		if err != nil {
			return "", "", err
		}

		if imgIndex.Subject != nil {
			subjectDigest = imgIndex.Subject.Digest
		}

		artifactType = zcommon.GetIndexArtifactType(imgIndex)
	}

	// write manifest to "blobs"
	dir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir, mDigest.Algorithm().String())
	manifestPath := path.Join(dir, mDigest.Encoded())

	binfo, err := is.storeDriver.Stat(manifestPath)
	if err != nil || binfo.Size() != desc.Size {
		// The blob isn't already there, or it is corrupted, and needs a correction
		if _, err = is.storeDriver.WriteFile(manifestPath, body); err != nil {
			is.log.Error().Err(err).Str("file", manifestPath).Msg("failed to write")

			return "", "", err
		}
	}

	var (
		lintDesc    ispec.Descriptor
		changedTags []string
	)

	if len(extraTags) > 0 {
		for midx := 0; midx < len(index.Manifests); {
			manifest := index.Manifests[midx]
			_, hasTag := manifest.Annotations[ispec.AnnotationRefName]
			if !hasTag && manifest.Digest.String() == mDigest.String() {
				index.Manifests = append(index.Manifests[:midx], index.Manifests[midx+1:]...)

				continue
			}

			midx++
		}

		anyIndexChange := false

		changedTags = make([]string, 0, len(extraTags))

		var (
			updateIndex bool
			oldDgst     godigest.Digest
		)

		for _, tag := range extraTags {
			descLocal := ispec.Descriptor{
				MediaType: mediaType,
				Size:      desc.Size,
				Digest:    mDigest,
				Annotations: map[string]string{
					ispec.AnnotationRefName: tag,
				},
			}

			updateIndex, oldDgst, err = common.CheckIfIndexNeedsUpdate(&index, &descLocal, is.log)
			if err != nil {
				return "", "", err
			}

			if !updateIndex {
				continue
			}

			anyIndexChange = true

			if err = common.UpdateIndexWithPrunedImageManifests(is, &index, repo, descLocal, oldDgst, is.log); err != nil {
				return "", "", err
			}

			index.Manifests = append(index.Manifests, descLocal)
			changedTags = append(changedTags, tag)
		}

		if !anyIndexChange {
			return mDigest, subjectDigest, nil
		}

		lintDesc = ispec.Descriptor{
			MediaType:    mediaType,
			Size:         desc.Size,
			Digest:       mDigest,
			ArtifactType: artifactType,
			Annotations: map[string]string{
				ispec.AnnotationRefName: changedTags[0],
			},
		}
	} else {
		updateIndex, oldDgst, err := common.CheckIfIndexNeedsUpdate(&index, &desc, is.log)
		if err != nil {
			return "", "", err
		}

		if !updateIndex {
			return mDigest, subjectDigest, nil
		}

		err = common.UpdateIndexWithPrunedImageManifests(is, &index, repo, desc, oldDgst, is.log)
		if err != nil {
			return "", "", err
		}

		// now update "index.json"
		for midx := 0; midx < len(index.Manifests); {
			manifest := index.Manifests[midx]
			_, ok := manifest.Annotations[ispec.AnnotationRefName]
			if !ok && manifest.Digest.String() == desc.Digest.String() {
				// matching descriptor does not have a tag, we need to remove it and add the new descriptor
				index.Manifests = append(index.Manifests[:midx], index.Manifests[midx+1:]...)

				continue
			}

			midx++
		}

		index.Manifests = append(index.Manifests, desc)

		// update the descriptors artifact type in order to check for signatures when applying the linter
		desc.ArtifactType = artifactType

		lintDesc = desc
		changedTags = []string{reference}
	}

	pass, err := common.ApplyLinter(is, is.linter, repo, lintDesc)
	if !pass {
		is.log.Error().Err(err).Str("repository", repo).Str("reference", reference).
			Msg("linter didn't pass")

		if is.events != nil {
			// lint is a property of the manifest, not of the tag(s) it is applied under,
			// so a single event is emitted per manifest regardless of how many tags changed.
			is.events.ImageLintFailed(repo, changedTags[0], mDigest.String(), mediaType, string(body),
				events.EventContextFromContext(ctx))
		}

		return "", "", err
	}

	if err := is.PutIndexContent(repo, index); err != nil {
		return "", "", err
	}

	if is.events != nil {
		evCtx := events.EventContextFromContext(ctx)
		for _, ref := range changedTags {
			is.events.ImageUpdated(repo, ref, mDigest.String(), mediaType, string(body), evCtx)
		}
	}

	return mDigest, subjectDigest, nil
}

// DeleteImageManifest deletes the image manifest from the repository.
func (is *ImageStore) DeleteImageManifest(ctx context.Context, repo, reference string, detectCollisions bool) error {
	dir := path.Join(is.rootDir, repo)
	if fi, err := is.storeDriver.Stat(dir); err != nil || !fi.IsDir() {
		return zerr.ErrRepoNotFound
	}

	return is.WithRepoLock(repo, func() error {
		return is.deleteImageManifest(ctx, repo, reference, detectCollisions)
	})
}

func (is *ImageStore) deleteImageManifest(ctx context.Context, repo, reference string, detectCollisions bool) error {
	defer func() {
		if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
			monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
		}
	}()

	index, err := common.GetIndex(is, repo, is.log)
	if err != nil {
		return err
	}

	manifestDesc, err := common.RemoveManifestDescByReference(&index, reference, detectCollisions)
	if err != nil {
		return err
	}

	/* check if manifest is referenced in image indexes, do not allow index images manipulations
	(ie. remove manifest being part of an image index)	*/
	if zcommon.IsDigest(reference) &&
		(manifestDesc.MediaType == ispec.MediaTypeImageManifest || manifestDesc.MediaType == ispec.MediaTypeImageIndex) {
		for _, mDesc := range index.Manifests {
			if mDesc.MediaType == ispec.MediaTypeImageIndex {
				if ok, _ := common.IsBlobReferencedInImageIndex(is, repo, manifestDesc.Digest, ispec.Index{
					Manifests: []ispec.Descriptor{mDesc},
				}, is.log); ok {
					return zerr.ErrManifestReferenced
				}
			}
		}
	}

	err = common.UpdateIndexWithPrunedImageManifests(is, &index, repo, manifestDesc, manifestDesc.Digest, is.log)
	if err != nil {
		return err
	}

	// now update "index.json"
	dir := path.Join(is.rootDir, repo)
	file := path.Join(dir, ispec.ImageIndexFile)

	buf, err := json.Marshal(index)
	if err != nil {
		return err
	}

	if _, err := is.storeDriver.WriteFile(file, buf); err != nil {
		is.log.Debug().Str("reference", reference).Str("repository", repo).Msg("failed to update index.json")

		return err
	}

	// Delete blob only when blob digest not present in manifest entry.
	// e.g. 1.0.1 & 1.0.2 have same blob digest so if we delete 1.0.1, blob should not be removed.
	toDelete := true

	for _, manifest := range index.Manifests {
		if manifestDesc.Digest.String() == manifest.Digest.String() {
			toDelete = false

			break
		}
	}

	if toDelete {
		p := path.Join(dir, ispec.ImageBlobsDir, manifestDesc.Digest.Algorithm().String(),
			manifestDesc.Digest.Encoded())

		err = is.storeDriver.Delete(p)
		if err != nil {
			return err
		}
	}

	if is.events != nil {
		is.events.ImageDeleted(repo, reference, manifestDesc.Digest.String(), manifestDesc.MediaType,
			events.EventContextFromContext(ctx))
	}

	return nil
}

// BlobUploadPath returns the upload path for a blob in this store.
func (is *ImageStore) BlobUploadPath(repo, uuid string) string {
	dir := path.Join(is.rootDir, repo)
	blobUploadPath := path.Join(dir, storageConstants.BlobUploadDir, uuid)

	return blobUploadPath
}

/*
ListBlobUploads returns all blob uploads present in the repository. The caller function MUST lock from outside.
*/
func (is *ImageStore) ListBlobUploads(repo string) ([]string, error) {
	blobUploadPaths, err := is.storeDriver.List(path.Join(is.RootDir(), repo, storageConstants.BlobUploadDir))
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			// blobs uploads folder does not exist
			return []string{}, nil
		}

		is.log.Debug().Str("repository", repo).Msg("failed to list .uploads/ dir")
	}

	blobUploads := []string{}
	for _, blobUploadPath := range blobUploadPaths {
		blobUploads = append(blobUploads, path.Base(blobUploadPath))
	}

	return blobUploads, err
}

// StatBlobUpload verifies if a blob upload is present inside a repository. The caller function MUST lock from outside.
func (is *ImageStore) StatBlobUpload(repo, uuid string) (bool, int64, time.Time, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	binfo, err := is.storeDriver.Stat(blobUploadPath)
	if err != nil {
		is.log.Error().Err(err).Str("blobUpload", blobUploadPath).Msg("failed to stat blob upload")

		return false, -1, time.Time{}, err
	}

	return true, binfo.Size(), binfo.ModTime(), nil
}

// NewBlobUpload returns the unique ID for an upload in progress.
func (is *ImageStore) NewBlobUpload(ctx context.Context, repo string) (string, error) {
	if err := is.InitRepo(ctx, repo); err != nil {
		is.log.Error().Err(err).Msg("failed to initialize repo")

		return "", err
	}

	uuid, err := guuid.NewV4()
	if err != nil {
		return "", err
	}

	uid := uuid.String()

	blobUploadPath := is.BlobUploadPath(repo, uid)

	// create multipart upload (append false)
	writer, err := is.storeDriver.Writer(blobUploadPath, false)
	if err != nil {
		is.log.Debug().Err(err).Str("blob", blobUploadPath).Msg("failed to start multipart writer")

		return "", zerr.ErrRepoNotFound
	}

	defer writer.Close()

	return uid, nil
}

// GetBlobUpload returns the current size of a blob upload.
func (is *ImageStore) GetBlobUpload(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	if !utf8.ValidString(blobUploadPath) {
		is.log.Error().Msg("invalid UTF-8 input")

		return -1, zerr.ErrInvalidRepositoryName
	}

	writer, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		return -1, err
	}

	defer writer.Close()

	return writer.Size(), nil
}

// PutBlobChunkStreamed appends another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunkStreamed(ctx context.Context, repo, uuid string, body io.Reader) (int64, error) {
	if err := is.InitRepo(ctx, repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	file, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		is.log.Error().Err(err).Msg("failed to continue multipart upload")

		return -1, err
	}

	var n int64 //nolint: varnamelen

	defer func() {
		err = file.Close()
	}()

	n, err = io.Copy(file, body)

	return n, err
}

// PutBlobChunk writes another chunk of data to the specified blob. It returns
// the number of actual bytes to the blob.
func (is *ImageStore) PutBlobChunk(ctx context.Context, repo, uuid string, from, to int64,
	body io.Reader,
) (int64, error) {
	if err := is.InitRepo(ctx, repo); err != nil {
		return -1, err
	}

	blobUploadPath := is.BlobUploadPath(repo, uuid)

	file, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		is.log.Error().Err(err).Msg("failed to continue multipart upload")

		return -1, err
	}

	defer file.Close()

	fsize := file.Size()

	if from != fsize {
		is.log.Error().Int64("expected", from).Int64("actual", file.Size()).
			Msg("invalid range start for blob upload")

		return -1, zerr.ErrBadUploadRange
	}

	n, err := io.Copy(file, body)

	return n + fsize, err
}

// BlobUploadInfo returns the current blob size in bytes.
func (is *ImageStore) BlobUploadInfo(repo, uuid string) (int64, error) {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	writer, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return -1, zerr.ErrUploadNotFound
		}

		return -1, err
	}

	defer writer.Close()

	return writer.Size(), nil
}

// FinishBlobUpload finalizes the blob upload and moves blob the repository.
func (is *ImageStore) FinishBlobUpload(repo, uuid string, body io.Reader, dstDigest godigest.Digest) error {
	if err := dstDigest.Validate(); err != nil {
		return err
	}

	src := is.BlobUploadPath(repo, uuid)

	// complete multiUploadPart
	fileWriter, err := is.storeDriver.Writer(src, true)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return zerr.ErrUploadNotFound
	}

	if err := fileWriter.Commit(context.Background()); err != nil {
		is.log.Error().Err(err).Msg("failed to commit file")

		return err
	}

	if err := fileWriter.Close(); err != nil {
		is.log.Error().Err(err).Msg("failed to close file")

		return err
	}

	srcDigest, err := getBlobDigest(is, src, dstDigest.Algorithm())
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return err
	}

	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return zerr.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir, dstDigest.Algorithm().String())

	err = is.storeDriver.EnsureDir(dir)
	if err != nil {
		is.log.Error().Str("directory", dir).Err(err).Msg("failed to create dir")

		return err
	}

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		// DedupeBlob is still whole-store-locked by its caller until it takes over
		// its own blobstore+repo locking (see the corresponding TODO there).
		var lockLatency time.Time

		is.Lock(&lockLatency)
		defer is.Unlock(&lockLatency)

		err = is.DedupeBlob(src, dstDigest, repo, dst)
		if err := inject.Error(err); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to dedupe blob")

			return err
		}

		return nil
	}

	return is.WithRepoLock(repo, func() error {
		if err := is.storeDriver.Move(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to finish blob")

			return err
		}

		return nil
	})
}

// FullBlobUpload handles a full blob upload, and no partial session is created.
func (is *ImageStore) FullBlobUpload(ctx context.Context, repo string, body io.Reader,
	dstDigest godigest.Digest,
) (string, int64, error) {
	if err := dstDigest.Validate(); err != nil {
		return "", -1, err
	}

	if err := is.InitRepo(ctx, repo); err != nil {
		return "", -1, err
	}

	u, err := guuid.NewV4()
	if err != nil {
		return "", -1, err
	}

	uuid := u.String()
	src := is.BlobUploadPath(repo, uuid)

	dstDigestAlgorithm := dstDigest.Algorithm()

	digester := dstDigestAlgorithm.Hash()

	blobFile, err := is.storeDriver.Writer(src, false)
	if err != nil {
		is.log.Error().Err(err).Str("blob", src).Msg("failed to open blob")

		return "", -1, zerr.ErrUploadNotFound
	}

	mw := io.MultiWriter(blobFile, digester)

	nbytes, err := io.Copy(mw, body)
	if err != nil {
		_ = blobFile.Close()

		is.log.Error().Err(err).Str("blob", src).Msg("failed to write blob")

		return "", -1, err
	}

	if err := blobFile.Commit(context.Background()); err != nil {
		_ = blobFile.Close()

		is.log.Error().Err(err).Str("blob", src).Msg("failed to commit blob")

		return "", -1, err
	}

	// Close explicitly before returning so the subsequent move/rename can succeed on Windows.
	// - Windows does not allow renaming/moving a file while there is any open handle to it.
	// - If we relied on a deferred close, the handle would be released only when the function returns,
	// which would prevent the move/rename operation from succeeding on Windows.
	if err := blobFile.Close(); err != nil {
		is.log.Error().Err(err).Msg("failed to close blob")

		return "", -1, err
	}

	srcDigest := godigest.NewDigestFromEncoded(dstDigestAlgorithm, hex.EncodeToString(digester.Sum(nil)))
	if srcDigest != dstDigest {
		is.log.Error().Str("srcDigest", srcDigest.String()).
			Str("dstDigest", dstDigest.String()).Msg("actual digest not equal to expected digest")

		return "", -1, zerr.ErrBadBlobDigest
	}

	dir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir, dstDigestAlgorithm.String())
	_ = is.storeDriver.EnsureDir(dir)

	dst := is.BlobPath(repo, dstDigest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		// DedupeBlob is still whole-store-locked by its caller until it takes over
		// its own blobstore+repo locking (see the corresponding TODO there).
		var lockLatency time.Time

		is.Lock(&lockLatency)
		defer is.Unlock(&lockLatency)

		if err := is.DedupeBlob(src, dstDigest, repo, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to dedupe blob")

			return "", -1, err
		}

		return uuid, nbytes, nil
	}

	err = is.WithRepoLock(repo, func() error {
		if err := is.storeDriver.Move(src, dst); err != nil {
			is.log.Error().Err(err).Str("src", src).Str("dstDigest", dstDigest.String()).
				Str("dst", dst).Msg("failed to finish blob")

			return err
		}

		return nil
	})
	if err != nil {
		return "", -1, err
	}

	return uuid, nbytes, nil
}

//nolint:gocyclo,cyclop // Dedupe logic handles multiple recovery and cache consistency paths.
func (is *ImageStore) DedupeBlob(src string, dstDigest godigest.Digest, dstRepo string, dst string) error {
	const maxDedupeSelfHealRetries = 16

	var lastRetryErr error

	// Retry loop is intentional: cache records can temporarily point to stale paths
	// during GC/migration windows, and one pass may only partially heal references.
	for range maxDedupeSelfHealRetries {
		is.log.Debug().Str("src", src).Str("dstDigest", dstDigest.String()).Str("dst", dst).Msg("dedupe begin")

		dstRecord, err := is.cache.GetBlob(dstDigest)
		if err := inject.Error(err); err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			is.log.Error().Err(err).Str("blobPath", dst).Str("component", "dedupe").Msg("failed to lookup blob record")

			return err
		}

		if dst == "" {
			return zerr.ErrEmptyValue
		}

		if err := dstDigest.Validate(); err != nil {
			return err
		}

		blobUploadRemoved := false

		if dstRecord == "" {
			// cache record doesn't exist, so first disk and cache entry for this digest
			// store the master copy in the global blobstore
			gdst := is.BlobPath(storageConstants.GlobalBlobsRepo, dstDigest)

			if err := is.putBlobRef(dstDigest, gdst); err != nil {
				is.log.Error().Err(err).Str("blobPath", gdst).Str("component", "dedupe").
					Msg("failed to insert blob record")

				return err
			}

			// move the blob from uploads to global blobstore
			if err := is.storeDriver.Move(src, gdst); err != nil {
				is.log.Error().Err(err).Str("src", src).Str("dst", gdst).Str("component", "dedupe").
					Msg("failed to rename blob")

				return err
			}

			blobUploadRemoved = true

			is.log.Debug().Str("src", src).Str("gdst", gdst).Str("component", "dedupe").Msg("moved to global blobstore")

			// update dstRecord to point to the global blobstore path for the link step below
			dstRecord = gdst
		}

		// cache record exists, but due to GC and upgrades from older versions,
		// disk content and cache records may go out of sync
		if is.cache.UsesRelativePaths() && !path.IsAbs(dstRecord) && !strings.HasPrefix(dstRecord, is.rootDir+"/") {
			dstRecord = path.Join(is.rootDir, dstRecord)
		}

		blobInfo, err := is.storeDriver.Stat(dstRecord)
		if err != nil {
			statErr := err

			is.log.Error().Err(err).Str("blobPath", dstRecord).Str("component", "dedupe").Msg("failed to stat")
			// the actual blob on disk may have been removed by GC, so sync the cache
			err := is.deleteBlobRef(dstDigest, dstRecord)
			if err = inject.Error(err); err != nil {
				//nolint:lll
				is.log.Error().Err(err).Str("dstDigest", dstDigest.String()).Str("dst", dst).
					Str("component", "dedupe").Msg("failed to delete blob record")

				return err
			}

			updatedRecord, err := is.cache.GetBlob(dstDigest)
			if err := inject.Error(err); err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
				is.log.Error().Err(err).Str("blobPath", dst).Str("component", "dedupe").Msg("failed to lookup blob record")

				return err
			}

			if is.cache.UsesRelativePaths() && !path.IsAbs(updatedRecord) && !strings.HasPrefix(updatedRecord, is.rootDir+"/") {
				updatedRecord = path.Join(is.rootDir, updatedRecord)
			}

			if updatedRecord == dstRecord {
				// Some cache drivers keep the current original while duplicates exist.
				// If that original path is missing on disk, aggressively clear all cached
				// paths for this digest so the next retry can promote the incoming blob.
				allRecords, allErr := is.cache.GetAllBlobs(dstDigest)
				if allErr != nil && !errors.Is(allErr, zerr.ErrCacheMiss) {
					return allErr
				}

				normalizedPaths := make([]string, 0, len(allRecords))
				for _, recordPath := range allRecords {
					normalized := recordPath
					if is.cache.UsesRelativePaths() && !path.IsAbs(normalized) &&
						!strings.HasPrefix(normalized, is.rootDir+"/") {
						normalized = path.Join(is.rootDir, normalized)
					}

					normalizedPaths = append(normalizedPaths, normalized)
				}

				// Delete non-stale entries first, then stale original path last.
				// Some cache drivers keep the original while duplicates exist.
				for _, normalized := range normalizedPaths {
					if normalized == dstRecord {
						continue
					}

					if delErr := is.deleteBlobRef(dstDigest, normalized); delErr != nil && !errors.Is(delErr, zerr.ErrCacheMiss) {
						return delErr
					}
				}

				if delErr := is.deleteBlobRef(dstDigest, dstRecord); delErr != nil && !errors.Is(delErr, zerr.ErrCacheMiss) {
					return delErr
				}

				updatedRecord, err = is.cache.GetBlob(dstDigest)
				if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
					return err
				}

				if is.cache.UsesRelativePaths() && !path.IsAbs(updatedRecord) &&
					!strings.HasPrefix(updatedRecord, is.rootDir+"/") {
					updatedRecord = path.Join(is.rootDir, updatedRecord)
				}

				if updatedRecord == dstRecord {
					return statErr
				}
			}

			lastRetryErr = statErr

			continue
		}

		// Normal dedupe path: link destination to the resolved original blob and add ref.
		if !is.storeDriver.SameFile(dst, dstRecord) {
			if err := is.lifecycle.LinkBlob(dstRecord, dst); err != nil {
				is.log.Error().Err(err).Str("blobPath", dstRecord).Str("component", "dedupe").
					Msg("failed to link blobs")

				return err
			}

			if err := is.putBlobRef(dstDigest, dst); err != nil {
				is.log.Error().Err(err).Str("blobPath", dst).Str("component", "dedupe").
					Msg("failed to insert blob record")

				return err
			}
		} else {
			// SameFile means destination already maps to this digest path. In that case,
			// only rewrite content when descriptor size proves the stored blob is corrupted.
			if desc, err := common.GetBlobDescriptorFromRepo(is, dstRepo, dstDigest, is.log); err == nil {
				// blob corrupted, replace content
				if desc.Size != blobInfo.Size() {
					if err := is.storeDriver.Move(src, dst); err != nil {
						is.log.Error().Err(err).Str("src", src).Str("dst", dst).Str("component", "dedupe").
							Msg("failed to rename blob")

						return err
					}

					is.log.Debug().Str("src", src).Str("component", "dedupe").Msg("remove")

					return nil
				}
			}
		}

		if !blobUploadRemoved {
			// remove temp blobupload
			if err := is.storeDriver.Delete(src); err != nil {
				is.log.Error().Err(err).Str("src", src).Str("component", "dedupe").
					Msg("failed to remove blob")

				return err
			}
		}

		is.log.Debug().Str("src", src).Str("component", "dedupe").Msg("remove")

		return nil
	}

	if lastRetryErr == nil {
		lastRetryErr = zerr.ErrBlobNotFound
	}

	is.log.Error().Err(lastRetryErr).Str("dstDigest", dstDigest.String()).Str("dst", dst).
		Int("maxRetries", maxDedupeSelfHealRetries).Str("component", "dedupe").
		Msg("dedupe retry limit exceeded while healing stale cache records")

	return lastRetryErr
}

// DeleteBlobUpload deletes an existing blob upload that is currently in progress.
func (is *ImageStore) DeleteBlobUpload(repo, uuid string) error {
	blobUploadPath := is.BlobUploadPath(repo, uuid)

	writer, err := is.storeDriver.Writer(blobUploadPath, true)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return zerr.ErrUploadNotFound
		}

		return err
	}

	defer writer.Close()

	if err := writer.Cancel(context.Background()); err != nil {
		is.log.Error().Err(err).Str("blobUploadPath", blobUploadPath).Msg("failed to delete blob upload")

		return err
	}

	return nil
}

// BlobPath returns the repository path of a blob.
func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
	return path.Join(is.rootDir, repo, ispec.ImageBlobsDir, digest.Algorithm().String(), digest.Encoded())
}

// GetAllDedupeReposCandidates does not take a lock: it only reads the dedupe cache
// (blobRefsForDigest), which has its own internal synchronization (BoltDB
// transactions, DynamoDB conditional writes, Redis distributed mutexes) and never
// touches per-repo filesystem state directly.
func (is *ImageStore) GetAllDedupeReposCandidates(digest godigest.Digest) ([]string, error) {
	if err := digest.Validate(); err != nil {
		return nil, err
	}

	if is.cache == nil {
		return nil, nil //nolint:nilnil
	}

	blobsPaths, err := is.blobRefsForDigest(digest)
	if err != nil {
		// A cache miss means the digest is not present in the cache yet, so there
		// are simply no dedupe/mount candidates for it — that is the normal case
		// for a not-yet-cached blob, not a failure. Treat it like the nil-cache
		// case above and return no candidates rather than propagating the error
		// (which callers log as an "unexpected error", spamming the logs on every
		// fresh blob during pushes/cross-repo mount checks).
		if errors.Is(err, zerr.ErrCacheMiss) {
			return nil, nil //nolint:nilnil
		}

		return nil, err
	}

	repos := []string{}
	rootDirSlash := filepath.ToSlash(is.rootDir)

	for _, blobPath := range blobsPaths {
		// Cache entries may be absolute or relative, and format can vary across restarts.
		// Normalize to a repo-relative slash path before extracting repo candidates.
		if filepath.IsAbs(blobPath) {
			relPath, relErr := filepath.Rel(is.rootDir, blobPath)
			if relErr == nil {
				blobPath = relPath
			}
		}

		blobPath = filepath.ToSlash(blobPath)
		blobPath = strings.TrimPrefix(blobPath, "./")

		if normalizedPath, ok := strings.CutPrefix(blobPath, rootDirSlash+"/"); ok {
			blobPath = normalizedPath
		}

		blobsDirIndex := strings.LastIndex(blobPath, "/blobs/")
		if blobsDirIndex <= 0 {
			continue
		}

		repo := strings.TrimPrefix(blobPath[:blobsDirIndex], "/")
		if repo == "" {
			continue
		}

		if !is.lifecycle.IncludeRepoInMountCandidates(repo) {
			continue
		}

		repos = append(repos, repo)
	}

	return repos, nil
}

// CheckBlob verifies a blob and returns true if the blob is correct.
// If the blob is not found but it's found in cache then it will be copied over.
func (is *ImageStore) CheckBlob(ctx context.Context, repo string, digest godigest.Digest) (bool, int64, error) {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return false, -1, err
	}

	blobPath := is.BlobPath(repo, digest)

	if is.dedupe && fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		// Dedupe mode can update cache refs (self-heal), so use write lock.
		is.Lock(&lockLatency)
		defer is.Unlock(&lockLatency)
	} else {
		// Non-dedupe read path only validates/reads blob state.
		is.RLock(&lockLatency)
		defer is.RUnlock(&lockLatency)
	}

	binfo, err := is.storeDriver.Stat(blobPath)
	if err != nil {
		dstRecord, err := is.checkCacheBlob(digest)
		if err != nil {
			if errors.Is(err, zerr.ErrCacheMiss) || errors.Is(err, zerr.ErrBlobNotFound) {
				is.log.Debug().Err(err).Str("digest", digest.String()).Msg("cache miss for blob")
			} else {
				is.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to lookup blob in cache")
			}

			return false, -1, zerr.ErrBlobNotFound
		}

		blobSize, err := is.copyBlob(ctx, repo, blobPath, dstRecord)
		if err != nil {
			return false, -1, zerr.ErrBlobNotFound
		}

		// put deduped blob in cache
		if err := is.putBlobRef(digest, blobPath); err != nil {
			is.log.Error().Err(err).Str("blobPath", blobPath).Str("component", "dedupe").Msg("failed to insert blob record")

			return false, -1, err
		}

		return true, blobSize, nil
	}

	globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)
	resolvedPath, err := is.lifecycle.ResolveReadPath(blobPath, globalBlobPath, digest, binfo.Size(), is.checkCacheBlob)
	if err != nil {
		// Cache miss / not-found is a normal condition when the blob truly doesn't exist.
		if errors.Is(err, zerr.ErrCacheMiss) || errors.Is(err, zerr.ErrBlobNotFound) {
			is.log.Debug().Err(err).Str("digest", digest.String()).Msg("cache miss for blob")
		} else {
			is.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to lookup blob in cache")
		}

		return false, -1, zerr.ErrBlobNotFound
	}

	if resolvedPath == blobPath {
		// When lifecycle resolves to repo path itself, validate against descriptor size
		// to catch marker/corrupted blobs that still physically exist at that path.
		desc, err := common.GetBlobDescriptorFromRepo(is, repo, digest, is.log)
		if err != nil || desc.Size == binfo.Size() {
			// blob not found in descriptors, can not compare, just return
			is.log.Debug().Str("blob path", blobPath).Msg("blob path found")

			return true, binfo.Size(), nil //nolint: nilerr
		}

		if desc.Size != binfo.Size() {
			is.log.Debug().Str("blob path", blobPath).Msg("blob path found, but it's corrupted")

			return false, -1, zerr.ErrBlobNotFound
		}
	}

	blobSize, err := is.copyBlob(ctx, repo, blobPath, resolvedPath)
	if err != nil {
		return false, -1, zerr.ErrBlobNotFound
	}

	// put deduped blob in cache
	if err := is.putBlobRef(digest, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Str("component", "dedupe").Msg("failed to insert blob record")

		return false, -1, err
	}

	return true, blobSize, nil
}

// StatBlob verifies if a blob is present inside a repository. The caller function MUST lock from outside.
func (is *ImageStore) StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	if err := digest.Validate(); err != nil {
		return false, -1, time.Time{}, err
	}

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return false, -1, time.Time{}, err
	}

	return true, binfo.Size(), binfo.ModTime(), nil
}

func (is *ImageStore) checkCacheBlob(digest godigest.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", err
	}

	if fmt.Sprintf("%v", is.cache) == fmt.Sprintf("%v", nil) {
		return "", zerr.ErrBlobNotFound
	}

	dstRecord, err := is.cache.GetBlob(digest)
	if err != nil {
		return "", err
	}

	if is.cache.UsesRelativePaths() && !path.IsAbs(dstRecord) && !strings.HasPrefix(dstRecord, is.rootDir+"/") {
		dstRecord = path.Join(is.rootDir, dstRecord)
	}

	if _, err := is.storeDriver.Stat(dstRecord); err != nil {
		is.log.Error().Err(err).Str("blob", dstRecord).Msg("failed to stat blob")

		// the actual blob on disk may have been removed by GC, so sync the blob refs
		if err := is.deleteBlobRef(digest, dstRecord); err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", dstRecord).
				Msg("failed to remove blob path from blob refs")

			return "", err
		}

		return "", zerr.ErrBlobNotFound
	}

	is.log.Debug().Str("digest", digest.String()).Str("dstRecord", dstRecord).Str("component", "cache").
		Msg("found dedupe record")

	return dstRecord, nil
}

func (is *ImageStore) copyBlob(ctx context.Context, repo string, blobPath, dstRecord string) (int64, error) {
	if err := is.initRepo(ctx, repo); err != nil {
		is.log.Error().Err(err).Str("repository", repo).Msg("failed to initialize an empty repo")

		return -1, err
	}

	_ = is.storeDriver.EnsureDir(filepath.Dir(blobPath))

	if err := is.lifecycle.LinkBlob(dstRecord, blobPath); err != nil {
		is.log.Error().Err(err).Str("blobPath", blobPath).Str("link", dstRecord).Str("component", "dedupe").
			Msg("failed to hard link")

		return -1, zerr.ErrBlobNotFound
	}

	// return original blob with content instead of the deduped one (blobPath)
	binfo, err := is.storeDriver.Stat(dstRecord)
	if err == nil {
		return binfo.Size(), nil
	}

	return -1, zerr.ErrBlobNotFound
}

// GetBlobPartial returns a partial stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ImageStore) GetBlobPartial(repo string, digest godigest.Digest, mediaType string, from, to int64,
) (io.ReadCloser, int64, int64, error) {
	if err := digest.Validate(); err != nil {
		return nil, -1, -1, err
	}

	var (
		blobReadCloser io.ReadCloser
		contentLength  int64
		totalSize      int64
	)

	err := is.WithRepoReadLock(repo, func() error {
		binfo, err := is.originalBlobInfo(repo, digest)
		if err != nil {
			return err
		}

		end := to

		if to < 0 || to >= binfo.Size() {
			end = binfo.Size() - 1
		}

		blobHandle, err := is.storeDriver.Reader(binfo.Path(), from)
		if err != nil {
			is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob")

			return err
		}

		stream, err := newBlobStream(blobHandle, from, end)
		if err != nil {
			is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob stream")

			return err
		}

		blobReadCloser = stream
		contentLength = end - from + 1
		totalSize = binfo.Size()

		return nil
	})
	if err != nil {
		return nil, -1, -1, err
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, contentLength, totalSize, nil
}

/*
	In the case of s3(which doesn't support links) we link them in our cache by
	keeping a reference to the original blob and its duplicates

On the storage, original blobs are those with contents, and duplicates one are just empty files.
This function helps handling this situation, by using this one you can make sure you always get the original blob.
*/
func (is *ImageStore) originalBlobInfo(repo string, digest godigest.Digest) (driver.FileInfo, error) {
	blobPath := is.BlobPath(repo, digest)

	binfo, err := is.storeDriver.Stat(blobPath)
	if err != nil {
		var pathNotFoundErr driver.PathNotFoundError

		if errors.As(err, &pathNotFoundErr) {
			is.log.Debug().Err(err).Str("blob", blobPath).Str("digest", digest.String()).Msg("blob not found")
		} else {
			is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")
		}

		return nil, zerr.ErrBlobNotFound
	}

	globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)
	resolvedPath, err := is.lifecycle.ResolveReadPath(blobPath, globalBlobPath, digest, binfo.Size(), is.checkCacheBlob)
	if err != nil {
		is.log.Debug().Err(err).Str("digest", digest.String()).Msg("not found in cache")

		return nil, zerr.ErrBlobNotFound
	}

	if resolvedPath != blobPath {
		binfo, err = is.storeDriver.Stat(resolvedPath)
		if err != nil {
			is.log.Error().Err(err).Str("blob", resolvedPath).Msg("failed to stat blob")

			return nil, zerr.ErrBlobNotFound
		}
	}

	return binfo, nil
}

// GetBlob returns a stream to read the blob.
// blob selector instead of directly downloading the blob.
func (is *ImageStore) GetBlob(repo string, digest godigest.Digest, mediaType string) (io.ReadCloser, int64, error) {
	if err := digest.Validate(); err != nil {
		return nil, -1, err
	}

	var (
		blobReadCloser io.ReadCloser
		size           int64
	)

	err := is.WithRepoReadLock(repo, func() error {
		binfo, err := is.originalBlobInfo(repo, digest)
		if err != nil {
			return err
		}

		reader, err := is.storeDriver.Reader(binfo.Path(), 0)
		if err != nil {
			is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob")

			return err
		}

		blobReadCloser = reader
		size = binfo.Size()

		return nil
	})
	if err != nil {
		return nil, -1, err
	}

	// The caller function is responsible for calling Close()
	return blobReadCloser, size, nil
}

func (is *ImageStore) GetBlobRedirectURL(r *http.Request, repo string, digest godigest.Digest) (string, error) {
	if err := digest.Validate(); err != nil {
		return "", zerr.ErrBadBlobDigest
	}

	// Local storage has no external signed URL endpoint; proxy path is expected.
	if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
		return "", nil
	}

	var redirectURL string

	err := is.WithRepoReadLock(repo, func() error {
		binfo, err := is.originalBlobInfo(repo, digest)
		if err != nil {
			return err
		}

		redirectURL, err = is.storeDriver.RedirectURL(r, binfo.Path())

		return err
	})

	return redirectURL, err
}

// GetBlobContent returns blob contents, the caller function MUST lock from outside.
// Should be used for small files(manifests/config blobs).
func (is *ImageStore) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	if err := digest.Validate(); err != nil {
		return []byte{}, err
	}

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return nil, err
	}

	blobBuf, err := is.storeDriver.ReadFile(binfo.Path())
	if err != nil {
		is.log.Error().Err(err).Str("blob", binfo.Path()).Msg("failed to open blob")

		return nil, err
	}

	return blobBuf, nil
}

// VerifyBlobDigestValue verifies that the blob which is addressed by given digest has a equivalent computed digest.
func (is *ImageStore) VerifyBlobDigestValue(repo string, digest godigest.Digest) error {
	if err := digest.Validate(); err != nil {
		return err
	}

	binfo, err := is.originalBlobInfo(repo, digest)
	if err != nil {
		return err
	}

	blobReadCloser, err := is.storeDriver.Reader(binfo.Path(), 0)
	if err != nil {
		return err
	}

	defer blobReadCloser.Close()

	// compute its real digest
	computedDigest, err := godigest.FromReader(blobReadCloser)
	if err != nil {
		return err
	}

	// if the computed digest is different than the blob name(its initial digest) then the blob has been corrupted.
	if computedDigest != digest {
		return zerr.ErrBadBlobDigest
	}

	return nil
}

func (is *ImageStore) GetReferrers(repo string, gdigest godigest.Digest, artifactTypes []string,
) (ispec.Index, error) {
	var index ispec.Index

	err := is.WithRepoReadLock(repo, func() error {
		var err error

		index, err = common.GetReferrers(is, repo, gdigest, artifactTypes, is.log)

		return err
	})

	return index, err
}

// GetIndexContent returns index.json contents, the caller function MUST lock from outside.
func (is *ImageStore) GetIndexContent(repo string) ([]byte, error) {
	dir := path.Join(is.rootDir, repo)

	buf, err := is.storeDriver.ReadFile(path.Join(dir, ispec.ImageIndexFile))
	if err != nil {
		if errors.Is(err, driver.PathNotFoundError{}) {
			is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

			return []byte{}, zerr.ErrRepoNotFound
		}

		is.log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")

		return []byte{}, err
	}

	return buf, nil
}

func (is *ImageStore) StatIndex(repo string) (bool, int64, time.Time, error) {
	repoIndexPath := path.Join(is.rootDir, repo, ispec.ImageIndexFile)

	fileInfo, err := is.storeDriver.Stat(repoIndexPath)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Error().Err(err).Str("indexFile", repoIndexPath).Msg("failed to stat index.json")

			return false, 0, time.Time{}, zerr.ErrRepoNotFound
		}

		is.log.Error().Err(err).Str("indexFile", repoIndexPath).Msg("failed to read index.json")

		return false, 0, time.Time{}, err
	}

	return true, fileInfo.Size(), fileInfo.ModTime(), nil
}

func (is *ImageStore) PutIndexContent(repo string, index ispec.Index) error {
	dir := path.Join(is.rootDir, repo)

	indexPath := path.Join(dir, ispec.ImageIndexFile)

	buf, err := json.Marshal(index)
	if err != nil {
		is.log.Error().Err(err).Str("file", indexPath).Msg("failed to marshal JSON")

		return err
	}

	// Write to a unique file under .uploads (same layout as blob uploads), then rename into place.
	// Stale files are picked up by the same blob-upload GC path as ordinary uploads.
	// This avoids truncating/removing index.json on failure (e.g. ENOSPC) — see local Driver.WriteFile + Cancel.
	stagingUUID, err := guuid.NewV4()
	if err != nil {
		is.log.Error().Err(err).Str("repository", repo).Msg("failed to generate staging UUID")

		return err
	}

	stagingID := stagingUUID.String()
	tmpPath := is.BlobUploadPath(repo, stagingID)

	if _, err = is.storeDriver.WriteFile(tmpPath, buf); err != nil {
		is.log.Error().Err(err).Str("file", tmpPath).Msg("failed to write staging index")

		_ = is.storeDriver.Delete(tmpPath)

		return err
	}

	if err := is.storeDriver.Move(tmpPath, indexPath); err != nil {
		is.log.Error().Err(err).Str("from", tmpPath).Str("to", indexPath).Msg("failed to replace index.json")

		_ = is.storeDriver.Delete(tmpPath)

		return err
	}

	return nil
}

// DeleteBlob removes the blob from the repository.
func (is *ImageStore) DeleteBlob(repo string, digest godigest.Digest) error {
	var lockLatency time.Time

	if err := digest.Validate(); err != nil {
		return err
	}

	is.Lock(&lockLatency)
	defer is.Unlock(&lockLatency)

	return is.deleteBlob(repo, digest)
}

/*
CleanupRepo removes blobs from the repository and removes repo if flag is true and all blobs were removed
the caller function MUST lock from outside.
*/
func (is *ImageStore) CleanupRepo(repo string, blobs []godigest.Digest, removeRepo bool) (int, error) {
	count := 0

	for _, digest := range blobs {
		is.log.Debug().Str("repository", repo).
			Str("digest", digest.String()).Msg("perform GC on blob")

		err := is.deleteBlob(repo, digest)
		if err == nil {
			count++

			continue
		}

		switch {
		case errors.Is(err, zerr.ErrBlobReferenced):
			if err := is.deleteImageManifest(context.Background(), repo, digest.String(), true); err != nil {
				if errors.Is(err, zerr.ErrManifestConflict) || errors.Is(err, zerr.ErrManifestReferenced) {
					continue
				}

				is.log.Error().Err(err).Str("repository", repo).Str("digest", digest.String()).Msg("failed to delete manifest")

				return count, err
			}

			count++
		case errors.Is(err, zerr.ErrBlobNotFound):
			is.log.Info().Str("repository", repo).Str("digest", digest.String()).
				Msg("blob already absent during GC, skipping")

			count++
		default:
			is.log.Error().Err(err).Str("repository", repo).Str("digest", digest.String()).Msg("failed to delete blob")

			return count, err
		}
	}

	blobUploads, _ := is.ListBlobUploads(repo)

	// if removeRepo flag is true and we cleanup all blobs and there are no blobs currently being uploaded.
	if removeRepo && count == len(blobs) && count > 0 && len(blobUploads) == 0 &&
		repo != storageConstants.GlobalBlobsRepo {
		is.log.Info().Str("repository", repo).Msg("removed all blobs, removing repo")

		if err := is.storeDriver.Delete(path.Join(is.rootDir, repo)); err != nil {
			is.log.Error().Err(err).Str("repository", repo).Msg("failed to remove repo")

			return count, err
		}
	}

	// finally update metrics
	if is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
		monitoring.SetStorageUsage(is.metrics, is.rootDir, repo)
	}

	return count, nil
}

func (is *ImageStore) deleteBlob(repo string, digest godigest.Digest) error {
	blobPath := is.BlobPath(repo, digest)

	binfo, err := is.storeDriver.Stat(blobPath)
	if err != nil {
		var pathNotFoundErr driver.PathNotFoundError
		if errors.As(err, &pathNotFoundErr) {
			return zerr.ErrBlobNotFound
		}

		is.log.Error().Err(err).Str("blob", blobPath).Msg("failed to stat blob")

		return err
	}

	// first check if this blob is not currently in use
	if ok, _ := common.IsBlobReferenced(is, repo, digest, is.log); ok {
		return zerr.ErrBlobReferenced
	}

	if fmt.Sprintf("%v", is.cache) != fmt.Sprintf("%v", nil) {
		dstRecord, err := is.cache.GetBlob(digest)
		if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("component", "dedupe").
				Msg("failed to lookup blob record")

			return err
		}

		// remove this repo's blob path from cache (cache may store relative paths)
		if err := is.deleteBlobRef(digest, blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", blobPath).
				Msg("failed to remove blob path from cache")

			return err
		}

		// Cache miss: with dedupe on remote storage this blob may be the only
		// content copy backing zero-size duplicates elsewhere.
		// Defer until the startup walk has rebuilt the cache; GC retries later.
		if dstRecord == "" && binfo.Size() > 0 && is.lifecycle.ShouldGateDeleteUntilRebuild() &&
			!is.dedupeRebuildDone.Load() {
			is.log.Warn().Str("digest", digest.String()).Str("blobPath", blobPath).Str("component", "dedupe").
				Msg("no cache record for content blob while dedupe rebuild is still running, deferring delete")

			return zerr.ErrDedupeRebuildInProgress
		}

		// delete the repo-specific blob file (hard link)
		if err := is.storeDriver.Delete(blobPath); err != nil {
			is.log.Error().Err(err).Str("blobPath", blobPath).Msg("failed to remove blob path")

			return err
		}

		globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)
		canDeleteGlobalBlob, err := is.lifecycle.ShouldDeleteGlobalBlob(globalBlobPath,
			digest, is.isDigestReferencedAcrossRepos)
		if err != nil {
			is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", globalBlobPath).
				Msg("failed to evaluate global blob reclaim decision")

			return err
		}

		if canDeleteGlobalBlob {
			if err := is.deleteBlobRef(digest, globalBlobPath); err != nil {
				is.log.Error().Err(err).Str("digest", digest.String()).Str("blobPath", globalBlobPath).
					Msg("failed to remove global blob path from cache")

				return err
			}

			if err := is.storeDriver.Delete(globalBlobPath); err != nil {
				var pathNotFoundErr driver.PathNotFoundError
				if !errors.As(err, &pathNotFoundErr) {
					is.log.Debug().Err(err).Str("blobPath", globalBlobPath).
						Msg("failed to remove global blob")

					return err
				}

				is.log.Debug().Str("blobPath", globalBlobPath).
					Msg("global blob already removed from storage, skipping")
			}
		}

		return nil
	}

	// No cache (dedupe off): leftover placeholders are refilled by the restore
	// walk; until it completes this blob may be their only content copy.
	if fmt.Sprintf("%v", is.cache) == fmt.Sprintf("%v", nil) && binfo.Size() > 0 &&
		is.lifecycle.ShouldGateDeleteUntilRebuild() && !is.dedupeRebuildDone.Load() {
		is.log.Warn().Str("digest", digest.String()).Str("blobPath", blobPath).Str("component", "dedupe").
			Msg("content blob delete requested before dedupe restore walk finished, deferring delete")

		return zerr.ErrDedupeRebuildInProgress
	}

	if err := is.storeDriver.Delete(blobPath); err != nil {
		var pathNotFoundErr driver.PathNotFoundError
		if errors.As(err, &pathNotFoundErr) {
			is.log.Warn().Str("repository", repo).Str("digest", digest.String()).
				Str("blobPath", blobPath).Msg("blob already removed from storage, skipping")

			return nil
		}

		is.log.Error().Err(err).Str("blobPath", blobPath).Msg("failed to remove blob path")

		return err
	}

	return nil
}

func getBlobDigest(imgStore *ImageStore, path string, digestAlgorithm godigest.Algorithm,
) (godigest.Digest, error) {
	fileReader, err := imgStore.storeDriver.Reader(path, 0)
	if err != nil {
		return "", zerr.ErrUploadNotFound
	}

	defer fileReader.Close()

	digest, err := digestAlgorithm.FromReader(fileReader)
	if err != nil {
		return "", zerr.ErrBadBlobDigest
	}

	return digest, nil
}

func (is *ImageStore) GetAllBlobs(repo string) ([]godigest.Digest, error) {
	blobsDir := path.Join(is.rootDir, repo, ispec.ImageBlobsDir)

	ret := []godigest.Digest{}

	algorithmPaths, err := is.storeDriver.List(blobsDir)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			is.log.Debug().Str("directory", blobsDir).Msg("empty blobs directory")

			return ret, nil
		}

		return ret, err
	}

	for _, algorithmPath := range algorithmPaths {
		algorithm := godigest.Algorithm(path.Base(algorithmPath))

		if !algorithm.Available() {
			continue
		}

		digestPaths, err := is.storeDriver.List(algorithmPath)
		if err != nil {
			// algorithmPath was obtained by looking up under the blobs directory
			// we are sure it already exists, so PathNotFoundError does not need to be checked
			return []godigest.Digest{}, err
		}

		for _, file := range digestPaths {
			digest := godigest.NewDigestFromEncoded(algorithm, filepath.Base(file))
			ret = append(ret, digest)
		}
	}

	if len(ret) == 0 {
		is.log.Debug().Str("directory", blobsDir).Msg("empty blobs directory")
	}

	return ret, nil
}

// GetNextDigestWithBlobPaths does not take a lock - see GetNextRepositories' doc
// comment; this is the same kind of whole-tree read-only Walk.
func (is *ImageStore) GetNextDigestWithBlobPaths(repos []string, lastDigests []godigest.Digest,
) (godigest.Digest, []string, error) {
	dir := is.rootDir

	var duplicateBlobs []string

	var digest godigest.Digest

	err := is.storeDriver.Walk(dir, func(fileInfo driver.FileInfo) error {
		// skip blobs under .sync and .uploads
		if strings.HasSuffix(fileInfo.Path(), syncConstants.SyncBlobUploadDir) ||
			strings.HasSuffix(fileInfo.Path(), storageConstants.BlobUploadDir) {
			return driver.ErrSkipDir
		}

		if fileInfo.IsDir() {
			// skip repositories not found in repos
			baseName := path.Base(fileInfo.Path())
			if slices.Contains(repos, baseName) || baseName == ispec.ImageBlobsDir {
				return nil
			}

			candidateAlgorithm := godigest.Algorithm(baseName)

			if !candidateAlgorithm.Available() {
				return driver.ErrSkipDir
			}

			return nil
		}

		baseName := path.Base(fileInfo.Path())

		skippedFiles := []string{ispec.ImageLayoutFile, ispec.ImageIndexFile, "meta.db", "cache.db"}
		if slices.Contains(skippedFiles, baseName) {
			return nil
		}

		// Verify path structure follows standard OCI: rootDir/repo/blobs/algorithm/digest
		parentDir := path.Clean(path.Dir(fileInfo.Path()))
		grandparentDir := path.Clean(path.Dir(parentDir))

		// Require grandparent directory to be ImageBlobsDir (standard OCI structure)
		if path.Base(grandparentDir) != ispec.ImageBlobsDir {
			return nil
		}

		// Verify parent directory is a valid digest algorithm (e.g., sha256, sha512)
		digestAlgorithm := godigest.Algorithm(path.Base(parentDir))
		if !digestAlgorithm.Available() {
			return nil
		}

		digestHash := baseName

		blobDigest := godigest.NewDigestFromEncoded(digestAlgorithm, digestHash)
		if err := blobDigest.Validate(); err != nil { //nolint: nilerr
			is.log.Debug().Str("path", fileInfo.Path()).Str("digestHash", digestHash).
				Str("digestAlgorithm", digestAlgorithm.String()).
				Msg("digest validation failed when walking blob paths")

			return nil //nolint: nilerr // ignore files which are not blobs
		}

		if digest == "" && !slices.Contains(lastDigests, blobDigest) {
			digest = blobDigest
		}

		if blobDigest == digest {
			duplicateBlobs = append(duplicateBlobs, fileInfo.Path())
		}

		return nil
	})

	// if the root directory is not yet created
	var perr driver.PathNotFoundError

	if errors.As(err, &perr) {
		return digest, duplicateBlobs, nil
	}

	return digest, duplicateBlobs, err
}

func (is *ImageStore) getOriginalBlobFromDisk(duplicateBlobs []string) (string, error) {
	for _, blobPath := range duplicateBlobs {
		binfo, err := is.storeDriver.Stat(blobPath)
		if err != nil {
			is.log.Error().Err(err).Str("path", blobPath).Str("component", "storage").Msg("failed to stat blob")

			return "", zerr.ErrBlobNotFound
		}

		if binfo.Size() > 0 {
			return blobPath, nil
		}
	}

	return "", zerr.ErrBlobNotFound
}

// getOriginalBlobFromGlobalBlobstore is the last-resort fallback for getOriginalBlob: under the
// global-blobstore scheme every per-repo copy for a digest is normally a zero-byte marker, with
// the real content living only under GlobalBlobsRepo. If the cache is stale/rebuilt and
// getOriginalBlobFromDisk finds nothing (all markers), the content can still be there. Resolve it
// through the same blobLifecycle seam GetBlob/GetBlobPartial reads use, instead of the disk-scan's
// own size>0 convention, so restore/rebuild agrees with the read path on what counts as real.
func (is *ImageStore) getOriginalBlobFromGlobalBlobstore(digest godigest.Digest) (string, error) {
	globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)

	resolvedPath, err := is.lifecycle.ResolveReadPath(globalBlobPath, globalBlobPath, digest, 0, is.checkCacheBlob)
	if err != nil {
		return "", zerr.ErrBlobNotFound
	}

	binfo, err := is.storeDriver.Stat(resolvedPath)
	if err != nil || binfo.Size() == 0 {
		return "", zerr.ErrBlobNotFound
	}

	return resolvedPath, nil
}

func (is *ImageStore) getOriginalBlob(digest godigest.Digest, duplicateBlobs []string) (string, error) {
	var originalBlob string

	var err error

	originalBlob, err = is.checkCacheBlob(digest)
	if err != nil && !errors.Is(err, zerr.ErrBlobNotFound) && !errors.Is(err, zerr.ErrCacheMiss) {
		is.log.Error().Err(err).Str("component", "dedupe").Msg("failed to find blob in cache")

		return originalBlob, err
	}

	// if we still don't have, search it
	if originalBlob == "" {
		is.log.Warn().Str("component", "dedupe").Msg("failed to find blob in cache, searching it in storage...")
		// a rebuild dedupe was attempted in the past
		// get original blob, should be found otherwise exit with error

		originalBlob, err = is.getOriginalBlobFromDisk(duplicateBlobs)
		if err != nil {
			originalBlob, err = is.getOriginalBlobFromGlobalBlobstore(digest)
			if err != nil {
				return "", err
			}
		}
	}

	is.log.Info().Str("originalBlob", originalBlob).Str("component", "dedupe").Msg("found original blob")

	return originalBlob, nil
}

func (is *ImageStore) dedupeBlobs(ctx context.Context, digest godigest.Digest, duplicateBlobs []string) error {
	if fmt.Sprintf("%v", is.cache) == fmt.Sprintf("%v", nil) {
		is.log.Error().Err(zerr.ErrDedupeRebuild).Msg("failed to dedupe blobs, no cache driver found")

		return zerr.ErrDedupeRebuild
	}

	is.log.Info().Str("digest", digest.String()).Str("component", "dedupe").Msg("deduping blobs for digest")

	var originalBlob string

	// rebuild from dedupe false to true
	for _, blobPath := range duplicateBlobs {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		binfo, err := is.storeDriver.Stat(blobPath)
		if err != nil {
			is.log.Error().Err(err).Str("path", blobPath).Str("component", "dedupe").Msg("failed to stat blob")

			return err
		}

		if binfo.Size() == 0 {
			is.log.Warn().Str("component", "dedupe").Msg("found file without content, trying to find the original blob")
			// a rebuild dedupe was attempted in the past
			// get original blob, should be found otherwise exit with error
			if originalBlob == "" {
				originalBlob, err = is.getOriginalBlob(digest, duplicateBlobs)
				if err != nil {
					is.log.Error().Err(err).Str("component", "dedupe").Msg("failed to find original blob")

					return zerr.ErrDedupeRebuild
				}

				// cache original blob
				if _, err := is.cache.GetBlob(digest); err != nil {
					if err := is.putBlobRef(digest, originalBlob); err != nil {
						return err
					}
				}
			}

			// cache dedupe blob
			if ok := is.cache.HasBlob(digest, blobPath); !ok {
				if err := is.putBlobRef(digest, blobPath); err != nil {
					return err
				}
			}
		} else {
			// if we have an original blob cached then we can safely dedupe the rest of them
			if originalBlob != "" {
				if err := is.lifecycle.LinkBlob(originalBlob, blobPath); err != nil {
					is.log.Error().Err(err).Str("path", blobPath).Str("component", "dedupe").Msg("failed to dedupe blob")

					return err
				}
			}

			// cache it
			if ok := is.cache.HasBlob(digest, blobPath); !ok {
				if err := is.putBlobRef(digest, blobPath); err != nil {
					return err
				}
			}

			// mark blob as preserved
			originalBlob = blobPath
		}
	}

	is.log.Info().Str("digest", digest.String()).Str("component", "dedupe").
		Msg("deduping blobs for digest finished successfully")

	return nil
}

func (is *ImageStore) restoreDedupedBlobs(ctx context.Context, digest godigest.Digest, duplicateBlobs []string) error {
	is.log.Info().Str("digest", digest.String()).Str("component", "dedupe").Msg("restoring deduped blobs for digest")

	// first we need to find the original blob, either in cache or by checking each blob size
	originalBlob, err := is.getOriginalBlob(digest, duplicateBlobs)
	if err != nil {
		is.log.Error().Err(err).Str("component", "dedupe").Msg("failed to find original blob")

		return zerr.ErrDedupeRebuild
	}

	for _, blobPath := range duplicateBlobs {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		binfo, err := is.storeDriver.Stat(blobPath)
		if err != nil {
			is.log.Error().Err(err).Str("path", blobPath).Str("component", "dedupe").Msg("failed to stat blob")

			return err
		}

		// if we find a deduped blob, then copy original blob content to deduped one
		if binfo.Size() == 0 {
			// Read the original blob content without holding the write lock - this can be a
			// large S3 GET and must not stall concurrent push operations.
			// Note: this buffers the whole blob in memory, which can spike memory usage for
			// large layers when many restore tasks run concurrently. Consider streaming the
			// copy instead in a follow-up; that refactor is heavier and riskier than this fix.
			buf, err := is.storeDriver.ReadFile(originalBlob)
			if err != nil {
				is.log.Error().Err(err).Str("path", originalBlob).Str("component", "dedupe").
					Msg("failed to get original blob content")

				return err
			}

			// Hold the write lock only for the actual blob write so that concurrent
			// CheckBlob (read lock) and FinishBlobUpload (write lock) are not starved
			// by the preceding slow S3 reads.
			err = func() error {
				var lockLatency time.Time

				is.Lock(&lockLatency)
				defer is.Unlock(&lockLatency)

				// Re-check size inside the lock: another goroutine may have already
				// restored or uploaded this blob between our Stat and Lock above.
				recheck, serr := is.storeDriver.Stat(blobPath)
				if serr == nil {
					if recheck.Size() > 0 {
						return nil
					}
				} else {
					var pathNotFound driver.PathNotFoundError
					if !errors.As(serr, &pathNotFound) {
						return serr
					}
				}

				_, err := is.storeDriver.WriteFile(blobPath, buf)

				return err
			}()
			if err != nil {
				return err
			}
		}
	}

	is.log.Info().Str("digest", digest.String()).
		Str("component", "dedupe").Msg("restoring deduped blobs for digest finished successfully")

	return nil
}

func (is *ImageStore) RunDedupeForDigest(ctx context.Context, digest godigest.Digest, dedupe bool,
	duplicateBlobs []string,
) error {
	if dedupe {
		var lockLatency time.Time

		is.Lock(&lockLatency)
		defer is.Unlock(&lockLatency)

		return is.dedupeBlobs(ctx, digest, duplicateBlobs)
	}

	return is.restoreDedupedBlobs(ctx, digest, duplicateBlobs)
}

func (is *ImageStore) RunDedupeBlobs(interval time.Duration, sch *scheduler.Scheduler) {
	markerPath := path.Join(is.rootDir, storageConstants.DedupeRestoreCompleteMarker)

	// Gate deletes of cache-unknown blobs until the walk completes (see deleteBlob).
	// Local storage dedupes via hardlinks, so deletes there never destroy shared content.
	if is.lifecycle.ShouldGateDeleteUntilRebuild() {
		is.dedupeRebuildDone.Store(false)
	}

	if is.dedupe {
		// Dedupe is active: remove the restore-complete marker so that a future dedupe→false
		// transition knows it must run restore again.
		if err := is.storeDriver.Delete(markerPath); err != nil {
			var pathNotFound driver.PathNotFoundError
			if !errors.As(err, &pathNotFound) {
				is.log.Warn().Err(err).Str("component", "dedupe").
					Msg("failed to remove restore-complete marker")

				// Overwrite with invalid content so future dedupe=false startups won't skip restore.
				if _, werr := is.storeDriver.WriteFile(markerPath,
					[]byte(storageConstants.DedupeRestoreMarkerInvalid)); werr != nil {
					is.log.Error().Err(werr).Str("component", "dedupe").
						Msg("failed to invalidate restore-complete marker; stale marker may cause incorrect skip on next startup")
				}
			}
		}
	} else {
		// Dedupe is disabled: skip the restore scan if a previous pass already completed.
		// The marker is absent on first run or after dedupe was re-enabled, in which case
		// we must run restore to handle any zero-size blobs left by prior deduplication.
		if data, err := is.storeDriver.ReadFile(markerPath); err == nil {
			content := strings.TrimSpace(string(data))

			if content == storageConstants.DedupeRestoreMarkerComplete {
				is.log.Info().Str("component", "dedupe").
					Msg("restore-complete marker present, skipping dedupe restore scan")

				// storage holds no deduped blobs, so deletes are safe without a walk
				is.dedupeRebuildDone.Store(true)

				return
			}

			is.log.Debug().Str("component", "dedupe").Str("content", content).
				Msg("restore-complete marker present but not complete, continuing with dedupe restore scan")
		} else {
			var pathNotFound driver.PathNotFoundError
			if !errors.As(err, &pathNotFound) {
				is.log.Warn().Err(err).Str("component", "dedupe").
					Msg("failed to check restore-complete marker; continuing with dedupe restore scan")
			}
		}
	}

	generator := &common.DedupeTaskGenerator{
		ImgStore: is,
		Dedupe:   is.dedupe,
		Log:      is.log,
	}

	generator.OnRunComplete = func() {
		// walk finished: deferred blob deletes may proceed (see deleteBlob)
		is.dedupeRebuildDone.Store(true)

		if is.dedupe {
			return
		}

		if _, err := is.storeDriver.WriteFile(markerPath,
			[]byte(storageConstants.DedupeRestoreMarkerComplete)); err != nil {
			is.log.Error().Err(err).Str("component", "dedupe").
				Msg("failed to write restore-complete marker")
		} else {
			is.log.Info().Str("component", "dedupe").
				Msg("restore-complete marker written; future startups will skip the restore scan")
		}
	}

	sch.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

func (is *ImageStore) PopulateStorageMetrics(interval time.Duration, sch *scheduler.Scheduler) {
	generator := common.NewStorageMetricsInitGenerator(is, is.metrics, is.log)

	sch.SubmitGenerator(generator, interval, scheduler.HighPriority)
}

type blobStream struct {
	reader io.Reader
	closer io.Closer
}

func newBlobStream(readCloser io.ReadCloser, from, to int64) (io.ReadCloser, error) {
	if from < 0 || to < from {
		return nil, zerr.ErrBadRange
	}

	return &blobStream{reader: io.LimitReader(readCloser, to-from+1), closer: readCloser}, nil
}

func (bs *blobStream) Read(buf []byte) (int, error) {
	return bs.reader.Read(buf)
}

func (bs *blobStream) Close() error {
	return bs.closer.Close()
}
