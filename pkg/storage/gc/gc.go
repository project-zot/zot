package gc

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/registry/storage/driver"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/retention"
	rTypes "zotregistry.dev/zot/v2/pkg/retention/types"
	"zotregistry.dev/zot/v2/pkg/scheduler"
	"zotregistry.dev/zot/v2/pkg/storage"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/types"
)

const (
	cosignSignatureTagSuffix = "sig"
	SBOMTagSuffix            = "sbom"
)

type Options struct {
	// will garbage collect blobs older than Delay
	Delay time.Duration

	// MaxSchedulerDelay is the maximum random delay for GC task scheduling
	// Defaults to 30 seconds if not specified
	MaxSchedulerDelay time.Duration

	// TimeWindow restricts when a new periodic GC sweep over all repositories may start
	// to a daily time-of-day window. A sweep that starts inside the window is allowed to
	// run to completion even past the window's end, so GC work stays amortized and
	// orphaned blobs don't outpace a narrow window. The zero value means no restriction.
	TimeWindow config.GCTimeWindow

	ImageRetention config.ImageRetention
}

type GarbageCollect struct {
	imgStore  types.ImageStore
	opts      Options
	metaDB    mTypes.MetaDB
	policyMgr rTypes.PolicyManager
	auditLog  *zlog.Logger
	log       zlog.Logger
	metrics   monitoring.MetricServer
}

func NewGarbageCollect(imgStore types.ImageStore, metaDB mTypes.MetaDB, opts Options,
	auditLog *zlog.Logger, log zlog.Logger, metrics monitoring.MetricServer,
) GarbageCollect {
	return GarbageCollect{
		imgStore:  imgStore,
		metaDB:    metaDB,
		opts:      opts,
		policyMgr: retention.NewPolicyManager(opts.ImageRetention, log, auditLog),
		auditLog:  auditLog,
		log:       log,
		metrics:   metrics,
	}
}

/*
CleanImageStorePeriodically runs a periodic garbage collect on the ImageStore provided in constructor,
given an interval and a Scheduler.
*/
func (gc GarbageCollect) CleanImageStorePeriodically(interval time.Duration, sch *scheduler.Scheduler) {
	processedRepos := make(map[string]struct{})

	maxDelay := gc.opts.MaxSchedulerDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second // default value
	}

	generator := &GCTaskGenerator{
		imgStore:       gc.imgStore,
		gc:             gc,
		processedRepos: processedRepos,
		maxDelay:       maxDelay,
		timeWindow:     gc.opts.TimeWindow,
	}

	sch.SubmitGenerator(generator, interval, scheduler.MediumPriority)
}

/*
CleanRepo executes a garbage collection of any blob found in storage which is not referenced
in any manifests referenced in repo's index.json
It also gc referrers with missing subject if the Referrer Option is enabled
It also gc untagged manifests.
*/
func (gc GarbageCollect) CleanRepo(ctx context.Context, repo string) error {
	gc.log.Info().Str("module", "gc").
		Msg("executing gc of orphaned blobs for " + path.Join(gc.imgStore.RootDir(), repo))

	start := time.Now()

	if err := gc.cleanRepo(ctx, repo); err != nil {
		monitoring.ObserveGCDuration(gc.metrics, time.Since(start))
		monitoring.IncGCRuns(gc.metrics, true)

		errMessage := "failed to run GC for " + path.Join(gc.imgStore.RootDir(), repo)
		gc.log.Error().Err(err).Str("module", "gc").Msg(errMessage)
		gc.log.Info().Str("module", "gc").
			Msg("gc unsuccessfully completed for " + path.Join(gc.imgStore.RootDir(), repo))

		return err
	}

	monitoring.ObserveGCDuration(gc.metrics, time.Since(start))
	monitoring.IncGCRuns(gc.metrics, false)

	gc.log.Info().Str("module", "gc").
		Msg("gc successfully completed for " + path.Join(gc.imgStore.RootDir(), repo))

	return nil
}

func (gc GarbageCollect) cleanRepo(ctx context.Context, repo string) error {
	var lockLatency time.Time

	dir := path.Join(gc.imgStore.RootDir(), repo)
	if !gc.imgStore.DirExists(dir) {
		return zerr.ErrRepoNotFound
	}

	gc.imgStore.Lock(&lockLatency)
	defer gc.imgStore.Unlock(&lockLatency)

	/* this index (which represents the index.json of this repo) is the root point from which we
	search for dangling manifests/blobs
	so this index is passed by reference in all functions that modifies it

	Instead of removing manifests one by one with storage APIs we just remove manifests descriptors
	from index.Manifests[] list and update repo's index.json afterwards.

	After updating repo's index.json we clean all unreferenced blobs (manifests included).
	*/
	index, err := common.GetIndex(gc.imgStore, repo, gc.log)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to read index.json in repo")

		return err
	}

	manifestsBefore := len(index.Manifests)

	// apply tags retention
	if err := gc.removeTagsPerRetentionPolicy(ctx, repo, &index); err != nil {
		return err
	}

	// gc referrers manifests with missing subject and untagged manifests
	if err := gc.removeManifestsPerRepoPolicy(ctx, repo, &index); err != nil {
		return err
	}

	// prune manifest/index descriptors with an unsupported/unknown media type: nothing else
	// in GC ever removes these, and leaving them referenced would orphan (and unchecked-delete)
	// their config/layers while the dangling index.json entry survives.
	if err := gc.removeUnknownMediaTypeManifestEntries(repo, &index); err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
			Msg("failed to prune unknown media type manifest entries")

		return err
	}

	// prune manifest/index descriptors whose blobs no longer exist in storage
	if err := gc.removeStaleManifestEntries(repo, &index); err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
			Msg("failed to prune stale manifest entries")

		return err
	}

	// update repos's index.json in storage
	if !gc.opts.ImageRetention.DryRun {
		/* this will update the index.json with manifest references removed above;
		orphan manifest/config/layer blobs are deleted by gc.deleteUnreferencedBlobs() */
		if err := gc.imgStore.PutIndexContent(repo, index); err != nil {
			return err
		}
	}

	manifestsDeleted := manifestsBefore - len(index.Manifests)

	var blobsDeleted, uploadsDeleted int

	// DryRun must be a non-destructive simulation: index.json was left untouched above, and blob GC
	// must not delete anything either - it re-reads the on-disk index.json, so running it here would
	// delete blobs for real (e.g. orphaned by manifest-pass edits) while their index entries survive.
	if !gc.opts.ImageRetention.DryRun {
		// delete unreferenced blobs from storage
		blobsDeleted, err = gc.deleteUnreferencedBlobs(repo, gc.opts.Delay, gc.log)
		if err != nil {
			return err
		}

		/* remove the repo layout once nothing is left: no manifests, no blobs, no uploads.
		This is the repository-level analogue of the manifest pruning above; the meta record
		is dropped right after, keeping metadb on the same lifetime as storage, so a reaped
		repo also stops counting towards storage.maxRepos. Blobs younger than the GC delay
		keep their grace period. This runs before deleteBlobUploads so that an upload not yet
		old enough to be reaped still counts as in progress and keeps the repo, as
		CleanupRepo's guard used to. */
		removed, err := gc.imgStore.RemoveIdleRepository(repo, gc.opts.Delay)
		if err != nil {
			gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
				Msg("failed to remove idle repo")

			return err
		}

		if removed && gc.metaDB != nil {
			if err := gc.metaDB.DeleteRepoMeta(repo); err != nil {
				/* log, don't fail: the layout is already gone, so aborting the rest of cleanRepo
				would not bring it back, and ParseStorage drops the stale record on next start */
				gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
					Msg("removed repo layout but failed to delete its meta record")
			}
		}

		// delete old blob uploads from storage
		uploadsDeleted, err = gc.deleteBlobUploads(repo, gc.opts.Delay)
		if err != nil {
			return err
		}
	}

	if !gc.opts.ImageRetention.DryRun {
		monitoring.IncGCDeleted(gc.metrics, "manifest", manifestsDeleted)
		monitoring.IncGCDeleted(gc.metrics, "blob", blobsDeleted)
		monitoring.IncGCDeleted(gc.metrics, "upload", uploadsDeleted)
	}

	return nil
}

// removeUnknownMediaTypeManifestEntries prunes index.Manifests descriptors whose media type is not a
// known manifest/index (or compat) type. common.GetReferencedBlobs marks every index.json descriptor's
// own digest as referenced regardless of media type (mirroring IsBlobReferencedInImageIndex), so an
// unknown-media-type entry would otherwise never become an orphan and would never be pruned - while its
// config/layers still fall out as real orphans and get deleted, leaving a dangling index.json entry.
func (gc GarbageCollect) removeUnknownMediaTypeManifestEntries(repo string, index *ispec.Index) error {
	if gc.opts.ImageRetention.DryRun {
		return nil
	}

	kept := make([]ispec.Descriptor, 0, len(index.Manifests))

	for _, desc := range index.Manifests {
		if isKnownManifestMediaType(desc.MediaType) {
			kept = append(kept, desc)

			continue
		}

		if err := gc.syncManifestRemoval(repo, desc, "unknownMediaTypePrune",
			"pruned unknown media type manifest entry from index"); err != nil {
			return err
		}
	}

	if removed := len(index.Manifests) - len(kept); removed > 0 {
		gc.log.Info().Str("module", "gc").Str("repository", repo).
			Int("removed", removed).Int("kept", len(kept)).
			Msg("pruned unknown media type manifest entries from index")
	}

	index.Manifests = kept

	return nil
}

func isKnownManifestMediaType(mediaType string) bool {
	return common.IsImageIndexMediaType(mediaType) || common.IsImageManifestMediaType(mediaType)
}

func (gc GarbageCollect) removeStaleManifestEntries(repo string, index *ispec.Index) error {
	if gc.opts.ImageRetention.DryRun {
		return nil
	}

	allBlobs, err := gc.imgStore.GetAllBlobs(repo)
	if err != nil {
		var pathNotFoundErr driver.PathNotFoundError
		if !errors.As(err, &pathNotFoundErr) {
			return err
		}

		allBlobs = []godigest.Digest{}
	}

	existingBlobs := make(map[string]bool, len(allBlobs))
	for _, d := range allBlobs {
		existingBlobs[d.String()] = true
	}

	kept := make([]ispec.Descriptor, 0, len(index.Manifests))

	for _, desc := range index.Manifests {
		if !existingBlobs[desc.Digest.String()] {
			if err := gc.syncManifestRemoval(repo, desc, "staleManifestPrune",
				"pruned stale manifest entry from index"); err != nil {
				return err
			}

			continue
		}

		if common.IsImageIndexMediaType(desc.MediaType) {
			stale, err := gc.imageIndexHasStaleNestedManifests(repo, desc, existingBlobs)
			if err != nil {
				return err
			}

			if stale {
				if err := gc.syncManifestRemoval(repo, desc, "staleManifestPrune",
					"pruned stale manifest entry from index"); err != nil {
					return err
				}

				continue
			}
		}

		kept = append(kept, desc)
	}

	if removed := len(index.Manifests) - len(kept); removed > 0 {
		gc.log.Info().Str("module", "gc").Str("repository", repo).
			Int("removed", removed).Int("kept", len(kept)).
			Msg("pruned stale manifest entries from index")
	}

	index.Manifests = kept

	return nil
}

// syncManifestRemoval best-effort syncs metaDB before a descriptor is removed from index.Manifests
// (index.json is persisted later in cleanRepo). metaDB failures are logged but do not abort pruning —
// storage repair must not depend on secondary index consistency. The blob is typically already absent
// from storage; cosign signatures are cleaned up via tag annotation. reason/message identify which
// prune path (stale vs. unknown media type) triggered the removal, for log/audit consumers.
func (gc GarbageCollect) syncManifestRemoval(repo string, desc ispec.Descriptor, reason, message string) error {
	tag, hasTag := getDescriptorTag(desc)
	ref := tag
	if ref == "" {
		ref = desc.Digest.String()
	}

	var subjectDigest godigest.Digest

	isCosignSig := hasTag && zcommon.IsCosignSignature(tag)
	if isCosignSig {
		subjectDigest = getSubjectFromCosignTag(tag)
		if err := subjectDigest.Validate(); err != nil {
			gc.log.Warn().Err(err).Str("module", "gc").Str("repository", repo).
				Str("reference", ref).Str("digest", desc.Digest.String()).
				Msg("invalid cosign tag subject digest, falling back to RemoveRepoReference")

			isCosignSig = false
			subjectDigest = ""
		}
	}

	if gc.metaDB != nil {
		if isCosignSig {
			if err := gc.metaDB.DeleteSignature(repo, subjectDigest, mTypes.SignatureMetadata{
				SignatureDigest: desc.Digest.String(),
				SignatureType:   storage.CosignType,
			}); err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("component", "metadb").
					Str("repository", repo).Str("digest", desc.Digest.String()).Str("reference", ref).
					Msg("failed to remove stale cosign signature from metaDB, continuing stale prune")
			}
		} else if err := gc.metaDB.RemoveRepoReference(repo, ref, desc.Digest); err != nil {
			gc.log.Error().Err(err).Str("module", "gc").Str("component", "metadb").
				Str("repository", repo).Str("digest", desc.Digest.String()).Str("reference", ref).
				Msg("failed to remove stale manifest reference from metaDB, continuing stale prune")
		}
	}

	logEvent := gc.log.Info().Str("module", "gc").
		Str("repository", repo).
		Str("reference", ref).
		Str("digest", desc.Digest.String()).
		Str("decision", "delete").
		Str("reason", reason)

	if subjectDigest != "" {
		logEvent = logEvent.Str("subject", subjectDigest.String())
	}

	logEvent.Msg(message)

	if gc.auditLog != nil {
		auditEvent := gc.auditLog.Info().Str("module", "gc").
			Str("repository", repo).
			Str("reference", ref).
			Str("digest", desc.Digest.String()).
			Str("decision", "delete").
			Str("reason", reason)

		if subjectDigest != "" {
			auditEvent = auditEvent.Str("subject", subjectDigest.String())
		}

		auditEvent.Msg(message)
	}

	return nil
}

// imageIndexHasStaleNestedManifests reports whether the top-level image index descriptor
// should be dropped from index.json. The index blob itself is never rewritten.
// Sparse indexes are supported: if any nested manifest blob still exists, return false
// (not stale) so the tagged index entry is kept even when other nested manifests are missing.
// Return true only when every nested manifest blob is gone (or the index blob is missing).
// Empty manifest lists are valid OCI and are kept when the index blob still exists.
func (gc GarbageCollect) imageIndexHasStaleNestedManifests(repo string, desc ispec.Descriptor,
	existingBlobs map[string]bool,
) (bool, error) {
	indexImage, err := common.GetImageIndex(gc.imgStore, repo, desc.Digest, gc.log)
	if err != nil {
		var pathNotFoundErr driver.PathNotFoundError
		if errors.Is(err, zerr.ErrBlobNotFound) || errors.As(err, &pathNotFoundErr) {
			// Index blob missing — top-level descriptor is stale.
			return true, nil
		}

		return false, err
	}

	if len(indexImage.Manifests) == 0 {
		return false, nil
	}

	for _, nested := range indexImage.Manifests {
		if existingBlobs[nested.Digest.String()] {
			// At least one nested manifest remains; keep this sparse index in index.json.
			// Early return (not continue): stale=false is decided as soon as one survivor exists.
			return false, nil
		}
	}

	// Every nested manifest blob is missing.
	return true, nil
}

func (gc GarbageCollect) removeManifestsPerRepoPolicy(ctx context.Context, repo string, index *ispec.Index) error {
	var err error

	/* gc all manifests that have a missing subject, stop when neither gc(referrer and untagged)
	happened in a full loop over index.json. */
	var stop bool
	for !stop {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		var gcedReferrer bool

		var gcedUntagged bool

		if gc.policyMgr.HasDeleteReferrer(repo) {
			gc.log.Debug().Str("module", "gc").Str("repository", repo).Msg("manifests with missing referrers")

			gcedReferrer, err = gc.removeReferrersWithMissingSubject(repo, index)
			if err != nil {
				return err
			}
		}

		if gc.policyMgr.HasDeleteUntagged(repo) {
			referenced := make(map[godigest.Digest]bool, 0)

			/* gather all manifests referenced in multiarch images/by other manifests
			so that we can skip them in cleanUntaggedManifests */
			if err := gc.identifyManifestsReferencedInIndex(*index, repo, referenced,
				map[godigest.Digest]struct{}{}); err != nil {
				return err
			}

			// apply image retention policy
			gcedUntagged, err = gc.removeUntaggedManifests(ctx, repo, index, referenced)
			if err != nil {
				return err
			}
		}

		/* if we gced any manifest then loop again and gc manifests with
		a subject pointing to the last ones which were gced. */
		stop = !gcedReferrer && !gcedUntagged
	}

	return nil
}

func isMissingBlobErr(err error) bool {
	var pathNotFoundErr driver.PathNotFoundError

	return errors.Is(err, zerr.ErrBlobNotFound) || errors.As(err, &pathNotFoundErr)
}

// removeReferrersWithMissingSubject walks root index.json and removes rows whose subject is no
// longer listed there. It does not delete blobs from storage.
//
// Flat iteration only: every root row is visited (multi-tag and cosign siblings share a digest but
// differ by ref annotation). missing skips re-fetch of absent blobs; indexes/manifests cache
// successful reads so duplicate digest siblings do not hit storage again (cleanRepo holds the lock).
func (gc GarbageCollect) removeReferrersWithMissingSubject(repo string, rootIndex *ispec.Index) (bool, error) {
	missing := make(map[godigest.Digest]struct{})
	indexes := make(map[godigest.Digest]ispec.Index)
	manifests := make(map[godigest.Digest]ispec.Manifest)

	var count int

	// Range captures the original Manifests slice; removals reassign rootIndex.Manifests.
	// Each original row is still visited. Rows re-added mid-pass (untagged leftovers from
	// last-tag delete) are handled by removeManifestsPerRepoPolicy's outer loop.
	for _, desc := range rootIndex.Manifests {
		var gced bool

		var err error

		switch {
		case common.IsImageIndexMediaType(desc.MediaType):
			gced, err = gc.removeReferrerByIndexDesc(repo, rootIndex, desc, missing, indexes)
		case common.IsImageManifestMediaType(desc.MediaType):
			gced, err = gc.removeReferrerByManifestDesc(repo, rootIndex, desc, missing, manifests)
		default:
			continue
		}

		if err != nil {
			return false, err
		}

		if gced {
			count++
		}
	}

	return count > 0, nil
}

// removeReferrerByIndexDesc handles one root index.json row whose media type is an image
// index: fetch/cache that index blob (or record it missing), then decide whether to remove
// the root index.json entry via removeReferrer. It does not mutate nested index blobs.
func (gc GarbageCollect) removeReferrerByIndexDesc(repo string, rootIndex *ispec.Index, desc ispec.Descriptor,
	missing map[godigest.Digest]struct{}, indexes map[godigest.Digest]ispec.Index,
) (bool, error) {
	if _, ok := missing[desc.Digest]; ok {
		return false, nil
	}

	indexImage, cached := indexes[desc.Digest]
	if !cached {
		var err error

		indexImage, err = common.GetImageIndex(gc.imgStore, repo, desc.Digest, gc.log)
		if err != nil {
			if isMissingBlobErr(err) {
				missing[desc.Digest] = struct{}{}
				gc.log.Warn().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", desc.Digest.String()).
					Msg("skipping missing image index blob, continuing GC")

				return false, nil
			}

			// Transient/hard read failures: skip this row so cleanRepo can still run stale
			// prune and blob/upload cleanup for the rest of the repo.
			gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", desc.Digest.String()).
				Msg("failed to read multiarch(index) image, continuing GC")

			return false, nil
		}

		indexes[desc.Digest] = indexImage
	}

	return gc.removeReferrer(repo, rootIndex, desc, indexImage.Subject, indexImage.ArtifactType)
}

// removeReferrerByManifestDesc handles one root index.json row whose media type is an image
// manifest: fetch/cache that manifest blob (or record it missing), then decide whether to
// remove the root index.json entry via removeReferrer (including legacy cosign tags when
// the blob is absent). It does not mutate the manifest blob itself.
func (gc GarbageCollect) removeReferrerByManifestDesc(repo string, rootIndex *ispec.Index, desc ispec.Descriptor,
	missing map[godigest.Digest]struct{}, manifests map[godigest.Digest]ispec.Manifest,
) (bool, error) {
	if _, ok := missing[desc.Digest]; ok {
		return gc.removeReferrer(repo, rootIndex, desc, nil, "")
	}

	image, cached := manifests[desc.Digest]
	if !cached {
		var err error

		image, err = common.GetImageManifest(gc.imgStore, repo, desc.Digest, gc.log)
		if err != nil {
			if isMissingBlobErr(err) {
				missing[desc.Digest] = struct{}{}
				gc.log.Warn().Err(err).Str("module", "gc").Str("repo", repo).Str("digest", desc.Digest.String()).
					Msg("skipping missing image manifest blob, continuing GC")

				return gc.removeReferrer(repo, rootIndex, desc, nil, "")
			}

			// Transient/hard read failures: skip this row so cleanRepo can still run stale
			// prune and blob/upload cleanup for the rest of the repo.
			gc.log.Error().Err(err).Str("module", "gc").Str("repo", repo).Str("digest", desc.Digest.String()).
				Msg("failed to read manifest image, continuing GC")

			return false, nil
		}

		manifests[desc.Digest] = image
	}

	artifactType := zcommon.GetManifestArtifactType(image)

	return gc.removeReferrer(repo, rootIndex, desc, image.Subject, artifactType)
}

func (gc GarbageCollect) removeReferrer(repo string, index *ispec.Index, manifestDesc ispec.Descriptor,
	subject *ispec.Descriptor, artifactType string,
) (bool, error) {
	var gced bool

	var err error

	if subject != nil {
		// try to find subject in index.json
		referenced := isManifestReferencedInIndex(index, subject.Digest)

		var signatureType string
		// check if its notation or cosign signature
		if artifactType == zcommon.ArtifactTypeNotation {
			signatureType = storage.NotationType
		} else if zcommon.IsArtifactTypeCosign(artifactType) {
			signatureType = storage.CosignType
		}

		if !referenced {
			gced, err = gc.removeManifestIfOlderThan(repo, index, manifestDesc, signatureType,
				subject.Digest, gc.opts.ImageRetention.Delay)
			if err != nil {
				return false, err
			}

			if gced {
				gc.log.Info().Str("module", "gc").
					Str("repository", repo).
					Str("reference", manifestDesc.Digest.String()).
					Str("subject", subject.Digest.String()).
					Str("decision", "delete").
					Str("reason", "deleteReferrers").Msg("removed manifest without reference")

				if gc.auditLog != nil {
					gc.auditLog.Info().Str("module", "gc").
						Str("repository", repo).
						Str("reference", manifestDesc.Digest.String()).
						Str("subject", subject.Digest.String()).
						Str("decision", "delete").
						Str("reason", "deleteReferrers").Msg("removed manifest without reference")
				}
			}
		}
	}

	// Legacy cosign tags (sha256-<digest>.sig / .sbom). Skip when the subject path above
	// already removed this descriptor — otherwise a second tag delete returns
	// ErrManifestNotFound and aborts GC after a partial metaDB update.
	if gced {
		return gced, nil
	}

	tag, ok := getDescriptorTag(manifestDesc)
	if ok {
		if zcommon.IsCosignTag(tag) {
			subjectDigest := getSubjectFromCosignTag(tag)
			referenced := isManifestReferencedInIndex(index, subjectDigest)

			if !referenced {
				gced, err = gc.removeManifestIfOlderThan(repo, index, manifestDesc, storage.CosignType,
					subjectDigest, gc.opts.Delay)
				if err != nil {
					return false, err
				}

				if gced {
					gc.log.Info().Str("module", "gc").
						Bool("dry-run", gc.opts.ImageRetention.DryRun).
						Str("repository", repo).
						Str("reference", tag).
						Str("subject", subjectDigest.String()).
						Str("decision", "delete").
						Str("reason", "deleteReferrers").Msg("removed cosign manifest without reference")

					if gc.auditLog != nil {
						gc.auditLog.Info().Str("module", "gc").
							Bool("dry-run", gc.opts.ImageRetention.DryRun).
							Str("repository", repo).
							Str("reference", tag).
							Str("subject", subjectDigest.String()).
							Str("decision", "delete").
							Str("reason", "deleteReferrers").Msg("removed cosign manifest without reference")
					}
				}
			}
		}
	}

	return gced, nil
}

func (gc GarbageCollect) removeTagsPerRetentionPolicy(ctx context.Context, repo string, index *ispec.Index) error {
	if !gc.policyMgr.HasTagRetention(repo) {
		return nil
	}

	var retainTags []string

	if gc.metaDB != nil {
		repoMeta, err := gc.metaDB.GetRepoMeta(ctx, repo)
		if err != nil {
			gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
				Msg("failed to get repoMeta")

			return err
		}

		retainTags = gc.policyMgr.GetRetainedTagsFromMetaDB(ctx, repoMeta, *index)
	} else {
		retainTags = gc.policyMgr.GetRetainedTagsFromIndex(ctx, repo, *index)
	}

	// remove
	for _, desc := range index.Manifests {
		if zcommon.IsContextDone(ctx) {
			return ctx.Err()
		}

		// check tag
		tag, ok := getDescriptorTag(desc)
		if ok && !slices.Contains(retainTags, tag) {
			// remove tags which should not be retained
			_, err := gc.removeManifest(repo, index, desc, tag, "", "")
			if err != nil && !errors.Is(err, zerr.ErrManifestNotFound) {
				return err
			}
		}
	}

	return nil
}

// removeManifestIfOlderThan removes a manifest reference from an index (and syncs metaDB) when
// the blob is older than delay. It does not delete the blob from storage.
func (gc GarbageCollect) removeManifestIfOlderThan(repo string, index *ispec.Index, desc ispec.Descriptor,
	signatureType string, subjectDigest godigest.Digest, delay time.Duration,
) (bool, error) {
	var gced bool

	canGC, err := isBlobOlderThan(gc.imgStore, repo, desc.Digest, delay, gc.log)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", desc.Digest.String()).
			Str("delay", delay.String()).Msg("failed to check if blob is older than delay")

		return false, err
	}

	if canGC {
		// Prefer tag when present so duplicate digest siblings (multi-tag, cosign .sig +
		// untagged) remove one index.json row. Digest-only removal hits ErrManifestConflict.
		// Last-tag delete re-adds an untagged row (RemoveManifestDescByReference API
		// semantics); removeManifestsPerRepoPolicy's outer loop clears it on a later pass.
		reference := desc.Digest.String()
		if tag, ok := getDescriptorTag(desc); ok {
			reference = tag
		}

		if gced, err = gc.removeManifest(repo, index, desc, reference, signatureType, subjectDigest); err != nil {
			return false, err
		}
	}

	return gced, nil
}

// removeManifest removes a manifest reference from an index and syncs metaDB. It does not delete
// the blob from storage (orphan blobs are deleted later by deleteUnreferencedBlobs).
func (gc GarbageCollect) removeManifest(repo string, index *ispec.Index,
	desc ispec.Descriptor, reference string, signatureType string, subjectDigest godigest.Digest,
) (bool, error) {
	_, err := common.RemoveManifestDescByReference(index, reference, true)
	if err != nil {
		if errors.Is(err, zerr.ErrManifestConflict) || errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		return false, err
	}

	if gc.opts.ImageRetention.DryRun {
		return true, nil
	}

	// sync metaDB
	if gc.metaDB != nil {
		if signatureType != "" {
			err = gc.metaDB.DeleteSignature(repo, subjectDigest, mTypes.SignatureMetadata{
				SignatureDigest: desc.Digest.String(),
				SignatureType:   signatureType,
			})
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("component", "metadb").
					Msg("failed to remove signature in metaDB")

				return false, err
			}
		} else {
			err := gc.metaDB.RemoveRepoReference(repo, reference, desc.Digest)
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("component", "metadb").
					Msg("failed to remove repo reference in metaDB")

				return false, err
			}
		}
	}

	return true, nil
}

func (gc GarbageCollect) removeUntaggedManifests(ctx context.Context, repo string, index *ispec.Index,
	referenced map[godigest.Digest]bool,
) (bool, error) {
	var gced bool

	var err error

	gc.log.Debug().Str("module", "gc").Str("repository", repo).Msg("manifests without tags")

	retainUntagged := make(map[string]bool)
	if gc.policyMgr.HasUntaggedRetention(repo) {
		if gc.metaDB != nil {
			repoMeta, err := gc.metaDB.GetRepoMeta(ctx, repo)
			if err != nil {
				gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
					Msg("failed to get repoMeta for untagged retention")

				return false, err
			}

			for _, digestStr := range gc.policyMgr.GetRetainedUntaggedFromMetaDB(ctx, repoMeta, *index) {
				retainUntagged[digestStr] = true
			}
		} else {
			gc.log.Warn().Str("module", "gc").Str("repository", repo).
				Msg("keepUntagged policy requires metadata database;" +
					" ignoring keepUntagged rules and using delay-based untagged cleanup")
		}
	}

	for _, desc := range index.Manifests {
		// skip manifests referenced in image indexes
		if _, referenced := referenced[desc.Digest]; referenced {
			continue
		}

		// remove untagged images
		if isKnownManifestMediaType(desc.MediaType) {
			_, ok := getDescriptorTag(desc)
			if !ok {
				if retainUntagged[desc.Digest.String()] {
					continue
				}

				gced, err = gc.removeManifestIfOlderThan(repo, index, desc, "", "", gc.opts.ImageRetention.Delay)
				if err != nil {
					return false, err
				}

				if gced {
					gc.log.Info().Str("module", "gc").
						Bool("dry-run", gc.opts.ImageRetention.DryRun).
						Str("repository", repo).
						Str("reference", desc.Digest.String()).
						Str("decision", "delete").
						Str("reason", "deleteUntagged").Msg("removed untagged manifest")

					if gc.auditLog != nil {
						gc.auditLog.Info().Str("module", "gc").
							Bool("dry-run", gc.opts.ImageRetention.DryRun).
							Str("repository", repo).
							Str("reference", desc.Digest.String()).
							Str("decision", "delete").
							Str("reason", "deleteUntagged").Msg("removed untagged manifest")
					}
				}
			}
		}
	}

	return gced, nil
}

// Adds both referenced manifests and referrers from an index.
// seen ensures each digest is fetched and recursed into at most once per walk,
// so an index DAG with shared/duplicate child digests stays O(distinct objects).
func (gc GarbageCollect) identifyManifestsReferencedInIndex(index ispec.Index, repo string,
	referenced map[godigest.Digest]bool, seen map[godigest.Digest]struct{},
) error {
	for _, desc := range index.Manifests {
		if _, ok := seen[desc.Digest]; ok {
			continue
		}

		seen[desc.Digest] = struct{}{}

		if common.IsImageIndexMediaType(desc.MediaType) {
			indexImage, err := common.GetImageIndex(gc.imgStore, repo, desc.Digest, gc.log)
			if err != nil {
				if isMissingBlobErr(err) {
					gc.log.Warn().Err(err).Str("module", "gc").Str("repository", repo).
						Str("digest", desc.Digest.String()).Msg("skipping missing image index blob, continuing GC")

					continue
				}

				// Fail closed: without this index's nested digests, removeUntaggedManifests
				// could delete platform/child manifests that are only "referenced" via this blob.
				gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
					Str("digest", desc.Digest.String()).Msg("failed to read multiarch(index) image")

				return err
			}

			if indexImage.Subject != nil {
				referenced[desc.Digest] = true
			}

			for _, indexDesc := range indexImage.Manifests {
				referenced[indexDesc.Digest] = true
			}

			if err := gc.identifyManifestsReferencedInIndex(indexImage, repo, referenced, seen); err != nil {
				return err
			}
		} else if common.IsImageManifestMediaType(desc.MediaType) {
			image, err := common.GetImageManifest(gc.imgStore, repo, desc.Digest, gc.log)
			if err != nil {
				if isMissingBlobErr(err) {
					gc.log.Warn().Err(err).Str("module", "gc").Str("repo", repo).
						Str("digest", desc.Digest.String()).Msg("skipping missing image manifest blob, continuing GC")

					continue
				}

				// Fail closed: subject-bearing untagged referrers are marked referenced only
				// after a successful read; skipping would allow removeUntaggedManifests to
				// drop them while their subject is still present.
				gc.log.Error().Err(err).Str("module", "gc").Str("repo", repo).
					Str("digest", desc.Digest.String()).Msg("failed to read manifest image")

				return err
			}

			if image.Subject != nil {
				referenced[desc.Digest] = true
			}
		}
	}

	return nil
}

// deleteBlobUploads deletes temporary blob uploads from storage that are past their gc delay.
func (gc GarbageCollect) deleteBlobUploads(repo string, delay time.Duration) (int, error) {
	gc.log.Debug().Str("module", "gc").Str("repository", repo).Msg("cleaning unclaimed blob uploads")

	if dir := path.Join(gc.imgStore.RootDir(), repo); !gc.imgStore.DirExists(dir) {
		// The repository was already cleaned up by a different codepath
		return 0, nil
	}

	blobUploads, err := gc.imgStore.ListBlobUploads(repo)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get list of blob uploads")

		return 0, err
	}

	var aggregatedErr error

	deleted := 0

	for _, uuid := range blobUploads {
		_, size, modtime, err := gc.imgStore.StatBlobUpload(repo, uuid)
		if err != nil {
			gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("blobUpload", uuid).
				Msg("failed to stat blob upload")

			aggregatedErr = errors.Join(aggregatedErr, err)

			continue
		}

		if modtime.Add(delay).After(time.Now()) {
			// Do not delete blob uploads which have been updated recently
			continue
		}

		err = gc.imgStore.DeleteBlobUpload(repo, uuid)
		if err != nil {
			gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("blobUpload", uuid).
				Str("size", strconv.FormatInt(size, 10)).Str("modified", modtime.String()).Msg("failed to delete blob upload")

			aggregatedErr = errors.Join(aggregatedErr, err)
		} else {
			deleted++
		}
	}

	return deleted, aggregatedErr
}

// deleteUnreferencedBlobs deletes from storage all blobs not referenced by the repo's index.json
// (and nested manifests/indexes), when older than delay.
func (gc GarbageCollect) deleteUnreferencedBlobs(repo string, delay time.Duration, log zlog.Logger,
) (int, error) {
	gc.log.Debug().Str("module", "gc").Str("repository", repo).Msg("cleaning orphan blobs")

	refBlobs, err := common.GetReferencedBlobs(gc.imgStore, repo, gc.log)
	if err != nil {
		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get referenced blobs in repo")

		return 0, err
	}

	allBlobs, err := gc.imgStore.GetAllBlobs(repo)
	if err != nil {
		// /blobs/sha256/ may be empty in the case of s3, no need to return err, we want to skip
		if errors.As(err, &driver.PathNotFoundError{}) {
			return 0, nil
		}

		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get all blobs")

		return 0, err
	}

	gcBlobs := make([]godigest.Digest, 0)

	for _, digest := range allBlobs {
		if err = digest.Validate(); err != nil {
			log.Error().Err(err).Str("module", "gc").Str("repository", repo).
				Str("digest", digest.String()).Msg("failed to parse digest")

			return 0, err
		}

		if _, ok := refBlobs[digest]; !ok {
			canGC, err := isBlobOlderThan(gc.imgStore, repo, digest, delay, log)
			if err != nil {
				log.Error().Err(err).Str("module", "gc").Str("repository", repo).
					Str("digest", digest.String()).Msg("failed to determine GC delay")

				return 0, err
			}

			if canGC {
				gcBlobs = append(gcBlobs, digest)
			}
		}
	}

	reaped, err := gc.imgStore.CleanupRepo(repo, gcBlobs)
	if err != nil {
		return 0, err
	}

	log.Info().Str("module", "gc").Str("repository", repo).Int("count", reaped).
		Msg("garbage collected blobs")

	return reaped, nil
}

func isManifestReferencedInIndex(index *ispec.Index, digest godigest.Digest) bool {
	for _, manifest := range index.Manifests {
		if manifest.Digest == digest {
			return true
		}
	}

	return false
}

func isBlobOlderThan(imgStore types.ImageStore, repo string,
	digest godigest.Digest, delay time.Duration, log zlog.Logger,
) (bool, error) {
	_, _, modtime, err := imgStore.StatBlob(repo, digest)
	if err != nil {
		// Fail closed: ImageStore.StatBlob maps any underlying Stat failure (including
		// transient S3/network errors) to ErrBlobNotFound, so treating "missing" as
		// GC-eligible would risk deleting live index rows during storage blips.
		// Stale prune can still remove truly absent blobs later when CleanRepo succeeds.
		log.Error().Err(err).Str("module", "gc").Str("repository", repo).Str("digest", digest.String()).
			Msg("failed to stat blob")

		return false, err
	}

	if modtime.Add(delay).After(time.Now()) {
		return false, nil
	}

	return true, nil
}

func getSubjectFromCosignTag(tag string) godigest.Digest {
	alg := strings.Split(tag, "-")[0]
	encoded := strings.Split(tag, "-")[1]
	encoded = strings.TrimSuffix(encoded, "."+cosignSignatureTagSuffix)
	encoded = strings.TrimSuffix(encoded, "."+SBOMTagSuffix)

	return godigest.NewDigestFromEncoded(godigest.Algorithm(alg), encoded)
}

func getDescriptorTag(desc ispec.Descriptor) (string, bool) {
	tag, ok := desc.Annotations[ispec.AnnotationRefName]

	return tag, ok
}

// GCTaskGenerator takes all repositories found in the storage.imagestore
// and it will execute garbage collection for each repository by creating a task
// for each repository and pushing it to the task scheduler.
type GCTaskGenerator struct {
	imgStore          types.ImageStore
	gc                GarbageCollect
	processedRepos    map[string]struct{}
	nextRun           time.Time
	done              bool
	rand              *rand.Rand
	maxDelay          time.Duration
	timeWindow        config.GCTimeWindow
	loggedWindowDefer bool
}

func (gen *GCTaskGenerator) getRandomDelay() time.Duration {
	maxDelay := gen.maxDelay
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second // default fallback
	}

	// Generate random delay with nanosecond precision by working directly with
	// time.Duration's internal representation (nanoseconds as int64).
	// This supports sub-second delays (milliseconds, microseconds).
	return time.Duration(gen.rand.Int63n(int64(maxDelay)))
}

func (gen *GCTaskGenerator) Name() string {
	return "GCTaskGenerator"
}

func (gen *GCTaskGenerator) Next() (scheduler.Task, error) {
	if len(gen.processedRepos) == 0 && gen.nextRun.IsZero() {
		gen.rand = rand.New(rand.NewSource(time.Now().UTC().UnixNano())) //nolint: gosec
	}

	delay := gen.getRandomDelay()

	gen.nextRun = time.Now().Add(delay)

	repo, err := gen.imgStore.GetNextRepository(gen.processedRepos)
	if err != nil {
		return nil, err
	}

	if repo == "" {
		gen.done = true

		return nil, nil //nolint:nilnil
	}

	gen.processedRepos[repo] = struct{}{}

	return NewGCTask(gen.imgStore, gen.gc, repo), nil
}

func (gen *GCTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *GCTaskGenerator) IsReady() bool {
	now := time.Now()

	if !now.After(gen.nextRun) {
		return false
	}

	// Only gate the start of a new sweep on the configured time window. Once a sweep
	// has begun (processedRepos is non-empty), let it run to completion regardless of
	// the window, so GC work stays amortized instead of stalling mid-sweep until the
	// window reopens the next day.
	startingNewSweep := len(gen.processedRepos) == 0 && gen.nextRun.IsZero()

	if startingNewSweep && !gen.timeWindow.Contains(now) {
		if !gen.loggedWindowDefer {
			if gen.gc.log.Logger != nil {
				gen.gc.log.Debug().Msg("gc sweep deferred, outside gcTimeWindow")
			}

			gen.loggedWindowDefer = true
		}

		return false
	}

	gen.loggedWindowDefer = false

	return true
}

func (gen *GCTaskGenerator) Reset() {
	gen.processedRepos = make(map[string]struct{})
	gen.done = false
	gen.nextRun = time.Time{}
}

type gcTask struct {
	imgStore types.ImageStore
	gc       GarbageCollect
	repo     string
}

func NewGCTask(imgStore types.ImageStore, gc GarbageCollect, repo string,
) *gcTask {
	return &gcTask{imgStore, gc, repo}
}

func (gct *gcTask) DoWork(ctx context.Context) error {
	// run task
	return gct.gc.CleanRepo(ctx, gct.repo) //nolint: contextcheck
}

func (gct *gcTask) String() string {
	return fmt.Sprintf("{Name: %s, repo: %s}",
		gct.Name(), gct.repo)
}

func (gct *gcTask) Name() string {
	return "GCTask"
}
