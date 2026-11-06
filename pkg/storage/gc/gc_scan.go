package gc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	zlog "zotregistry.dev/zot/v2/pkg/log"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
	"zotregistry.dev/zot/v2/pkg/retention"
	common "zotregistry.dev/zot/v2/pkg/storage/common"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
	"zotregistry.dev/zot/v2/pkg/storage/types"
)

// metaAction is a metaDB write the unlocked scan implies. The commit replays it.
type metaAction struct {
	repo       string
	reference  string
	digest     godigest.Digest
	subject    godigest.Digest
	sigMeta    mTypes.SignatureMetadata
	signature  bool
	bestEffort bool
}

type metaRecorder struct {
	actions []metaAction
}

func (m *metaRecorder) record(action metaAction) {
	m.actions = append(m.actions, action)
}

func (gc GarbageCollect) removeRepoReference(repo, reference string, digest godigest.Digest, bestEffort bool) error {
	if gc.recorder != nil {
		gc.recorder.record(metaAction{repo: repo, reference: reference, digest: digest, bestEffort: bestEffort})

		return nil
	}

	return gc.metaDB.RemoveRepoReference(repo, reference, digest)
}

func (gc GarbageCollect) deleteSignature(repo string, subject godigest.Digest, sigMeta mTypes.SignatureMetadata,
	bestEffort bool,
) error {
	if gc.recorder != nil {
		gc.recorder.record(metaAction{
			repo: repo, subject: subject, sigMeta: sigMeta, signature: true, bestEffort: bestEffort,
		})

		return nil
	}

	return gc.metaDB.DeleteSignature(repo, subject, sigMeta)
}

// repoMeta returns the repository metadata as the locked pass would see it at this point: the
// metaDB writes the scan has deferred so far are applied to a copy of the stored record.
func (gc GarbageCollect) repoMeta(ctx context.Context, repo string) (mTypes.RepoMeta, error) {
	repoMeta, err := gc.metaDB.GetRepoMeta(ctx, repo)
	if err != nil || gc.recorder == nil {
		return repoMeta, err
	}

	return applyMetaActions(repoMeta, gc.recorder.actions), nil
}

// applyMetaActions mirrors on a copy of repoMeta what RemoveRepoReference does to the fields
// retention reads: the reference's tag rows go, and once no tag points to the digest its
// statistics, signatures and referrers go with them.
func applyMetaActions(repoMeta mTypes.RepoMeta, actions []metaAction) mTypes.RepoMeta {
	if len(actions) == 0 {
		return repoMeta
	}

	repoMeta.Tags = maps.Clone(repoMeta.Tags)
	repoMeta.Statistics = maps.Clone(repoMeta.Statistics)
	repoMeta.Signatures = maps.Clone(repoMeta.Signatures)
	repoMeta.Referrers = maps.Clone(repoMeta.Referrers)

	for _, action := range actions {
		if action.signature {
			continue
		}

		digest := action.digest.String()

		if action.reference == digest {
			maps.DeleteFunc(repoMeta.Tags, func(_ mTypes.Tag, desc mTypes.Descriptor) bool {
				return desc.Digest == digest
			})
		} else {
			delete(repoMeta.Tags, action.reference)
		}

		referenced := false

		for _, desc := range repoMeta.Tags {
			if desc.Digest == digest {
				referenced = true

				break
			}
		}

		if !referenced {
			delete(repoMeta.Statistics, digest)
			delete(repoMeta.Signatures, digest)
			delete(repoMeta.Referrers, digest)
		}
	}

	return repoMeta
}

// deferredWrites reports how many metaDB writes the scan has recorded so far, so a retention
// snapshot can be rechecked against the same metadata view it was computed from.
func (gc GarbageCollect) deferredWrites() int {
	if gc.recorder == nil {
		return 0
	}

	return len(gc.recorder.actions)
}

// applyMetaAction replays a recorded metaDB write with the error handling its call site would
// have applied had it written directly.
func (gc GarbageCollect) applyMetaAction(action metaAction) error {
	var err error

	if action.signature {
		err = gc.metaDB.DeleteSignature(action.repo, action.subject, action.sigMeta)
	} else {
		err = gc.metaDB.RemoveRepoReference(action.repo, action.reference, action.digest)
	}

	if err == nil {
		return nil
	}

	event := gc.log.Error().Err(err).Str("module", "gc").Str("component", "metadb").
		Str("repository", action.repo).Str("digest", action.digest.String()).Str("reference", action.reference)

	switch {
	case action.bestEffort:
		event.Msg("failed to sync metaDB for stale manifest entry, continuing stale prune")

		return nil
	case action.signature && (errors.Is(err, zerr.ErrImageMetaNotFound) || errors.Is(err, zerr.ErrRepoMetaNotFound)):
		gc.log.Debug().Err(err).Str("module", "gc").Str("component", "metadb").
			Msg("signature meta already removed")

		return nil
	default:
		event.Msg("failed to sync metaDB for removed manifest")

		return err
	}
}

// ageDecision is a manifest removal the scan made because the blob was older than delay. The
// commit re-checks it: a same-digest upload during the scan refreshes the blob's age.
type ageDecision struct {
	digest godigest.Digest
	delay  time.Duration
}

// retainedSet is one metaDB-derived keep set the scan used, with the index it was computed from
// and the number of deferred metaDB writes applied to the metadata it saw.
type retainedSet struct {
	retained []string
	index    ispec.Index
	applied  int
}

// retentionSnapshot holds every keep set the scan used, one per retention pass. A pull during
// the scan changes LastPullTimestamp without touching storage, so the commit recomputes each set
// from fresh metadata. Passes are kept separately because the untagged pass runs repeatedly on a
// shrinking index; only the first pass still contains a manifest it removed.
type retentionSnapshot struct {
	tags     []retainedSet
	untagged []retainedSet
}

// scanRecorder collects the decisions of an unlocked scan that depend on state outside
// index.json, so the commit can re-check them under the lock.
type scanRecorder struct {
	ages      []ageDecision
	missing   []godigest.Digest
	retention retentionSnapshot
}

func (gc GarbageCollect) noteMissing(digest godigest.Digest) {
	if gc.scan != nil {
		gc.scan.missing = append(gc.scan.missing, digest)
	}
}

// auditBuffer holds the audit records a scan would have written. They are published only when the
// plan commits; a rejected plan's proposed deletions never happened.
type auditBuffer struct {
	records []slog.Record
}

func (b *auditBuffer) Enabled(context.Context, slog.Level) bool { return true }

func (b *auditBuffer) Handle(_ context.Context, record slog.Record) error {
	b.records = append(b.records, record)

	return nil
}

func (b *auditBuffer) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &auditBufferView{parent: b, attrs: slices.Clone(attrs)}
}

func (b *auditBuffer) WithGroup(string) slog.Handler { return b }

// publish writes the buffered records to target and drains the buffer, so calling it again is a
// no-op. It runs as soon as the index write that makes the removals durable has succeeded, so a
// later cleanup failure cannot lose them.
func (b *auditBuffer) publish(ctx context.Context, target *zlog.Logger) {
	records := b.records
	b.records = nil

	if target == nil || target.Logger == nil {
		return
	}

	handler := target.Handler()

	for _, record := range records {
		if handler.Enabled(ctx, record.Level) {
			_ = handler.Handle(ctx, record)
		}
	}
}

// auditBufferView is a handler derived through WithAttrs that writes into its parent buffer.
type auditBufferView struct {
	parent *auditBuffer
	attrs  []slog.Attr
}

func (v *auditBufferView) Enabled(context.Context, slog.Level) bool { return true }

func (v *auditBufferView) Handle(ctx context.Context, record slog.Record) error {
	record = record.Clone()
	record.AddAttrs(v.attrs...)

	return v.parent.Handle(ctx, record)
}

func (v *auditBufferView) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &auditBufferView{parent: v.parent, attrs: append(slices.Clone(v.attrs), attrs...)}
}

func (v *auditBufferView) WithGroup(string) slog.Handler { return v }

// readLockedStore takes the store read lock around each blob read and stat, which the store
// expects its callers to hold. PutImageManifest rewrites a missing or wrong-sized manifest blob
// in place under the write lock, so an unlocked read could see a partially written document, and
// StatBlob resolves dedupe placeholders through the cache and drops a record whose origin it
// cannot find, which an unlocked stat could do to an origin that dedupe is moving.
type readLockedStore struct {
	types.ImageStore
}

// errBlobDigestMismatch reports that the scan read a blob whose content does not hash to the
// digest it was requested by. The scan memoizes what it reads, and a corrupt manifest can be
// repaired in place without changing index.json, so a plan built from it must not commit.
var errBlobDigestMismatch = errors.New("gc scan read a blob that does not match its digest")

func (s readLockedStore) GetBlobContent(repo string, digest godigest.Digest) ([]byte, error) {
	if err := digest.Validate(); err != nil {
		return nil, err
	}

	var content []byte

	err := s.ImageStore.WithRepoReadLock(repo, func() error {
		var readErr error

		content, readErr = s.ImageStore.GetBlobContent(repo, digest)

		return readErr
	})
	if err != nil {
		return nil, err
	}

	if digest.Algorithm().FromBytes(content) != digest {
		return nil, fmt.Errorf("%w: %s", errBlobDigestMismatch, digest)
	}

	return content, nil
}

func (s readLockedStore) StatBlob(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	return s.statLocked(repo, s.ImageStore.StatBlob, digest)
}

func (s readLockedStore) StatBlobEntry(repo string, digest godigest.Digest) (bool, int64, time.Time, error) {
	return s.statLocked(repo, s.ImageStore.StatBlobEntry, digest)
}

func (s readLockedStore) statLocked(repo string,
	stat func(string, godigest.Digest) (bool, int64, time.Time, error), digest godigest.Digest,
) (bool, int64, time.Time, error) {
	var (
		exists  bool
		size    int64
		modtime time.Time
	)

	err := s.ImageStore.WithRepoReadLock(repo, func() error {
		var statErr error

		exists, size, modtime, statErr = stat(repo, digest)

		return statErr
	})

	return exists, size, modtime, err
}

func (s readLockedStore) ConcurrentReadSafe() bool {
	reader, ok := s.ImageStore.(interface{ ConcurrentReadSafe() bool })

	return ok && reader.ConcurrentReadSafe()
}

// repoPlan is the outcome of scanning a repository without holding the lock: the edited index,
// the metaDB writes that edit implies, and the blobs eligible for deletion. It is only valid
// against the exact index.json bytes it was computed from.
type repoPlan struct {
	indexBefore     []byte
	index           ispec.Index
	manifestsBefore int
	metaActions     []metaAction
	stalePruned     []ispec.Descriptor
	ageDecisions    []ageDecision
	missingRefs     []godigest.Digest
	retention       retentionSnapshot
	audit           *auditBuffer
	blobs           []godigest.Digest
}

// planRepo scans a repository without the cleanup lock. It does not change storage or metaDB:
// index edits land in plan.index and metaDB writes in plan.metaActions, applied by commitRepo.
func (gc GarbageCollect) planRepo(ctx context.Context, repo string) (*repoPlan, error) {
	raw, err := gc.snapshotIndex(repo)
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			err = zerr.ErrRepoNotFound
		}

		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to read index.json in repo")

		return nil, err
	}

	var index ispec.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("invalid JSON")

		return nil, zerr.ErrRepoBadVersion
	}

	plan := &repoPlan{indexBefore: raw, manifestsBefore: len(index.Manifests), audit: &auditBuffer{}}
	dryRun := gc.opts.ImageRetention.DryRun

	// Blobs are listed right after index.json was read, so every manifest in the snapshot had its
	// blob written before the listing started and cannot be mistaken for stale. A manifest the
	// listing contains but a later read misses vanished mid-scan.
	var allBlobs []godigest.Digest

	if !dryRun {
		if allBlobs, err = gc.listBlobs(repo); err != nil {
			return nil, err
		}
	}

	planner := gc
	planner.scan = &scanRecorder{}
	planner.memos = &sync.Map{}
	planner.imgStore = readLockedStore{ImageStore: gc.imgStore}

	if gc.metaDB != nil {
		planner.recorder = &metaRecorder{}
	}

	if gc.auditLog != nil {
		buffered := zlog.Logger{Logger: slog.New(plan.audit)}
		planner.auditLog = &buffered
		planner.policyMgr = retention.NewPolicyManager(gc.opts.ImageRetention, gc.log, &buffered)
	}

	planner.memos.Store(repo, common.NewWalkMemo())

	planner.memo(repo).Prefetch(ctx, planner.imgStore, repo, index.Manifests, gc.log)
	if zcommon.IsContextDone(ctx) {
		return nil, ctx.Err()
	}

	if err := planner.removeTagsPerRetentionPolicy(ctx, repo, &index); err != nil {
		return nil, err
	}

	if err := planner.removeManifestsPerRepoPolicy(ctx, repo, &index); err != nil {
		return nil, err
	}

	if err := planner.removeUnknownMediaTypeManifestEntries(repo, &index); err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
			Msg("failed to prune unknown media type manifest entries")

		return nil, err
	}

	stalePruned, err := planner.removeStaleManifestEntriesFromBlobs(repo, &index, allBlobs)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
			Msg("failed to prune stale manifest entries")

		return nil, err
	}

	plan.index = index
	plan.stalePruned = stalePruned
	plan.ageDecisions = planner.scan.ages
	plan.retention = planner.scan.retention

	if planner.recorder != nil {
		plan.metaActions = planner.recorder.actions
	}

	if dryRun {
		return plan, nil
	}

	listed := make(map[godigest.Digest]struct{}, len(allBlobs))
	for _, digest := range allBlobs {
		listed[digest] = struct{}{}
	}

	refBlobs, missing, err := common.GetReferencedBlobsFromIndex(ctx, planner.memo(repo), planner.imgStore, repo,
		index, gc.log)
	if err != nil {
		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get referenced blobs in repo")

		return nil, err
	}

	// A manifest that was listed but could not be read vanished after the listing. Its
	// dependencies are missing from refBlobs, so the plan would treat them as orphans.
	// Manifests missing from the listing too (sparse indexes) are legitimately absent now, but
	// one restored before commit would leave index.json unchanged with its dependencies planned
	// for deletion, so the commit checks they are still absent.
	unreadable := slices.Concat(planner.scan.missing, slices.Collect(maps.Keys(missing)))

	for _, digest := range unreadable {
		if _, ok := listed[digest]; ok {
			return nil, errScanConflict
		}

		plan.missingRefs = append(plan.missingRefs, digest)
	}

	plan.blobs = make([]godigest.Digest, 0)

	for _, digest := range allBlobs {
		if zcommon.IsContextDone(ctx) {
			return nil, ctx.Err()
		}

		if err := digest.Validate(); err != nil {
			gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).
				Str("digest", digest.String()).Msg("failed to parse digest")

			return nil, err
		}

		if _, ok := refBlobs[digest]; ok {
			continue
		}

		canGC, err := isBlobOlderThan(planner.imgStore, repo, digest, gc.opts.Delay, gc.log)
		if err != nil {
			gc.log.Warn().Err(err).Str("module", "gc").Str("repository", repo).
				Str("digest", digest.String()).Msg("skipping orphan blob after StatBlobEntry failure, continuing GC")

			continue
		}

		if canGC {
			plan.blobs = append(plan.blobs, digest)
		}
	}

	return plan, nil
}

// snapshotIndex reads index.json under the read lock: DeleteImageManifest rewrites the file in
// place, so an unlocked read could see a truncated document.
func (gc GarbageCollect) snapshotIndex(repo string) ([]byte, error) {
	var raw []byte

	err := gc.imgStore.WithRepoReadLock(repo, func() error {
		var readErr error

		raw, readErr = gc.imgStore.GetIndexContent(repo)

		return readErr
	})

	return raw, err
}

// listBlobs returns the repository's blobs; a repository without a blobs directory has none.
func (gc GarbageCollect) listBlobs(repo string) ([]godigest.Digest, error) {
	allBlobs, err := gc.imgStore.GetAllBlobs(repo)
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return []godigest.Digest{}, nil
		}

		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get all blobs")

		return nil, err
	}

	return allBlobs, nil
}

// commitRepo applies a plan. It must run under the repository cleanup lock. It returns
// committed=false without changing anything when storage no longer matches what the plan was
// computed from.
func (gc GarbageCollect) commitRepo(ctx context.Context, repo string, plan *repoPlan) (bool, error) {
	if zcommon.IsContextDone(ctx) {
		return false, ctx.Err()
	}

	current, err := gc.imgStore.GetIndexContent(repo)
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			err = zerr.ErrRepoNotFound
		}

		return false, err
	}

	if !bytes.Equal(current, plan.indexBefore) {
		return false, nil
	}

	holds, err := gc.planHolds(ctx, repo, plan)
	if err != nil || !holds {
		return false, err
	}

	for _, action := range plan.metaActions {
		if zcommon.IsContextDone(ctx) {
			return false, ctx.Err()
		}

		if err := gc.applyMetaAction(action); err != nil {
			return false, err
		}
	}

	// Free stale uploads before rewriting index.json. PutIndexContent stages under
	// .uploads/ and needs free space; a leftover failed upload can be what filled the volume.
	uploadsDeleted, err := gc.deleteBlobUploads(repo, gc.opts.Delay)
	if err != nil {
		return false, err
	}

	if zcommon.IsContextDone(ctx) {
		return false, ctx.Err()
	}

	if err := gc.imgStore.PutIndexContent(repo, plan.index); err != nil {
		return false, err
	}

	// The manifest removals are durable from here on, whatever happens to blob cleanup.
	plan.audit.publish(ctx, gc.auditLog)

	blobsDeleted, err := gc.deletePlannedBlobs(ctx, repo, plan)
	if err != nil {
		return false, err
	}

	if err := gc.removeIdleRepository(repo); err != nil {
		return false, err
	}

	monitoring.IncGCDeleted(gc.metrics, "manifest", plan.manifestsBefore-len(plan.index.Manifests))
	monitoring.IncGCDeleted(gc.metrics, "blob", blobsDeleted)
	monitoring.IncGCDeleted(gc.metrics, "upload", uploadsDeleted)

	return true, nil
}

// planHolds re-checks, under the lock, the scan decisions that an unchanged index.json does not
// cover. Equal index bytes do not cover a manifest blob deleted and restored during the scan, a
// same-digest upload that refreshes a blob's age, or a pull that changes what retention keeps.
// A stat that fails for any reason other than the blob being absent aborts the run.
func (gc GarbageCollect) planHolds(ctx context.Context, repo string, plan *repoPlan) (bool, error) {
	for _, digest := range plan.missingRefs {
		missing, err := gc.confirmBlobMissing(repo, digest)
		if err != nil {
			return false, err
		}

		if !missing {
			return false, nil
		}
	}

	for _, desc := range plan.stalePruned {
		holds, err := gc.staleDecisionHolds(repo, desc)
		if err != nil || !holds {
			return false, err
		}
	}

	for _, decision := range plan.ageDecisions {
		if !gc.ageDecisionHolds(repo, decision) {
			return false, nil
		}
	}

	if len(plan.retention.tags) == 0 && len(plan.retention.untagged) == 0 {
		return true, nil
	}

	return gc.retentionDecisionsHold(ctx, repo, plan)
}

// ageDecisionHolds re-checks that a manifest the scan removed for being older than its retention
// delay still is. A stat failure counts as a conflict.
func (gc GarbageCollect) ageDecisionHolds(repo string, decision ageDecision) bool {
	canGC, err := isBlobOlderThan(gc.imgStore, repo, decision.digest, decision.delay, gc.log)

	return err == nil && canGC
}

// staleDecisionHolds re-checks a descriptor the scan pruned because its blobs were missing.
func (gc GarbageCollect) staleDecisionHolds(repo string, desc ispec.Descriptor) (bool, error) {
	missing, err := gc.confirmBlobMissing(repo, desc.Digest)
	if err != nil {
		return false, err
	}

	if missing {
		return true, nil
	}

	if !compat.IsImageIndexMediaType(desc.MediaType) {
		return false, nil
	}

	indexImage, err := common.GetImageIndex(gc.imgStore, repo, desc.Digest, gc.log)
	if err != nil || len(indexImage.Manifests) == 0 {
		return false, nil //nolint:nilerr
	}

	for _, nested := range indexImage.Manifests {
		missing, err := gc.confirmBlobMissing(repo, nested.Digest)
		if err != nil {
			return false, err
		}

		if !missing {
			return false, nil
		}
	}

	return true, nil
}

// retentionDecisionsHold recomputes the metaDB-driven keep sets the scan used against fresh repo
// metadata, with the same deferred writes applied that the scan had applied when it computed each
// set. A recomputed set that only lost entries is accepted: the day-based rules evaluate against
// the current clock, so an entry aging out between scan and commit is expected, and the plan
// keeping it is the conservative outcome. Any entry the scan did not keep is a conflict.
func (gc GarbageCollect) retentionDecisionsHold(ctx context.Context, repo string, plan *repoPlan) (bool, error) {
	snapshot := plan.retention

	repoMeta, err := gc.metaDB.GetRepoMeta(ctx, repo)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoMetaNotFound) {
			return false, nil
		}

		gc.log.Error().Err(err).Str("module", "gc").Str("repository", repo).Msg("failed to get repoMeta")

		return false, err
	}

	quiet := retention.NewPolicyManager(gc.opts.ImageRetention, zlog.Logger{Logger: slog.New(slog.DiscardHandler)}, nil)

	for _, set := range snapshot.tags {
		view := applyMetaActions(repoMeta, plan.metaActions[:set.applied])

		if !containsAll(set.retained, quiet.GetRetainedTagsFromMetaDB(ctx, view, set.index)) {
			return false, nil
		}
	}

	for _, set := range snapshot.untagged {
		view := applyMetaActions(repoMeta, plan.metaActions[:set.applied])

		if !containsAll(set.retained, quiet.GetRetainedUntaggedFromMetaDB(ctx, view, set.index)) {
			return false, nil
		}
	}

	return true, nil
}

// containsAll reports whether every value in required is present in available.
func containsAll(available, required []string) bool {
	set := make(map[string]struct{}, len(available))
	for _, value := range available {
		set[value] = struct{}{}
	}

	for _, value := range required {
		if _, ok := set[value]; !ok {
			return false
		}
	}

	return true
}

// cloneIndex copies the descriptors and their annotation maps. RemoveManifestDescByReference
// deletes the tag annotation in place when it re-adds a last-tag row untagged, which would
// otherwise rewrite an earlier snapshot.
func cloneIndex(index ispec.Index) ispec.Index {
	out := ispec.Index{Manifests: make([]ispec.Descriptor, 0, len(index.Manifests))}

	for _, desc := range index.Manifests {
		desc.Annotations = maps.Clone(desc.Annotations)
		out.Manifests = append(out.Manifests, desc)
	}

	return out
}

// deletePlannedBlobs deletes the plan's candidates that are still past the GC delay: a
// same-digest upload during the scan refreshes the blob's modification time without touching
// index.json.
func (gc GarbageCollect) deletePlannedBlobs(ctx context.Context, repo string, plan *repoPlan) (int, error) {
	eligible := make([]godigest.Digest, 0, len(plan.blobs))

	for _, digest := range plan.blobs {
		if zcommon.IsContextDone(ctx) {
			return 0, ctx.Err()
		}

		canGC, err := isBlobOlderThan(gc.imgStore, repo, digest, gc.opts.Delay, gc.log)
		if err != nil {
			gc.log.Warn().Err(err).Str("module", "gc").Str("repository", repo).
				Str("digest", digest.String()).Msg("skipping orphan blob after StatBlobEntry failure, continuing GC")

			continue
		}

		if canGC {
			eligible = append(eligible, digest)
		}
	}

	if zcommon.IsContextDone(ctx) {
		return 0, ctx.Err()
	}

	reaped, err := gc.imgStore.CleanupRepo(repo, eligible)
	if err != nil {
		return 0, err
	}

	gc.log.Info().Str("module", "gc").Str("repository", repo).Int("count", reaped).
		Msg("garbage collected blobs")

	return reaped, nil
}
