package imagestore

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"time"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// Reclaiming global blobstore payloads on remote storage, where several zot instances may share
// one bucket and one cache. A payload is never deleted when its last owner goes: another instance
// may be linking the same digest at that moment. The reference index in the cache decides instead
// (see types.BlobRefIndex): a delete removes its reference and, once nothing owns the digest,
// leaves a reclaim marker; a periodic sweep claims each marked digest in the cache, which fails
// while anything owns it, and deletes the payload only under the claim. A linker adds its
// reference before relying on the payload, which fails while a claim is held, so the two never
// both proceed. The markers are only hints telling the sweep where to look; safety comes from the
// claim alone.
//
// What the claim does not cover is a delete and a push of the same repo and digest on two
// instances: a reference names a path, and the repo lock that orders the two is per instance.
// See DeleteBlobRef.

const (
	// _blobstore/_reclaim/<algorithm>/<encoded> holds a digest's reclaim marker.
	globalReclaimDir = "_reclaim"
	// reclaimDeleteDeadline is how soon after asking for its claim a sweep must start deleting a
	// payload. It is well under the claim's lease (constants.DefaultReclaimClaimLease), after which
	// a linker takes the sweep for stopped, breaks the claim and relies on the payload again.
	reclaimDeleteDeadline = 15 * time.Second
)

// reclaimMarker is what a reclaim marker holds.
type reclaimMarker struct {
	// MarkedAt is when the digest was found unowned; the sweep leaves it alone until gcDelay
	// has passed, so that a re-push or mount meanwhile reuses the payload.
	MarkedAt time.Time `json:"markedAt"`
}

// reclaimMarkerPath is where the hint that digest may be unowned is kept, under _blobstore.
func reclaimMarkerPath(rootDir string, digest godigest.Digest) string {
	return path.Join(rootDir, storageConstants.GlobalBlobsRepo, globalReclaimDir,
		digest.Algorithm().String(), digest.Encoded())
}

func (r *remoteSharedBlobLifecycle) DeleteBlobRef(digest godigest.Digest, repoPath string) error {
	// without a cache there is no index, and no sweep to tell
	if r.refs == nil {
		return nil
	}

	/* The placeholder is gone by now, and its reference goes next, so that a failure in between
	only leaks the reference. Within an instance the repo lock keeps a push of the same blob to
	the same repo out of that gap. Across instances nothing does: another instance can add the
	reference again (a no-op, as the path is still recorded) and write the placeholder anew, and
	this removal then takes away the reference that push relied on, leaving the payload to a
	later sweep. Follow-up: tag each reference with a generation, read before the placeholder is
	deleted, and remove it only if unchanged, with the linker adding again once its placeholder
	is written; or serialize link and delete per path with a lease in the cache. */
	unowned, err := r.refs.RemoveReference(digest, repoPath)
	if err != nil || !unowned {
		return err
	}

	// Only a payload the index records is for the sweep: a digest it does not know, such as a
	// copy pushed with dedupe off, has none, and a marker for it would never be cleared.
	if _, err := r.refs.GetReferences(digest); err != nil {
		if errors.Is(err, zerr.ErrCacheMiss) {
			return nil
		}

		return err
	}

	return r.markGlobalBlobReclaimable(digest)
}

// markGlobalBlobReclaimable leaves a reclaim marker for digest. An existing one is kept, so that deletes
// repeated meanwhile do not keep pushing the reclaim out.
func (r *remoteSharedBlobLifecycle) markGlobalBlobReclaimable(digest godigest.Digest) error {
	markerPath := reclaimMarkerPath(r.rootDir, digest)

	if _, err := r.storeDriver.Stat(markerPath); err == nil {
		return nil
	} else if !errclass.IsStorageObjectMissing(err) {
		return err
	}

	buf, err := json.Marshal(reclaimMarker{MarkedAt: time.Now()})
	if err != nil {
		return err
	}

	_, err = r.storeDriver.WriteFile(markerPath, buf)

	return err
}

func (r *remoteSharedBlobLifecycle) ReclaimGlobalBlobs(ctx context.Context, delay time.Duration) error {
	// without a cache there is no index to tell an unowned payload by
	if r.refs == nil {
		return nil
	}

	markersDir := path.Join(r.rootDir, storageConstants.GlobalBlobsRepo, globalReclaimDir)

	algorithmPaths, err := r.storeDriver.List(markersDir)
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return nil
		}

		return err
	}

	var sweepErr error

	for _, algorithmPath := range algorithmPaths {
		algorithm := godigest.Algorithm(path.Base(algorithmPath))

		markerPaths, err := r.storeDriver.List(algorithmPath)
		if err != nil {
			if errclass.IsStorageObjectMissing(err) {
				continue
			}

			return err
		}

		for _, markerPath := range markerPaths {
			if err := ctx.Err(); err != nil {
				return err
			}

			digest := godigest.NewDigestFromEncoded(algorithm, path.Base(markerPath))
			if digest.Validate() != nil {
				continue
			}

			// one digest failing must not hold up the rest; the next sweep retries it
			if err := r.reclaimGlobalBlob(digest, delay); err != nil {
				r.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to reclaim global blob")

				sweepErr = errors.Join(sweepErr, err)
			}
		}
	}

	return sweepErr
}

// reclaimGlobalBlob deletes the payload of one marked digest, if nothing has owned it for delay.
func (r *remoteSharedBlobLifecycle) reclaimGlobalBlob(digest godigest.Digest, delay time.Duration) error {
	markerPath := reclaimMarkerPath(r.rootDir, digest)

	buf, err := r.storeDriver.ReadFile(markerPath)
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return nil
		}

		return err
	}

	// an unreadable marker still says "look here", so it is taken as old
	var marker reclaimMarker
	if err := json.Unmarshal(buf, &marker); err != nil {
		r.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to parse global blob reclaim marker")
	}

	// a re-push or mount within delay reuses the payload without uploading it again
	if time.Since(marker.MarkedAt) < delay {
		return nil
	}

	/* The delete has to land while the claim is held: past the lease, a linker may break it and
	rely on the payload. The lease runs from when the cache took the claim, so the deadline is
	taken before asking for it: a slow claim response, or a stall before it is acted on, eats into
	the window instead of starting a fresh one. It is read off this instance's clock, which the
	monotonic reading keeps from jumping, rather than off claim.At, which may be the cache
	server's. */
	deadline := time.Now().Add(r.deleteDeadline)

	claim, err := r.refs.ClaimReclaim(digest)

	switch {
	case errors.Is(err, zerr.ErrDigestReferenced):
		// owned again: nothing to reclaim, and the next owner to go marks it again
		return r.dropReclaimMarker(digest, markerPath)
	case errors.Is(err, zerr.ErrDigestClaimed):
		// another sweep is on it
		return nil
	case errors.Is(err, zerr.ErrCacheMiss):
		// The index does not know the payload, so who owns it cannot be told, as when the cache
		// was lost or replaced. It stays, marked, until the index knows it again.
		return nil
	case err != nil:
		return err
	}

	globalBlobPath := path.Join(r.rootDir, storageConstants.GlobalBlobsRepo, "blobs",
		digest.Algorithm().String(), digest.Encoded())

	if err := r.deleteClaimedPayload(globalBlobPath, deadline); err != nil {
		if aerr := r.refs.AbandonReclaim(claim); aerr != nil {
			r.log.Error().Err(aerr).Str("digest", digest.String()).Msg("failed to abandon global blob reclaim")
		}

		return err
	}

	/* The payload's own origin record goes while the claim still fences linkers out. Once
	FinishReclaim releases it, a waiting push stores a new payload at the same path and records it
	as the origin; removing the record then would take that origin away and promote the push's
	placeholder in its place, leaving the pushed blob unreadable. Past the deadline a linker may
	have broken the claim already, so the record is left: one naming a missing origin is healed
	by the write paths, as is one left by a failed removal. */
	if time.Now().Before(deadline) {
		if err := r.refs.DeleteBlob(digest, globalBlobPath); err != nil {
			r.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to remove reclaimed global blob from cache")
		}
	}

	if err := r.refs.FinishReclaim(claim); err != nil {
		// Broken after the lease by a linker, which found the payload gone and stored its own.
		if errors.Is(err, zerr.ErrReclaimClaimLost) {
			r.log.Warn().Str("digest", digest.String()).Msg("global blob reclaim claim was broken")

			return nil
		}

		return err
	}

	return r.dropReclaimMarker(digest, markerPath)
}

// dropReclaimMarker removes digest's marker, then marks digest again if it is unowned by now. A
// last owner that went while this sweep was deciding found the marker still there and left it,
// so without the second look its payload would never be swept.
func (r *remoteSharedBlobLifecycle) dropReclaimMarker(digest godigest.Digest, markerPath string) error {
	if err := r.removeReclaimMarker(markerPath); err != nil {
		return err
	}

	refs, err := r.refs.GetReferences(digest)
	if err != nil {
		// no record: the payload is gone, or the index does not know it, so there is nothing to sweep
		if errors.Is(err, zerr.ErrCacheMiss) {
			return nil
		}

		return err
	}

	if len(refs) > 0 {
		return nil
	}

	return r.markGlobalBlobReclaimable(digest)
}

// contextDeleter is implemented by the remote storage drivers.
type contextDeleter interface {
	DeleteContext(ctx context.Context, path string) error
}

// deleteClaimedPayload deletes a payload under a claim, as long as deadline has not passed: a
// sweep that stalled between its claim and the delete must not delete once a linker may have
// broken the claim. The deadline also bounds the delete itself, and the SDK's retries of it,
// where the driver allows; a delete the store has already accepted cannot be recalled, though.
func (r *remoteSharedBlobLifecycle) deleteClaimedPayload(globalBlobPath string, deadline time.Time) error {
	if time.Now().After(deadline) {
		return zerr.ErrReclaimClaimLost
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	var err error

	if deleter, ok := r.storeDriver.(contextDeleter); ok {
		err = deleter.DeleteContext(ctx, globalBlobPath)
	} else {
		err = r.storeDriver.Delete(globalBlobPath)
	}

	if err != nil && !errclass.IsStorageObjectMissing(err) {
		return err
	}

	return nil
}

func (r *remoteSharedBlobLifecycle) removeReclaimMarker(markerPath string) error {
	if err := r.storeDriver.Delete(markerPath); err != nil && !errclass.IsStorageObjectMissing(err) {
		return err
	}

	return nil
}
