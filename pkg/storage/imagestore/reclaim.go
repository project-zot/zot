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

const (
	// _blobstore/_reclaim/<algorithm>/<encoded> holds a digest's reclaim marker.
	globalReclaimDir = "_reclaim"
	// reclaimDeleteDeadline is how soon after its claim a sweep must start deleting a payload. It
	// is well under the claim's lease (constants.DefaultReclaimClaimLease), after which a linker
	// takes the sweep for stopped, breaks the claim and relies on the payload again.
	reclaimDeleteDeadline = 15 * time.Second
)

// reclaimMarker is what a reclaim marker holds.
type reclaimMarker struct {
	// MarkedAt is when the digest was found unowned; the sweep leaves it alone until gcDelay
	// has passed, so that a re-push or mount meanwhile reuses the payload.
	MarkedAt time.Time `json:"markedAt"`
}

func reclaimMarkerPath(rootDir string, digest godigest.Digest) string {
	return path.Join(rootDir, storageConstants.GlobalBlobsRepo, globalReclaimDir,
		digest.Algorithm().String(), digest.Encoded())
}

func (r *remoteSharedBlobLifecycle) DeleteBlobRef(digest godigest.Digest, repoPath string) error {
	// without a cache there is no index, and no sweep to tell
	if r.refs == nil {
		return nil
	}

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

	claim, err := r.refs.ClaimReclaim(digest)

	switch {
	case errors.Is(err, zerr.ErrDigestReferenced):
		// owned again: nothing to reclaim, and the next owner to go marks it again
		return r.removeReclaimMarker(markerPath)
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

	deadline := time.Now().Add(reclaimDeleteDeadline)
	globalBlobPath := path.Join(r.rootDir, storageConstants.GlobalBlobsRepo, "blobs",
		digest.Algorithm().String(), digest.Encoded())

	if err := r.deleteClaimedPayload(globalBlobPath, deadline); err != nil {
		if aerr := r.refs.AbandonReclaim(claim); aerr != nil {
			r.log.Error().Err(aerr).Str("digest", digest.String()).Msg("failed to abandon global blob reclaim")
		}

		return err
	}

	if err := r.refs.FinishReclaim(claim); err != nil {
		// Broken after the lease by a linker, which found the payload gone and stored its own.
		if errors.Is(err, zerr.ErrReclaimClaimLost) {
			r.log.Warn().Str("digest", digest.String()).Msg("global blob reclaim claim was broken")

			return nil
		}

		return err
	}

	// the payload's own origin record; a record left behind names a missing origin, which the
	// write paths heal
	if err := r.refs.DeleteBlob(digest, globalBlobPath); err != nil {
		r.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to remove reclaimed global blob from cache")
	}

	return r.removeReclaimMarker(markerPath)
}

// deleteClaimedPayload deletes a payload under a claim, as long as deadline has not passed: a
// sweep that stalled between its claim and the delete must not delete once a linker may have
// broken the claim. A delete the store has already accepted cannot be recalled, though.
func (r *remoteSharedBlobLifecycle) deleteClaimedPayload(globalBlobPath string, deadline time.Time) error {
	if time.Now().After(deadline) {
		return zerr.ErrReclaimClaimLost
	}

	if err := r.storeDriver.Delete(globalBlobPath); err != nil && !errclass.IsStorageObjectMissing(err) {
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
