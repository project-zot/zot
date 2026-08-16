package imagestore

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"time"

	guuid "github.com/gofrs/uuid"
	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// Deferred reclaim of global blobstore payloads on stores that track repository ownership
// only as logical refs (remote backends).
//
// The store locks are process-local, but several zot instances may share one bucket and one
// blob-ref index. Deleting a payload the moment its last ref goes away is then a
// check-then-act race: another instance can link the digest into a repository between the
// reference check and the delete, and is left holding a ref to nothing. Coordination
// therefore goes through marker objects in the bucket itself, which every instance sees:
//
//   - Dropping the last ref only writes a reclaim marker (markGlobalBlobReclaimable).
//   - A periodic sweep (ReclaimGlobalBlobs) deletes payloads whose marker is older than the
//     reclaim delay. It first writes a claim into the marker, then looks for pins and refs,
//     and only then deletes.
//   - Anything about to link a digest (guardGlobalBlobLink) checks for a marker. If there is
//     one it writes a pin, then waits for any claim to clear, before it looks at the payload.
//
// The sweep claims before it reads pins and the linker pins before it reads the claim, so at
// least one of the two always sees the other.
//
// A linker that found no marker skips the pin, which keeps the common path to a single read.
// A marker written after that read cannot be swept until the reclaim delay has passed, and a
// linker still running after reclaimLatePinAfter pins itself anyway, long before then. So a
// sweep finds either the linker's ref or its pin however long the link takes. Pins are
// refreshed while held, so a slow link is never mistaken for a crashed one. A late pin that
// cannot be written is retried, and a link that ends without one is checked afterwards (see
// confirmLinkedWhileUnpinned) rather than trusted. What remains is
// an assumption about clocks, not durations: instances must agree on the time to within
// MinGlobalReclaimDelay minus reclaimLatePinAfter, which is why the delay has a floor.
//
// The object store offers no compare-and-swap, so a claim is an overwrite followed by a
// read-back and cannot by itself keep two sweeps off the same digest. That exclusion comes
// from the shared cache instead: a sweep holds its reclaim lock (reclaimLocker; Redis and
// DynamoDB provide one) from before the claim until it is done. A cache without one is not
// shared between instances, and there the blobstore write lock already serialises sweeps.
//
// One limit remains. A linker stops honouring a claim after the lease, and the sweep bounds
// its delete by the same clock (see deleteGlobalBlobBefore). That stops a stalled or retried
// request from going out late, but cannot recall one the store has already accepted.
const (
	// MinGlobalReclaimDelay is the shortest reclaim delay that is safe with several instances
	// on one store: it must outlast reclaimLatePinAfter plus the clock skew between instances.
	MinGlobalReclaimDelay = 5 * time.Minute

	// defaultReclaimLatePinAfter is how long a linker that found no marker may run unpinned.
	defaultReclaimLatePinAfter = MinGlobalReclaimDelay / 5

	// _blobstore/_reclaim/<algorithm>/<encoded> holds a digest's reclaim marker.
	globalReclaimDir = "_reclaim"
	// _blobstore/_reclaim_pins/<algorithm>/<encoded>/<id> holds one pin per in-flight linker.
	globalReclaimPinsDir = "_reclaim_pins"

	// defaultReclaimClaimLease bounds how long a claim is honoured. A sweep must have finished
	// deleting within half of it; a linker stops waiting after all of it.
	defaultReclaimClaimLease = 30 * time.Second
	// reclaimPinTTL is the age past which a pin is taken to be left over from a crashed linker.
	// Live linkers rewrite theirs every reclaimPinRefresh, well inside it.
	reclaimPinTTL     = time.Hour
	reclaimPinRefresh = reclaimPinTTL / 4
	// reclaimPinRetriesPerAllowance sets how often a failed pin write is retried: this many
	// times per reclaimLatePinAfter, so every five seconds by default.
	reclaimPinRetriesPerAllowance = 12

	reclaimPollInterval = 100 * time.Millisecond

	// reclaimLockTTL is how long a crashed sweep's cache lock keeps other sweeps off its
	// digest. The lock is only needed for half a claim lease; the rest is room for clock skew,
	// which matters to caches that judge expiry by the caller's clock.
	reclaimLockTTL = MinGlobalReclaimDelay
)

// reclaimLocker is implemented by cache drivers that several instances can share. The lock
// makes sweeps of one digest mutually exclusive across instances.
type reclaimLocker interface {
	TryLockBlobReclaim(digest godigest.Digest, ttl time.Duration) (unlock func(), acquired bool, err error)
}

// contextDeleter is implemented by the remote storage drivers.
type contextDeleter interface {
	DeleteContext(ctx context.Context, path string) error
}

// reclaimMarker is the content of a reclaim marker object.
type reclaimMarker struct {
	MarkedAt time.Time `json:"markedAt"`
	// ClaimID is set while a sweep is deciding whether to delete the payload.
	ClaimID   string    `json:"claimId,omitempty"`
	ClaimedAt time.Time `json:"claimedAt,omitzero"`
}

func (is *ImageStore) reclaimMarkerPath(digest godigest.Digest) string {
	return path.Join(is.rootDir, storageConstants.GlobalBlobsRepo, globalReclaimDir,
		digest.Algorithm().String(), digest.Encoded())
}

func (is *ImageStore) reclaimPinDir(digest godigest.Digest) string {
	return path.Join(is.rootDir, storageConstants.GlobalBlobsRepo, globalReclaimPinsDir,
		digest.Algorithm().String(), digest.Encoded())
}

func (is *ImageStore) reclaimLease() time.Duration {
	if is.reclaimClaimLease > 0 {
		return is.reclaimClaimLease
	}

	return defaultReclaimClaimLease
}

func (is *ImageStore) reclaimLatePin() time.Duration {
	if is.reclaimLatePinAfter > 0 {
		return is.reclaimLatePinAfter
	}

	return defaultReclaimLatePinAfter
}

// readReclaimMarker returns nil, nil when digest has no marker.
func (is *ImageStore) readReclaimMarker(digest godigest.Digest) (*reclaimMarker, error) {
	buf, err := is.storeDriver.ReadFile(is.reclaimMarkerPath(digest))
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return nil, nil //nolint:nilnil // no marker is an expected answer, not an error
		}

		return nil, err
	}

	// Markers are never written empty, so an empty object is not one.
	if len(buf) == 0 {
		return nil, nil //nolint:nilnil // as above
	}

	marker := &reclaimMarker{}
	if err := json.Unmarshal(buf, marker); err != nil {
		// An unreadable marker still means "reclaim pending": keep it, unclaimed and with a
		// zero MarkedAt so the next sweep is free to take it.
		is.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to parse global blob reclaim marker")

		return &reclaimMarker{}, nil
	}

	return marker, nil
}

func (is *ImageStore) writeReclaimMarker(digest godigest.Digest, marker reclaimMarker) error {
	buf, err := json.Marshal(marker)
	if err != nil {
		return err
	}

	_, err = is.storeDriver.WriteFile(is.reclaimMarkerPath(digest), buf)

	return err
}

func (is *ImageStore) removeReclaimMarker(digest godigest.Digest) error {
	if err := is.storeDriver.Delete(is.reclaimMarkerPath(digest)); err != nil && !errclass.IsStorageObjectMissing(err) {
		return err
	}

	return nil
}

// markGlobalBlobReclaimable records that digest's global payload lost its last known ref.
// An existing marker is left alone so repeated deletes do not keep pushing the reclaim out.
func (is *ImageStore) markGlobalBlobReclaimable(digest godigest.Digest) error {
	marker, err := is.readReclaimMarker(digest)
	if err != nil || marker != nil {
		return err
	}

	return is.writeReclaimMarker(digest, reclaimMarker{MarkedAt: time.Now()})
}

// guardGlobalBlobLink runs link, which is about to give a repository a ref to digest's global
// payload (or write that payload), so that a concurrent sweep on any instance cannot delete
// the payload underneath it. Everything that inspects the payload must happen inside link:
// by the time it runs, a sweep has either seen this linker's pin and backed off, or finished.
//
// The usual cost is one read that finds no marker.
func (is *ImageStore) guardGlobalBlobLink(digest godigest.Digest, link func() error) error {
	if !is.lifecycle.UsesLogicalRepoRefs() {
		return link()
	}

	marker, err := is.readReclaimMarker(digest)
	if err != nil {
		// Fail closed: without the marker there is no telling whether a sweep is under way.
		return err
	}

	if marker == nil {
		// No sweep can touch this digest for a while yet, so the pin is put off and most
		// links finish without ever writing one.
		pin, err := is.holdReclaimPin(digest, is.reclaimLatePin())
		if err != nil {
			return err
		}

		linkErr := link()

		if unpinned := pin.release(); unpinned && linkErr == nil {
			return is.confirmLinkedWhileUnpinned(digest)
		}

		return linkErr
	}

	// The pin has to be visible before the claim is read; see the protocol note above.
	pin, err := is.holdReclaimPin(digest, 0)
	if err != nil {
		return err
	}
	defer pin.release()

	if err := is.awaitReclaimClaim(digest); err != nil {
		return err
	}

	return link()
}

// confirmLinkedWhileUnpinned is the fallback for a link whose late pin was due but could never
// be written: for part of its run a sweep could see neither its pin nor, yet, its ref. The ref
// is in the index now, so wait out any sweep that got in before it, then see what is left. A
// missing payload fails the link as retryable instead of leaving a ref to nothing behind a
// success; the caller's retry starts from a store the sweep is done with.
func (is *ImageStore) confirmLinkedWhileUnpinned(digest godigest.Digest) error {
	if err := is.awaitReclaimClaim(digest); err != nil {
		return err
	}

	globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)

	if _, err := is.storeDriver.Stat(globalBlobPath); err != nil {
		if errclass.IsStorageObjectMissing(err) {
			is.log.Error().Str("digest", digest.String()).
				Msg("global blob was reclaimed while an unpinned link was running")

			return errclass.MarkTransient(zerr.ErrGlobalBlobReclaimed)
		}

		return err
	}

	return nil
}

// reclaimPin is one linker's pin on a digest, kept fresh for as long as it is held.
type reclaimPin struct {
	is     *ImageStore
	digest godigest.Digest
	path   string
	// retry is how soon a failed write is tried again.
	retry time.Duration
	stop  chan struct{}
	done  chan struct{}
	// due and written are owned by the keeper goroutine until done is closed. due is set
	// once the first write has been attempted, written once any write has succeeded.
	due     bool
	written bool
}

// holdReclaimPin pins digest after the given delay and keeps the pin's timestamp fresh until
// release. With no delay the first write happens before it returns, and its error is returned.
func (is *ImageStore) holdReclaimPin(digest godigest.Digest, after time.Duration) (*reclaimPin, error) {
	pinID, err := guuid.NewV4()
	if err != nil {
		return nil, err
	}

	pin := &reclaimPin{
		is:     is,
		digest: digest,
		path:   path.Join(is.reclaimPinDir(digest), pinID.String()),
		// A handful of tries inside the unpinned allowance, however that is configured.
		retry: is.reclaimLatePin() / reclaimPinRetriesPerAllowance,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}

	if after <= 0 {
		if err := pin.write(); err != nil {
			return nil, err
		}

		pin.due, pin.written = true, true
		after = reclaimPinRefresh
	}

	go pin.keep(after)

	return pin, nil
}

func (pin *reclaimPin) write() error {
	_, err := pin.is.storeDriver.WriteFile(pin.path, []byte(time.Now().UTC().Format(time.RFC3339Nano)))

	return err
}

// keep writes the pin once first has passed and then again every reclaimPinRefresh.
func (pin *reclaimPin) keep(first time.Duration) {
	defer close(pin.done)

	timer := time.NewTimer(first)
	defer timer.Stop()

	for {
		select {
		case <-pin.stop:
			return
		case <-timer.C:
		}

		pin.due = true

		if err := pin.write(); err != nil {
			// The link is already running and cannot be called back, so keep trying, and
			// soon: waiting for the regular refresh would leave it unpinned far too long.
			// If no try ever succeeds, release reports it and the link is double-checked.
			pin.is.log.Warn().Err(err).Str("digest", pin.digest.String()).
				Msg("failed to write global blob reclaim pin, retrying")

			timer.Reset(pin.retry)

			continue
		}

		pin.written = true

		timer.Reset(reclaimPinRefresh)
	}
}

// release stops the keeper and removes the pin. It reports whether the pin was due but never
// got written, in which case the link ran without the protection it was owed.
func (pin *reclaimPin) release() bool {
	close(pin.stop)
	<-pin.done

	if !pin.written {
		return pin.due
	}

	if err := pin.is.storeDriver.Delete(pin.path); err != nil && !errclass.IsStorageObjectMissing(err) {
		// Harmless beyond delaying this digest's reclaim until the pin ages out.
		pin.is.log.Warn().Err(err).Str("digest", pin.digest.String()).Msg("failed to remove global blob reclaim pin")
	}

	return false
}

// awaitReclaimClaim blocks while another sweep holds a claim on digest. It measures the wait
// on the local clock only, so it does not depend on instances agreeing on the time.
func (is *ImageStore) awaitReclaimClaim(digest godigest.Digest) error {
	deadline := time.Now().Add(is.reclaimLease())

	for {
		marker, err := is.readReclaimMarker(digest)
		if err != nil {
			return err
		}

		if marker == nil || marker.ClaimID == "" {
			return nil
		}

		if time.Now().After(deadline) {
			// A sweep abandons its claim well inside the lease, so this one is dead.
			//
			// Proceeding is safe against a sweep that is merely slow, not only a crashed one:
			// the sweep does not just check the clock before deleting. Its payload delete
			// carries a context deadline at half the lease (deleteGlobalBlobBefore), so a
			// stalled or SDK-retried delete is cancelled a full half-lease before any linker
			// can get here, and it skips the index delete once that point has passed. The
			// claim is therefore not renewed or fenced; the lease is enforced on the sweep's
			// side. What stays open is listed at claimAndDeleteGlobalBlob.
			is.log.Warn().Str("digest", digest.String()).Str("claim", marker.ClaimID).
				Msg("global blob reclaim claim outlived its lease, ignoring it")

			return nil
		}

		time.Sleep(reclaimPollInterval)
	}
}

// ReclaimGlobalBlobs deletes global blobstore payloads that were marked reclaimable at least
// delay ago and are still unreferenced. It does nothing on stores that keep per-repo copies.
//
// A delay below MinGlobalReclaimDelay is only safe when no other instance uses the store.
func (is *ImageStore) ReclaimGlobalBlobs(ctx context.Context, delay time.Duration) error {
	if !is.lifecycle.UsesLogicalRepoRefs() || is.isCacheNil() {
		// Without the blob-ref index there is no way to tell a payload is unreferenced.
		return nil
	}

	// This pass must judge manifest references as they are now, not as last cached.
	is.repoGraphs.refresh()

	markersDir := path.Join(is.rootDir, storageConstants.GlobalBlobsRepo, globalReclaimDir)

	algorithmPaths, err := is.storeDriver.List(markersDir)
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return nil
		}

		return err
	}

	var sweepErr error

	for _, algorithmPath := range algorithmPaths {
		algorithm := godigest.Algorithm(path.Base(algorithmPath))

		markerPaths, err := is.storeDriver.List(algorithmPath)
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
			if err := digest.Validate(); err != nil {
				continue
			}

			// One digest failing must not hold up the rest; it is retried next sweep.
			if err := is.reclaimGlobalBlob(digest, delay); err != nil {
				is.log.Error().Err(err).Str("digest", digest.String()).Msg("failed to reclaim global blob")

				sweepErr = errors.Join(sweepErr, err)
			}
		}
	}

	return sweepErr
}

// reclaimGlobalBlob runs the sweep side of the protocol for one marked digest.
func (is *ImageStore) reclaimGlobalBlob(digest godigest.Digest, delay time.Duration) error {
	marker, err := is.readReclaimMarker(digest)
	if err != nil || marker == nil {
		return err
	}

	now := time.Now()
	if now.Sub(marker.MarkedAt) < delay {
		return nil
	}

	// Leave a digest another sweep is working on. A claim twice the lease old is dead.
	if marker.ClaimID != "" && now.Sub(marker.ClaimedAt) < 2*is.reclaimLease() {
		return nil
	}

	// The manifest-graph walk covers repositories whose ownership records are missing from the
	// index. It can be slow, and such repositories are not racing linkers, so it runs before
	// the claim rather than inside the lease.
	if known, err := is.reclaimIndexKnows(digest); err != nil || !known {
		return err
	}

	referenced, err := is.isDigestReferencedAcrossRepos(digest)
	if err != nil {
		// Keep the marker: dropping it on a failed check would leak the payload for good.
		return err
	}

	if referenced {
		return is.dropSpentReclaimMarker(digest)
	}

	inGraphs, err := is.isDigestInOtherRepoGraphs(storageConstants.GlobalBlobsRepo, digest)
	if err != nil {
		return err
	}

	if inGraphs {
		// Keep the marker. A manifest reference comes with no index ref whose removal would
		// mark the payload again, so dropping the marker here could strand it once that
		// manifest is deleted. The next sweep simply looks again.
		return nil
	}

	// One sweep per digest across all instances. Losing the race is not an error: the other
	// sweep is doing this work.
	if locker, ok := is.cache.(reclaimLocker); ok {
		unlock, acquired, err := locker.TryLockBlobReclaim(digest, reclaimLockTTL)
		if err != nil || !acquired {
			return err
		}
		defer unlock()
	}

	// The blobstore write lock keeps this instance's own linkers out; the claim and pins
	// below do the same for other instances.
	return is.WithBlobstoreLock(func() error {
		return is.claimAndDeleteGlobalBlob(digest, marker.MarkedAt)
	})
}

func (is *ImageStore) claimAndDeleteGlobalBlob(digest godigest.Digest, markedAt time.Time) error {
	claimID, err := guuid.NewV4()
	if err != nil {
		return err
	}

	claim := reclaimMarker{MarkedAt: markedAt, ClaimID: claimID.String(), ClaimedAt: time.Now()}
	if err := is.writeReclaimMarker(digest, claim); err != nil {
		return err
	}

	claimStart := time.Now()
	finished := false

	defer func() {
		if finished {
			return
		}

		// Backing off: release the claim so waiting linkers proceed and a later sweep can
		// retry, unless another sweep has since taken the marker over.
		if owned, err := is.ownsReclaimClaim(digest, claim.ClaimID); err == nil && owned {
			if err := is.writeReclaimMarker(digest, reclaimMarker{MarkedAt: markedAt}); err != nil {
				is.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to release global blob reclaim claim")
			}
		}
	}()

	if owned, err := is.ownsReclaimClaim(digest, claim.ClaimID); err != nil || !owned {
		return err
	}

	// Pins are read only after the claim is visible; see the protocol note above.
	pinned, err := is.hasLiveReclaimPins(digest)
	if err != nil || pinned {
		return err
	}

	// The index may have been lost since the look before the claim.
	if known, err := is.reclaimIndexKnows(digest); err != nil || !known {
		return err
	}

	// A linker that never saw the marker has its ref in the index by now, or was pinned above.
	referenced, err := is.isDigestReferencedAcrossRepos(digest)
	if err != nil {
		return err
	}

	if referenced {
		finished = true

		return is.dropSpentReclaimMarker(digest)
	}

	// Last look before the irreversible step: the claim must still be ours and young enough
	// that no linker has given up waiting on it.
	if owned, err := is.ownsReclaimClaim(digest, claim.ClaimID); err != nil || !owned {
		return err
	}

	// Linkers wait a full lease; everything destructive has to be over in half of it.
	deadline := claimStart.Add(is.reclaimLease() / 2)
	if !time.Now().Before(deadline) {
		is.log.Warn().Str("digest", digest.String()).Msg("global blob reclaim took too long, retrying next sweep")

		return nil
	}

	globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)

	// Payload first, then its index record, then the marker. A linker is released only once
	// all of it is gone. A crash after the payload leaves the record, which is what lets the
	// next sweep recognise the digest and finish (see reclaimIndexKnows), and which the
	// dedupe path heals as a stale origin if a push gets there first.
	if err := is.deleteGlobalBlobBefore(deadline, globalBlobPath); err != nil {
		// The marker stays, so the next sweep picks the payload up again.
		return err
	}

	// Not past the deadline either: by then a linker may have written the payload and this
	// record anew, and removing the record would orphan them.
	if !time.Now().Before(deadline) {
		return nil
	}

	// Unlike the payload delete, this call is only checked before it starts: the cache
	// interface takes no context, so it cannot be cancelled at the deadline. For it to hurt,
	// it has to stall for more than the remaining half lease, and a linker has to give up on
	// the claim and re-create payload and record in that time. The late delete then removes
	// the new record. The payload and the linker's repo ref are untouched, so nothing a
	// client can pull is lost; the cost is a payload with no global record, which
	// reclaimIndexKnows will later refuse to sweep.

	if err := is.deleteBlobRef(digest, globalBlobPath); err != nil {
		return err
	}

	finished = true

	is.log.Info().Str("digest", digest.String()).Msg("reclaimed unreferenced global blob")

	return is.removeReclaimMarker(digest)
}

// reclaimIndexKnows reports whether the blob-ref index has any record of digest. A payload
// waiting for reclaim always has at least its own global record there, so none at all means
// the index was lost or replaced, and then "no repository refs" proves nothing: a repository
// may own the payload through a blob no manifest references yet, which the graph walk cannot
// see either. Such a digest is left alone until its ownership is known again.
//
// The exception is a marker with neither record nor payload, which is only what a sweep
// interrupted after its deletes leaves behind; that marker is removed.
func (is *ImageStore) reclaimIndexKnows(digest godigest.Digest) (bool, error) {
	refs, err := is.blobRefsForDigest(digest)
	if err != nil && !errors.Is(err, zerr.ErrCacheMiss) {
		return false, err
	}

	if err == nil && len(refs) > 0 {
		return true, nil
	}

	if _, err := is.storeDriver.Stat(is.BlobPath(storageConstants.GlobalBlobsRepo, digest)); err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return false, is.removeReclaimMarker(digest)
		}

		return false, err
	}

	is.log.Warn().Str("digest", digest.String()).
		Msg("blob reference index has no record of a global blob marked for reclaim, keeping the blob")

	return false, nil
}

// deleteGlobalBlobBefore deletes the payload unless that cannot be done by deadline. A delete
// that stalls, or that the SDK retries, past the point where linkers stop honouring the claim
// would remove a payload a linker has since taken; the deadline cancels it instead.
func (is *ImageStore) deleteGlobalBlobBefore(deadline time.Time, globalBlobPath string) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	var err error

	if deleter, ok := is.storeDriver.(contextDeleter); ok {
		err = deleter.DeleteContext(ctx, globalBlobPath)
	} else {
		// No way to bound the call itself; at least do not start it late.
		if err = ctx.Err(); err == nil {
			err = is.storeDriver.Delete(globalBlobPath)
		}
	}

	if err != nil && !errclass.IsStorageObjectMissing(err) {
		return err
	}

	return nil
}

// dropSpentReclaimMarker removes the marker of a digest found to be referenced again. The ref
// that was seen may be deleted by another instance right then, whose own marking finds this
// marker still present and writes nothing; so look once more afterwards and mark afresh if
// the digest ended up unreferenced. Without that the payload would never be swept.
func (is *ImageStore) dropSpentReclaimMarker(digest godigest.Digest) error {
	if err := is.removeReclaimMarker(digest); err != nil {
		return err
	}

	referenced, err := is.isDigestReferencedAcrossRepos(digest)
	if err != nil || referenced {
		return err
	}

	return is.markGlobalBlobReclaimable(digest)
}

func (is *ImageStore) ownsReclaimClaim(digest godigest.Digest, claimID string) (bool, error) {
	marker, err := is.readReclaimMarker(digest)
	if err != nil || marker == nil {
		return false, err
	}

	return marker.ClaimID == claimID, nil
}

// hasLiveReclaimPins reports whether a linker currently pins digest, removing pins old enough
// to have been left behind by a crash.
func (is *ImageStore) hasLiveReclaimPins(digest godigest.Digest) (bool, error) {
	pinPaths, err := is.storeDriver.List(is.reclaimPinDir(digest))
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return false, nil
		}

		return false, err
	}

	live := false

	for _, pinPath := range pinPaths {
		buf, err := is.storeDriver.ReadFile(pinPath)
		if err != nil {
			if errclass.IsStorageObjectMissing(err) {
				continue
			}

			return false, err
		}

		// A pin that cannot be dated counts as live: wrongly honouring one only delays the
		// reclaim, wrongly ignoring one loses a blob.
		pinnedAt, err := time.Parse(time.RFC3339Nano, string(buf))
		if err != nil || time.Since(pinnedAt) < reclaimPinTTL {
			live = true

			continue
		}

		if err := is.storeDriver.Delete(pinPath); err != nil && !errclass.IsStorageObjectMissing(err) {
			return false, err
		}
	}

	return live, nil
}
