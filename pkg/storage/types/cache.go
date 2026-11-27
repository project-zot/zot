package types

import (
	"time"

	godigest "github.com/opencontainers/go-digest"
)

type Cache interface {
	// Returns the human-readable "name" of the driver.
	Name() string

	// Retrieves the blob matching provided digest.
	GetBlob(digest godigest.Digest) (string, error)

	// Retrieves all blobs matching provided digest.
	GetAllBlobs(digest godigest.Digest) ([]string, error)

	// Uploads blob to cachedb.
	PutBlob(digest godigest.Digest, path string) error

	// Check if blob exists in cachedb.
	HasBlob(digest godigest.Digest, path string) bool

	// DeleteBlob removes path from the paths tracked for digest. It is idempotent: it returns
	// nil, not a cache-miss error, when the digest or the path is already untracked.
	DeleteBlob(digest godigest.Digest, path string) error

	// SetOrigin makes the origin record for digest match path. Unlike PutBlob, which
	// never replaces an existing origin, SetOrigin overwrites the origin while keeping
	// the duplicate set.
	SetOrigin(digest godigest.Digest, path string) error

	// UsesRelativePaths returns if cache is storing blobs relative to cache rootDir
	UsesRelativePaths() bool

	// BlobRefIndex records which repositories own a payload in the global blobstore. Remote
	// stores with dedupe on rely on it; local ones reclaim through hardlink counts instead.
	BlobRefIndex
}

// CacheBatchWriter is implemented by a cache that commits each write durably on its own, at the
// cost of a sync to disk (BoltDB), so that a bulk pass, such as the upgrade to the global
// blobstore, can commit many writes at once instead.
type CacheBatchWriter interface {
	// WriteBatch runs write with a Cache whose writes are committed together once write returns
	// nil, and discarded if it returns an error. Until then write must reach the cache only
	// through the Cache it is given: a write through another would wait for the batch, which
	// never ends.
	WriteBatch(write func(batch Cache) error) error
}

// BlobRefIndex records which repositories own a digest whose payload is kept once, in the
// global blobstore, and coordinates deleting that payload across zot instances sharing the
// cache. Each digest has one record: whether the payload is recorded in the global blobstore,
// the repository paths that own it, and at most one claim, held by a sweep deleting the
// payload. Every operation is a single atomic write on that record, so a linker adding a
// reference and a sweep claiming the digest never both succeed.
type BlobRefIndex interface {
	// AddReference records path as an owner of digest. It fails with ErrDigestClaimed while a
	// sweep holds a live claim on digest, and breaks a claim older than the lease. Idempotent.
	AddReference(digest godigest.Digest, path string) error

	// RemoveReference forgets path as an owner of digest, and reports whether digest has no
	// owners left. Idempotent: a digest or path the index does not know has none.
	RemoveReference(digest godigest.Digest, path string) (unowned bool, err error)

	// GetReferences returns the paths that own digest, or ErrCacheMiss when digest has no record.
	GetReferences(digest godigest.Digest) ([]string, error)

	// RecordGlobal records that the payload of digest is in the global blobstore. Idempotent.
	RecordGlobal(digest godigest.Digest) error

	// ClaimReclaim claims digest for a sweep about to delete its payload. It succeeds only when
	// the payload is recorded, nothing owns digest and no live claim is held, breaking a claim
	// older than the lease. Otherwise it fails with ErrDigestReferenced, ErrDigestClaimed, or
	// ErrCacheMiss when the index does not know the payload, so ownership cannot be established.
	ClaimReclaim(digest godigest.Digest) (ReclaimClaim, error)

	// FinishReclaim deletes the record of claim's digest, once its payload is deleted. It fails
	// with ErrReclaimClaimLost when claim is no longer held. A held claim means no owners: a
	// reference can only be added once the claim is broken.
	FinishReclaim(claim ReclaimClaim) error

	// AbandonReclaim drops claim and keeps the record. It does nothing when claim is no longer held.
	AbandonReclaim(claim ReclaimClaim) error
}

// ReclaimClaim is a sweep's claim on a digest, returned by BlobRefIndex.ClaimReclaim.
type ReclaimClaim struct {
	Digest godigest.Digest
	// ID tells this claim apart from a later one on the same digest.
	ID string
	// At is when the claim was taken, by the clock that judges its lease: the cache server's
	// where it has one (Redis), the instance's otherwise.
	At time.Time
}
