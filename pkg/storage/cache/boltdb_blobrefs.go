package cache

import (
	"encoding/json"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"go.etcd.io/bbolt"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/storage/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// The BoltDB blob reference index keeps a bucket per digest under BlobRefsBucket, holding a
// "global" key once the payload is recorded, a "claim" key while a sweep holds a claim, and a
// "refs" bucket whose keys are the owning paths. Each operation is one Update transaction,
// which BoltDB serializes, so the conditions in them hold atomically.

const (
	boltGlobalKey  = "global"
	boltClaimKey   = "claim"
	boltRefsBucket = "refs"
)

type boltClaim struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
}

// SetReclaimClaimLease sets how long a reclaim claim stays live, constants.DefaultReclaimClaimLease
// unless set.
func (d *BoltDBDriver) SetReclaimClaimLease(lease time.Duration) {
	d.claimLease = lease
}

// blobRefsRoot returns the bucket holding one sub-bucket per digest, created with the database.
func (d *BoltDBDriver) blobRefsRoot(tx *bbolt.Tx) (*bbolt.Bucket, error) {
	root := tx.Bucket([]byte(constants.BlobRefsBucket))
	if root == nil {
		d.log.Error().Err(zerr.ErrCacheRootBucket).Msg("failed to access blob refs root bucket")

		return nil, zerr.ErrCacheRootBucket
	}

	return root, nil
}

// boltClaimOf returns the claim recorded on record, or nil when there is none.
func boltClaimOf(record *bbolt.Bucket) (*boltClaim, error) {
	raw := record.Get([]byte(boltClaimKey))
	if raw == nil {
		return nil, nil //nolint:nilnil // no claim
	}

	var claim boltClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		return nil, err
	}

	return &claim, nil
}

// liveClaim returns the claim on record unless it is older than the lease, as of now.
func (d *BoltDBDriver) liveClaim(record *bbolt.Bucket, now time.Time) (*boltClaim, error) {
	claim, err := boltClaimOf(record)
	if err != nil || claim == nil {
		return nil, err
	}

	if now.Sub(claim.At) >= d.claimLease {
		return nil, nil //nolint:nilnil // a claim older than the lease is dead
	}

	return claim, nil
}

// boltHasRefs reports whether any path owns the digest of record.
func boltHasRefs(record *bbolt.Bucket) bool {
	refs := record.Bucket([]byte(boltRefsBucket))
	if refs == nil {
		return false
	}

	key, _ := refs.Cursor().First()

	return key != nil
}

// forgetIfEmpty deletes the record of digest once it holds nothing: no payload, owner or claim.
func forgetIfEmpty(root, record *bbolt.Bucket, digest godigest.Digest) error {
	if record.Get([]byte(boltGlobalKey)) != nil || record.Get([]byte(boltClaimKey)) != nil ||
		boltHasRefs(record) {
		return nil
	}

	return root.DeleteBucket([]byte(digest.String()))
}

func (d *BoltDBDriver) AddReference(digest godigest.Digest, path string) error {
	if path == "" {
		return zerr.ErrEmptyValue
	}

	return d.db.Update(func(tx *bbolt.Tx) error {
		root, err := d.blobRefsRoot(tx)
		if err != nil {
			return err
		}

		record, err := root.CreateBucketIfNotExists([]byte(digest.String()))
		if err != nil {
			return err
		}

		claim, err := d.liveClaim(record, time.Now())
		if err != nil {
			return err
		}

		if claim != nil {
			return zerr.ErrDigestClaimed
		}

		// break a dead claim, if any
		if err := record.Delete([]byte(boltClaimKey)); err != nil {
			return err
		}

		refs, err := record.CreateBucketIfNotExists([]byte(boltRefsBucket))
		if err != nil {
			return err
		}

		return refs.Put([]byte(path), nil)
	})
}

func (d *BoltDBDriver) RemoveReference(digest godigest.Digest, path string) (bool, error) {
	unowned := true

	err := d.db.Update(func(tx *bbolt.Tx) error {
		root, err := d.blobRefsRoot(tx)
		if err != nil {
			return err
		}

		record := root.Bucket([]byte(digest.String()))
		if record == nil {
			return nil
		}

		if refs := record.Bucket([]byte(boltRefsBucket)); refs != nil {
			if err := refs.Delete([]byte(path)); err != nil {
				return err
			}
		}

		unowned = !boltHasRefs(record)

		return forgetIfEmpty(root, record, digest)
	})

	return unowned, err
}

func (d *BoltDBDriver) GetReferences(digest godigest.Digest) ([]string, error) {
	var paths []string

	err := d.db.View(func(tx *bbolt.Tx) error {
		root, err := d.blobRefsRoot(tx)
		if err != nil {
			return err
		}

		record := root.Bucket([]byte(digest.String()))
		if record == nil {
			return zerr.ErrCacheMiss
		}

		paths = []string{}

		refs := record.Bucket([]byte(boltRefsBucket))
		if refs == nil {
			return nil
		}

		return refs.ForEach(func(path, _ []byte) error {
			paths = append(paths, string(path))

			return nil
		})
	})

	return paths, err
}

func (d *BoltDBDriver) RecordGlobal(digest godigest.Digest) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		root, err := d.blobRefsRoot(tx)
		if err != nil {
			return err
		}

		record, err := root.CreateBucketIfNotExists([]byte(digest.String()))
		if err != nil {
			return err
		}

		return record.Put([]byte(boltGlobalKey), []byte("1"))
	})
}

func (d *BoltDBDriver) ClaimReclaim(digest godigest.Digest) (storageTypes.ReclaimClaim, error) {
	claim := storageTypes.ReclaimClaim{Digest: digest, ID: newClaimID(), At: time.Now()}

	err := d.db.Update(func(tx *bbolt.Tx) error {
		root, err := d.blobRefsRoot(tx)
		if err != nil {
			return err
		}

		record := root.Bucket([]byte(digest.String()))
		if record != nil && boltHasRefs(record) {
			return zerr.ErrDigestReferenced
		}

		if record == nil || record.Get([]byte(boltGlobalKey)) == nil {
			return zerr.ErrCacheMiss
		}

		held, err := d.liveClaim(record, claim.At)
		if err != nil {
			return err
		}

		if held != nil {
			return zerr.ErrDigestClaimed
		}

		raw, err := json.Marshal(boltClaim{ID: claim.ID, At: claim.At})
		if err != nil {
			return err
		}

		return record.Put([]byte(boltClaimKey), raw)
	})
	if err != nil {
		return storageTypes.ReclaimClaim{}, err
	}

	return claim, nil
}

// heldClaim returns the record of claim's digest when claim is still the one recorded on it.
func (d *BoltDBDriver) heldClaim(root *bbolt.Bucket, claim storageTypes.ReclaimClaim) (*bbolt.Bucket, error) {
	record := root.Bucket([]byte(claim.Digest.String()))
	if record == nil {
		return nil, nil //nolint:nilnil // no record, so no claim
	}

	recorded, err := boltClaimOf(record)
	if err != nil || recorded == nil || recorded.ID != claim.ID {
		return nil, err
	}

	return record, nil
}

func (d *BoltDBDriver) FinishReclaim(claim storageTypes.ReclaimClaim) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		root, err := d.blobRefsRoot(tx)
		if err != nil {
			return err
		}

		record, err := d.heldClaim(root, claim)
		if err != nil {
			return err
		}

		if record == nil {
			return zerr.ErrReclaimClaimLost
		}

		return root.DeleteBucket([]byte(claim.Digest.String()))
	})
}

func (d *BoltDBDriver) AbandonReclaim(claim storageTypes.ReclaimClaim) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		root, err := d.blobRefsRoot(tx)
		if err != nil {
			return err
		}

		record, err := d.heldClaim(root, claim)
		if err != nil || record == nil {
			return err
		}

		return record.Delete([]byte(boltClaimKey))
	})
}
