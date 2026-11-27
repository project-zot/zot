package cache

import (
	"github.com/google/uuid"
)

// What the BlobRefIndex implementations share. Each keeps one record per digest: whether the
// payload is recorded in the global blobstore, the paths that own the digest, and the claim of
// a sweep deleting the payload, if any (see types.BlobRefIndex).

// newClaimID returns a unique claim ID, so a sweep can tell its own claim from a later one.
func newClaimID() string {
	return uuid.NewString()
}
