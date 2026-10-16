package cache

import (
	"github.com/google/uuid"
)

// What the BlobRefIndex implementations share. Each keeps one record per digest: whether the
// payload is recorded in the global blobstore, the paths that own the digest, and the claim of
// a sweep deleting the payload, if any (see types.BlobRefIndex).

func newClaimID() string {
	return uuid.NewString()
}
