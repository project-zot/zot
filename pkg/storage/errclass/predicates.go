package errclass

import (
	"errors"

	zerr "zotregistry.dev/zot/v2/errors"
)

// IsStorageObjectMissing reports that the storage object/path is absent
// (zerr.ErrStorageMissing). Drivers' formatErr MarkMissing on PathNotFound,
// so callers need not also As PathNotFoundError.
func IsStorageObjectMissing(err error) bool {
	return errors.Is(err, zerr.ErrStorageMissing)
}

// IsBlobUnavailable reports registry "content not available" suitable for
// soft-skip inside pkg/storage: ErrBlobNotFound, ErrStorageMissing, or
// ErrCacheMiss. Transient/Permanent failures do not match.
func IsBlobUnavailable(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, zerr.ErrBlobNotFound) ||
		errors.Is(err, zerr.ErrStorageMissing) ||
		errors.Is(err, zerr.ErrCacheMiss)
}
