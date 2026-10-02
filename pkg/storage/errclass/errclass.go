// Package errclass wraps storage driver failures with the shared sentinels in
// zotregistry.dev/zot/v2/errors (ErrStorageMissing / Transient / Permanent).
//
// Inventory of how each backend maps raw SDK/OS errors: driver-error-matrix.md.
// Caller policy (HTTP vs pkg/storage): ../README.md.
package errclass

import (
	"errors"
	"fmt"
	"strings"

	zerr "zotregistry.dev/zot/v2/errors"
)

// Wrap returns an error that unwraps to both outer and inner (outer first), so
// errors.Is / errors.As see both. If inner already unwraps to outer, inner is
// returned unchanged — that keeps outer wrappers and errors.Join siblings.
func Wrap(outer, inner error) error {
	if outer == nil {
		return nil
	}

	if inner == nil {
		return outer
	}

	if contains(inner, outer) {
		return inner
	}

	return fmt.Errorf("%w: %w", outer, inner)
}

// contains is errors.Is with a recover: errors.Is can panic when the target
// error value is "comparable" at the type level but holds an uncomparable
// dynamic value (e.g. storagedriver.Error{Detail: storagedriver.Errors{…}}).
func contains(err, target error) bool {
	if target == nil {
		return err == nil
	}

	var matched bool

	func() {
		defer func() {
			if recover() != nil {
				matched = false
			}
		}()

		matched = errors.Is(err, target)
	}()

	return matched
}

// isClassified reports whether err already carries any ErrStorage* class marker.
// Classes are mutually exclusive: re-marking must not stack a second sentinel.
func isClassified(err error) bool {
	return errors.Is(err, zerr.ErrStorageMissing) ||
		errors.Is(err, zerr.ErrStorageTransient) ||
		errors.Is(err, zerr.ErrStoragePermanent)
}

// MarkMissing wraps err so callers can use errors.Is(..., zerr.ErrStorageMissing)
// while still unwrapping to the original cause (e.g. PathNotFoundError).
func MarkMissing(err error) error {
	if err == nil {
		return nil
	}

	if isClassified(err) {
		return err
	}

	return fmt.Errorf("%w: %w", zerr.ErrStorageMissing, err)
}

// MarkTransient wraps err for retryable / unreliable storage answers.
func MarkTransient(err error) error {
	if err == nil {
		return nil
	}

	if isClassified(err) {
		return err
	}

	return fmt.Errorf("%w: %w", zerr.ErrStorageTransient, err)
}

// MarkPermanent wraps err for non-retryable failures that are not "missing".
func MarkPermanent(err error) error {
	if err == nil {
		return nil
	}

	if isClassified(err) {
		return err
	}

	return fmt.Errorf("%w: %w", zerr.ErrStoragePermanent, err)
}

// IsWriterLifecycleError reports deterministic FileWriter API-state failures
// (distribution "already closed/committed/cancelled" strings and zot
// ErrFileAlready*). Callers' formatErr must return these unchanged — they are
// not storage I/O failures and must not become ErrStorageTransient.
func IsWriterLifecycleError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, zerr.ErrFileAlreadyClosed) ||
		errors.Is(err, zerr.ErrFileAlreadyCommitted) ||
		errors.Is(err, zerr.ErrFileAlreadyCancelled) {
		return true
	}

	// Distribution S3/GCS/Azure (and filesystem) use bare fmt.Errorf strings.
	msg := err.Error()

	return msg == "already closed" ||
		msg == "already committed" ||
		msg == "already cancelled" ||
		strings.HasSuffix(msg, ": already closed") ||
		strings.HasSuffix(msg, ": already committed") ||
		strings.HasSuffix(msg, ": already cancelled")
}
