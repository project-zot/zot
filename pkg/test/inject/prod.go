//go:build !dev
// +build !dev

package inject

func Error(err error) error {
	return err
}

func Ok(ok bool) bool {
	return ok
}

func ErrStatusCode(statusCode int) int {
	return statusCode
}

/**
 *
 * Failure injection infrastructure to cover hard-to-reach code paths (nop in production).
 *
 **/

func InjectFailure(skip int) bool { return false }
