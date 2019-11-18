package errors

import "errors"

var (
	ErrBadConfig           = errors.New("config: invalid config")
	ErrRepoNotFound        = errors.New("repository: not found")
	ErrRepoIsNotDir        = errors.New("repository: not a directory")
	ErrRepoBadVersion      = errors.New("repository: unsupported layout version")
	ErrManifestNotFound    = errors.New("manifest: not found")
	ErrBadManifest         = errors.New("manifest: invalid contents")
	ErrUploadNotFound      = errors.New("uploads: not found")
	ErrBadUploadRange      = errors.New("uploads: bad range")
	ErrBlobNotFound        = errors.New("blob: not found")
	ErrBadBlob             = errors.New("blob: bad blob")
	ErrBadBlobDigest       = errors.New("blob: bad blob digest")
	ErrUnknownCode         = errors.New("error: unknown error code")
	ErrBadCACert           = errors.New("tls: invalid ca cert")
	ErrBadUser             = errors.New("ldap: non-existent user")
	ErrEntriesExceeded     = errors.New("ldap: too many entries returned")
	ErrLDAPEmptyPassphrase = errors.New("ldap: empty passphrase")
	ErrLDAPBadConn         = errors.New("ldap: bad connection")
	ErrLDAPConfig          = errors.New("config: invalid LDAP configuration")
)
