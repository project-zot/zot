package errors

import (
	"errors"
)

type Error struct {
	err     error
	details map[string]string
}

func (e *Error) Error() string {
	return e.err.Error()
}

func (e *Error) Is(target error) bool {
	return errors.Is(e.err, target)
}

func (e *Error) AddDetail(key, value string) *Error {
	e.details[key] = value

	return e
}

func (e *Error) GetDetails() map[string]string {
	return e.details
}

func NewError(err error) *Error {
	return &Error{
		err:     err,
		details: GetDetails(err), // preserve details if chained error
	}
}

func GetDetails(err error) map[string]string {
	var internalErr *Error
	details := make(map[string]string)

	if errors.As(err, &internalErr) {
		details = internalErr.GetDetails()
	}

	return details
}

var (
	ErrBadConfig                      = errors.New("config: invalid config")
	ErrCliBadConfig                   = errors.New("cli: bad config")
	ErrRepoNotFound                   = errors.New("repository: not found")
	ErrRepoBadVersion                 = errors.New("repository: unsupported layout version")
	ErrRepoBadLayout                  = errors.New("repository: invalid layout")
	ErrManifestNotFound               = errors.New("manifest: not found")
	ErrBadManifest                    = errors.New("manifest: invalid contents")
	ErrUploadNotFound                 = errors.New("uploads: not found")
	ErrBadUploadRange                 = errors.New("uploads: bad range")
	ErrBlobNotFound                   = errors.New("blob: not found")
	ErrBadBlob                        = errors.New("blob: bad blob")
	ErrBadBlobDigest                  = errors.New("blob: bad blob digest")
	ErrBlobReferenced                 = errors.New("blob: referenced by manifest")
	ErrManifestReferenced             = errors.New("manifest: referenced by index image")
	ErrUnknownCode                    = errors.New("error: unknown error code")
	ErrBadCACert                      = errors.New("tls: invalid ca cert")
	ErrBadUser                        = errors.New("auth: non-existent user")
	ErrEntriesExceeded                = errors.New("ldap: too many entries returned")
	ErrLDAPEmptyPassphrase            = errors.New("ldap: empty passphrase")
	ErrLDAPBadConn                    = errors.New("ldap: bad connection")
	ErrLDAPConfig                     = errors.New("config: invalid LDAP configuration")
	ErrCacheRootBucket                = errors.New("cache: unable to create/update root bucket")
	ErrCacheNoBucket                  = errors.New("cache: unable to find bucket")
	ErrCacheMiss                      = errors.New("cache: miss")
	ErrRequireCred                    = errors.New("ldap: bind credentials required")
	ErrInvalidCred                    = errors.New("ldap: invalid credentials")
	ErrEmptyJSON                      = errors.New("cli: config json is empty")
	ErrInvalidArgs                    = errors.New("cli: Invalid Arguments")
	ErrInvalidFlagsCombination        = errors.New("cli: Invalid combination of flags")
	ErrInvalidURL                     = errors.New("cli: invalid URL format")
	ErrExtensionNotEnabled            = errors.New("cli: functionality is not built/configured in the current server")
	ErrUnauthorizedAccess             = errors.New("auth: unauthorized access. check credentials")
	ErrCannotResetConfigKey           = errors.New("cli: cannot reset given config key")
	ErrConfigNotFound                 = errors.New("cli: config with the given name does not exist")
	ErrNoURLProvided                  = errors.New("cli: no URL provided in argument or via config")
	ErrIllegalConfigKey               = errors.New("cli: given config key is not allowed")
	ErrScanNotSupported               = errors.New("search: scanning of image media type not supported")
	ErrCLITimeout                     = errors.New("cli: Query timed out while waiting for results")
	ErrDuplicateConfigName            = errors.New("cli: cli config name already added")
	ErrInvalidRoute                   = errors.New("routes: invalid route prefix")
	ErrImgStoreNotFound               = errors.New("routes: image store not found corresponding to given route")
	ErrEmptyValue                     = errors.New("cache: empty value")
	ErrEmptyRepoList                  = errors.New("search: no repository found")
	ErrCVESearchDisabled              = errors.New("search: CVE search is disabled")
	ErrCVEDBNotFound                  = errors.New("cve: CVE DB is not present")
	ErrInvalidRepositoryName          = errors.New("repository: not a valid repository name")
	ErrSyncMissingCatalog             = errors.New("sync: couldn't fetch upstream registry's catalog")
	ErrMethodNotSupported             = errors.New("storage: method not supported")
	ErrInvalidMetric                  = errors.New("metrics: invalid metric func")
	ErrInjected                       = errors.New("test: injected failure")
	ErrSyncInvalidUpstreamURL         = errors.New("sync: upstream url not found in sync config")
	ErrRegistryNoContent              = errors.New("sync: could not find a Content that matches localRepo")
	ErrSyncReferrerNotFound           = errors.New("sync: couldn't find upstream referrer")
	ErrImageLintAnnotations           = errors.New("routes: lint checks failed")
	ErrParsingAuthHeader              = errors.New("auth: failed parsing authorization header")
	ErrBadType                        = errors.New("core: invalid type")
	ErrParsingHTTPHeader              = errors.New("routes: invalid HTTP header")
	ErrBadRange                       = errors.New("storage: bad range")
	ErrBadLayerCount                  = errors.New("manifest: layers count doesn't correspond to config history")
	ErrManifestConflict               = errors.New("manifest: multiple manifests found")
	ErrManifestMetaNotFound           = errors.New("metadb: image metadata not found for given manifest reference")
	ErrManifestDataNotFound           = errors.New("metadb: image data not found for given manifest digest")
	ErrIndexDataNotFount              = errors.New("metadb: index data not found for given digest")
	ErrRepoMetaNotFound               = errors.New("metadb: repo metadata not found for given repo name")
	ErrTagMetaNotFound                = errors.New("metadb: tag metadata not found for given repo and tag names")
	ErrTypeAssertionFailed            = errors.New("storage: failed DatabaseDriver type assertion")
	ErrInvalidRequestParams           = errors.New("resolver: parameter sent has invalid value")
	ErrBadCtxFormat                   = errors.New("type assertion failed")
	ErrEmptyRepoName                  = errors.New("metadb: repo name can't be empty string")
	ErrEmptyTag                       = errors.New("metadb: tag can't be empty string")
	ErrEmptyDigest                    = errors.New("metadb: digest can't be empty string")
	ErrInvalidRepoRefFormat           = errors.New("invalid image reference format [repo:tag] or [repo@digest]")
	ErrLimitIsNegative                = errors.New("pageturner: limit has negative value")
	ErrOffsetIsNegative               = errors.New("pageturner: offset has negative value")
	ErrSortCriteriaNotSupported       = errors.New("pageturner: the sort criteria is not supported")
	ErrMediaTypeNotSupported          = errors.New("metadb: media type is not supported")
	ErrTimeout                        = errors.New("operation timeout")
	ErrNotImplemented                 = errors.New("not implemented")
	ErrDedupeRebuild                  = errors.New("dedupe: couldn't rebuild dedupe index")
	ErrMissingAuthHeader              = errors.New("auth: required authorization header is missing")
	ErrUserAPIKeyNotFound             = errors.New("userDB: user info for given API key hash not found")
	ErrUserSessionNotFound            = errors.New("userDB: user session for given ID not found")
	ErrBucketDoesNotExist             = errors.New("DB: bucket does not exist")
	ErrOpenIDProviderDoesNotExist     = errors.New("openID: provider does not exist in given config")
	ErrHashKeyNotCreated              = errors.New("cookiestore: generated random hash key is nil, not continuing")
	ErrFailedTypeAssertion            = errors.New("type assertion failed")
	ErrInvalidOldUserStarredRepos     = errors.New("metadb: invalid old entry for user starred repos")
	ErrUnmarshalledRepoListIsNil      = errors.New("metadb: list of repos is still nil")
	ErrCouldNotMarshalStarredRepos    = errors.New("metadb: could not repack entry for user starred repos")
	ErrInvalidOldUserBookmarkedRepos  = errors.New("metadb: invalid old entry for user bookmarked repos")
	ErrCouldNotMarshalBookmarkedRepos = errors.New("metadb: could not repack entry for user bookmarked repos")
	ErrUserDataNotFound               = errors.New("metadb: user data not found for given user identifier")
	ErrUserDataNotAllowed             = errors.New("metadb: user data operations are not allowed")
	ErrCouldNotPersistData            = errors.New("metadb: could not persist to db")
	ErrSignConfigDirNotSet            = errors.New("signatures: signature config dir not set")
	ErrBadManifestDigest              = errors.New("signatures: bad manifest digest")
	ErrInvalidSignatureType           = errors.New("signatures: invalid signature type")
	ErrSyncPingRegistry               = errors.New("sync: unable to ping any registry URLs")
	ErrSyncImageNotSigned             = errors.New("sync: image is not signed")
	ErrSyncImageFilteredOut           = errors.New("sync: image is filtered out by sync config")
	ErrCallerInfo                     = errors.New("runtime: failed to get info regarding the current runtime")
	ErrInvalidTruststoreType          = errors.New("signatures: invalid truststore type")
	ErrInvalidTruststoreName          = errors.New("signatures: invalid truststore name")
	ErrInvalidCertificateContent      = errors.New("signatures: invalid certificate content")
	ErrInvalidPublicKeyContent        = errors.New("signatures: invalid public key content")
	ErrInvalidStateCookie             = errors.New("auth: state cookie not present or differs from original state")
	ErrSyncNoURLsLeft                 = errors.New("sync: no valid registry urls left after filtering local ones")
	ErrInvalidCLIParameter            = errors.New("cli: invalid parameter")
	ErrGQLEndpointNotFound            = errors.New("cli: the server doesn't have a gql endpoint")
	ErrGQLQueryNotSupported           = errors.New("cli: query is not supported or has different arguments")
	ErrBadHTTPStatusCode              = errors.New("cli: the response doesn't contain the expected status code")
	ErrFileAlreadyCancelled           = errors.New("storageDriver: file already cancelled")
	ErrFileAlreadyClosed              = errors.New("storageDriver: file already closed")
	ErrFileAlreadyCommitted           = errors.New("storageDriver: file already committed")
	ErrInvalidOutputFormat            = errors.New("cli: invalid output format")
	ErrFlagValueUnsupported           = errors.New("supported values ")
	ErrUnknownSubcommand              = errors.New("cli: unknown subcommand")
)
