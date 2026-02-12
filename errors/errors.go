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
	ErrBadConfig                        = errors.New("invalid server config")
	ErrCliBadConfig                     = errors.New("invalid cli config")
	ErrRepoNotFound                     = errors.New("repository not found")
	ErrRepoBadVersion                   = errors.New("unsupported repository layout version")
	ErrRepoBadLayout                    = errors.New("invalid repository layout")
	ErrManifestNotFound                 = errors.New("manifest not found")
	ErrBadManifest                      = errors.New("invalid manifest content")
	ErrUploadNotFound                   = errors.New("upload destination not found")
	ErrBadUploadRange                   = errors.New("bad upload content-length")
	ErrBlobNotFound                     = errors.New("blob not found")
	ErrBadBlob                          = errors.New("bad blob")
	ErrBadBlobDigest                    = errors.New("bad blob digest")
	ErrBlobReferenced                   = errors.New("blob referenced by manifest")
	ErrManifestReferenced               = errors.New("manifest referenced by index image")
	ErrUnknownCode                      = errors.New("unknown error code")
	ErrBadCACert                        = errors.New("invalid tls ca cert")
	ErrBadUser                          = errors.New("non-existent user")
	ErrEntriesExceeded                  = errors.New("too many entries returned")
	ErrLDAPEmptyPassphrase              = errors.New("empty ldap passphrase")
	ErrLDAPBadConn                      = errors.New("bad ldap connection")
	ErrLDAPConfig                       = errors.New("invalid LDAP configuration")
	ErrCacheRootBucket                  = errors.New("unable to create/update root cache bucket")
	ErrCacheNoBucket                    = errors.New("unable to find cache bucket")
	ErrCacheMiss                        = errors.New("cache miss")
	ErrRequireCred                      = errors.New("bind ldap credentials required")
	ErrInvalidCred                      = errors.New("invalid ldap credentials")
	ErrEmptyJSON                        = errors.New("cli config json is empty")
	ErrInvalidArgs                      = errors.New("invalid cli arguments")
	ErrInvalidFlagsCombination          = errors.New("invalid cli combination of flags")
	ErrInvalidURL                       = errors.New("invalid URL format")
	ErrExtensionNotEnabled              = errors.New("functionality is not built/configured in the current server")
	ErrUnauthorizedAccess               = errors.New("unauthorized access. check credentials")
	ErrCannotResetConfigKey             = errors.New("cannot reset given config key")
	ErrConfigNotFound                   = errors.New("config with the given name does not exist")
	ErrNoURLProvided                    = errors.New("no URL provided")
	ErrIllegalConfigKey                 = errors.New("given config key is not allowed")
	ErrScanNotSupported                 = errors.New("scanning is not supported for given media type")
	ErrCLITimeout                       = errors.New("query timed out while waiting for results")
	ErrDuplicateConfigName              = errors.New("cli config name already added")
	ErrInvalidRoute                     = errors.New("invalid route prefix")
	ErrImgStoreNotFound                 = errors.New("image store not found corresponding to given route")
	ErrLocalImgStoreNotFound            = errors.New("local image store not found corresponding to given route")
	ErrEmptyValue                       = errors.New("empty cache value")
	ErrEmptyRepoList                    = errors.New("no repository found")
	ErrCVESearchDisabled                = errors.New("cve search is disabled")
	ErrCVEDBNotFound                    = errors.New("cve-db is not present")
	ErrInvalidRepositoryName            = errors.New("not a valid repository name")
	ErrSyncMissingCatalog               = errors.New("couldn't fetch upstream registry's catalog")
	ErrInvalidMetric                    = errors.New("invalid metric func")
	ErrInjected                         = errors.New("injected failure")
	ErrSyncInvalidUpstreamURL           = errors.New("upstream url not found in sync config")
	ErrRegistryNoContent                = errors.New("could not find a Content that matches localRepo")
	ErrSyncReferrerNotFound             = errors.New("couldn't find upstream referrer")
	ErrImageLintAnnotations             = errors.New("lint checks failed")
	ErrParsingAuthHeader                = errors.New("failed parsing authorization header")
	ErrBadType                          = errors.New("invalid type")
	ErrParsingHTTPHeader                = errors.New("invalid HTTP header")
	ErrBadRange                         = errors.New("bad range for streaming blob")
	ErrBadLayerCount                    = errors.New("manifest layers count doesn't correspond to config history")
	ErrManifestConflict                 = errors.New("multiple manifests found")
	ErrImageMetaNotFound                = errors.New("image meta not found")
	ErrUnexpectedMediaType              = errors.New("unexpected media type")
	ErrRepoMetaNotFound                 = errors.New("repo metadata not found for given repo name")
	ErrTagMetaNotFound                  = errors.New("tag metadata not found for given repo and tag names")
	ErrTypeAssertionFailed              = errors.New("failed DatabaseDriver type assertion")
	ErrInvalidRequestParams             = errors.New("request parameter has invalid value")
	ErrBadCtxFormat                     = errors.New("type assertion failed")
	ErrEmptyRepoName                    = errors.New("repo name can't be empty string")
	ErrEmptyTag                         = errors.New("tag can't be empty string")
	ErrEmptyDigest                      = errors.New("digest can't be empty string")
	ErrInvalidRepoRefFormat             = errors.New("invalid image reference format, use [repo:tag] or [repo@digest]")
	ErrLimitIsNegative                  = errors.New("pagination limit has negative value")
	ErrLimitIsExcessive                 = errors.New("pagination limit has excessive value")
	ErrOffsetIsNegative                 = errors.New("pagination offset has negative value")
	ErrSortCriteriaNotSupported         = errors.New("the pagination sort criteria is not supported")
	ErrMediaTypeNotSupported            = errors.New("media type is not supported")
	ErrTimeout                          = errors.New("operation timeout")
	ErrNotImplemented                   = errors.New("not implemented")
	ErrDedupeRebuild                    = errors.New("couldn't rebuild dedupe index")
	ErrMissingAuthHeader                = errors.New("required authorization header is missing")
	ErrUserAPIKeyNotFound               = errors.New("user info for given API key hash not found")
	ErrUserSessionNotFound              = errors.New("user session for given ID not found")
	ErrInvalidMetaDBVersion             = errors.New("unrecognized version meta")
	ErrBucketDoesNotExist               = errors.New("bucket does not exist")
	ErrOpenIDProviderDoesNotExist       = errors.New("openid provider does not exist in given config")
	ErrHashKeyNotCreated                = errors.New("cookiestore generated random hash key is nil, aborting")
	ErrFailedTypeAssertion              = errors.New("type assertion failed")
	ErrInvalidOldUserStarredRepos       = errors.New("invalid old entry for user starred repos")
	ErrUnmarshalledRepoListIsNil        = errors.New("list of repos is still nil")
	ErrCouldNotMarshalStarredRepos      = errors.New("could not repack entry for user starred repos")
	ErrInvalidOldUserBookmarkedRepos    = errors.New("invalid old entry for user bookmarked repos")
	ErrCouldNotMarshalBookmarkedRepos   = errors.New("could not repack entry for user bookmarked repos")
	ErrUserDataNotFound                 = errors.New("user data not found for given user identifier")
	ErrUserDataNotAllowed               = errors.New("user data operations are not allowed")
	ErrCouldNotPersistData              = errors.New("could not persist to db")
	ErrSignConfigDirNotSet              = errors.New("signature config dir not set")
	ErrBadSignatureManifestDigest       = errors.New("bad signature manifest digest")
	ErrInvalidSignatureType             = errors.New("invalid signature type")
	ErrSyncPingRegistry                 = errors.New("unable to ping any registry URLs")
	ErrSyncImageNotSigned               = errors.New("synced image is not signed")
	ErrSyncImageFilteredOut             = errors.New("image is filtered out by sync config")
	ErrSyncParseRemoteRepo              = errors.New("failed to parse remote repo")
	ErrInvalidTruststoreType            = errors.New("invalid signature truststore type")
	ErrInvalidTruststoreName            = errors.New("invalid signature truststore name")
	ErrInvalidCertificateContent        = errors.New("invalid signature certificate content")
	ErrInvalidPublicKeyContent          = errors.New("invalid signature public key content")
	ErrInvalidStateCookie               = errors.New("auth state cookie not present or differs from original state")
	ErrSyncNoURLsLeft                   = errors.New("no valid registry urls left after filtering local ones")
	ErrInvalidCLIParameter              = errors.New("invalid cli parameter")
	ErrGQLEndpointNotFound              = errors.New("the server doesn't have a gql endpoint")
	ErrGQLQueryNotSupported             = errors.New("query is not supported or has different arguments")
	ErrBadHTTPStatusCode                = errors.New("the response doesn't contain the expected status code")
	ErrFileAlreadyCancelled             = errors.New("storageDriver file already cancelled")
	ErrFileAlreadyClosed                = errors.New("storageDriver file already closed")
	ErrFileAlreadyCommitted             = errors.New("storageDriver file already committed")
	ErrInvalidOutputFormat              = errors.New("invalid cli output format")
	ErrServerIsRunning                  = errors.New("server is running")
	ErrDatabaseFileAlreadyInUse         = errors.New("boltdb file is already in use")
	ErrFlagValueUnsupported             = errors.New("supported values ")
	ErrUnknownSubcommand                = errors.New("unknown cli subcommand")
	ErrMultipleReposSameName            = errors.New("can't have multiple repos with the same name")
	ErrRetentionPolicyNotFound          = errors.New("retention repo or tag policy not found")
	ErrFormatNotSupported               = errors.New("the given output format is not supported")
	ErrAPINotSupported                  = errors.New("registry at the given address doesn't implement the correct API")
	ErrURLNotFound                      = errors.New("url not found")
	ErrInvalidSearchQuery               = errors.New("invalid search query")
	ErrImageNotFound                    = errors.New("image not found")
	ErrAmbiguousInput                   = errors.New("input is not specific enough")
	ErrReceivedUnexpectedAuthHeader     = errors.New("received unexpected www-authenticate header")
	ErrNoBearerToken                    = errors.New("no bearer token given")
	ErrInvalidBearerToken               = errors.New("invalid bearer token given")
	ErrInvalidOrUnreachableOIDCIssuer   = errors.New("invalid or unreachable oidc issuer")
	ErrInsufficientScope                = errors.New("bearer token does not have sufficient scope")
	ErrCouldNotLoadPublicKey            = errors.New("failed to load public key")
	ErrEventTypeEmpty                   = errors.New("event type empty")
	ErrEventSinkIsNil                   = errors.New("event sink is nil")
	ErrUnsupportedEventSink             = errors.New("event sink is not supported")
	ErrInvalidEventSinkType             = errors.New("invalid sink type")
	ErrEventSinkAddressEmpty            = errors.New("address field cannot be empty")
	ErrCouldNotCreateHTTPEventTransport = errors.New("default transport is not *http.Transport")
	ErrNoIdentityInCommonName           = errors.New("no identity found in CommonName")
	ErrNoURISANFound                    = errors.New("no URI SAN found")
	ErrURISANIndexOutOfRange            = errors.New("URI SAN index out of range")
	ErrURISANPatternDidNotMatch         = errors.New("URI SAN pattern did not match")
	ErrInvalidURISANPattern             = errors.New("invalid URI SAN pattern")
	ErrNoDNSANFound                     = errors.New("no DNS SAN found")
	ErrDNSANIndexOutOfRange             = errors.New("DNS SAN index out of range")
	ErrNoEmailSANFound                  = errors.New("no Email SAN found")
	ErrEmailSANIndexOutOfRange          = errors.New("Email SAN index out of range")
	ErrUnsupportedIdentityAttribute     = errors.New("unsupported identity attribute")
	ErrOIDCNoAudiences                  = errors.New("at least one audience must be specified")
	ErrOIDCInvalidAudiences             = errors.New("invalid audiences claim in token")
	ErrOIDCEmptyAudience                = errors.New("audience is empty")
	ErrOIDCEmptyVariableName            = errors.New("variable name is empty")
	ErrOIDCEmptyValidationMsg           = errors.New("validation error message is empty")
	ErrOIDCValidationFailed             = errors.New("OIDC claim validation failed")
	ErrOIDCAudienceMismatch             = errors.New("token audience does not match any of the expected audiences")
	ErrCertificateNotLoaded             = errors.New("tls certificate not yet loaded")
	ErrCertificateWatcherAlreadyRunning = errors.New("certificate watcher is already running")
)
