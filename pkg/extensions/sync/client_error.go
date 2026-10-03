//go:build sync

package sync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"

	"github.com/regclient/regclient/types/errs"

	zerr "zotregistry.dev/zot/v2/errors"
)

// isSoftOnDemandSyncErr reports a soft on-demand outcome: this registry answered
// but had nothing useful for the path (filter / not-found / unsigned / unsupported
// media). Soft errors surface to clients as HTTP 404, not as a sync outage.
func isSoftOnDemandSyncErr(err error) bool {
	// Local layout / destination storage failures stay hard even when they wrap
	// a not-found sentinel (e.g. CommitAll staging without index.json).
	// Misconfigured host stamped ErrSyncParseRemoteRepo also wraps regclient's
	// ErrInvalidReference; that must stay weak, not soft.
	if errors.Is(err, zerr.ErrRepoBadLayout) ||
		errors.Is(err, zerr.ErrStorageTransient) ||
		errors.Is(err, zerr.ErrStoragePermanent) ||
		errors.Is(err, zerr.ErrSyncParseRemoteRepo) {
		return false
	}

	return errors.Is(err, zerr.ErrSyncImageFilteredOut) ||
		errors.Is(err, zerr.ErrManifestNotFound) ||
		errors.Is(err, zerr.ErrRepoNotFound) ||
		errors.Is(err, zerr.ErrSyncImageNotSigned) ||
		errors.Is(err, zerr.ErrMediaTypeNotSupported) ||
		// Client/reference parse failure from GetImageReference (not host config;
		// misconfigured hosts are stamped ErrSyncParseRemoteRepo instead).
		errors.Is(err, errs.ErrInvalidReference)
}

// isTransientRemoteConnectivityErr reports a weak remote failure: the registry
// never produced a content answer (dial/DNS/timeout/TLS/misconfigured host). Soft
// misses outrank weak failures so a dead sibling does not force HTTP 503 on every
// miss. Alone, a weak failure still classifies as ErrSyncInternal (503).
func isTransientRemoteConnectivityErr(err error) bool {
	if err == nil {
		return false
	}

	// Destination/object-store outages stay hard even when they wrap dial/TLS causes.
	if errors.Is(err, zerr.ErrStorageTransient) ||
		errors.Is(err, zerr.ErrStoragePermanent) ||
		errors.Is(err, zerr.ErrStorageMissing) {
		return false
	}

	// Sync timeout / regclient backoff cancel: upstream never finished answering.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errs.ErrCanceled) {
		return true
	}

	// Registry unreachable at ping time (legacy sentinel; still treated as weak).
	if errors.Is(err, zerr.ErrSyncPingRegistry) {
		return true
	}

	// Misconfigured remote URL/host (empty host, absolute path, host with path, …).
	// Client-invalid references stay soft via errs.ErrInvalidReference instead.
	if errors.Is(err, zerr.ErrSyncParseRemoteRepo) {
		return true
	}

	var (
		opErr       *net.OpError
		dnsErr      *net.DNSError
		urlErr      *url.Error
		tlsVerify   *tls.CertificateVerificationError
		unknownCA   x509.UnknownAuthorityError
		hostname    x509.HostnameError
		invalidCert x509.CertificateInvalidError
		systemRoots x509.SystemRootsError
	)

	// Transport never established: dial/DNS, TLS verify, or other HTTP client
	// transport failures (e.g. HTTPS client talking to plaintext HTTP) that
	// surface as *url.Error without a net/x509 type in the chain.
	return errors.As(err, &opErr) ||
		errors.As(err, &dnsErr) ||
		errors.As(err, &urlErr) ||
		errors.As(err, &tlsVerify) ||
		errors.As(err, &unknownCA) ||
		errors.As(err, &hostname) ||
		errors.As(err, &invalidCert) ||
		errors.As(err, &systemRoots)
}

// classifyOnDemandClientError maps a hard on-demand failure to an opaque sentinel for
// HTTP clients. Soft misses are left unchanged. context.Canceled is treated as hard:
// runOnDemandServices detaches from the HTTP request, so a cancel that reaches here is
// an internal sync/copy abort, not a client disconnect. All other hard failures also
// collapse to ErrSyncInternal (HTTP 503) so clients cannot distinguish upstream vs local
// causes and do not receive TLS/path details. Callers that need the root cause in logs
// must record it before calling this helper.
func classifyOnDemandClientError(err error) error {
	if err == nil || isSoftOnDemandSyncErr(err) {
		return err
	}

	return zerr.ErrSyncInternal
}
