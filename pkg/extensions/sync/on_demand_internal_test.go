//go:build sync

package sync

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
	"time"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient/types/errs"
	. "github.com/smartystreets/goconvey/convey"

	"github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// stubOnDemandService is a synchronous Service stub for BaseOnDemand unit tests.
type stubOnDemandService struct {
	syncImageErr           error
	syncReferrersErr       error
	canRetry               bool
	timeout                time.Duration
	syncImageCalls         int
	onDemandInBackground   bool
	isOnDemandInBackground func(repo string) bool
}

func (s *stubOnDemandService) GetNextRepo(_ string) (string, error) { return "", nil }

func (s *stubOnDemandService) SyncRepo(_ context.Context, _ string) error { return nil }

func (s *stubOnDemandService) SyncImage(_ context.Context, _, _ string) error {
	s.syncImageCalls++

	return s.syncImageErr
}

func (s *stubOnDemandService) SyncReferrers(_ context.Context, _, _ string, _ []string) error {
	return s.syncReferrersErr
}

func (s *stubOnDemandService) ResetCatalog() {}

func (s *stubOnDemandService) CanRetryOnError() bool { return s.canRetry }

func (s *stubOnDemandService) GetSyncTimeout() time.Duration {
	if s.timeout == 0 {
		return time.Minute
	}

	return s.timeout
}

func (s *stubOnDemandService) ShouldCheckUpstream(_, _ string) bool { return true }

func (s *stubOnDemandService) IsOnDemandInBackgroundForRepo(repo string) bool {
	if s.isOnDemandInBackground != nil {
		return s.isOnDemandInBackground(repo)
	}

	return s.onDemandInBackground
}

func (s *stubOnDemandService) FetchManifest(_ context.Context, _, _ string) (manifest.Manifest, error) {
	return nil, zerr.ErrManifestNotFound
}

func (s *stubOnDemandService) IsStreamingForRepo(_ string) bool { return false }

func (s *stubOnDemandService) IsImageLocal(_, _ string, _ godigest.Digest) (bool, error) {
	return false, nil
}

func TestOnDemandDockerCompatPreference(t *testing.T) {
	Convey("SyncImage prefers docker-compat over a later skippable miss", t, func() {
		dockerErr := fmt.Errorf("%w: docker list", zerr.ErrSyncDockerCompatRequired)
		first := &stubOnDemandService{syncImageErr: dockerErr, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrSyncImageFilteredOut, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "repo", "tag")
		// docker-compat is a hard config failure from the client's point of view.
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeTrue)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestOnDemandKeepsHardErrorOverLaterFilter(t *testing.T) {
	Convey("SyncImage keeps a hard failure when a later registry is filtered out", t, func() {
		hardErr := &os.PathError{Op: "write", Path: "/var/lib/registry/blob", Err: syscall.ENOSPC}
		first := &stubOnDemandService{syncImageErr: hardErr, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrSyncImageFilteredOut, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "docker-hub/app", "tag")
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrSyncImageFilteredOut), ShouldBeFalse)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestOnDemandKeepsUnauthorizedOverLaterFilter(t *testing.T) {
	Convey("SyncImage keeps upstream auth failure when a later registry is filtered out", t, func() {
		first := &stubOnDemandService{syncImageErr: zerr.ErrUnauthorizedAccess, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrSyncImageFilteredOut, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "docker-hub/app", "tag")
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrSyncImageFilteredOut), ShouldBeFalse)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestOnDemandPrefersSoftMissOverDialFailure(t *testing.T) {
	Convey("SyncImage prefers a soft miss over an earlier remote dial failure", t, func() {
		dialErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
		first := &stubOnDemandService{syncImageErr: dialErr, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrRepoNotFound, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "missing/app", "tag")
		So(errors.Is(err, zerr.ErrRepoNotFound), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeFalse)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestOnDemandClientInvalidReferenceStaysSoft(t *testing.T) {
	Convey("SyncImage keeps client ErrInvalidReference as a soft miss (not opaque 503)", t, func() {
		// GetImageReference returns ErrInvalidReference for a bad client reference
		// when the configured host is usable; that must stay 404-shaped.
		svc := &stubOnDemandService{syncImageErr: errs.ErrInvalidReference, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(svc)

		err := onDemand.SyncImage(context.Background(), "repo", "BAD TAG")
		So(errors.Is(err, errs.ErrInvalidReference), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeFalse)
		So(svc.syncImageCalls, ShouldEqual, 1)
	})
}

func TestOnDemandPrefersAuthOverEarlierDialFailure(t *testing.T) {
	Convey("SyncImage prefers auth failure over an earlier remote dial failure", t, func() {
		dialErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
		first := &stubOnDemandService{syncImageErr: dialErr, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrUnauthorizedAccess, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "docker-hub/app", "tag")
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeTrue)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestClassifyOnDemandClientError(t *testing.T) {
	Convey("classifyOnDemandClientError maps hard failures to ErrSyncInternal", t, func() {
		tlsErr := &url.Error{
			Op:  "GET",
			URL: "https://upstream.example/v2/repo/manifests/tag",
			Err: x509.UnknownAuthorityError{},
		}
		enospcErr := &os.PathError{Op: "write", Path: "/var/lib/registry/blob", Err: syscall.ENOSPC}

		So(errors.Is(classifyOnDemandClientError(tlsErr), zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(zerr.ErrUnauthorizedAccess), zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(context.DeadlineExceeded), zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(errs.ErrCanceled), zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(enospcErr), zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(errs.ErrHTTPStatus), zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(errs.ErrHTTPRateLimit), zerr.ErrSyncInternal), ShouldBeTrue)
		storageNetErr := fmt.Errorf("%w: %w", zerr.ErrStorageTransient,
			&net.OpError{Op: "dial", Err: errors.New("connection refused")})
		So(errors.Is(classifyOnDemandClientError(storageNetErr), zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(zerr.ErrSyncImageFilteredOut), zerr.ErrSyncImageFilteredOut),
			ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(zerr.ErrRepoNotFound), zerr.ErrRepoNotFound), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(errs.ErrInvalidReference), errs.ErrInvalidReference), ShouldBeTrue)
		// Non-empty sync staging without index.json: BadLayout wraps RepoNotFound → hard 503.
		stagingLayoutErr := fmt.Errorf("%w: %w", zerr.ErrRepoBadLayout, zerr.ErrRepoNotFound)
		So(isSoftOnDemandSyncErr(stagingLayoutErr), ShouldBeFalse)
		So(errors.Is(classifyOnDemandClientError(stagingLayoutErr), zerr.ErrSyncInternal), ShouldBeTrue)
		// Host-config stamp wraps regclient ErrInvalidReference; must stay weak → 503.
		hostParseErr := fmt.Errorf("%w: %w", zerr.ErrSyncParseRemoteRepo, errs.ErrInvalidReference)
		So(isSoftOnDemandSyncErr(hostParseErr), ShouldBeFalse)
		So(isTransientRemoteConnectivityErr(hostParseErr), ShouldBeTrue)
		So(errors.Is(classifyOnDemandClientError(hostParseErr), zerr.ErrSyncInternal), ShouldBeTrue)
		// Detached syncCtx: Canceled is an internal abort, not client disconnect → opaque 503.
		So(errors.Is(classifyOnDemandClientError(context.Canceled), zerr.ErrSyncInternal), ShouldBeTrue)
		So(classifyOnDemandClientError(nil), ShouldBeNil)
	})
}

func TestIsTransientRemoteConnectivityErr(t *testing.T) {
	Convey("isTransientRemoteConnectivityErr classifies unanswered remotes and excludes storage", t, func() {
		So(isTransientRemoteConnectivityErr(nil), ShouldBeFalse)
		So(isTransientRemoteConnectivityErr(zerr.ErrStorageMissing), ShouldBeFalse)
		So(isTransientRemoteConnectivityErr(zerr.ErrStoragePermanent), ShouldBeFalse)
		So(isTransientRemoteConnectivityErr(zerr.ErrStorageTransient), ShouldBeFalse)
		storageDial := fmt.Errorf("%w: %w", zerr.ErrStorageMissing,
			&net.OpError{Op: "dial", Err: errors.New("connection refused")})
		So(isTransientRemoteConnectivityErr(storageDial), ShouldBeFalse)
		storageTLS := fmt.Errorf("%w: %w", zerr.ErrStorageTransient,
			&url.Error{Op: "GET", URL: "https://s3.example/blob", Err: x509.UnknownAuthorityError{}})
		So(isTransientRemoteConnectivityErr(storageTLS), ShouldBeFalse)

		So(isTransientRemoteConnectivityErr(context.DeadlineExceeded), ShouldBeTrue)
		So(isTransientRemoteConnectivityErr(errs.ErrCanceled), ShouldBeTrue)
		So(isTransientRemoteConnectivityErr(zerr.ErrSyncPingRegistry), ShouldBeTrue)
		So(isTransientRemoteConnectivityErr(errs.ErrInvalidReference), ShouldBeFalse)
		So(isTransientRemoteConnectivityErr(zerr.ErrSyncParseRemoteRepo), ShouldBeTrue)
		So(isTransientRemoteConnectivityErr(&net.OpError{Op: "dial", Err: errors.New("connection refused")}),
			ShouldBeTrue)
		So(isTransientRemoteConnectivityErr(&net.DNSError{Err: "no such host", Name: "missing.invalid"}),
			ShouldBeTrue)
		tlsUnknownCA := &url.Error{
			Op:  "GET",
			URL: "https://upstream.example/v2/",
			Err: x509.UnknownAuthorityError{},
		}
		So(isTransientRemoteConnectivityErr(tlsUnknownCA), ShouldBeTrue)
		So(isTransientRemoteConnectivityErr(x509.HostnameError{Host: "upstream.example"}), ShouldBeTrue)
		// HTTPS client against plaintext HTTP: *url.Error with no net/x509 cause.
		httpsToHTTP := &url.Error{
			Op:  "Get",
			URL: "https://upstream.example/v2/",
			Err: errors.New("http: server gave HTTP response to HTTPS client"),
		}
		So(isTransientRemoteConnectivityErr(httpsToHTTP), ShouldBeTrue)
		So(isTransientRemoteConnectivityErr(zerr.ErrUnauthorizedAccess), ShouldBeFalse)
	})
}

func TestRankOnDemandErr(t *testing.T) {
	Convey("rankOnDemandErr covers soft/connectivity/docker-compat precedence", t, func() {
		dialErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
		parseRepoErr := zerr.ErrSyncParseRemoteRepo
		tlsErr := &url.Error{
			Op:  "GET",
			URL: "https://upstream.example/v2/",
			Err: x509.UnknownAuthorityError{},
		}
		httpsToHTTP := &url.Error{
			Op:  "Get",
			URL: "https://upstream.example/v2/",
			Err: errors.New("http: server gave HTTP response to HTTPS client"),
		}
		soft := zerr.ErrRepoNotFound
		auth := zerr.ErrUnauthorizedAccess
		docker := zerr.ErrSyncDockerCompatRequired
		hard := errors.New("commit failed")

		So(rankOnDemandErr(soft, nil), ShouldEqual, soft)
		So(rankOnDemandErr(nil, soft), ShouldEqual, soft)

		// Soft first: connectivity from a dead sibling must not replace the soft miss.
		So(rankOnDemandErr(soft, dialErr), ShouldEqual, soft)
		So(rankOnDemandErr(soft, parseRepoErr), ShouldEqual, soft)
		So(rankOnDemandErr(soft, tlsErr), ShouldEqual, soft)
		So(rankOnDemandErr(soft, httpsToHTTP), ShouldEqual, soft)
		// Soft first: a later actionable hard failure wins.
		So(rankOnDemandErr(soft, auth), ShouldEqual, auth)

		// Hard first: soft miss must not mask auth/storage-style failures.
		So(rankOnDemandErr(auth, soft), ShouldEqual, auth)
		// Connectivity first: soft miss from a registry that answered wins.
		So(rankOnDemandErr(dialErr, soft), ShouldEqual, soft)
		So(rankOnDemandErr(parseRepoErr, soft), ShouldEqual, soft)
		So(rankOnDemandErr(tlsErr, soft), ShouldEqual, soft)
		So(rankOnDemandErr(httpsToHTTP, soft), ShouldEqual, soft)

		// Among hard errors, docker-compat is preferred either side.
		So(rankOnDemandErr(hard, docker), ShouldEqual, docker)
		So(rankOnDemandErr(docker, hard), ShouldEqual, docker)

		// Connectivity loses to a later non-connectivity hard failure.
		So(rankOnDemandErr(dialErr, auth), ShouldEqual, auth)
		So(rankOnDemandErr(parseRepoErr, auth), ShouldEqual, auth)
		So(rankOnDemandErr(tlsErr, auth), ShouldEqual, auth)
		So(rankOnDemandErr(httpsToHTTP, auth), ShouldEqual, auth)
		// Non-connectivity hard failure stays preferred over later connectivity.
		So(rankOnDemandErr(auth, dialErr), ShouldEqual, auth)
		So(rankOnDemandErr(auth, parseRepoErr), ShouldEqual, auth)
		So(rankOnDemandErr(auth, tlsErr), ShouldEqual, auth)
		So(rankOnDemandErr(auth, httpsToHTTP), ShouldEqual, auth)

		// Two ordinary hard failures: keep the first.
		So(rankOnDemandErr(auth, hard), ShouldEqual, auth)
	})
}

func TestOnDemandPrefersSoftMissOverParseRemoteRepo(t *testing.T) {
	Convey("SyncImage prefers a soft miss over an earlier ErrSyncParseRemoteRepo", t, func() {
		first := &stubOnDemandService{syncImageErr: zerr.ErrSyncParseRemoteRepo, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrManifestNotFound, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "missing/app", "tag")
		So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeFalse)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestOnDemandPrefersSoftMissOverTLSFailure(t *testing.T) {
	Convey("SyncImage prefers a soft miss over an earlier TLS verify failure", t, func() {
		tlsErr := &url.Error{
			Op:  "GET",
			URL: "https://upstream.example/v2/repo/manifests/tag",
			Err: x509.UnknownAuthorityError{},
		}
		first := &stubOnDemandService{syncImageErr: tlsErr, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrManifestNotFound, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "missing/app", "tag")
		So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeFalse)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestOnDemandPrefersSoftMissOverHTTPSToHTTP(t *testing.T) {
	Convey("SyncImage prefers a soft miss over HTTPS-to-plaintext HTTP transport failure", t, func() {
		httpsToHTTP := &url.Error{
			Op:  "Get",
			URL: "https://upstream.example/v2/repo/manifests/tag",
			Err: errors.New("http: server gave HTTP response to HTTPS client"),
		}
		first := &stubOnDemandService{syncImageErr: httpsToHTTP, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrManifestNotFound, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "missing/app", "tag")
		So(errors.Is(err, zerr.ErrManifestNotFound), ShouldBeTrue)
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeFalse)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}

func TestSyncImageClassifiesSharedBackgroundFlight(t *testing.T) {
	Convey("SyncImage classifies a raw error shared from a background-style flight leader", t, func() {
		hardErr := &os.PathError{Op: "write", Path: "/var/lib/registry/blob", Err: syscall.ENOSPC}
		onDemand := NewOnDemand(log.NewTestLogger())

		started := make(chan struct{})
		release := make(chan struct{})
		key := onDemandKey(onDemandKindImage, "repo", "tag")

		// Mimic maybeRetryInBackground: same key, raw sync result, no classify in the closure.
		go func() {
			_ = onDemand.doOnDemandFlight(key, "repo", "tag",
				"image already demanded, on-demand sync result was shared",
				func() error {
					close(started)
					<-release

					return hardErr
				})
		}()

		<-started

		errCh := make(chan error, 1)

		go func() {
			errCh <- onDemand.SyncImage(context.Background(), "repo", "tag")
		}()

		// Let the SyncImage caller join the in-flight background leader before it finishes.
		time.Sleep(50 * time.Millisecond)
		close(release)

		err := <-errCh
		So(errors.Is(err, zerr.ErrSyncInternal), ShouldBeTrue)
		So(errors.Is(err, hardErr), ShouldBeFalse)
	})
}

func TestOnDemandNoBackgroundWhenCannotRetry(t *testing.T) {
	Convey("non-skippable error without retries does not schedule background work", t, func() {
		svc := &stubOnDemandService{
			syncImageErr: errors.New("upstream unavailable"),
			canRetry:     false,
		}
		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(svc)

		err := onDemand.SyncImage(context.Background(), "repo", "tag")
		So(err, ShouldNotBeNil)

		count := 0
		onDemand.requestStore.Range(func(_, _ any) bool {
			count++

			return true
		})
		So(count, ShouldEqual, 0)
	})
}

func TestQueueImageNoopWithoutBackgroundServices(t *testing.T) {
	Convey("QueueImage returns immediately when no registry uses onDemandInBackground", t, func() {
		svc := &stubOnDemandService{onDemandInBackground: false}
		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(svc)

		So(onDemand.ShouldQueueOnDemandSync("repo"), ShouldBeFalse)
		So(func() { onDemand.QueueImage(context.Background(), "repo", "tag") }, ShouldNotPanic)
		So(svc.syncImageCalls, ShouldEqual, 0)
	})
}

func TestSyncImageInBackgroundEmptyServices(t *testing.T) {
	Convey("syncImageInBackground is a no-op without matching registries", t, func() {
		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(&stubOnDemandService{onDemandInBackground: false})

		So(onDemand.syncImageInBackground(context.Background(), "repo", "tag"), ShouldBeNil)
	})
}

func TestSyncImageInBackgroundDockerCompatPreference(t *testing.T) {
	Convey("syncImageInBackground prefers docker-compat over a later skippable miss", t, func() {
		dockerErr := fmt.Errorf("%w: docker list", zerr.ErrSyncDockerCompatRequired)
		first := &stubOnDemandService{
			syncImageErr:         dockerErr,
			onDemandInBackground: true,
		}
		second := &stubOnDemandService{
			syncImageErr:         zerr.ErrSyncImageFilteredOut,
			onDemandInBackground: true,
		}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.syncImageInBackground(context.Background(), "repo", "tag")
		So(errors.Is(err, zerr.ErrSyncDockerCompatRequired), ShouldBeTrue)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
	})
}
