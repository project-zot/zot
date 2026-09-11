//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/log"
)

// stubOnDemandService is a synchronous Service stub for BaseOnDemand unit tests.
type stubOnDemandService struct {
	syncImageErr     error
	syncReferrersErr error
	canRetry         bool
	timeout          time.Duration
	syncImageCalls   int
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

func TestOnDemandDockerCompatPreference(t *testing.T) {
	Convey("SyncImage prefers docker-compat over a later skippable miss", t, func() {
		dockerErr := fmt.Errorf("%w: docker list", zerr.ErrSyncDockerCompatRequired)
		first := &stubOnDemandService{syncImageErr: dockerErr, canRetry: false}
		second := &stubOnDemandService{syncImageErr: zerr.ErrSyncImageFilteredOut, canRetry: false}

		onDemand := NewOnDemand(log.NewTestLogger())
		onDemand.Add(first)
		onDemand.Add(second)

		err := onDemand.SyncImage(context.Background(), "repo", "tag")
		So(errors.Is(err, zerr.ErrSyncDockerCompatRequired), ShouldBeTrue)
		So(first.syncImageCalls, ShouldEqual, 1)
		So(second.syncImageCalls, ShouldEqual, 1)
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
