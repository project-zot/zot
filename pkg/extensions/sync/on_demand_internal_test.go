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
