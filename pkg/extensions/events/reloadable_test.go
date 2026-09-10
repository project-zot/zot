package events_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/extensions/events"
)

// countingRecorder counts what it was asked to publish.
type countingRecorder struct {
	created    atomic.Int64
	updated    atomic.Int64
	deleted    atomic.Int64
	lintFailed atomic.Int64
	scanned    atomic.Int64
	closed     atomic.Bool
}

func (r *countingRecorder) Close() { r.closed.Store(true) }

func (r *countingRecorder) RepositoryCreated(string, *events.EventContext) { r.created.Add(1) }

func (r *countingRecorder) ImageUpdated(_, _, _, _, _ string, _ *events.EventContext) {
	r.updated.Add(1)
}

func (r *countingRecorder) ImageDeleted(_, _, _, _ string, _ *events.EventContext) {
	r.deleted.Add(1)
}

func (r *countingRecorder) ImageLintFailed(_, _, _, _, _ string, _ *events.EventContext) {
	r.lintFailed.Add(1)
}

func (r *countingRecorder) ImageScanned(_, _, _, _ string, _ events.ImageScanSummary,
	_ *events.EventContext,
) {
	r.scanned.Add(1)
}

func TestReloadableRecorder(t *testing.T) {
	Convey("A swap routes later events to the new delegate", t, func() {
		first, second := &countingRecorder{}, &countingRecorder{}
		reloadable := events.NewReloadableRecorder(first)

		reloadable.RepositoryCreated("repo", nil)
		So(first.created.Load(), ShouldEqual, 1)

		replaced := reloadable.Swap(second)
		So(replaced, ShouldEqual, first)

		reloadable.RepositoryCreated("repo", nil)
		reloadable.ImageUpdated("repo", "tag", "digest", "mediaType", "manifest", nil)

		So(first.created.Load(), ShouldEqual, 1)
		So(second.created.Load(), ShouldEqual, 1)
		So(second.updated.Load(), ShouldEqual, 1)
	})

	Convey("Events are dropped while no delegate is installed", t, func() {
		recorder := &countingRecorder{}
		reloadable := events.NewReloadableRecorder(nil)

		So(func() { reloadable.RepositoryCreated("repo", nil) }, ShouldNotPanic)

		// disabled at startup, enabled by a reload
		So(reloadable.Swap(recorder), ShouldBeNil)
		reloadable.RepositoryCreated("repo", nil)
		So(recorder.created.Load(), ShouldEqual, 1)

		// and disabled again by a later reload
		So(reloadable.Swap(nil), ShouldEqual, recorder)
		reloadable.RepositoryCreated("repo", nil)
		So(recorder.created.Load(), ShouldEqual, 1)
	})

	Convey("Close reaches the current delegate", t, func() {
		recorder := &countingRecorder{}
		reloadable := events.NewReloadableRecorder(recorder)

		reloadable.Close()
		So(recorder.closed.Load(), ShouldBeTrue)
	})

	Convey("Close detaches the delegate it closed", t, func() {
		recorder := &countingRecorder{}
		reloadable := events.NewReloadableRecorder(recorder)

		reloadable.Close()
		So(recorder.closed.Load(), ShouldBeTrue)

		// emitting into sinks that are already closed is what detaching avoids
		reloadable.RepositoryCreated("repo", nil)
		So(recorder.created.Load(), ShouldEqual, 0)

		So(func() { reloadable.Close() }, ShouldNotPanic)
	})

	Convey("Close waits for a call already inside the delegate", t, func() {
		entered, release := make(chan struct{}), make(chan struct{})
		blocking := &blockingRecorder{entered: entered, release: release}
		reloadable := events.NewReloadableRecorder(blocking)

		go reloadable.RepositoryCreated("repo", nil)
		<-entered

		closed := make(chan struct{})

		go func() {
			reloadable.Close()
			close(closed)
		}()

		// the call has not dispatched its publish yet
		select {
		case <-closed:
			t.Fatal("Close returned while the delegate was still in use")
		case <-time.After(200 * time.Millisecond):
		}

		close(release)

		select {
		case <-closed:
			So(blocking.closed.Load(), ShouldBeTrue)
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not return after the call finished")
		}
	})

	Convey("Closing a wrapper with no delegate is safe and still terminal", t, func() {
		var reloadable events.ReloadableRecorder

		So(func() { reloadable.Close() }, ShouldNotPanic)

		// nothing was there to close, but the wrapper is closed all the same
		recorder := &countingRecorder{}
		So(reloadable.Swap(recorder), ShouldEqual, recorder)
	})

	Convey("A swap after close installs nothing and hands the recorder back", t, func() {
		installed, late := &countingRecorder{}, &countingRecorder{}
		reloadable := events.NewReloadableRecorder(installed)

		reloadable.Close()
		So(installed.closed.Load(), ShouldBeTrue)

		// a reload still in flight when shutdown closed the wrapper: its
		// recorder comes straight back, so the caller closes it
		So(reloadable.Swap(late), ShouldEqual, late)

		reloadable.RepositoryCreated("repo", nil)
		So(late.created.Load(), ShouldEqual, 0)
		So(installed.created.Load(), ShouldEqual, 0)

		// and closing stays a no-op rather than closing what was handed back
		So(func() { reloadable.Close() }, ShouldNotPanic)
	})

	Convey("A nil wrapper records nothing instead of panicking", t, func() {
		var reloadable *events.ReloadableRecorder

		So(func() { reloadable.RepositoryCreated("repo", nil) }, ShouldNotPanic)
		So(func() { reloadable.Close() }, ShouldNotPanic)
	})

	Convey("Publishing while swapping is race free", t, func() {
		reloadable := events.NewReloadableRecorder(&countingRecorder{})

		var waitGroup sync.WaitGroup

		waitGroup.Add(2)

		go func() {
			defer waitGroup.Done()

			for range 200 {
				reloadable.RepositoryCreated("repo", nil)
			}
		}()

		go func() {
			defer waitGroup.Done()

			for range 200 {
				reloadable.Swap(&countingRecorder{})
			}
		}()

		waitGroup.Wait()
	})

	Convey("Every event kind reaches the delegate and is safe without one", t, func() {
		recorder := &countingRecorder{}
		reloadable := events.NewReloadableRecorder(recorder)

		reloadable.ImageDeleted("repo", "tag", "digest", "mediaType", nil)
		reloadable.ImageLintFailed("repo", "tag", "digest", "mediaType", "manifest", nil)
		reloadable.ImageScanned("repo", "tag", "digest", "mediaType", events.ImageScanSummary{}, nil)
		reloadable.ImageUpdated("repo", "tag", "digest", "mediaType", "manifest", nil)
		reloadable.RepositoryCreated("repo", nil)

		// each kind has to land on its own method
		So(recorder.deleted.Load(), ShouldEqual, 1)
		So(recorder.lintFailed.Load(), ShouldEqual, 1)
		So(recorder.scanned.Load(), ShouldEqual, 1)
		So(recorder.updated.Load(), ShouldEqual, 1)
		So(recorder.created.Load(), ShouldEqual, 1)

		So(reloadable.Swap(nil), ShouldEqual, recorder)

		// the same calls with nothing installed must be no-ops
		So(func() {
			reloadable.ImageDeleted("repo", "tag", "digest", "mediaType", nil)
			reloadable.ImageLintFailed("repo", "tag", "digest", "mediaType", "manifest", nil)
			reloadable.ImageScanned("repo", "tag", "digest", "mediaType", events.ImageScanSummary{}, nil)
			reloadable.ImageUpdated("repo", "tag", "digest", "mediaType", "manifest", nil)
			reloadable.RepositoryCreated("repo", nil)
		}, ShouldNotPanic)

		So(recorder.deleted.Load(), ShouldEqual, 1)
		So(recorder.lintFailed.Load(), ShouldEqual, 1)
		So(recorder.scanned.Load(), ShouldEqual, 1)
		So(recorder.updated.Load(), ShouldEqual, 1)
		So(recorder.created.Load(), ShouldEqual, 1)
	})

	Convey("A nil wrapper is safe for every event kind", t, func() {
		var reloadable *events.ReloadableRecorder

		So(func() {
			reloadable.ImageUpdated("repo", "tag", "digest", "mediaType", "manifest", nil)
			reloadable.ImageDeleted("repo", "tag", "digest", "mediaType", nil)
			reloadable.ImageLintFailed("repo", "tag", "digest", "mediaType", "manifest", nil)
			reloadable.ImageScanned("repo", "tag", "digest", "mediaType", events.ImageScanSummary{}, nil)
		}, ShouldNotPanic)
	})

	Convey("A zero value wrapper is usable before anything is installed", t, func() {
		var reloadable events.ReloadableRecorder

		So(func() { reloadable.RepositoryCreated("repo", nil) }, ShouldNotPanic)

		recorder := &countingRecorder{}
		So(reloadable.Swap(recorder), ShouldBeNil)

		reloadable.RepositoryCreated("repo", nil)
		So(recorder.created.Load(), ShouldEqual, 1)
	})

	Convey("Swap waits for a call already inside the delegate", t, func() {
		entered, release := make(chan struct{}), make(chan struct{})
		blocking := &blockingRecorder{entered: entered, release: release}
		reloadable := events.NewReloadableRecorder(blocking)

		go reloadable.RepositoryCreated("repo", nil)
		<-entered

		swapped := make(chan events.Recorder, 1)

		go func() { swapped <- reloadable.Swap(&countingRecorder{}) }()

		// it cannot be handed back while a call is still inside it
		select {
		case <-swapped:
			t.Fatal("Swap returned while the delegate was still in use")
		case <-time.After(200 * time.Millisecond):
		}

		close(release)

		select {
		case replaced := <-swapped:
			So(replaced, ShouldEqual, blocking)
		case <-time.After(5 * time.Second):
			t.Fatal("Swap did not return after the call finished")
		}
	})
}

// blockingRecorder holds a forwarded call open.
type blockingRecorder struct {
	countingRecorder

	entered chan struct{}
	release chan struct{}
}

func (r *blockingRecorder) RepositoryCreated(string, *events.EventContext) {
	close(r.entered)
	<-r.release
}
