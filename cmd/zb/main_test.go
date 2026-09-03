package main //nolint:testpackage // separate binary

import (
	"errors"
	"net"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
)

var (
	errSomethingElse     = errors.New("something else")
	errIOTimeout         = errors.New("i/o timeout")
	errDeadlineExceeded  = errors.New("context deadline exceeded")
	errClosedConn        = errors.New("write tcp: use of closed network connection")
	errUnexpectedStatus  = errors.New("unexpected status")
	errConnectionRefused = errors.New("connection refused")
)

func TestIntegration(t *testing.T) {
	Convey("Make a new controller", t, func() {
		conf := config.New()
		c := api.NewController(conf)
		So(c, ShouldNotBeNil)

		cl := NewPerfRootCmd()
		So(cl, ShouldNotBeNil)

		So(cl.Execute(), ShouldBeNil)
	})
}

func TestMaxTimeoutFailuresFlag(t *testing.T) {
	Convey("max-timeout-failures flag is registered with default 0", t, func() {
		cl := NewPerfRootCmd()
		flag := cl.Flags().Lookup("max-timeout-failures")
		So(flag, ShouldNotBeNil)
		So(flag.DefValue, ShouldEqual, "0")
	})
}

func TestShouldFailRun(t *testing.T) {
	Convey("run fails on hard failures or timeout budget overrun", t, func() {
		So(shouldFailRun(0, 0, 0), ShouldBeFalse)
		So(shouldFailRun(0, 1, 0), ShouldBeTrue)
		So(shouldFailRun(0, 1, 1), ShouldBeFalse)
		So(shouldFailRun(0, 2, 1), ShouldBeTrue)
		So(shouldFailRun(1, 0, 5), ShouldBeTrue)
		So(shouldFailRun(1, 1, 1), ShouldBeTrue)
		So(shouldFailRun(0, 0, 5), ShouldBeFalse)
	})
}

func TestIsTimeoutError(t *testing.T) {
	Convey("timeout error classification", t, func() {
		So(isTimeoutError(nil), ShouldBeFalse)
		So(isTimeoutError(errSomethingElse), ShouldBeFalse)
		So(isTimeoutError(errIOTimeout), ShouldBeTrue)
		So(isTimeoutError(errDeadlineExceeded), ShouldBeTrue)
		So(isTimeoutError(errClosedConn), ShouldBeTrue)
		So(isTimeoutError(&timeoutNetError{}), ShouldBeTrue)
	})
}

type timeoutNetError struct{}

func (e *timeoutNetError) Error() string   { return "read tcp: i/o timeout" }
func (e *timeoutNetError) Timeout() bool   { return true }
func (e *timeoutNetError) Temporary() bool { return true }

var _ net.Error = (*timeoutNetError)(nil)

func TestUpdateStatsTimeoutCount(t *testing.T) {
	Convey("timeoutErrorCount increments only for timeout errors", t, func() {
		summary := newStatsSummary("test")

		updateStats(&summary, statsRecord{
			latency:    time.Second,
			isConnFail: true,
			err:        errIOTimeout,
		})
		updateStats(&summary, statsRecord{
			latency: time.Second,
			isErr:   true,
			err:     errUnexpectedStatus,
		})
		updateStats(&summary, statsRecord{
			latency:    time.Second,
			isConnFail: true,
			err:        errConnectionRefused,
		})

		So(summary.errorCount, ShouldEqual, 3)
		So(summary.timeoutErrorCount, ShouldEqual, 1)
	})
}
