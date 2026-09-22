package extensions

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
	extconf "zotregistry.dev/zot/v2/pkg/extensions/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
)

// stubExpiryMetricServer records ForceSendMetric calls so tests can observe that
// ExpireRepoMetrics was invoked, without depending on the build-tag-specific payload.
type stubExpiryMetricServer struct {
	forced chan any
}

func newStubExpiryMetricServer() *stubExpiryMetricServer {
	return &stubExpiryMetricServer{forced: make(chan any, 16)}
}

func (s *stubExpiryMetricServer) SendMetric(any) {}

func (s *stubExpiryMetricServer) ForceSendMetric(metric any) {
	select {
	case s.forced <- metric:
	default:
	}
}

func (s *stubExpiryMetricServer) ReceiveMetrics() any { return monitoring.MetricsCopy{} }
func (s *stubExpiryMetricServer) IsEnabled() bool     { return true }
func (s *stubExpiryMetricServer) Stop()               {}

func newExpiryTestLogger(t *testing.T) (log.Logger, string) {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "zot-log.txt")

	return log.NewLogger("info", logPath), logPath
}

func TestMetricsExpiryTask(t *testing.T) {
	Convey("Task metadata", t, func() {
		task := &metricsExpiryTask{ms: newStubExpiryMetricServer()}

		So(task.Name(), ShouldEqual, "MetricsExpiryTask")
		So(task.String(), ShouldEqual, task.Name())
	})

	Convey("DoWork triggers a repo metrics expiry sweep", t, func() {
		stub := newStubExpiryMetricServer()
		task := &metricsExpiryTask{ms: stub}

		So(task.DoWork(context.Background()), ShouldBeNil)
		So(len(stub.forced), ShouldEqual, 1)
	})
}

func TestMetricsExpiryGenerator(t *testing.T) {
	Convey("Generator metadata and readiness", t, func() {
		stub := newStubExpiryMetricServer()
		gen := &metricsExpiryGenerator{ms: stub}

		So(gen.Name(), ShouldEqual, "MetricsExpiryGenerator")
		So(gen.IsReady(), ShouldBeTrue)
		So(gen.IsDone(), ShouldBeFalse)
	})

	Convey("Next yields one task per arming, then reports done", t, func() {
		stub := newStubExpiryMetricServer()
		gen := &metricsExpiryGenerator{ms: stub}

		// The first call must return the real task with IsDone() still false: generate()
		// in pkg/scheduler checks IsDone() right after Next() returns and discards
		// whatever Next() just handed back if IsDone() is already true. Only the call
		// after the task was issued may flip done - see metricsExpiryGenerator.Next().
		task, err := gen.Next()
		So(err, ShouldBeNil)
		So(task, ShouldNotBeNil)
		So(gen.IsDone(), ShouldBeFalse)

		expiryTask, ok := task.(*metricsExpiryTask)
		So(ok, ShouldBeTrue)
		So(expiryTask.ms, ShouldEqual, stub)

		next, err := gen.Next()
		So(err, ShouldBeNil)
		So(next, ShouldBeNil)
		So(gen.IsDone(), ShouldBeTrue)

		gen.Reset()
		So(gen.IsDone(), ShouldBeFalse)

		rearmed, err := gen.Next()
		So(err, ShouldBeNil)
		So(rearmed, ShouldNotBeNil)
	})
}

func TestEnableMetricsExpiry(t *testing.T) {
	Convey("Skips when metrics are disabled", t, func() {
		conf := config.New()
		logger, logPath := newExpiryTestLogger(t)
		stub := newStubExpiryMetricServer()
		sch := scheduler.NewScheduler(config.New(), monitoring.NewNopMetricServer(), log.NewTestLogger())

		EnableMetricsExpiry(conf, sch, stub, logger)

		sch.RunScheduler()
		defer sch.Shutdown()

		select {
		case <-stub.forced:
			t.Fatal("expiry task ran although metrics are disabled")
		case <-time.After(200 * time.Millisecond):
		}

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "metrics repo label expiry not configured, skipping")
	})

	Convey("Skips when repoLabelExpiry is zero", t, func() {
		conf := config.New()
		logger, logPath := newExpiryTestLogger(t)
		stub := newStubExpiryMetricServer()
		sch := scheduler.NewScheduler(config.New(), monitoring.NewNopMetricServer(), log.NewTestLogger())

		trueValue := true
		conf.Extensions = &extconf.ExtensionConfig{Metrics: &extconf.MetricsConfig{Enable: &trueValue}}

		EnableMetricsExpiry(conf, sch, stub, logger)

		sch.RunScheduler()
		defer sch.Shutdown()

		select {
		case <-stub.forced:
			t.Fatal("expiry task ran although metrics are disabled")
		case <-time.After(200 * time.Millisecond):
		}

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "metrics repo label expiry not configured, skipping")
	})

	// This Convey leaves process-wide repo-label tracking on for the rest of the test binary:
	// calling monitoring.EnableRepoLabelExpiryTracking() is a one-way, harmless flip (it only
	// starts populating a map), so no other test in this binary should assert tracking is off
	// after this one runs.
	Convey("Submits the expiry generator when configured", t, func() {
		conf := config.New()
		logger, logPath := newExpiryTestLogger(t)
		stub := newStubExpiryMetricServer()
		sch := scheduler.NewScheduler(config.New(), monitoring.NewNopMetricServer(), log.NewTestLogger())

		trueValue := true
		conf.Extensions = &extconf.ExtensionConfig{
			Metrics: &extconf.MetricsConfig{Enable: &trueValue, RepoLabelExpiry: 100 * time.Millisecond},
		}

		EnableMetricsExpiry(conf, sch, stub, logger)

		sch.RunScheduler()
		defer sch.Shutdown()

		select {
		case <-stub.forced:
		case <-time.After(10 * time.Second):
			t.Fatal("expiry task did not run after the generator was submitted")
		}

		data, err := os.ReadFile(logPath)
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "metrics repo label expiry enabled")
	})
}
