package scheduler_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/extensions/monitoring"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/scheduler"
)

type task struct {
	log log.Logger
	msg string
	err bool
}

var errInternal = errors.New("task: internal error")

func (t *task) DoWork(ctx context.Context) error {
	if t.err {
		return errInternal
	}

	for idx := 0; idx < 5; idx++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.log.Info().Msg(t.msg)

	return nil
}

func (t *task) String() string {
	return t.Name()
}

func (t *task) Name() string {
	return "TestTask"
}

type generator struct {
	log      log.Logger
	priority string
	done     bool
	index    int
	step     int
}

func (g *generator) Next() (scheduler.Task, error) {
	if g.step > 100 {
		g.done = true
	}
	g.step++
	g.index++

	if g.step%11 == 0 {
		return nil, nil
	}

	if g.step%13 == 0 {
		return nil, errInternal
	}

	return &task{log: g.log, msg: fmt.Sprintf("executing %s task; index: %d", g.priority, g.index), err: false}, nil
}

func (g *generator) IsDone() bool {
	return g.done
}

func (g *generator) IsReady() bool {
	return true
}

func (g *generator) Reset() {
	g.done = false
	g.step = 0
}

type shortGenerator struct {
	log      log.Logger
	priority string
	done     bool
	index    int
	step     int
}

func (g *shortGenerator) Next() (scheduler.Task, error) {
	g.done = true

	return &task{log: g.log, msg: fmt.Sprintf("executing %s task; index: %d", g.priority, g.index), err: false}, nil
}

func (g *shortGenerator) IsDone() bool {
	return g.done
}

func (g *shortGenerator) IsReady() bool {
	return true
}

func (g *shortGenerator) Reset() {
	g.done = true
	g.step = 0
}

func TestScheduler(t *testing.T) {
	Convey("Test active to waiting periodic generator", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(config.New(), metrics, logger)

		genH := &shortGenerator{log: logger, priority: "high priority"}
		// interval has to be higher than throttle value to simulate
		sch.SubmitGenerator(genH, 6*time.Second, scheduler.HighPriority)

		sch.RunScheduler()
		time.Sleep(7 * time.Second)
		sch.Shutdown()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "waiting generator is ready, pushing to ready generators")
	})

	Convey("Test order of generators in queue", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		cfg := config.New()
		cfg.Scheduler = &config.SchedulerConfig{NumWorkers: 3}
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(cfg, metrics, logger)

		genL := &generator{log: logger, priority: "low priority"}
		sch.SubmitGenerator(genL, time.Duration(0), scheduler.LowPriority)

		genM := &generator{log: logger, priority: "medium priority"}
		sch.SubmitGenerator(genM, time.Duration(0), scheduler.MediumPriority)

		genH := &generator{log: logger, priority: "high priority"}
		sch.SubmitGenerator(genH, time.Duration(0), scheduler.HighPriority)

		sch.RunScheduler()
		time.Sleep(4 * time.Second)
		sch.Shutdown()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)

		So(string(data), ShouldContainSubstring, "executing high priority task; index: 1")
		So(string(data), ShouldContainSubstring, "executing high priority task; index: 2")
		So(string(data), ShouldNotContainSubstring, "executing medium priority task; index: 1")
		So(string(data), ShouldNotContainSubstring, "failed to execute task")
	})

	Convey("Test task returning an error", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(config.New(), metrics, logger)

		t := &task{log: logger, msg: "", err: true}
		sch.SubmitTask(t, scheduler.MediumPriority)

		sch.RunScheduler()
		time.Sleep(500 * time.Millisecond)
		sch.Shutdown()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "adding a new task")
		So(string(data), ShouldContainSubstring, "failed to execute task")
	})

	Convey("Test resubmit generator", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(config.New(), metrics, logger)

		genL := &generator{log: logger, priority: "low priority"}
		sch.SubmitGenerator(genL, 20*time.Millisecond, scheduler.LowPriority)

		sch.RunScheduler()
		time.Sleep(4 * time.Second)
		sch.Shutdown()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "executing low priority task; index: 1")
		So(string(data), ShouldContainSubstring, "executing low priority task; index: 2")
	})

	Convey("Try to add a task with wrong priority", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(config.New(), metrics, logger)

		t := &task{log: logger, msg: "", err: false}
		sch.SubmitTask(t, -1)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldNotContainSubstring, "adding a new task")
	})

	Convey("Test adding a new task when context is done", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(config.New(), metrics, logger)

		sch.RunScheduler()
		sch.Shutdown()
		time.Sleep(500 * time.Millisecond)

		t := &task{log: logger, msg: "", err: false}
		sch.SubmitTask(t, scheduler.LowPriority)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldNotContainSubstring, "adding a new task")
	})

	Convey("Test stopping scheduler by calling Shutdown()", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(config.New(), metrics, logger)

		genL := &generator{log: logger, priority: "medium priority"}
		sch.SubmitGenerator(genL, 20*time.Millisecond, scheduler.MediumPriority)

		sch.RunScheduler()
		time.Sleep(4 * time.Second)
		sch.Shutdown()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "executing medium priority task; index: 1")
		So(string(data), ShouldContainSubstring, "executing medium priority task; index: 2")
		So(string(data), ShouldContainSubstring, "received stop signal, gracefully shutting down...")
	})

	Convey("Test scheduler Priority.String() method", t, func() {
		var p scheduler.Priority //nolint: varnamelen
		// test invalid priority
		p = 6238734
		So(p.String(), ShouldEqual, "invalid")
		p = scheduler.LowPriority
		So(p.String(), ShouldEqual, "low")
		p = scheduler.MediumPriority
		So(p.String(), ShouldEqual, "medium")
		p = scheduler.HighPriority
		So(p.String(), ShouldEqual, "high")
	})

	Convey("Test scheduler State.String() method", t, func() {
		var s scheduler.State //nolint: varnamelen
		// test invalid state
		s = -67
		So(s.String(), ShouldEqual, "invalid")
		s = scheduler.Ready
		So(s.String(), ShouldEqual, "ready")
		s = scheduler.Waiting
		So(s.String(), ShouldEqual, "waiting")
		s = scheduler.Done
		So(s.String(), ShouldEqual, "done")
	})
}

func TestGetNumWorkers(t *testing.T) {
	Convey("Test setting the number of workers - default value", t, func() {
		logger := log.NewLogger("debug", "logFile")
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(config.New(), metrics, logger)
		defer os.Remove("logFile")
		So(sch.NumWorkers, ShouldEqual, runtime.NumCPU()*4)
	})

	Convey("Test setting the number of workers - getting the value from config", t, func() {
		cfg := config.New()
		cfg.Scheduler = &config.SchedulerConfig{NumWorkers: 3}
		logger := log.NewLogger("debug", "logFile")
		metrics := monitoring.NewMetricsServer(true, logger)
		sch := scheduler.NewScheduler(cfg, metrics, logger)
		defer os.Remove("logFile")
		So(sch.NumWorkers, ShouldEqual, 3)
	})
}
