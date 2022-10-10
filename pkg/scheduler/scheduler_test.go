package scheduler_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/scheduler"
)

type task struct {
	log log.Logger
	msg string
	err bool
}

var errInternal = errors.New("task: internal error")

func (t *task) DoWork() error {
	if t.err {
		return errInternal
	}

	t.log.Info().Msg(t.msg)

	return nil
}

type generator struct {
	log      log.Logger
	priority string
	done     bool
	index    int
	step     int
}

func (g *generator) GenerateTask() (scheduler.Task, error) {
	if g.step > 1 {
		g.done = true
	}
	g.step++
	g.index++

	return &task{log: g.log, msg: fmt.Sprintf("executing %s task; index: %d", g.priority, g.index), err: false}, nil
}

func (g *generator) IsDone() bool {
	return g.done
}

func (g *generator) Reset() {
	g.done = false
	g.step = 0
}

func TestScheduler(t *testing.T) {
	Convey("Test order of generators in queue", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		sch := scheduler.NewScheduler(logger)

		genL := &generator{log: logger, priority: "low priority"}
		sch.SubmitGenerator(genL, time.Duration(0), scheduler.LowPriority)

		genH := &generator{log: logger, priority: "high priority"}
		sch.SubmitGenerator(genH, time.Duration(0), scheduler.HighPriority)

		ctx, cancel := context.WithCancel(context.Background())
		sch.RunScheduler(ctx)

		time.Sleep(500 * time.Millisecond)
		cancel()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "executing high priority task; index: 1")
		So(string(data), ShouldNotContainSubstring, "executing low priority task; index: 1")
		So(string(data), ShouldNotContainSubstring, "error while executing task")
	})

	Convey("Test task returning an error", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		sch := scheduler.NewScheduler(logger)

		t := &task{log: logger, msg: "", err: true}
		sch.SubmitTask(t, scheduler.MediumPriority)

		ctx, cancel := context.WithCancel(context.Background())
		sch.RunScheduler(ctx)

		time.Sleep(500 * time.Millisecond)
		cancel()

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldContainSubstring, "Adding a new task to the scheduler")
		So(string(data), ShouldContainSubstring, "error while executing task")
	})

	Convey("Test resubmit generator", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		sch := scheduler.NewScheduler(logger)

		genL := &generator{log: logger, priority: "low priority"}
		sch.SubmitGenerator(genL, 20*time.Millisecond, scheduler.LowPriority)

		ctx, cancel := context.WithCancel(context.Background())
		sch.RunScheduler(ctx)

		time.Sleep(6 * time.Second)
		cancel()

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
		sch := scheduler.NewScheduler(logger)

		t := &task{log: logger, msg: "", err: false}
		sch.SubmitTask(t, -1)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldNotContainSubstring, "Adding a new task to the scheduler")
	})

	Convey("Test adding a new task when context is done", t, func() {
		logFile, err := os.CreateTemp("", "zot-log*.txt")
		So(err, ShouldBeNil)

		defer os.Remove(logFile.Name()) // clean up

		logger := log.NewLogger("debug", logFile.Name())
		sch := scheduler.NewScheduler(logger)

		ctx, cancel := context.WithCancel(context.Background())

		sch.RunScheduler(ctx)
		cancel()
		time.Sleep(500 * time.Millisecond)

		t := &task{log: logger, msg: "", err: false}
		sch.SubmitTask(t, scheduler.LowPriority)

		data, err := os.ReadFile(logFile.Name())
		So(err, ShouldBeNil)
		So(string(data), ShouldNotContainSubstring, "Adding a new task to the scheduler")
	})
}
