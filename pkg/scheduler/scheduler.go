package scheduler

import (
	"container/heap"
	"context"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
)

type Task interface {
	DoWork(ctx context.Context) error
	Name() string
	String() string
}

type generatorsPriorityQueue []*generator

func (pq generatorsPriorityQueue) Len() int {
	return len(pq)
}

func (pq generatorsPriorityQueue) Less(i, j int) bool {
	return pq[i].getRanking() > pq[j].getRanking()
}

func (pq generatorsPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *generatorsPriorityQueue) Push(x any) {
	n := len(*pq)

	item, ok := x.(*generator)
	if !ok {
		return
	}

	item.index = n
	*pq = append(*pq, item)
}

func (pq *generatorsPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]

	return item
}

const (
	rateLimiterScheduler = 400
	rateLimit            = 50 * time.Millisecond
	NumWorkersMultiplier = 4
	sendMetricsInterval  = 5 * time.Second
	idleSleepInterval    = 1 * time.Second
)

type Scheduler struct {
	tasksQLow         chan Task
	tasksQMedium      chan Task
	tasksQHigh        chan Task
	tasksDoWork       int
	tasksLock         *sync.Mutex
	generators        generatorsPriorityQueue
	waitingGenerators []*generator
	doneGenerators    []*generator
	generatorsLock    *sync.Mutex
	log               log.Logger
	RateLimit         time.Duration
	NumWorkers        int
	workerChan        chan Task
	metricsChan       chan struct{}
	workerWg          *sync.WaitGroup
	isShuttingDown    atomic.Bool
	metricServer      monitoring.MetricServer
	cancelFunc        context.CancelFunc
}

func NewScheduler(cfg *config.Config, ms monitoring.MetricServer, logC log.Logger) *Scheduler { //nolint: varnamelen
	chLow := make(chan Task, rateLimiterScheduler)
	chMedium := make(chan Task, rateLimiterScheduler)
	chHigh := make(chan Task, rateLimiterScheduler)
	generatorPQ := make(generatorsPriorityQueue, 0)
	numWorkers := getNumWorkers(cfg)
	sublogger := logC.With().Str("component", "scheduler").Logger()

	heap.Init(&generatorPQ)
	// force pushing this metric (for zot minimal metrics are enabled on first scraping)
	monitoring.SetSchedulerNumWorkers(ms, numWorkers)

	return &Scheduler{
		tasksQLow:      chLow,
		tasksQMedium:   chMedium,
		tasksQHigh:     chHigh,
		tasksDoWork:    0, // number of tasks that are in working state
		tasksLock:      new(sync.Mutex),
		generators:     generatorPQ,
		generatorsLock: new(sync.Mutex),
		log:            sublogger,
		// default value
		metricServer: ms,
		RateLimit:    rateLimit,
		NumWorkers:   numWorkers,
		workerChan:   make(chan Task, numWorkers),
		metricsChan:  make(chan struct{}, 1),
		workerWg:     new(sync.WaitGroup),
	}
}

func (scheduler *Scheduler) poolWorker(ctx context.Context) {
	for i := 0; i < scheduler.NumWorkers; i++ {
		go func(workerID int) {
			defer scheduler.workerWg.Done()

			var workStart time.Time

			var workDuration time.Duration

			for task := range scheduler.workerChan {
				// leave below line here (for zot minimal metrics can be enabled on first scraping)
				metricsEnabled := scheduler.metricServer.IsEnabled()
				scheduler.log.Debug().Int("worker", workerID).Str("task", task.String()).Msg("starting task")

				if metricsEnabled {
					scheduler.tasksLock.Lock()
					scheduler.tasksDoWork++
					scheduler.tasksLock.Unlock()

					workStart = time.Now()
				}

				if err := task.DoWork(ctx); err != nil {
					scheduler.log.Error().Int("worker", workerID).Str("task", task.String()).Err(err).
						Msg("failed to execute task")
				}

				if metricsEnabled {
					scheduler.tasksLock.Lock()
					scheduler.tasksDoWork--
					scheduler.tasksLock.Unlock()

					workDuration = time.Since(workStart)
					monitoring.ObserveWorkersTasksDuration(scheduler.metricServer, task.Name(), workDuration)
				}

				scheduler.log.Debug().Int("worker", workerID).Str("task", task.String()).Msg("finished task")
			}
		}(i + 1)
	}
}

func (scheduler *Scheduler) metricsWorker() {
	ticker := time.NewTicker(sendMetricsInterval)

	for {
		if scheduler.inShutdown() {
			return
		}

		select {
		case <-scheduler.metricsChan:
			ticker.Stop()

			return
		case <-ticker.C:
			genMap := make(map[string]map[string]uint64)
			tasksMap := make(map[string]int)
			// initialize map
			for _, p := range []Priority{LowPriority, MediumPriority, HighPriority} {
				priority := p.String()
				genMap[priority] = make(map[string]uint64)

				for _, s := range []State{Ready, Waiting, Done} {
					genMap[priority][s.String()] = 0
				}
			}

			scheduler.generatorsLock.Lock()
			generators := append(append(scheduler.generators, scheduler.waitingGenerators...),
				scheduler.doneGenerators...)

			for _, gen := range generators {
				p := gen.priority.String()
				s := gen.getState().String()
				genMap[p][s]++
			}

			// tasks queue size by priority
			tasksMap[LowPriority.String()] = len(scheduler.tasksQLow)
			tasksMap[MediumPriority.String()] = len(scheduler.tasksQMedium)
			tasksMap[HighPriority.String()] = len(scheduler.tasksQHigh)
			scheduler.generatorsLock.Unlock()

			monitoring.SetSchedulerGenerators(scheduler.metricServer, genMap)
			monitoring.SetSchedulerTasksQueue(scheduler.metricServer, tasksMap)

			workersMap := make(map[string]int)

			scheduler.tasksLock.Lock()
			workersMap["idle"] = scheduler.NumWorkers - scheduler.tasksDoWork
			workersMap["working"] = scheduler.tasksDoWork
			scheduler.tasksLock.Unlock()
			monitoring.SetSchedulerWorkers(scheduler.metricServer, workersMap)
		}
	}
}

// Shutdown stops the scheduler. It will wait for all tasks being run to finish their work before exiting.
func (scheduler *Scheduler) Shutdown() {
	defer scheduler.workerWg.Wait()

	if !scheduler.inShutdown() {
		scheduler.shutdown()
	}
}

func (scheduler *Scheduler) inShutdown() bool {
	return scheduler.isShuttingDown.Load()
}

func (scheduler *Scheduler) shutdown() {
	scheduler.isShuttingDown.Store(true)

	scheduler.cancelFunc()
	close(scheduler.metricsChan)
}

func (scheduler *Scheduler) RunScheduler() {
	/*This context is passed to all task generators
	calling scheduler.Shutdown() will cancel this context and will wait for all tasks
	to finish their work gracefully.*/
	ctx, cancel := context.WithCancel(context.Background())
	scheduler.cancelFunc = cancel

	throttle := time.NewTicker(scheduler.RateLimit).C

	numWorkers := scheduler.NumWorkers

	// wait all workers to finish their work before exiting from Shutdown()
	scheduler.workerWg.Add(numWorkers)

	// start worker pool
	go scheduler.poolWorker(ctx)

	// periodically send metrics
	go scheduler.metricsWorker()

	go func() {
		// will close workers chan when either ctx is canceled or scheduler.Shutdown()
		defer close(scheduler.workerChan)

		for {
			select {
			case <-ctx.Done():
				if !scheduler.inShutdown() {
					scheduler.shutdown()
				}

				scheduler.log.Debug().Msg("received stop signal, gracefully shutting down...")

				return
			default:
				// we don't want to block on sending task in workerChan.
				if len(scheduler.workerChan) == scheduler.NumWorkers {
					<-throttle

					continue
				}

				task := scheduler.getTask()

				if task == nil {
					// No tasks available - sleep longer when idle instead of polling every 50ms
					// This reduces CPU usage when the system is completely idle
					time.Sleep(idleSleepInterval)

					continue
				}

				// push tasks into worker pool until workerChan is full.
				scheduler.workerChan <- task
			}
		}
	}()
}

func (scheduler *Scheduler) pushReadyGenerators() {
	// iterate through waiting generators list and resubmit those which become ready to run
	for {
		modified := false

		for i, gen := range scheduler.waitingGenerators {
			if gen.getState() == Ready {
				gen.done = false
				heap.Push(&scheduler.generators, gen)
				scheduler.waitingGenerators = append(scheduler.waitingGenerators[:i], scheduler.waitingGenerators[i+1:]...)
				modified = true

				scheduler.log.Debug().Str("generator", gen.taskGenerator.Name()).
					Msg("waiting generator is ready, pushing to ready generators")

				break
			}
		}

		if !modified {
			break
		}
	}
}

func (scheduler *Scheduler) generateTasks() {
	scheduler.generatorsLock.Lock()
	defer scheduler.generatorsLock.Unlock()

	// resubmit ready generators(which were in a waiting state) to generators priority queue
	scheduler.pushReadyGenerators()

	// get the highest priority generator from queue
	if scheduler.generators.Len() == 0 {
		return
	}

	var gen *generator

	// check if the generator with highest priority is ready to run
	if scheduler.generators[0].getState() == Ready {
		// we are not popping it as we will generate multiple tasks until it is done
		// we are going to pop after all tasks are generated
		gen = scheduler.generators[0]

		// trigger a generator reorder, as generating a task may impact the order
		// equivalent of pop/remove followed by push, but more efficient
		heap.Fix(&scheduler.generators, 0)
	} else {
		gen, _ = heap.Pop(&scheduler.generators).(*generator)
		if gen.getState() == Waiting {
			scheduler.waitingGenerators = append(scheduler.waitingGenerators, gen)
		} else if gen.getState() == Done {
			scheduler.doneGenerators = append(scheduler.doneGenerators, gen)
		}

		return
	}

	// run generator to generate a new task which will be added to a channel by priority
	gen.generate(scheduler)
}

func (scheduler *Scheduler) getTask() Task {
	// first, generate a task with highest possible priority
	scheduler.generateTasks()

	// then, return a task with highest possible priority
	select {
	case t := <-scheduler.tasksQHigh:
		return t
	default:
	}

	select {
	case t := <-scheduler.tasksQMedium:
		return t
	default:
	}

	select {
	case t := <-scheduler.tasksQLow:
		return t
	default:
	}

	return nil
}

func (scheduler *Scheduler) getTasksChannelByPriority(priority Priority) chan Task {
	switch priority {
	case LowPriority:
		return scheduler.tasksQLow
	case MediumPriority:
		return scheduler.tasksQMedium
	case HighPriority:
		return scheduler.tasksQHigh
	}

	return nil
}

func (scheduler *Scheduler) SubmitTask(task Task, priority Priority) {
	// get by priority the channel where the task should be added to
	tasksQ := scheduler.getTasksChannelByPriority(priority)
	if tasksQ == nil {
		return
	}

	// check if the scheduler is still running in order to add the task to the channel
	if scheduler.inShutdown() {
		return
	}

	select {
	case tasksQ <- task:
		scheduler.log.Info().Msg("adding a new task")
	default:
		if scheduler.inShutdown() {
			return
		}
	}
}

type Priority int

const (
	LowPriority Priority = iota
	MediumPriority
	HighPriority
)

type State int

const (
	Ready State = iota
	Waiting
	Done
)

type TaskGenerator interface {
	Next() (Task, error)
	IsDone() bool
	IsReady() bool
	Name() string
	Reset()
}

type generator struct {
	interval      time.Duration
	lastRun       time.Time
	done          bool
	priority      Priority
	taskGenerator TaskGenerator
	remainingTask Task
	index         int
	taskCount     int64
}

func (gen *generator) generate(sch *Scheduler) {
	// get by priority the channel where the new generated task should be added to
	taskQ := sch.getTasksChannelByPriority(gen.priority)

	task := gen.remainingTask

	// in case there is no task already generated, generate a new task
	if gen.remainingTask == nil {
		nextTask, err := gen.taskGenerator.Next()
		if err != nil {
			sch.log.Error().Err(err).Str("generator", gen.taskGenerator.Name()).
				Msg("failed to execute generator")

			return
		}

		// check if the generator is done
		if gen.taskGenerator.IsDone() {
			gen.done = true
			gen.lastRun = time.Now()
			gen.taskCount = 0
			gen.taskGenerator.Reset()

			sch.log.Debug().Str("generator", gen.taskGenerator.Name()).
				Msg("generator is done")

			return
		}

		task = nextTask
	}

	// keep track of generated task count to use it for generator ordering
	gen.taskCount++

	// check if it's possible to add a new task to the channel
	// if not, keep the generated task and retry to add it next time
	select {
	case taskQ <- task:
		gen.remainingTask = nil

		return
	default:
		gen.remainingTask = task
	}
}

// getState() returns the state of a generator.
// if the generator is not periodic then it can be done or ready to generate a new task.
// if the generator is periodic then it can be waiting (finished its work and wait for its interval to pass)
// or ready to generate a new task.
func (gen *generator) getState() State {
	if gen.interval == time.Duration(0) {
		if gen.done && gen.remainingTask == nil {
			return Done
		}
	} else {
		if gen.done && time.Since(gen.lastRun) < gen.interval && gen.remainingTask == nil {
			return Waiting
		}
	}

	if !gen.taskGenerator.IsReady() {
		return Waiting
	}

	return Ready
}

func (gen *generator) getRanking() float64 {
	// take into account the priority, but also how many tasks of
	// a specific generator were executed in the current generator run
	return math.Pow(10, float64(gen.priority)) / (1 + float64(gen.taskCount)) //nolint:mnd
}

func (scheduler *Scheduler) SubmitGenerator(taskGenerator TaskGenerator, interval time.Duration, priority Priority) {
	newGenerator := &generator{
		interval:      interval,
		done:          false,
		priority:      priority,
		taskGenerator: taskGenerator,
		taskCount:     0,
		remainingTask: nil,
	}

	scheduler.generatorsLock.Lock()
	defer scheduler.generatorsLock.Unlock()

	// add generator to the generators priority queue
	heap.Push(&scheduler.generators, newGenerator)
	// force pushing this metric (for zot minimal metrics are enabled on first scraping)
	monitoring.IncSchedulerGenerators(scheduler.metricServer)
}

func getNumWorkers(cfg *config.Config) int {
	schedulerConfig := cfg.CopySchedulerConfig()
	if schedulerConfig != nil && schedulerConfig.NumWorkers != 0 {
		return schedulerConfig.NumWorkers
	}

	return runtime.NumCPU() * NumWorkersMultiplier
}

func (p Priority) String() string {
	var priority string

	switch p {
	case LowPriority:
		priority = "low"
	case MediumPriority:
		priority = "medium"
	case HighPriority:
		priority = "high"
	default:
		priority = "invalid"
	}

	return priority
}

func (s State) String() string {
	var status string

	switch s {
	case Ready:
		status = "ready"
	case Waiting:
		status = "waiting"
	case Done:
		status = "done"
	default:
		status = "invalid"
	}

	return status
}
