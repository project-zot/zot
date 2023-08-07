package scheduler

import (
	"container/heap"
	"context"
	"runtime"
	"sync"
	"time"

	"zotregistry.io/zot/pkg/api/config"
	"zotregistry.io/zot/pkg/log"
)

type Task interface {
	DoWork() error
}

type generatorsPriorityQueue []*generator

func (pq generatorsPriorityQueue) Len() int {
	return len(pq)
}

func (pq generatorsPriorityQueue) Less(i, j int) bool {
	return pq[i].priority > pq[j].priority
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
	rateLimit            = 5 * time.Second
	numWorkersMultiplier = 4
)

type Scheduler struct {
	tasksQLow         chan Task
	tasksQMedium      chan Task
	tasksQHigh        chan Task
	generators        generatorsPriorityQueue
	waitingGenerators []*generator
	generatorsLock    *sync.Mutex
	log               log.Logger
	stopCh            chan struct{}
	RateLimit         time.Duration
	NumWorkers        int
}

func NewScheduler(cfg *config.Config, logC log.Logger) *Scheduler {
	chLow := make(chan Task, rateLimiterScheduler)
	chMedium := make(chan Task, rateLimiterScheduler)
	chHigh := make(chan Task, rateLimiterScheduler)
	generatorPQ := make(generatorsPriorityQueue, 0)
	numWorkers := getNumWorkers(cfg)
	sublogger := logC.With().Str("component", "scheduler").Logger()

	heap.Init(&generatorPQ)

	return &Scheduler{
		tasksQLow:      chLow,
		tasksQMedium:   chMedium,
		tasksQHigh:     chHigh,
		generators:     generatorPQ,
		generatorsLock: new(sync.Mutex),
		log:            log.Logger{Logger: sublogger},
		stopCh:         make(chan struct{}),
		// default value
		RateLimit:  rateLimit,
		NumWorkers: numWorkers,
	}
}

func (scheduler *Scheduler) poolWorker(numWorkers int, tasks chan Task) {
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			for task := range tasks {
				scheduler.log.Debug().Int("worker", workerID).Msg("scheduler: starting task")

				if err := task.DoWork(); err != nil {
					scheduler.log.Error().Int("worker", workerID).Err(err).Msg("scheduler: error while executing task")
				}

				scheduler.log.Debug().Int("worker", workerID).Msg("scheduler: finished task")
			}
		}(i + 1)
	}
}

func (scheduler *Scheduler) RunScheduler(ctx context.Context) {
	throttle := time.NewTicker(rateLimit).C

	numWorkers := scheduler.NumWorkers
	tasksWorker := make(chan Task, numWorkers)

	// start worker pool
	go scheduler.poolWorker(numWorkers, tasksWorker)

	go func() {
		for {
			select {
			case <-ctx.Done():
				close(tasksWorker)
				close(scheduler.stopCh)

				scheduler.log.Debug().Msg("scheduler: received stop signal, exiting...")

				return
			default:
				i := 0
				for i < numWorkers {
					task := scheduler.getTask()
					if task != nil {
						// push tasks into worker pool
						scheduler.log.Debug().Msg("scheduler: pushing task into worker pool")
						tasksWorker <- task
					}
					i++
				}
			}

			<-throttle
		}
	}()
}

func (scheduler *Scheduler) pushReadyGenerators() {
	// iterate through waiting generators list and resubmit those which become ready to run
	for {
		modified := false

		for i, gen := range scheduler.waitingGenerators {
			if gen.getState() == ready {
				gen.done = false
				heap.Push(&scheduler.generators, gen)
				scheduler.waitingGenerators = append(scheduler.waitingGenerators[:i], scheduler.waitingGenerators[i+1:]...)
				modified = true

				scheduler.log.Debug().Msg("scheduler: waiting generator is ready, pushing to ready generators")

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

	// check if the generator with highest prioriy is ready to run
	if scheduler.generators[0].getState() == ready {
		gen = scheduler.generators[0]
	} else {
		gen, _ = heap.Pop(&scheduler.generators).(*generator)
		if gen.getState() == waiting {
			scheduler.waitingGenerators = append(scheduler.waitingGenerators, gen)
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

	// check if the scheduler it's still running in order to add the task to the channel
	select {
	case <-scheduler.stopCh:
		return
	default:
	}

	select {
	case <-scheduler.stopCh:
		return
	case tasksQ <- task:
		scheduler.log.Info().Msg("scheduler: adding a new task")
	}
}

type Priority int

const (
	LowPriority Priority = iota
	MediumPriority
	HighPriority
)

type state int

const (
	ready state = iota
	waiting
	done
)

type TaskGenerator interface {
	Next() (Task, error)
	IsDone() bool
	IsReady() bool
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
}

func (gen *generator) generate(sch *Scheduler) {
	// get by priority the channel where the new generated task should be added to
	taskQ := sch.getTasksChannelByPriority(gen.priority)

	task := gen.remainingTask

	// in case there is no task already generated, generate a new task
	if gen.remainingTask == nil {
		nextTask, err := gen.taskGenerator.Next()
		if err != nil {
			sch.log.Error().Err(err).Msg("scheduler: error while executing generator")

			return
		}

		task = nextTask

		// check if the generator is done
		if gen.taskGenerator.IsDone() {
			gen.done = true
			gen.lastRun = time.Now()
			gen.taskGenerator.Reset()

			return
		}
	}

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
func (gen *generator) getState() state {
	if gen.interval == time.Duration(0) {
		if gen.done && gen.remainingTask == nil {
			return done
		}
	} else {
		if gen.done && time.Since(gen.lastRun) < gen.interval && gen.remainingTask == nil {
			return waiting
		}
	}

	if !gen.taskGenerator.IsReady() {
		return waiting
	}

	return ready
}

func (scheduler *Scheduler) SubmitGenerator(taskGenerator TaskGenerator, interval time.Duration, priority Priority) {
	newGenerator := &generator{
		interval:      interval,
		done:          false,
		priority:      priority,
		taskGenerator: taskGenerator,
		remainingTask: nil,
	}

	scheduler.generatorsLock.Lock()
	defer scheduler.generatorsLock.Unlock()

	// add generator to the generators priority queue
	heap.Push(&scheduler.generators, newGenerator)
}

func getNumWorkers(cfg *config.Config) int {
	if cfg.Scheduler != nil && cfg.Scheduler.NumWorkers != 0 {
		return cfg.Scheduler.NumWorkers
	}

	return runtime.NumCPU() * numWorkersMultiplier
}
