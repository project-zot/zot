package scheduler

import "time"

type task struct {
	// wait for 'preDelay' before doing 'work'
	preDelay time.Duration
	// wait for 'postDelay' before finishing 'work'
	postDelay time.Duration
	// actual work, modify the signature
	work func()
	// once work is done, signal via this
	cb func()
}

type Task interface {
	Cancel() error
}

type scheduler struct {
	workQ []Task
}

func NewScheduler() *scheduler {
	return &scheduler{workQ: []Task{}}
}

func (sch *scheduler) AddTask(t *Task) {
}

func (sch *scheduler) CancelTask(t *Task) {
	// if not scheduled, remove it

	// if scheduled, attempt to cancel it
}
