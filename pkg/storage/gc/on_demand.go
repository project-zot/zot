package gc

import (
	"path"
	"sync"
	"time"

	zerr "zotregistry.dev/zot/v2/errors"
	zreg "zotregistry.dev/zot/v2/pkg/regexp"
	"zotregistry.dev/zot/v2/pkg/scheduler"
)

// RunStatus is the status of a GC run, either a sweep of the whole image store or of a single repository.
type RunStatus struct {
	Running    bool      `json:"running"`
	StartedAt  time.Time `json:"startedAt,omitzero"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	// Error is the last error returned during the run, while listing or collecting repositories.
	Error string `json:"error,omitempty"`
}

// OnDemand runs GC for an image store, or a single repository, before the next periodic sweep is due.
type OnDemand struct {
	gc  GarbageCollect
	sch *scheduler.Scheduler
	gen *GCTaskGenerator

	reposLock sync.Mutex
	repos     map[string]*RunStatus
}

func newOnDemand(gc GarbageCollect, sch *scheduler.Scheduler, gen *GCTaskGenerator) *OnDemand {
	return &OnDemand{
		gc:    gc,
		sch:   sch,
		gen:   gen,
		repos: make(map[string]*RunStatus),
	}
}

// SweepNow starts a sweep of the whole image store, through the same generator as the periodic sweep,
// so at most one sweep runs at a time, paced like the periodic sweep.
// A requested sweep may start outside the configured GC time window.
// It returns ErrGCAlreadyRunning if a sweep is already running, since that sweep may have collected
// some repositories before the request.
func (od *OnDemand) SweepNow() error {
	// The scheduler considers the generator done once it handed out the last repository, while that
	// repository may still be collected, so check the sweep itself to avoid starting an overlapping sweep.
	// The sweep is reported as running from now on, not only once the scheduler starts it.
	previous, requested := od.gen.sweep.request()
	if !requested {
		return zerr.ErrGCAlreadyRunning
	}

	od.gen.forceSweep.Store(true)

	if !od.sch.RunGeneratorNow(od.gen) {
		od.gen.forceSweep.Store(false)
		od.gen.sweep.cancelRequest(previous)

		return zerr.ErrGCNotScheduled
	}

	return nil
}

// Status returns the status of the current or last sweep of the whole image store.
func (od *OnDemand) Status() RunStatus {
	return od.gen.sweep.status()
}

// CleanRepoNow submits GC of a single repository to the scheduler.
func (od *OnDemand) CleanRepoNow(repo string) error {
	if !zreg.FullNameRegexp.MatchString(repo) {
		return zerr.ErrInvalidRepositoryName
	}

	if !od.gc.imgStore.DirExists(path.Join(od.gc.imgStore.RootDir(), repo)) {
		return zerr.ErrRepoNotFound
	}

	od.reposLock.Lock()
	defer od.reposLock.Unlock()

	if status, ok := od.repos[repo]; ok && status.Running {
		return zerr.ErrGCAlreadyRunning
	}

	task := NewGCTask(od.gc.imgStore, od.gc, repo)
	task.onDone = func(err error) {
		od.repoDone(repo, err)
	}

	previous, hadPrevious := od.repos[repo]
	od.repos[repo] = &RunStatus{Running: true, StartedAt: time.Now()}

	if !od.sch.SubmitTask(task, scheduler.HighPriority) {
		// the task will never run, so keep the status of the previous run, if any
		if hadPrevious {
			od.repos[repo] = previous
		} else {
			delete(od.repos, repo)
		}

		return zerr.ErrGCNotScheduled
	}

	return nil
}

// RepoStatus returns the status of the current or last on-demand GC of a repository,
// and false if GC was never requested for it.
func (od *OnDemand) RepoStatus(repo string) (RunStatus, bool) {
	od.reposLock.Lock()
	defer od.reposLock.Unlock()

	status, ok := od.repos[repo]
	if !ok {
		return RunStatus{}, false
	}

	return *status, true
}

func (od *OnDemand) repoDone(repo string, err error) {
	od.reposLock.Lock()
	defer od.reposLock.Unlock()

	status := od.repos[repo]
	status.Running = false
	status.FinishedAt = time.Now()

	if err != nil {
		status.Error = err.Error()
	}
}

// sweepState tracks a sweep of the image store: it is running while the generator is still generating
// tasks for repositories, or while any of those tasks is still running.
type sweepState struct {
	lock       sync.Mutex
	generating bool
	inflight   int
	last       RunStatus
}

// start marks the sweep as started, unless it already is, e.g. when retried after an error.
func (s *sweepState) start() {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.generating {
		return
	}

	s.generating = true
	s.last = RunStatus{Running: true, StartedAt: time.Now()}
}

func (s *sweepState) setError(err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.last.Error = err.Error()
}

// request marks a sweep as running before the scheduler starts it, unless one is already running.
// It returns the status to restore if the sweep can't be scheduled, and false if a sweep is running.
func (s *sweepState) request() (RunStatus, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.last.Running {
		return RunStatus{}, false
	}

	previous := s.last
	s.last = RunStatus{Running: true, StartedAt: time.Now()}

	return previous, true
}

// cancelRequest restores the status from before a request the scheduler did not accept.
func (s *sweepState) cancelRequest(previous RunStatus) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.last = previous
}

func (s *sweepState) generationDone() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.generating = false
	s.finishIfDone()
}

func (s *sweepState) taskStarted() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.inflight++
}

func (s *sweepState) taskDone(err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.inflight--

	if err != nil {
		s.last.Error = err.Error()
	}

	s.finishIfDone()
}

func (s *sweepState) finishIfDone() {
	if s.generating || s.inflight > 0 || !s.last.Running {
		return
	}

	s.last.Running = false
	s.last.FinishedAt = time.Now()
}

func (s *sweepState) status() RunStatus {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.last
}
