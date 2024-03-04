package cveinfo

import (
	"context"
	"fmt"
	"sync"
	"time"

	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/scheduler"
)

type state int

const (
	pending state = iota
	running
	done
)

func NewDBUpdateTaskGenerator(
	interval time.Duration,
	scanner Scanner,
	log log.Logger,
) scheduler.TaskGenerator {
	generator := &DBUpdateTaskGenerator{
		interval,
		scanner,
		log,
		pending,
		0,
		time.Now(),
		&sync.Mutex{},
	}

	return generator
}

type DBUpdateTaskGenerator struct {
	interval     time.Duration
	scanner      Scanner
	log          log.Logger
	status       state
	waitTime     time.Duration
	lastTaskTime time.Time
	lock         *sync.Mutex
}

func (gen *DBUpdateTaskGenerator) Name() string {
	return "CVEDBUpdateGenerator"
}

func (gen *DBUpdateTaskGenerator) Next() (scheduler.Task, error) {
	var newTask scheduler.Task

	gen.lock.Lock()

	if gen.status == pending && time.Since(gen.lastTaskTime) >= gen.waitTime {
		newTask = newDBUpdadeTask(gen.interval, gen.scanner, gen, gen.log)
		gen.status = running
	}

	gen.lock.Unlock()

	return newTask, nil
}

func (gen *DBUpdateTaskGenerator) IsDone() bool {
	gen.lock.Lock()
	status := gen.status
	gen.lock.Unlock()

	return status == done
}

func (gen *DBUpdateTaskGenerator) IsReady() bool {
	return true
}

func (gen *DBUpdateTaskGenerator) Reset() {
	gen.lock.Lock()
	gen.status = pending
	gen.waitTime = 0
	gen.lock.Unlock()
}

type dbUpdateTask struct {
	interval  time.Duration
	scanner   Scanner
	generator *DBUpdateTaskGenerator
	log       log.Logger
}

func newDBUpdadeTask(interval time.Duration, scanner Scanner,
	generator *DBUpdateTaskGenerator, log log.Logger,
) *dbUpdateTask {
	return &dbUpdateTask{interval, scanner, generator, log}
}

func (dbt *dbUpdateTask) DoWork(ctx context.Context) error {
	dbt.log.Info().Msg("updating cve-db")

	err := dbt.scanner.UpdateDB(ctx)
	if err != nil {
		dbt.generator.lock.Lock()
		dbt.generator.status = pending

		if dbt.generator.waitTime == 0 {
			dbt.generator.waitTime = time.Second
		}

		dbt.generator.waitTime *= 2
		dbt.generator.lastTaskTime = time.Now()
		dbt.generator.lock.Unlock()

		return err
	}

	dbt.generator.lock.Lock()
	dbt.generator.lastTaskTime = time.Now()
	dbt.generator.status = done
	dbt.generator.lock.Unlock()

	dbt.log.Info().Interface("interval", dbt.interval).Msg("cve-db update completed, next update scheduled after interval")

	return nil
}

func (dbt *dbUpdateTask) String() string {
	return fmt.Sprintf("{Name: %s}", dbt.Name())
}

func (dbt *dbUpdateTask) Name() string {
	return "DBUpdateTask"
}
