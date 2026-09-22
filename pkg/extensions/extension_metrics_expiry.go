package extensions

import (
	"context"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
)

// EnableMetricsExpiry enables the periodic sweep that evicts stale per-repo metric label values.
func EnableMetricsExpiry(cfg *config.Config, sch *scheduler.Scheduler, metricServer monitoring.MetricServer,
	log log.Logger,
) {
	extensionsConfig := cfg.CopyExtensionsConfig()

	if !extensionsConfig.IsMetricsEnabled() || extensionsConfig.GetMetricsRepoLabelExpiry() == 0 {
		log.Info().Msg("metrics repo label expiry not configured, skipping")

		return
	}

	interval := extensionsConfig.GetMetricsRepoLabelExpiry()

	monitoring.EnableRepoLabelExpiryTracking()

	generator := &metricsExpiryGenerator{
		ms: metricServer,
	}

	sch.SubmitGenerator(generator, interval, scheduler.LowPriority)

	log.Info().Dur("interval", interval).Msg("metrics repo label expiry enabled")
}

type metricsExpiryTask struct {
	ms monitoring.MetricServer
}

func (t *metricsExpiryTask) DoWork(ctx context.Context) error {
	monitoring.ExpireRepoMetrics(t.ms)

	return nil
}

func (t *metricsExpiryTask) Name() string {
	return "MetricsExpiryTask"
}

func (t *metricsExpiryTask) String() string {
	return t.Name()
}

type metricsExpiryGenerator struct {
	ms         monitoring.MetricServer
	taskIssued bool
	done       bool
}

func (gen *metricsExpiryGenerator) Name() string {
	return "MetricsExpiryGenerator"
}

// Next returns the one task this generator produces per cycle on its first call, then
// signals done on the call after. Scheduler.generate() checks IsDone() right after Next()
// returns and discards whatever Next() just returned if IsDone() is already true - so
// done must not flip true on the same call that hands back a real task, or that task is
// silently dropped and never run. See extension_scrub.go's taskGenerator for the same
// pattern (done only set once nothing is left to return).
func (gen *metricsExpiryGenerator) Next() (scheduler.Task, error) {
	if gen.taskIssued {
		gen.done = true

		return nil, nil //nolint:nilnil
	}

	gen.taskIssued = true

	return &metricsExpiryTask{ms: gen.ms}, nil
}

func (gen *metricsExpiryGenerator) IsDone() bool {
	return gen.done
}

func (gen *metricsExpiryGenerator) IsReady() bool {
	return true
}

func (gen *metricsExpiryGenerator) Reset() {
	gen.taskIssued = false
	gen.done = false
}
