package extensions

import (
	"context"

	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/extensions/monitoring"
	"zotregistry.dev/zot/v2/pkg/log"
	"zotregistry.dev/zot/v2/pkg/scheduler"
)

// EnableMetricsExpiry enables the periodic sweep that evicts stale per-repo metric label values.
func EnableMetricsExpiry(cfg *config.Config, sch *scheduler.Scheduler, ms monitoring.MetricServer, log log.Logger) {
	extensionsConfig := cfg.CopyExtensionsConfig()

	if !extensionsConfig.IsMetricsEnabled() || extensionsConfig.GetMetricsRepoLabelExpiry() == 0 {
		log.Info().Msg("metrics repo label expiry not configured, skipping")

		return
	}

	interval := extensionsConfig.GetMetricsRepoLabelExpiry()

	monitoring.EnableRepoLabelExpiryTracking()

	generator := &metricsExpiryGenerator{
		ms: ms,
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
	ms   monitoring.MetricServer
	done bool
}

func (gen *metricsExpiryGenerator) Name() string {
	return "MetricsExpiryGenerator"
}

func (gen *metricsExpiryGenerator) Next() (scheduler.Task, error) {
	if gen.done {
		return nil, nil //nolint:nilnil
	}

	gen.done = true

	return &metricsExpiryTask{ms: gen.ms}, nil
}

func (gen *metricsExpiryGenerator) IsDone() bool {
	return gen.done
}

func (gen *metricsExpiryGenerator) IsReady() bool {
	return true
}

func (gen *metricsExpiryGenerator) Reset() {
	gen.done = false
}
