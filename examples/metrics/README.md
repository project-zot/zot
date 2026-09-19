
A quick zot Metrics setup can be deployed locally in a kind cluster.
It contains:
 * a Prometheus server deployed through an Operator
 * a dist-spec-only zot deployment (a pod with 2 containers: the zot server & the node exporter)
 * a zot with all extensions enabled

## Prerequisites
  * [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)
  * [Kind](https://kind.sigs.k8s.io/)
  * [Docker](https://www.docker.com/)

In case the prerequisites tool list is not fulfilled the script will install them (needs root privileges)

## Metrics setup
To run a quick setup:

```
./kind-setup.sh

```

At the end of the script below ports are locally available (using *kubectl port-forward*) to easy access the Prometheus & zot servers on the host:
 * 9090 - for accessing Prometheus server
 * 5000 - for zot with all extensions enabled
 * 5050 - for accessing dist-spec-only zot server
 * 5051 - for zxp access (a Prometheus Node exporter)

## Repo label expiry

Long-running registries with many transient/short-lived repos can accumulate an
unbounded number of distinct `repo` label values on zot's per-repo metrics, causing
Prometheus cardinality to grow without bound. `extensions.metrics.repoLabelExpiry`
opts in to periodically evicting `repo` label values that have gone stale.

```json
{
  "extensions": {
    "metrics": {
      "enable": true,
      "repoLabelExpiry": "10m"
    }
  }
}
```

 * Config key: `extensions.metrics.repoLabelExpiry` (a duration string).
 * Default: `0`, which disables repo label expiry entirely.
 * Valid values are `0` (disabled) or `>= 1m`; anything negative or strictly
   between `0` and `1m` is rejected at startup.
 * Effective series lifetime: a given `repo` label value survives between 1x
   and 2x the configured interval after its last use, since eviction uses a
   mark-and-sweep over two consecutive sweep windows rather than an immediate
   per-use TTL.
 * Applies only to the following repo-labeled metrics:
   * `zot_http_repo_latency_seconds`
   * `zot_repo_uploads_total` (Counter)
   * `zot_repo_downloads_total` (Counter)
 * `zot_repo_storage_bytes` is deliberately excluded from expiry. It's
   populated once at startup and then only on write paths, so evicting it
   would permanently blank out idle-but-still-present repos in scrape output;
   its cardinality is already bounded by the number of repos actually on disk.

### External semantics caveat

Evicted series disappear entirely from scrape output, and if a repo becomes
active again its `zot_repo_uploads_total`/`zot_repo_downloads_total` counters
restart from 0 rather than resuming from their prior value. `rate()` and
`increase()` handle counter resets natively, so dashboards built on those
functions are unaffected. However:

 * Raw-counter panels that sum by repo (e.g. `sum by (repo) (zot_repo_uploads_total)`)
   will show a drop when a series is evicted and a restart from 0 when it
   reappears, rather than a continuously increasing value.
 * Long-window `max_over_time()` queries over `zot_repo_uploads_total` or
   `zot_repo_downloads_total` can show gaps for repos that were evicted and
   have not yet become active again within the query window.

