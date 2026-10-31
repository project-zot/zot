# PostgreSQL MetaDB and remote dedupe cache proposal

Design and implementation plan for [zot#4590](https://github.com/project-zot/zot/issues/4590).
**Status: proposed, not implemented.** This document does not announce roadmap commitments or maintainer approval.
The driver choice, configuration contract, and supported PostgreSQL versions need agreement before implementation.

## Scope and driver choice

Add PostgreSQL as an opt-in alternative to DynamoDB and Redis for deployments that already operate PostgreSQL.
Keep OCI manifests and blobs in the configured image store (for example, S3); PostgreSQL holds registry metadata
and dedupe location records, not image contents.

Propose [`github.com/jackc/pgx/v5`](https://github.com/jackc/pgx) with `pgxpool`: it provides a pure-Go PostgreSQL
driver, connection pooling, transactions, context cancellation, and TLS support without requiring CGO.
Its `stdlib` adapter remains an option if `database/sql` integration becomes necessary; no ORM is needed.
Choose a supported release and check dependency advisories when implementing, rather than adding a dependency
for this proposal.

Follow the existing Redis/DynamoDB backend shape, implementing both independent contracts:

- [`MetaDB`, including `UserDB`](https://github.com/project-zot/zot/blob/main/pkg/meta/types/types.go):
  repositories, image metadata, tags, referrers, signatures, statistics, user preferences, groups, and API keys.
  Include repository blob accounting, projected sizes for quota checks, version patching, and fast-restart stamps.
- [`Cache`](https://github.com/project-zot/zot/blob/main/pkg/storage/types/cache.go):
  blob locations, duplicate membership, and canonical origin selection.

Image retention and quota policies remain application responsibilities; do not implement metadata TTLs that
independently delete records. Database authentication is distinct from registry authentication.
PostgreSQL does not by itself provide distributed registry locking or make every feature safe across replicas.
OIDC/session storage and trust-store material are separate concerns and are outside this initial backend scope;
document any remaining shared-service requirements for the chosen authentication setup.

## Configuration and lifecycle

Use the existing `storage.remoteCache: true` and `storage.cacheDriver` selection model with proposed driver name
`postgres`. Continue selecting BoltDB when remote caching is disabled and leave existing drivers unchanged.
Treat these additional fields as a proposed API, not configuration accepted by current releases:

| Proposed field | Purpose |
| --- | --- |
| `name` | `postgres` |
| `dsnFile` | Path to a mounted secret file containing a pgx connection string, including database and TLS options |
| `namespace` | Logical registry identifier, included in every primary key and query |
| `maxConns` | Positive bounded pool size; budget the total across replicas and backend instances |
| `connectTimeout`, `queryTimeout` | Bounded startup and operation timeouts |

Prefer a secret-file connection string to embedding passwords in registry configuration or Helm values.
For remote production connections, require certificate/hostname verification (`sslmode=verify-full`) and allow
a mounted CA certificate; permit unencrypted connections only as an explicit development opt-in.
Never log the connection string, credentials, or API-key contents, including through wrapped connection errors.
Validate field types, required values, pool bounds, namespace isolation, and TLS settings before opening a pool.
Use fixed SQL identifiers and bound parameters for all data, including namespace, repository names, and digests.

Integration points:

1. Add shared PostgreSQL configuration parsing/client construction alongside the existing Redis configuration
   helper, and a driver-name constant in
   [`storage constants`](https://github.com/project-zot/zot/tree/main/pkg/storage/constants).
2. Add the MetaDB implementation under `pkg/meta/postgres` and select it in
   [`meta.New`](https://github.com/project-zot/zot/blob/main/pkg/meta/meta.go).
3. Add `pkg/storage/cache/postgres.go`, wired through both `CreateCacheDatabaseDriver` and `Create` in
   [`storage/cache.go`](https://github.com/project-zot/zot/blob/main/pkg/storage/cache.go).
4. Extend `validateCacheConfig` in
   [`CLI validation`](https://github.com/project-zot/zot/blob/main/pkg/cli/server/root.go),
   including default storage and subpaths. Test local storage, S3, and dedupe enabled/disabled combinations.
   Define distinct cache namespaces for independent storage roots so equal digests cannot mix unrelated locations.
5. Define pool ownership explicitly: close pools on failed initialization and shutdown, without double-closing
   a shared pool. The current cache interface has no `Close`; integrate cleanup at the owning storage/controller
   lifecycle rather than leaving a pool per cache unmanaged.

## Persistence and concurrency

Use versioned SQL migrations and fixed tables with namespace-scoped keys. Start with tables for repository
metadata, image metadata, repository blob accounting, user data, API-key lookup, schema versions, restart stamps,
and dedupe origins/locations. Retain existing serialization/conversion semantics for complex metadata; choose
JSONB or opaque serialized payloads according to round-trip tests, with relational columns for keys and accounting.
Preserve digest algorithms and existing missing-record errors; distinguish database outages from cache misses.

Use transactions for multi-record changes. Serialize repository read/modify/write operations using row locks
and atomic upserts, including concurrent creation of previously absent rows. Lock related user/repository rows
in a consistent order for stars and bookmarks. Use atomic counters or locked updates to prevent lost statistics
and blob reference-count updates. Keep existing filter callback semantics; do not assume arbitrary Go predicates
can be translated to SQL. Add indexes based on lookup patterns and measured query plans.

For dedupe, use unique `(namespace, digest, location)` membership and one origin per `(namespace, digest)`.
Serialize mutations per digest, including first insertion. `PutBlob` must not overwrite an existing origin;
`SetOrigin` replaces it while retaining duplicate membership. Deletion is idempotent, rotates an origin when
necessary, and removes empty records atomically. Match existing relative filesystem versus S3 location behavior.
Database transactions do not include S3/filesystem writes: preserve image-store ordering and recovery behavior.

Propagate caller contexts where interfaces provide them; otherwise use bounded operation contexts.
Retry only bounded, safe transaction conflicts (serialization/deadlock failures), not arbitrary writes after
ambiguous connection failures. Roll back failed transactions and release connections on every path.
Use the primary database for consistency-sensitive reads; read-replica routing is not part of the initial scope.

Coordinate schema migration across starting replicas with a database lock and a version table.
Separate SQL schema versions from zot metadata `PatchDB` versions. Reject incompatible newer schemas without
resetting data, and make upgrades restart-safe. Support pre-applied migrations with a least-privilege runtime
role; document required migration privileges and backup/restore procedures.
Avoid destructive migrations during rolling upgrades and test old/new binary compatibility.

Rebuilding layout-derived metadata from object storage is not a complete database migration: API keys, user
preferences, groups, and statistics need backup/export handling. Initially document a maintenance-window cutover
and rollback procedure; automatic import from other backends is a separate feature.

## Testing and acceptance

- Add a PostgreSQL wrapper to the existing `RunMetaDBTests` suite, currently used by BoltDB, DynamoDB, and Redis.
  Cover the full interface rather than a CRUD-only subset, including quota accounting and restart/patch behavior.
- Mirror existing cache-driver tests for misses, empty/duplicate paths, origin replacement/rotation, idempotent
  deletion, digest handling, and relative/S3 paths. Add configuration/factory and failed-initialization tests.
- Use real disposable PostgreSQL in CI, following existing service-backed test conventions, with isolated test
  namespaces and cleanup. Local service tests may skip without an endpoint; the PostgreSQL CI job must not skip.
  Agree on a supported server-version range and exercise its minimum and current supported versions.
- Add multi-client concurrency tests for first writes, tags, counters, user toggles, and dedupe mutations.
  Verify no lost updates, cross-namespace leakage, partial commits, or pool leaks, including with `go test -race`.
- Exercise transaction rollback, database restart/outage, timeouts/cancellation, connection exhaustion, TLS and
  invalid credentials, migration races, upgrades, and rejection of a newer schema. Ensure logs redact secrets.
- Run S3-backed end-to-end push/pull/delete, retention/GC, API-key authentication, quota boundary checks, and
  restart/reconciliation tests. Test two registry replicas against the same database and object store, explicitly
  checking existing distributed-locking assumptions before documenting HA support.
- Compare representative metadata/search/dedupe latency and connection usage with existing remote backends.
  Run existing backend regression tests, lint, and minimal/full builds; do not introduce a PostgreSQL build tag
  merely to hide an incomplete implementation.

## Helm chart follow-up

Implement chart changes in a coordinated PR to
[`project-zot/helm-charts`](https://github.com/project-zot/helm-charts), not in this repository.
The current `charts/zot/values.yaml` already exposes `config`, `env`, `externalSecrets`, and extra volume mounts.
`templates/config.yaml` renders `config` into a Secret; `configFiles` uses a ConfigMap instead.

1. Add a documented external-PostgreSQL values example using the proposed cache-driver fields, S3 storage,
   `replicaCount`, and an existing Secret mounted with `externalSecrets` for `dsnFile` and CA material.
   When using `config`, unset `configFiles["config.json"]` as required by the chart.
   Do not assume the registry expands environment placeholders in configuration.
2. Reuse existing mounts in both Deployment and StatefulSet templates; add template changes only if a verified
   gap remains. Keep credentials out of ConfigMaps, examples, command arguments, and rendered test output.
   Explain that Helm-managed Secret values are retained in release history and external Secrets are preferable.
3. Target a zot image version that actually includes the driver. Keep PostgreSQL opt-in, with no bundled database
   dependency or changes to default storage/persistence behavior. S3 deployments can use the existing Deployment
   mode; PostgreSQL alone is not a reason to disable a PVC required by other configured features.
4. Document externally managed migrations and least-privilege roles rather than adding a mandatory privileged
   initialization job. Explain startup-probe budgeting for migrations, aggregate pool limits across replicas,
   database network access/TLS, backups, credential rotation, and rolling-restart requirements for Secret changes.
5. Extend existing chart tests under `tests/ci` and `templates/tests`: render default and PostgreSQL configurations,
   test Deployment/StatefulSet secret mounts and config conflicts, and check that no credential enters a ConfigMap.
   Run `helm lint`, `helm template`, and the chart's existing install tests; add an S3/PostgreSQL multi-replica
   smoke test with push/pull and restart. Bump the chart version and update its README in the chart PR.

## Suggested delivery sequence

1. Agree on pgx, supported PostgreSQL versions, configuration, schema, and cross-replica guarantees with maintainers.
2. Implement connection configuration, migrations, and the complete MetaDB behind internal constructors, with
   shared-suite and migration tests. Do not expose a selectable partially implemented backend.
3. Implement the dedupe cache, pool cleanup, factories, and validation together; enable `postgres` only once both
   interfaces pass their tests. Add user documentation and configuration examples for the released behavior.
4. Complete fault/concurrency/S3 acceptance tests and security review, then ship a driver-capable zot release.
5. Merge the coordinated Helm examples/tests against that release and publish operational guidance.
