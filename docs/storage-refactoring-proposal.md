# Storage refactoring proposal: reducing global lock contention

## Context

Today, `ImageStore` uses a single global `sync.RWMutex` for storage operations:

- source: https://github.com/project-zot/zot/blob/main/pkg/storage/imagestore/imagestore.go#L47

As repository count and write throughput increase, this lock becomes a bottleneck because unrelated repositories are forced to wait on each other.

## Problem statement

A single global lock introduces unnecessary contention:

- write activity in one repository can block writes in all other repositories
- mixed read/write traffic across many repositories is serialized more than necessary
- lock wait time grows with repository cardinality and concurrent clients

This is especially visible in multi-tenant deployments where repositories are independent in practice but coupled by lock scope.

## Goals

- preserve correctness for manifest/index/tag/blob lifecycle operations
- reduce lock contention for unrelated repositories
- keep dedupe behavior for shared blobs
- improve remote backend efficiency and OCI distribution spec alignment

## Non-goals

- changing storage driver APIs beyond what is required for lock scoping and dedupe paths
- changing external registry API semantics

## Proposed design

### 1) Introduce a global blobstore namespace

Use a dedicated hidden namespace (for example `_blobstore`) to store all deduplicated blob payloads.

Rationale:

- blob bytes are global content-addressed objects by digest
- storing them once naturally supports dedupe across repositories
- `_blobstore` naming keeps it hidden from normal repository listings

### 2) Use split lock domains

Replace the single global lock domain with two levels:

- global blobstore lock: `RWMutex` protecting `_blobstore` metadata/data mutations
- per-repository locks: `RWMutex` per repository protecting repo-local metadata (manifests, tags, links, indexes)

#### Locking intent

- operations touching only repository metadata should use only that repository lock
- operations touching shared blob data should use blobstore lock
- operations spanning both should acquire both with a consistent lock order

#### Required lock order (to prevent deadlocks)

Always acquire:

1. blobstore lock (if needed)
2. repository lock (if needed)

Never invert this order in any call path.

### 3) Dedupe behavior by storage type

- local/filesystem-backed: keep content-addressed dedupe in `_blobstore`
- remote/object-backed: dedupe should not require creating empty marker files

## Operation impact summary

The table below summarizes where improvements are expected.

| Case | Current (single global lock) | Proposed (blobstore + per-repo locks) | Expected impact |
| --- | --- | --- | --- |
| Concurrent writes to different repos, different blobs | serialized globally | parallel (independent repo locks; short blobstore sections only when needed) | major throughput gain |
| Writes to different repos, same blob digest | serialized globally | contention mostly scoped to blobstore lock around dedupe check/insert | better than current; bounded shared contention |
| Read in repo A + write in repo B | often blocked by global write lock | independent locks allow progress unless shared blobstore mutation conflicts | lower read latency under write load |
| Tag/manifest updates in independent repos | serialized globally | parallel under different repo locks | major reduction in lock wait |
| Heavy read workload with light writes | write lock stalls unrelated reads | writes primarily block only affected lock domains | improved tail latency |
| High churn in one hot repo + quiet other repos | hot repo impacts everyone | isolation: hot repo mostly impacts itself (+ shared blobstore moments) | improved tenant isolation |

## Pathological case

The new scheme still has a worst-case contention pattern:

- many concurrent writes across repositories targeting the same small set of blob digests
- each flow needs blobstore coordination for dedupe decision/creation

In this case, the blobstore lock becomes the hotspot. This is still preferable to a single global lock because:

- contention is limited to shared blob paths instead of all storage operations
- repo-local operations that do not require blobstore mutation can continue concurrently

## Remote dedupe change: stop creating empty entries

For remote storage dedupe, do not create empty file entries as dedupe markers.

Why this change is required:

- empty marker entries can interfere with OCI distribution spec expectations around blob/object layout and semantics
- each marker introduces additional backend operations (HEAD/LIST/PUT-like checks), increasing cloud API calls and cost

Expected result:

- cleaner, spec-aligned remote storage behavior
- fewer backend queries and lower cloud cost under dedupe-heavy workloads

## Correctness and safety notes

- lock acquisition order must be uniformly enforced in all code paths
- blob existence checks and blob writes must remain atomic with respect to dedupe decisions
- repo metadata operations must remain atomic per repository
- metrics should track lock wait/hold times separately for blobstore and repository locks to validate improvement

## Rollout guidance

- keep changes behind internal implementation boundaries first (no API break)
- run existing storage, dedupe, and conformance suites
- add concurrency-focused tests for lock ordering and deadlock absence
- add benchmark scenarios: multi-repo parallel push/pull, shared-digest fan-in, hot-repo isolation

## Upgrade behavior

The migration story should support both in-place upgrade and side-by-side cutover.

Version scope for this proposal:

- source deployment series: zot 2.1.x
- target deployment series: zot 2.2.x (where this refactor is expected to land)

### In-place upgrade on startup

When a new zot binary starts with data written by an older zot version, startup may run storage migration steps to move data to the new layout/metadata conventions.

Implications:

- startup can be blocked while migration work is in progress
- large datasets or high repository counts can increase startup latency
- operationally simple (single deployment), but downtime/startup delay risk is higher

Recommended use:

- smaller deployments where startup delay is acceptable
- environments where a one-time maintenance window is available

### Side-by-side sync/mirror migration

Stand up a new zot instance and configure sync/mirror from the old zot server. The new instance writes incoming data directly in the new storage format.

Implications:

- avoids long startup migration blocking on the new instance
- reduces upgrade risk by separating data movement from process startup
- enables progressive cutover after validation

Recommended use:

- large deployments where startup blocking is unacceptable
- environments needing lower-risk migration with rollback options

### Cutover and validation notes

- validate repository listing behavior and hidden `_blobstore` visibility rules before traffic switch
- compare blob/manifest counts between old and new instances during sync
- perform a staged cutover (read-only checks, then write traffic shift) to reduce migration risk

## Related WIP PRs

- https://github.com/project-zot/zot/pull/3906
- https://github.com/project-zot/zot/pull/2968
- https://github.com/project-zot/zot/pull/3922

These PRs can be used to stage and validate the refactor incrementally.
