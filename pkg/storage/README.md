`zot` currently supports two types of underlying filesystems:

1. **local** - a locally mounted filesystem

2. **remote** - a remote filesystem such as AWS S3

The cache database can be configured independently of storage. Right now, `zot` supports the following database implementations:

1. **BoltDB** - local storage. Set the "cloudCache" field in the config file to false. Example: examples/config-boltdb.json

## Storage error classification

Goal: callers can distinguish true absence from unreliable or permanent storage failures via `errors.Is` / `errors.As`, without collapsing every failure to bare `zerr.ErrBlobNotFound` and without treating Missing as GC age-eligible.

Non-goals (still open or later stages): EmptyPrefix as its own Go type; retry/backoff; flipping `isBlobOlderThan` to treat Missing as age-eligible; finer Permanent → 4xx mapping (Permanent stays HTTP 500 today).

**Rule:** when unsure between Missing and Transient → Transient (never invent Missing).

### Layers

1. **Drivers** (`local` / `s3` / `gcs` / `azure`) map SDK/OS errors through `formatErr` onto `zerr.ErrStorageMissing` / `ErrStorageTransient` / `ErrStoragePermanent` (via [`errclass`](./errclass/) `Mark*`), keeping PathNotFound / causes in the chain. PathNotFound must be Missing before it leaves the driver. Typed PathNotFound / Invalid* / Unsupported stamp DriverName/Path then `Mark*` that value only (never `Wrap(stamped, err)` — distribution typed errors lack `Is`).
2. **ImageStore** (`imagestore.go`: `mapStorageErr`) preserves those classes on blob APIs (`StatBlob`, `GetBlob*`, `CheckBlob`, …). Absence also wraps `zerr.ErrBlobNotFound` so HTTP stays 404-shaped; Transient/Permanent are never wrapped with `ErrBlobNotFound`. Repo-dir `Stat` (`statRepoDir`, used by `GetImageManifest` / `GetImageTags` / `DeleteImageManifest`) wraps Missing with `ErrRepoNotFound` (keeps Missing in the chain), propagates Transient/Permanent, marks a non-directory path as Permanent `ErrRepoBadLayout`, and treats unclassified Stat as Transient. `ValidateRepo` List and upload `Writer` open use the same Missing-only → not-found mapping (else preserve class). `GetIndexContent` Missing uses `IsStorageObjectMissing` + Wrap `ErrRepoNotFound`.
3. **Caller policy** — HTTP / product code keys off `ErrBlobNotFound` for absence (404-shaped) and off `ErrStorageTransient` / `ErrStoragePermanent` for outages (503 / 500); code inside `pkg/storage` keys off class predicates (below). GC and scrub apply class-aware policy (see [Caller policy decisions](#caller-policy-decisions)).

Per-backend raw→class inventory: [errclass/driver-error-matrix.md](./errclass/driver-error-matrix.md).

### Sentinels

| Sentinel | Meaning |
|----------|---------|
| `ErrStorageMissing` | Exact object/path absent (often with `PathNotFoundError`) |
| `ErrStorageTransient` | Unreliable answer (timeout, 429, 5xx, …) |
| `ErrStoragePermanent` | Definite non-retryable failure (auth, invalid path, …) |
| `ErrCacheMiss` | Digest not present in the dedupe cache index (not a storage Stat miss) |
| `ErrBlobNotFound` | Registry/HTTP “blob unavailable” (ImageStore wraps this on absence) |

These are different axes: **Missing** = storage said the object is gone; **BlobNotFound** = registry clients should treat the blob as unavailable; **CacheMiss** = no digests-index row. Do **not** always pair BlobNotFound with Missing, and do **not** `MarkMissing` an `ErrCacheMiss` — that would claim storage confirmed absence.

### Who checks what

| Caller | Predicate |
|--------|-----------|
| HTTP routes (absence) | `errors.Is(err, ErrBlobNotFound)` / repo/upload/manifest not-found sentinels → 404-shaped |
| HTTP routes (local storage outage) | `errors.Is(err, ErrStorageTransient)` → 503; `ErrStoragePermanent` → 500 (`writeStorageClassError`, before not-found arms) |
| On-demand sync hard fail | `errors.Is(err, ErrSyncInternal)` → 503 (opaque; not a storage-driver class) |
| `pkg/storage` “object gone” (heal, delete-idempotent, GC empty inventory) | `errclass.IsStorageObjectMissing` |
| `pkg/storage` soft-skip / “content unavailable” (GC walk rows) | `errclass.IsBlobUnavailable` |
| Scrub | Top-level `index.json` Missing → omit row; Transient/Permanent + nested Missing/config/layers → `affected` |
| `pkg/storage` / cache “no digest row” (dedupe only) | `errors.Is(err, ErrCacheMiss)` — internal; outside packages do not check this |

Outside `pkg/storage`, callers never need to distinguish a cache-index miss from other absence: when `GetBlob` returns `ErrCacheMiss`, ImageStore `mapStorageErr` wraps it as `ErrBlobNotFound` (+ `ErrCacheMiss` in the chain). Paths with no cache configured return bare `ErrBlobNotFound`.

### ImageStore wrapping (`mapStorageErr`)

Applied on blob-API return paths in `imagestore.go`:

- Already `ErrBlobNotFound` → return unchanged.
- `ErrCacheMiss` → `Wrap(ErrBlobNotFound, err)` (no `MarkMissing`).
- `ErrStorageMissing` → `Wrap(ErrBlobNotFound, err)` (keeps Missing; drivers already MarkMissing on PathNotFound).
- Transient / Permanent → return unchanged (no `ErrBlobNotFound`).
- Unclassified → `MarkTransient` (should not happen in production if drivers classify everything).

Serve-as-unknown (empty dedupe origin for non-empty digest, size mismatch) returns bare `ErrBlobNotFound` — **not** `MarkMissing`, because storage found an object; Missing means path absence only.

**CheckBlob cache fallback:** only after a classified Missing `Stat`. Transient/Permanent `Stat` returns the mapped error and must not call `checkCacheBlob` / `copyBlob` / `Link` (remote `Link` can write an empty stub and overwrite a live blob after a flaky Stat). `StatBlob` / `originalBlobInfo` do not fall back to the cache on a failed Stat either; cache resolution runs only for size-0 S3-style stubs after a successful Stat.

### Predicates (`errclass`)

- `IsStorageObjectMissing(err)` — `ErrStorageMissing` only (drivers MarkMissing on PathNotFound in `formatErr`)
- `IsBlobUnavailable(err)` — `ErrBlobNotFound` or `ErrStorageMissing` or `ErrCacheMiss`

Use `errors.Is(err, ErrCacheMiss)` directly when only a cache-row miss matters.

### Caller policy decisions

| Area | Missing / unavailable | Transient / Permanent |
|------|----------------------|------------------------|
| **ValidateManifest** (`StatBlob` on config/layers) | → `ErrBadManifest` (reject push as bad content) | Propagate unchanged (fail closed; do not claim the blob is absent). HTTP `UpdateManifest` maps Transient → 503 / Permanent → 500 **without** `DeleteImageManifest` cleanup (an existing tag must survive a storage blip on overwrite). |
| **HTTP `ListTags`** (`GetImageTags` / `statRepoDir`) | → `NAME_UNKNOWN` / 404 | Transient → 503 / Permanent → 500 (do not present a storage blip as a missing repository) |
| **HTTP catalog** (`ValidateRepo` / `GetNextRepositories` / `ListRepositories`) | Per-path Missing / non-layout → soft-skip candidate (partial 200). Walk-level failure fails the catalog. | Per-path ValidateRepo Transient/Permanent → soft-skip that candidate with Warn (partial 200). Walk-level Transient → 503 / Permanent → 500. |
| **HTTP blob / manifest / upload / referrers** (direct ImageStore I/O) | Missing → 404-shaped (`BLOB_UNKNOWN` / `NAME_UNKNOWN` / `BLOB_UPLOAD_UNKNOWN` / `MANIFEST_UNKNOWN` as appropriate) | Transient → 503; Permanent → 500. Storage classes are checked before not-found sentinels so an outage cannot surface as 404. Sync hard failures stay opaque 503 via `ErrSyncInternal` (separate from storage classes). |
| **GC `GetAllBlobs` inventory** (`removeStaleManifestEntries`, `deleteUnreferencedBlobs`) | Treat as empty inventory (Missing only) | Abort the GC step; do **not** prune index entries or call `PutIndexContent` / blob cleanup |
| **GC per-blob soft-skips** (walk / age checks) | `IsBlobUnavailable` → skip that row | Skip that row (fail closed for destructive age eligibility; do not treat as older-than) |
| **Scrub** (top-level listed manifest/index from `index.json`) | Soft-skip Missing only (concurrent delete after index snapshot) | Record as **affected** |
| **Scrub** (nested children, config, layers, subjects) | Record as **affected** (parent was read; absence is an integrity gap) | Record as **affected** |

### Phased rollout

| Stage | Scope | Status |
|-------|--------|--------|
| 0 | Driver error matrix | Done |
| 1 | Sentinels + per-driver `formatErr` | Done |
| 2 | ImageStore preserves classes; storage soft-skips use predicates; CheckBlob Missing-only cache fallback | Done |
| 3 | GC / scrub / ValidateManifest class-aware policy (+ metrics later) | In progress (policy wired; metrics still open) |
| 4 | Retry/backoff for Transient (optional) | Planned |
| 5 | Typed EmptyPrefix / PrefixHasNoChildren (optional) | Follow-up — see resolved decision |
| 6 | Public HTTP: Transient → 503 (direct storage routes); Permanent → 500 | Transient→503 done; finer Permanent → 4xx still open |

### Open questions

1. **GC / scrub metrics** — Stage 3 metrics for class-tagged skip vs abort vs affected (counts by Missing / Transient / Permanent).
2. **Retries** — If stage 4 adds Transient retry/backoff, should it live in the driver, ImageStore, or only the next scheduler GC/sync interval?

### Resolved decisions

- **Deduped / cache-backed Stat (CheckBlob)** — Cache/`copyBlob`/`Link` only after classified Missing; Transient/Permanent Stat returns mapped without touching the cache.
- **Scrub** — Soft-skip only Missing for top-level `index.json` descriptors (manifest/index may vanish mid-scrub vs concurrent delete). Transient/Permanent at that boundary, and any nested config/layer/child/subject problem (including Missing), are reported as `affected`.
- **GC listing Transient/Permanent** — Fail closed (return error); only Missing means “empty blob store.”
- **EmptyPrefix / nested List** — For now: no dedicated type (see non-goals). Remote empty nested prefixes still overload PathNotFound→Missing; call sites that must not treat that as “empty store” reclassify (e.g. `GetAllBlobs` nested alg `List` → Transient without `%w` Missing). Root `blobs/` Missing still means empty. **Follow-up (stage 5):** a typed `PrefixHasNoChildren` / EmptyPrefix stamped in List/Walk wrappers (Stat stays Missing) would let GC and Walk key off a predicate instead of Transient-as-fiction — needs four-driver mapping + a full List/Walk call-site audit; not required to close the nested-inventory prune hole.
- **Corruption / empty dedupe origin** — Bare `ErrBlobNotFound`, never `MarkMissing`.
- **Context cancellation** — No separate storage class. S3/GCS/Azure `formatErr` already map `context.Canceled` / `DeadlineExceeded` to Transient (cause kept in the chain); callers that need cancel vs other Transient can still `errors.Is(err, context.Canceled)` / `DeadlineExceeded`. Revisit only if a GC/walk path needs distinct policy.
- **S3 Stat List failover** — Keep distribution’s List failover on some Stat `awserr` shapes as-is; do not tighten the mapping in zot for now (documented quirk in the driver matrix).
- **Public HTTP** — Direct local storage Transient → HTTP 503; Permanent → HTTP 500; Missing stays 404-shaped (`BLOB_UNKNOWN` / `NAME_UNKNOWN` / …). Sync hard failures remain opaque 503 via `ErrSyncInternal` (not storage-driver classification). **Follow-up:** finer Permanent → 4xx/5xx mapping where product semantics allow.
- **Catalog fail-soft** — Per-path `ValidateRepo` Transient/Permanent soft-skips that candidate with Warn and continues the Walk (partial catalog 200). Walk-level failures still fail `ListRepositories` (Transient → 503 / Permanent → 500).
- **UpdateManifest cleanup** — All `PutImageManifest` failures return without calling `DeleteImageManifest`. Deleting by reference after an uncertain PUT can remove an existing tag when `index.json` was never updated (e.g. `io.ErrShortWrite`, Transient validation). Unreferenced partial blobs are left for GC.

### Tests

| Kind | Purpose | Where |
|------|---------|--------|
| Characterization | What distribution / OS / emulator returns | `{local,s3,gcs,azure}/upstream_driver_errors_test.go`; Azure also `azure_test.go` (Azurite) |
| Mapping | How zot `formatErr` maps those onto sentinels | `{s3,gcs,azure}/storage_error_mapping_test.go`; local `driver_internal_test.go` |
| ImageStore boundary | `mapStorageErr` class wrapping | `imagestore/imagestore_internal_test.go` |
| Predicates | `IsStorageObjectMissing` / `IsBlobUnavailable` | `errclass/errclass_test.go` |
| ValidateManifest classes | Missing → BadManifest; Transient/Permanent propagate | `common/common_test.go` (`TestValidateManifestStorageErrorClasses`) |
| UpdateManifest PUT fail | Transient → 503 / Permanent/`ErrShortWrite` → 500; no `DeleteImageManifest` | `api/routes_manifest_test.go` (`TestUpdateManifestStorageErrorsSkipCleanup`) |
| HTTP storage classes | Transient → 503; Permanent → 500; not 404 | `api/routes_manifest_test.go` (`TestHTTPStorageClassStatusMapping`, ListTags/UpdateManifest cases) |
| Catalog ValidateRepo / soft-skip | Missing wraps RepoNotFound; Transient/Permanent soft-skip in Walk | `imagestore/imagestore_test.go` (`TestValidateRepoListStorageClasses`, `TestGetNextRepositoriesValidateRepoSoftSkip`) |
| GC listing fail-closed | Transient `GetAllBlobs` does not prune / `PutIndexContent` | `gc/gc_internal_test.go` |
| GetAllBlobs nested Missing | Nested alg `List` Missing → Transient, not soft-empty Missing | `imagestore/imagestore_test.go` |
| Repo-dir Stat classes | Missing wraps RepoNotFound; Transient/non-dir Permanent preserved | `imagestore/imagestore_test.go` (`TestGetImageManifestRepoStatClasses`) |
