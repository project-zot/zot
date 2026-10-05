`zot` currently supports these underlying filesystems:

1. **local** — a locally mounted filesystem
2. **remote** — AWS S3, Google Cloud Storage, and Azure Blob Storage

The cache database can be configured independently of storage (BoltDB locally; Redis / DynamoDB when `cloudCache` is enabled). Examples: `examples/config-boltdb.json`, `examples/config-redis.json`, `examples/config-dynamodb.json`.

## Storage error classification

Goal: callers can distinguish true absence from unreliable or permanent storage failures via `errors.Is` / `errors.As`, without collapsing every failure to bare `zerr.ErrBlobNotFound` and without treating Missing as GC age-eligible.

Non-goals (still open or later stages): EmptyPrefix as its own Go type; retry/backoff; flipping `isBlobOlderThan` to treat Missing as age-eligible. Permanent stays HTTP 500 (no finer Permanent → 4xx mapping).

**Rule:** when unsure between Missing and Transient → Transient (never invent Missing).

### Layers

1. **Drivers** (`local` / `s3` / `gcs` / `azure`) map SDK/OS errors through `formatErr` onto `zerr.ErrStorageMissing` / `ErrStorageTransient` / `ErrStoragePermanent` (via [`errclass`](./errclass/) `Mark*`), keeping PathNotFound / causes in the chain. PathNotFound must be Missing before it leaves the driver. Typed PathNotFound / Invalid* / Unsupported stamp DriverName/Path then `Mark*` that value only (never `Wrap(stamped, err)` — distribution typed errors lack `Is`).
2. **ImageStore** (`imagestore.go`: `mapStorageErr`) preserves those classes on blob APIs (`StatBlob`, `GetBlob*`, `CheckBlob`, …). Absence also wraps `zerr.ErrBlobNotFound` so HTTP stays 404-shaped; Transient/Permanent are never wrapped with `ErrBlobNotFound`. Repo-dir `Stat` (`statRepoDir`, used by `GetImageManifest` / `GetImageTags` / `DeleteImageManifest`) wraps Missing with `ErrRepoNotFound` (keeps Missing in the chain), propagates Transient/Permanent, marks a non-directory path as Permanent `ErrRepoBadLayout`, and treats unclassified Stat as Transient. `ValidateRepo` List and upload `Writer` open use the same Missing-only → not-found mapping (else preserve class). On local FS only, `ValidateRepo` also `Stat`s `blobs/` (not bool `DirExists`): Missing / non-dir → invalid layout `(false, nil)`; Transient/Permanent propagate so inventory walks cannot soft-complete a live repo. `GetIndexContent` Missing uses `IsStorageObjectMissing` + Wrap `ErrRepoNotFound`.
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
| `pkg/storage` soft-skip / “content unavailable” (GC walk rows, stale-prune Stat confirm) | `errclass.IsBlobUnavailable` |
| Scrub | Top-level listed manifest/index from `index.json` Missing → omit row; Transient/Permanent + nested Missing/config/layers → `affected` |
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
| **HTTP catalog** (`ValidateRepo` / `GetNextRepositories` / `ListRepositories`) | Per-path Missing / non-layout → soft-skip candidate (partial 200). Soft-skip does not stop the walk from descending: local / GCS / Azure walks still `List` that directory looking for nested repos. Walk-level Missing is an empty catalog only when the root is absent or lists empty (`confirmEmptyStore`); with a non-empty root it is reclassified Transient (503), not a truncated 200. Catalog `last` cursor: `catalogLastExists` `Stat`s the path (not `DirExists`); Missing stays quiet and uses lexical after-last; Transient/Permanent Warn and treat as missing (page still soft-succeeds). | Per-path ValidateRepo Transient/Permanent → soft-skip that candidate with Warn (partial 200). Soft-skip applies only to ValidateRepo: if the walk's own later `List` of that directory fails (e.g. local `chmod 000`), that is Walk-level Transient → 503 / Permanent → 500, not a soft-skip. Root Walk Transient → 503 / Permanent → 500. |
| **Inventory listing** (`GetRepositories`, `GetNextRepository` — used by GC / dedupe / scrub / storage-metrics generators; not the HTTP catalog) | Same walk as catalog for non-repos: InvalidRepositoryName → `ErrSkipDir`; Missing List / not-yet-OCI layout (`ValidateRepo` ok=false, including local `blobs/` Missing or non-dir) → skip that path and keep walking children so nested repos are still found. Walk-level Missing → empty list only if the root is absent or lists empty (`confirmEmptyStore`). With a non-empty root it means a nested prefix aborted the walk (local `doWalk` or GCS/Azure `WalkFallback` on an empty or concurrently emptied prefix; S3's flat recursive Walk is unaffected), and it is reclassified Transient so a partial listing is never returned as complete. | Unlike `GetNextRepositories` (catalog soft-skip), a per-path ValidateRepo Transient/Permanent (List or local `blobs/` Stat) **returns that error from the Walk** and aborts the listing. Callers must not treat a partial result as complete: GC must not mark the sweep done, dedupe must not fire `OnRunComplete` / restore markers, scrub must not claim the store was fully checked. Walk-level Transient/Permanent (including `confirmEmptyStore`) likewise abort. |
| **HTTP blob / manifest / upload / referrers** (direct ImageStore I/O) | Missing → 404-shaped (`BLOB_UNKNOWN` / `NAME_UNKNOWN` / `BLOB_UPLOAD_UNKNOWN` / `MANIFEST_UNKNOWN` as appropriate) | Transient → 503; Permanent → 500. Storage classes are checked before not-found sentinels so an outage cannot surface as 404. Sync hard failures stay opaque 503 via `ErrSyncInternal` (separate from storage classes). |
| **GC repo entry** (`cleanRepo` / `deleteBlobUploads` / `RemoveIdleRepository`) | GetIndex Missing → `ErrRepoNotFound` (cleanRepo) or no-op `(false, nil)` (`RemoveIdleRepository`); ListBlobUploads Missing → empty | No `DirExists` bool gate. GetIndex / ListBlobUploads propagate Transient/Permanent; `RemoveIdleRepository` returns those errors instead of silently skipping |
| **GC `GetAllBlobs` inventory** (shared by `removeStaleManifestEntries` and `deleteUnreferencedBlobs`) | Empty inventory (Missing only). `GetAllBlobs` maps root `blobs/` Missing → empty `nil`; GC also treats a returned Missing as empty. Nested alg `List` Missing is Transient from ImageStore (never soft-empty) | Abort the GC step; do **not** prune index entries, call `PutIndexContent`, or run orphan blob cleanup |
| **GC stale index prune** (`removeStaleManifestEntries`) | After an inventory miss, `StatBlob` via `confirmBlobMissing`: prune only on `IsBlobUnavailable`. Nested digests absent from the inventory use the same Stat confirm before dropping a sparse index. An index blob that `GetBlobContent` already reports unavailable is treated as stale without a second Stat | `StatBlob` Transient/Permanent aborts the prune step (no `PutIndexContent`). A successful Stat keeps the index row (inventory lag / eventual consistency) |
| **GC walk soft-skips** (referrer / untagged / nested index reads) | `IsBlobUnavailable` → skip that row | See referrer vs untagged rows below |
| **GC age checks** (`isBlobOlderThan` / orphan StatBlob in `deleteUnreferencedBlobs`) | Any StatBlob error → not age-eligible; skip that candidate and continue | Same (fail closed for destructive age eligibility; do not treat as older-than). Unlike stale index prune, a Transient orphan Stat does **not** abort CleanRepo |
| **GC referrer subject prune** (`removeReferrers*`) | Soft-skip unavailable blob; may still prune cosign tags via `removeReferrer` | Soft-skip that row and continue CleanRepo (intentional: stale prune / blob / upload cleanup still run). Untagged discovery fail-closes instead |
| **GC untagged discovery** (`identifyManifestsReferencedInIndex`) | Soft-skip unavailable nested blob | Fail closed (abort): a wrong untagged delete is worse than deferring |
| **DedupeBlob / checkCacheBlob origin Stat** | Missing → cache heal (`DeleteBlob`) + retry as miss | Return mapped error; do **not** `cache.DeleteBlob` (remote Link can race a live origin) |
| **Scrub** (top-level listed manifest/index from `index.json`) | Soft-skip Missing only (concurrent delete after index snapshot) | Record as **affected** |
| **Scrub** (nested children, config, layers, subjects) | Record as **affected** (parent was read; absence is an integrity gap) | Record as **affected** |

### Phased rollout

| Stage | Scope | Status |
|-------|--------|--------|
| 0 | Driver error matrix | Done |
| 1 | Sentinels + per-driver `formatErr` | Done |
| 2 | ImageStore preserves classes; storage soft-skips use predicates; CheckBlob Missing-only cache fallback | Done |
| 3 | GC / scrub / ValidateManifest / dedupe / inventory listing class-aware policy | Done |
| 4 | Public HTTP: Transient → 503 (direct storage routes); Permanent → 500 | Done |
| 5 | Retry/backoff for Transient | Optional — new feature; open if we want automatic Transient retries |
| 6 | Typed EmptyPrefix / PrefixHasNoChildren | Optional — new feature; nested Missing→Transient in `GetAllBlobs` and the repository enumerators is enough for Stage 3 |
| 7 | Class-tagged GC/scrub metrics (skip / abort / affected by Missing / Transient / Permanent) | Optional — new feature; not required for Stage 3 policy |

### Open questions

1. **Retries (if stage 5 is pursued)** — Should Transient retry/backoff live in the driver, ImageStore, or only the next scheduler GC/sync interval?

### Resolved decisions

- **Transient retry/backoff** — Optional later-stage new feature (stage 5). Classification + fail-closed / soft-skip policy does not require automatic retries; callers may retry at their own layer today.
- **Class-tagged GC/scrub metrics** — Optional later-stage new feature (stage 7). Existing `zot_gc_runs_total` / duration / deleted remain sufficient for Stage 3. Not a policy prerequisite.
- **Deduped / cache-backed Stat (CheckBlob)** — Cache/`copyBlob`/`Link` only after classified Missing; Transient/Permanent Stat returns mapped without touching the cache.
- **Scrub** — Soft-skip only Missing for top-level `index.json` descriptors (manifest/index may vanish mid-scrub vs concurrent delete). Transient/Permanent at that boundary, and any nested config/layer/child/subject problem (including Missing), are reported as `affected`.
- **GC listing Transient/Permanent** — Fail closed (return error); only Missing means “empty blob store.” Nested `GetAllBlobs` alg `List` Missing is reclassified Transient in ImageStore so GC never soft-empties a partial inventory.
- **GC stale index prune Stat confirm** — `removeStaleManifestEntries` does not trust an inventory miss alone. It `StatBlob`s each missing top-level (and nested) digest and prunes only on `IsBlobUnavailable`; Transient/Permanent abort the step; a successful Stat keeps the row. This is separate from age-check Stat soft-skip in `deleteUnreferencedBlobs`.
- **EmptyPrefix / nested List** — Optional later-stage new feature (stage 6). For now: no dedicated type (see non-goals). Remote empty nested prefixes still overload PathNotFound→Missing; call sites that must not treat that as “empty store” reclassify via `incompleteListingErr` (Transient, cause stringified with no `%w` so `IsStorageObjectMissing` cannot soft-empty): `GetAllBlobs` nested alg `List`, and repository enumerators’ `confirmEmptyStore` (re-`List`s the root after a Missing Walk; Transient when the root has entries). Root `blobs/` Missing and an absent/empty storage root still mean empty. A typed `PrefixHasNoChildren` / EmptyPrefix would replace that Transient-as-fiction if we want clearer List/Walk semantics later — not required for Stage 3.
- **Corruption / empty dedupe origin** — Bare `ErrBlobNotFound`, never `MarkMissing`.
- **Context cancellation** — No separate storage class. S3/GCS/Azure `formatErr` already map `context.Canceled` / `DeadlineExceeded` to Transient (cause kept in the chain); callers that need cancel vs other Transient can still `errors.Is(err, context.Canceled)` / `DeadlineExceeded`. Revisit only if a GC/walk path needs distinct policy.
- **S3 Stat List failover** — Keep distribution’s List failover on some Stat `awserr` shapes as-is; do not tighten the mapping in zot for now (documented quirk in the driver matrix).
- **Public HTTP** — Direct local storage Transient → HTTP 503; Permanent → HTTP 500; Missing stays 404-shaped (`BLOB_UNKNOWN` / `NAME_UNKNOWN` / …). Sync hard failures remain opaque 503 via `ErrSyncInternal` (not storage-driver classification). Finer Permanent → 4xx mapping is out of scope unless product needs it later.
- **Catalog fail-soft** — Per-path `ValidateRepo` Transient/Permanent soft-skips that candidate with Warn and continues the Walk (partial catalog 200 via `GetNextRepositories`). Soft-skip applies only to ValidateRepo: after skipping, local / GCS / Azure walks still `List` that directory for nested repos, so a Permanent List there (e.g. local `chmod 000`) fails the catalog Walk as Permanent (HTTP 500), not as a soft-skipped page. Walk-level Transient/Permanent still fail `ListRepositories` (503 / 500). Walk-level Missing is empty only when the storage root is absent or lists empty; with a non-empty root, `confirmEmptyStore` reclassifies it Transient (503), not a truncated 200. Catalog `last` is probed with `Stat` (`catalogLastExists`), not `DirExists`: Missing is quiet + lexical after-last; Transient/Permanent Warn and treat as missing.
- **Inventory fail-closed** — `GetRepositories` / `GetNextRepository` share catalog’s soft-skip for Missing / non-layout paths, but on per-path ValidateRepo Transient/Permanent they return the error (log Error) instead of Warn+continue. That includes local `blobs/` Stat outages (ValidateRepo no longer uses bool `DirExists` for that check). Walk-level Missing uses the same `confirmEmptyStore` rule as the catalog (empty root → empty; non-empty root → Transient). Nested mid-walk Missing aborts on local `doWalk` and GCS/Azure `WalkFallback`; S3's flat recursive Walk is unaffected. That stops GC/dedupe/scrub/metrics generators from finishing a sweep that never visited a live repo because validate blipped or a nested prefix aborted the walk. HTTP `_catalog` keeps per-path soft-skip via `GetNextRepositories` only.
- **DirExists is soft-only** — Driver / ImageStore `DirExists` remains a bool presence probe (any Stat error → false). Fail-closed paths must not gate on it: use `Stat` / `List` / `GetIndex` and propagate Transient/Permanent. Applied to GC repo entry, `RemoveIdleRepository`, ValidateRepo local `blobs/`, and catalog `last` probe.
- **RemoveIdleRepository** — No `DirExists` gate. `GetIndex` Missing / `ErrRepoNotFound` → `(false, nil)` (already gone); Transient/Permanent propagate so an outage cannot look like a successful skip.
- **GC referrer Transient soft-skip** — Referrer subject prune soft-skips Transient/Permanent rows so the rest of CleanRepo (stale prune, orphan blobs, uploads) still runs. Untagged nested discovery fail-closes because deleting a still-referenced untagged manifest is worse than deferring.
- **Dedupe origin Stat** — `DedupeBlob` and `checkCacheBlob` heal the cache only after classified Missing; Transient/Permanent return without `DeleteBlob`.
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
| HTTP storage classes | Transient → 503; Permanent → 500; not 404 | `api/routes_manifest_test.go` (`TestHTTPStorageClassStatusMapping`, ListTags/UpdateManifest cases); real local EACCES: `api/controller_test.go` (`TestHTTPStorageFSPermissionDenied`, skips when euid==0) |
| Catalog ValidateRepo / soft-skip | Missing wraps RepoNotFound; Transient/Permanent soft-skip in `GetNextRepositories`; catalog `last` Stat probe (`catalogLastExists`) | `imagestore/imagestore_test.go` (`TestValidateRepoListStorageClasses`, `TestGetNextRepositoriesValidateRepoSoftSkip`, `TestGetNextRepositoriesLastRepoProbe`) |
| Inventory ValidateRepo fail-closed | Transient/Permanent abort `GetRepositories` / `GetNextRepository` (List and local `blobs/` Stat) | `imagestore/imagestore_test.go` (`TestGetRepositoriesValidateRepoFailClosed`, `TestGetNextRepositoryValidateRepoFailClosed`, `TestValidateRepoLocalBlobsStatStorageClasses`) |
| RemoveIdleRepository | Missing/`ErrRepoNotFound` → no-op; Transient GetIndex fails closed | `imagestore/imagestore_test.go` (`TestRemoveIdleRepository`) |
| GC listing fail-closed | Transient `GetAllBlobs` does not prune / `PutIndexContent` / orphan cleanup; GetIndex Transient ≠ RepoNotFound | `gc/gc_internal_test.go` |
| GC stale prune Stat confirm | Inventory miss + Stat unavailable → prune; inventory miss + Stat present → keep; Stat Transient → abort; nested inventory miss Stat-confirmed before dropping sparse index | `gc/gc_internal_test.go` (`removeStaleManifestEntries` StatBlob conveys) |
| DedupeBlob origin Stat | Transient does not `DeleteBlob`; Missing still heals | `s3/s3_test.go` (`TestDedupeBlobOriginStatClasses`) |
| GetBlobDescriptorFromIndex | Transient from image-manifest or nested-index search propagates (not ErrBlobNotFound) | `common/common_test.go` (`TestGetBlobDescriptorFromIndexCoverage`) |
| GetAllBlobs nested Missing | Nested alg `List` Missing → Transient, not soft-empty Missing | `imagestore/imagestore_test.go` (`TestGetAllBlobsNestedListMissing`); real drivers: `errclass_integration_test.go` (`TestErrClassGarbageCollectIntegration`) |
| Real-driver repository walk (inventory) | `GetRepositories`, a `GetNextRepository` sweep and metaDB `ParseStorage`. Missing: a repo deleted mid-walk fails local / Azure walks as Transient; S3 flat Walk and GCS under the emulator DeleteOnVisit race soft-complete (vanished children Stat-skipped). Transient / Permanent on one candidate's `List` (and local `blobs/` Stat) or on the root `List` / `Walk`: every enumerator returns that class, the sweep is not done, metaDB keeps every repo, and the next run completes. Local `chmod 000` repo (real Permanent): inventory aborts | `errclass_integration_test.go` (`TestErrClassRepositoryWalkIntegration`); mocks: `imagestore/imagestore_test.go` (`TestConfirmEmptyStoreWalkMissing`, `TestWalkFallbackNestedMissingFailsClosed`) |
| Real-driver catalog | `GetNextRepositories`. Missing mid-walk → Transient (not a truncated page) on local / GCS / Azure (S3 unaffected). Per-candidate ValidateRepo Transient / Permanent → soft-skip, partial page. Root `Walk` Transient / Permanent → that class. Transient Stat on the `last` cursor still pages lexically. Local `chmod 000` repo: ValidateRepo soft-skips it, but the walk's own later `List` of that directory (looking for nested repos) fails Permanent — Walk-level, not a ValidateRepo soft-skip | `errclass_integration_test.go` (`TestErrClassCatalogIntegration`) |
| Real-driver GC (`CleanRepo`) | Missing: Stat-confirmed dangling row pruned; List omission that Stat still finds kept; missing layer kept; nested inventory loss aborts and the next run prunes. Transient / Permanent on `index.json` read, root `blobs/` List, stale-row confirm Stat, or `.uploads` List → CleanRepo returns that class and nothing is pruned or reaped; `RemoveIdleRepository` keeps the repo; a Transient orphan age Stat skips only that orphan. A `GetNextRepository` + `CleanRepo` sweep stops on a per-repo failure and visits every repo once it clears | `errclass_integration_test.go` (`TestErrClassGarbageCollectIntegration`) |
| Real-driver scrub | Vanished top-level manifest skipped; missing layer flagged `affected` | `errclass_integration_test.go` (`TestErrClassScrubIntegration`) |
| GC task generator sweep | `GCTaskGenerator.Next` returns the class of a per-repo Transient / Permanent and is not done; after `Reset` it visits every repo once. Missing mid-walk stops the sweep on walk-aborting backends | `gc/gc_internal_test.go` (`TestGCTaskGeneratorStorageErrClasses`; Local / S3 / Azure) |
| HTTP catalog on a real store | Root walk Transient → 503, Permanent → 500; per-repo Transient → partial 200 | `api/routes_manifest_test.go` (`TestHTTPStorageClassStatusMapping`, local) |
| Repo-dir Stat classes | Missing wraps RepoNotFound; Transient/non-dir Permanent preserved | `imagestore/imagestore_test.go` (`TestGetImageManifestRepoStatClasses`) |

The `TestErrClass*` tests run on Local, S3 and Azure in normal CI (S3 / Azure need `S3MOCK_ENDPOINT` / `AZURITEMOCK_ENDPOINT`) and on GCS only in `make privileged-test`: `storageerrclass.GCS()` builds the driver; `errclass_gcs_integration_test.go` (build tag `needprivileges`) appends that backend and starts the emulator harness from `pkg/test/gcsemulator`. Missing comes from real deletes and List omissions; Transient / Permanent are injected as one classified failure of one operation on one path by the hook driver in `pkg/test/storageerrclass`.
