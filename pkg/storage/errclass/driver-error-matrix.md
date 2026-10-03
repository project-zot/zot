# Storage driver error matrix

Sources (code as of zot `go.mod` → `github.com/distribution/distribution/v3@v3.1.1`):

- Distribution types: `registry/storage/driver/storagedriver.go`
- Distribution Walk: `registry/storage/driver/walk.go` (`WalkFallback`)
- Distribution Base wrapper: `registry/storage/driver/base/base.go` (`setDriverName`)
- S3: `registry/storage/driver/s3-aws/s3.go`
- GCS: `registry/storage/driver/gcs/gcs.go`
- Azure: `registry/storage/driver/azure/azure.go`
- Zot local: `pkg/storage/local/driver.go`
- Zot thin wrappers: `pkg/storage/s3/driver.go`, `pkg/storage/gcs/driver.go` / `pkg/storage/azure/driver.go` (`formatErr` → `errclass.Mark*`)
- Zot classification helpers: `pkg/storage/errclass` (this directory)
- Zot ImageStore: preserves ErrStorage* on blob APIs and wraps absence with `ErrBlobNotFound` (see ../README.md); soft-skips use `errclass.IsBlobUnavailable` / `IsStorageObjectMissing`
- Call-site / quirk evidence (still current):
  - `pkg/storage/gcs/nextrepo_walk_abort_test.go` — regression test for the fixed walk abort when a ghost/empty `.uploads` (or similar) prefix returned `PathNotFound` on List. Driver still returns `PathNotFound` on empty List; zot `GetNextRepository` now `ErrSkipDir`s `.uploads`/`.sync`/`blobs` so enumeration no longer aborts. Keep the test.
  - `pkg/storage/s3/s3_test.go` Stat/IsDir convey — documents an open distribution S3 quirk (partial prefix Stat → `err == nil`, `IsDir == true`). Not fixed; test still asserts the buggy behavior. Keep.

Type column (after zot `formatErr` where the wrapper applies): Missing | Transient | Permanent | `*`.
Rule: Missing only from `PathNotFound` / not-found maps; Permanent from InvalidPath/Offset, permission, or auth-style codes; **unsure → Transient** (never invent Missing). Sentinels in `errors/`; wrappers in `errclass`.

`*` = quirk / not an error class — unexpected success, silent empty, or non-sentinel control path. The **Notes** cell on that row states what the quirk is (not mapped to `ErrStorage*`).

Legend for “Raw return”:

- `PathNotFound` = `storagedriver.PathNotFoundError`
- `driver.Error` = `storagedriver.Error{Detail: …}` after Base/`formatErr`
- `SDK err` = underlying AWS/GCS/Azure/OS error not mapped to `PathNotFound`

---

## Cross-cutting layers (before backends)

### Distribution typed errors

| Type | Role today |
|------|------------|
| `PathNotFoundError` | Only first-class “absence” signal |
| `InvalidPathError` | Path fails `PathRegexp` (Base) |
| `InvalidOffsetError` | Bad Reader offset |
| `ErrUnsupportedMethod` | Optional method not implemented (Base sets `DriverName`) |
| `Error{Detail}` | Catch-all after Base/`formatErr` |
| `Errors{Errs}` | Multi-error (S3 DeleteObjects partial failures) |
| `ErrSkipDir` / `ErrFilledBuffer` | WalkFn control sentinels (`walk.go`), not storage failures |

There is no Transient type in distribution.

### `base.Base.setDriverName`

Any error that is not already `PathNotFound` / `InvalidPath` / `InvalidOffset` / `ErrUnsupportedMethod` becomes `storagedriver.Error{DriverName, Detail: e}`. Transient SDK errors therefore usually surface as `driver.Error` once the factory-wrapped Driver is used — not as bare AWS/GCS types.

### Walk

GCS and Azure `Walk` call `storagedriver.WalkFallback` (List + Stat recursion). Nested `List` returning `PathNotFound` for an empty prefix still aborts that walk branch upward unless the caller skips the directory (`ErrSkipDir`).

Zot estate-wide abort from ghost `.uploads` is fixed at the call site (`ErrSkipDir` on reserved dirs). `nextrepo_walk_abort_test.go` is a regression guard for that fix — not an open bug report. The underlying driver “empty List → PathNotFound” behavior remains (classified as Missing).

S3 implements a custom `Walk` (not only WalkFallback); still driven by List/Stat semantics below. Empty/missing S3 Walk returns `nil` (see Walk matrix), unlike GCS/Azure.

Local uses its own Walk (List + Stat recursion), not `WalkFallback`. Mid-walk `PathNotFound` on Stat is skipped; other Stat errors abort.

WalkFn returning `io.EOF`: distribution Base wraps it as `driver.Error{Detail: EOF}`. Zot Walk wrappers (local, S3, GCS, Azure) peel bare/`Detail` EOF back to `io.EOF` before `formatErr` so callers treat it as a stop signal, not Transient. Application WalkFn errors (e.g. `GetNextRepositories` filterFn) are returned unchanged — not stamped Transient.

### GCS retry scope

Distribution GCS `retry()` (429 / ≥500, `maxTries=5`) applies to resumable upload session/chunk HTTP only — not Stat, GetContent, Reader, List, Delete, or Walk. Transient read/list failures are not retried inside the driver.

---

## Matrix: Operation × Backend × Scenario

### Stat

| Backend | Scenario | Raw return (distribution / zot driver) | Type | Notes |
|---------|----------|----------------------------------------|------|-------|
| local | Existing file | `FileInfo`, nil | — | `os.Stat` |
| local | Missing object | `PathNotFound` | Missing | Call sites map `os.IsNotExist` → `PathNotFound` + Missing; `Link` attributes ENOENT to missing `src` or missing `path.Dir(dest)` (else raw ENOENT → Missing, no empty-Path invent) |
| local | Missing parent dir | `PathNotFound` | Missing | Same `IsNotExist` |
| local | Permission denied | `driver.Error{Detail}` via `formatErr` | Permanent | OS errors default Permanent (`os.ErrPermission`) |
| local | Invalid path/arg (`EINVAL` / `ENOTDIR` / `EISDIR` / …) | `driver.Error{Detail}` via `formatErr` | Permanent | Any non-retryable OS/syscall errno (no per-errno allowlist) |
| local | Capacity / RO FS (`ENOSPC` / `EDQUOT` / `EROFS` / …) | `driver.Error{Detail}` via `formatErr` | Permanent | Same OS→Permanent default |
| local | Retryable OS (`EINTR` / `EAGAIN` / `EBUSY` / `EIO` / `EMFILE` / `ENFILE`) | `driver.Error{Detail}` via `formatErr` | Transient | Explicit local Transient errno set |
| local | Non-OS / unknown | `driver.Error{Detail}` via `formatErr` | Transient | Unsure → Transient (never invent Missing) |
| local | Empty directory | `FileInfo` IsDir=true, nil | — | Real directory exists |
| s3 | Existing object | HeadObject → file `FileInfo` | — | `statHead` |
| s3 | Missing object (no key, no children) | Head fails with AWS err → `statList` → `PathNotFound` | Missing | Any `awserr.Error` from Head triggers List failover (`Stat` ~754–768), not only NotFound |
| s3 | Prefix with children (virtual dir) | Head NotFound/Forbidden → List finds Contents/CommonPrefixes → IsDir=true, nil | `*` | Virtual dir: Stat succeeds with IsDir when only a prefix exists (no object key) |
| s3 | Partial path under longer key (IsDir quirk) | Often nil + IsDir=true | `*` | Partial-prefix Stat: Stat(`…/ab/c`) while object is `…/ab/cd/file` can succeed as dir (List MaxKeys=1). Not PathNotFound |
| s3 | Forbidden Head, List finds children | Head Forbidden → List OK → IsDir=true, nil | `*` | IAM: Head denied but List allowed → Stat looks like a successful directory |
| s3 | Forbidden Head, List empty | Head Forbidden → List empty → `PathNotFound` | Missing | |
| s3 | Forbidden Head, List AccessDenied | Head Forbidden → List denied | Permanent | `isS3Permanent` |
| s3 | Non-AWS Head error (timeout, etc.) | Returned as-is (then Base → `driver.Error`) | Transient | No List failover for non-`awserr.Error`; `formatErr` → Transient |
| s3 | Throttle / 5xx on Head that is `awserr` | Failover to List; if List also fails, `parseError` or raw err | Transient | List success can mask blip as dir (quirk). On error: SlowDown/5xx → Transient; NoSuchKey → Missing |
| gcs | Existing object | Attrs OK → file `FileInfo` | — | |
| gcs | Upload-session content-type object | `PathNotFound` | Missing | Distribution hides upload sessions as not found |
| gcs | Missing object, no children under dir key | Attrs fail → Objects Next → `iterator.Done` → `PathNotFound` | Missing | Any Attrs error (not only `ErrObjectNotExist`) falls through to the folder/prefix probe before PathNotFound |
| gcs | Attrs fail with non-NotExist, Objects finds a child | IsDir=true, nil | `*` | Transient Attrs blip masked as virtual-dir success if List still returns a child |
| gcs | Attrs fail, Objects returns non-Done err | SDK/`googleapi` err (→ `driver.Error`) | Transient / Permanent | 429/5xx → Transient; 401/403 → Permanent (`isGCSPermanent`); else Transient default |
| azure | Existing blob | GetProperties OK → file `FileInfo` | — | |
| azure | Missing blob, no children under prefix | is404 on GetProperties → list prefix MaxResults=1 empty → `PathNotFound` | Missing | `is404` = BlobNotFound / ContainerNotFound / ResourceNotFound / CannotVerifyCopySource |
| azure | Virtual directory (prefix has blobs) | IsDir=true, nil | `*` | Virtual dir: Stat succeeds with IsDir when blobs exist under `path/` (trailing-slash list probe) |
| azure | Partial path (S3-style `/ab/c` vs `/ab/cd/…`) | `PathNotFound` | Missing | Unlike S3: Azure list probe uses `path/` so `/ab/c/` does not match `/ab/cd/file` |
| azure | Auth / invalid URI on GetProperties | Returned as-is (→ `driver.Error`) | Permanent | `isAzurePermanent` |
| azure | Timeout / 503 / busy on GetProperties | Returned as-is (→ `driver.Error`) | Transient | `isAzureTransient`; else unclassified → Transient. Driver `maxRetries` is for Move/writer, not Stat |
| azure | List pager err while probing dir | Returned as-is | Transient | Same as other non-404 errors |

### GetContent / Reader

| Backend | Scenario | Raw return | Type | Notes |
|---------|----------|------------|------|-------|
| local | Missing | `PathNotFound` | Missing | Reader maps `IsNotExist` |
| local | Permission denied | `driver.Error` | Permanent | OS→Permanent default |
| local | Capacity / RO FS / other non-retryable OS | `driver.Error` | Permanent | Same OS→Permanent default (`ENOSPC` / `EROFS` / …) |
| local | Retryable OS (`EAGAIN` / `EIO` / …) | `driver.Error` | Transient | Explicit Transient errno set |
| local | Non-OS / unknown read err | `driver.Error` | Transient | Unsure → Transient |
| s3 | Missing key (`NoSuchKey` / `NotFound`) | `parseError` → `PathNotFound` | Missing | `isS3NotFound` (object codes only; not `NoSuchBucket`) |
| s3 | `NoSuchBucket` | raw / `driver.Error` | Permanent | Backend/config absent — not object Missing (`isS3Permanent`) |
| s3 | AccessDenied / invalid credentials on Get | raw / `driver.Error` | Permanent | `isS3Permanent` |
| s3 | Timeout / 5xx / SlowDown on Get | raw / `driver.Error` | Transient | `isS3Transient` / default |
| gcs | `storage.ErrObjectNotExist` / 404 | `PathNotFound` | Missing | Typed + narrow string (`object doesn't exist`, `Error 404`) |
| gcs | Auth (401 / 403) on Get | raw / `driver.Error` | Permanent | `isGCSPermanent` (typed `*googleapi.Error` or `"Error 401"`/`"Error 403"` after distribution `%v`) |
| gcs | Timeout / 429 / 5xx / other on Get | raw / `driver.Error` | Transient | `isGCSTransient` / default |
| azure | is404 / BlobNotFound string forms | `PathNotFound` | Missing | Typed `bloberror` + narrow strings |
| azure | Auth / invalid URI on Get | raw / `driver.Error` | Permanent | `isAzurePermanent` (typed codes or service-code text after distribution `%v`) |
| azure | Timeout / 503 / other on Get | raw / `driver.Error` | Transient | `isAzureTransient` / default |

### List

| Backend | Scenario | Raw return | Type | Notes |
|---------|----------|------------|------|-------|
| local | Existing dir with entries | paths, nil | — | |
| local | Missing dir | `PathNotFound` | Missing | `os.ReadDir` IsNotExist |
| local | Empty existing dir | `[]`, nil | — | Real empty directory ≠ PathNotFound (contrast object-storage List) |
| s3 | Root `/` empty | `[]`, nil | — | Special-cased: empty root allowed (never PathNotFound) |
| s3 | Non-root empty / missing prefix | `PathNotFound` | Missing | “Treat empty response as missing directory” (`List` ~830–834) |
| s3 | List API err | `parseError` or raw (continuation path returns raw without parseError ~826) | Transient / Permanent / Missing | After `formatErr`: SlowDown/5xx → Transient; AccessDenied/`NoSuchBucket` → Permanent; `NoSuchKey`/`NotFound` (via `parseError`) → Missing. First page uses `parseError`, later pages may return raw |
| gcs | Non-root empty prefix | `PathNotFound` | Missing | Same “empty = missing directory” (`List` ~699–702). Nested empty List can abort WalkFallback |
| gcs | List iterator non-Done err | raw | Transient / Permanent | After `formatErr`: 429/5xx/timeout → Transient; 401/403 → Permanent (`isGCSPermanent`); else Transient default |
| gcs | Eventual consistency after DELETE | May omit or briefly include deleted | `*` | List may lag deletes (eventual consistency); not a typed storage error |
| azure | Non-root empty | `PathNotFound` | Missing | `List` ~333–334 |
| azure | listBlobs err | raw | Transient / Permanent | After `formatErr`: timeout/503/busy → Transient; auth 401/403 / auth service codes → Permanent (`isAzurePermanent`); else Transient default |

Implication: on object storage, List of an empty non-root prefix returns the same `PathNotFound` (+ `ErrStorageMissing`) as a missing object key. Callers that need different behavior for “no children under this prefix” vs “no such blob” must key off operation + path shape, not a separate error type.

### Walk

| Backend | Scenario | Raw return | Type | Notes |
|---------|----------|------------|------|-------|
| local | Mid-walk child vanished | Skip on `PathNotFound`, continue | `*` | Stat miss mid-walk ignored (no error returned to Walk caller) |
| local | WalkFn returns `io.EOF` | Returned as bare `io.EOF` | — | `isEOF` before classification (same as GCS/Azure/S3) |
| local | WalkFn returns `ErrFilledBuffer` | `nil` (stop) | — | Propagates stop through recursive frames (`doWalk` ok flag), like `WalkFallback` |
| local | WalkFn returns application error | Same err unchanged | — | Not stamped Transient (List/Stat already classified) |
| local | Permission denied mid-walk | Abort walk with err | Permanent | `os.ErrPermission` |
| local | Other Stat err mid-walk | Abort walk with err | Permanent / Transient | OS→Permanent (default); retryable errno / non-OS → Transient |
| gcs/azure | Nested empty prefix List | `PathNotFound` bubbles from WalkFallback | Missing | Can abort entire walk; zot GetNextRepository now ErrSkipDir on `.uploads`/`.sync`/`blobs` |
| gcs/azure | WalkFallback StartAfterHint on missing base | Swallows `PathNotFound`, continues | `*` | StartAfterHint walk-up loop swallows PNF (`walk.go` ~55–64); normal Walk still propagates List PNF |
| gcs/azure | Concurrent delete: Stat mid-walk | `PathNotFound` ignored; continue | `*` | WalkFallback Stat race: PNF skipped, walk continues (no error) |
| gcs/azure | Concurrent delete: nested List empty | `PathNotFound` still fails walk | Missing | List PNF is not ignored |
| gcs (zot) | WalkFn / Base `io.EOF` | Returned as bare `io.EOF` | — | `isEOF` before `formatErr` |
| azure (zot) | WalkFn / Base `io.EOF` | Returned as bare `io.EOF` | — | Same EOF peel as zot GCS |
| s3 (zot) | WalkFn / Base `io.EOF` | Returned as bare `io.EOF` | — | Same EOF peel as zot GCS |
| s3 | Custom Walk on prefix with objects | `nil`; invokes walk fn | — | Custom `doWalk` / ListObjectsV2Pages |
| s3 | Custom Walk on missing / empty prefix | `nil` (no callbacks) | `*` | Silent empty Walk: unlike GCS/Azure WalkFallback, missing/empty prefix returns nil (not PathNotFound) |
| s3 | Concurrent delete mid-walk | List snapshot only | `*` | No WalkFallback Stat-PNF skip; empty/missing → nil Walk. SDK List err → Transient (or Permanent if auth) |
| any | Transient List/Stat mid-walk | Abort with `driver.Error` (except S3 empty Walk → nil) | Transient | Must not be treated as “no more repos” when err ≠ nil |

### Delete

| Backend | Scenario | Raw return | Type | Notes |
|---------|----------|------------|------|-------|
| local | Missing | `PathNotFound` | Missing | Not idempotent (unlike zot GCS Delete) |
| local | Permission denied | `driver.Error` | Permanent | OS→Permanent default |
| local | Capacity / RO FS / other non-retryable OS | `driver.Error` | Permanent | Same OS→Permanent default |
| local | Retryable OS / non-OS unknown | `driver.Error` | Transient | Transient errno set, else unsure → Transient |
| s3 | Nothing under prefix | `PathNotFound` | Missing | Empty List Contents; zot wrapper returns Missing (not idempotent) |
| s3 | Partial DeleteObjects errors | `storagedriver.Errors` | Transient | `formatErr` has no special `Errors` map → Transient default |
| s3 | AccessDenied on Delete | raw / `driver.Error` | Permanent | `isS3Permanent` |
| gcs | Object gone after list (race) | 404 ignored; success | — | Distribution eventual-consistency no-op |
| gcs | No keys and object delete NotExist | `PathNotFound` (distribution) → zot Delete nil | — | Idempotent: wrapper swallows PathNotFound / Missing |
| azure | Blob delete 404 then empty virtual container | `PathNotFound` (distribution) → zot Delete nil | — | Idempotent: wrapper swallows PathNotFound / Missing |
| zot gcs wrapper | Delete already PathNotFound | nil (idempotent) | — | `gcs/driver.go` Delete |
| zot azure wrapper | Delete already PathNotFound | nil (idempotent) | — | Same pattern as zot GCS; distribution Azure Delete is not idempotent |
| zot s3 wrapper | Delete already PathNotFound | Missing returned (not idempotent) | Missing | Align with GCS/Azure later; local stays non-idempotent |

---

## Transient signals (distribution vs zot)

Distribution does not define a Transient type. Zot wrappers map retryable/unclassified failures onto `ErrStorageTransient` via `formatErr`.

| Backend | Mechanism | After zot `formatErr` |
|---------|-----------|------------------------|
| s3 | AWS SDK default retries; non-NoSuchKey codes returned raw; Base wraps as `driver.Error`. Head `awserr` always tries List — can mask Forbidden/NotFound/throttle as dir success | Peel `Error.Detail`, then Missing / Permanent / Transient maps (`isS3*`); `NoSuchBucket` → Permanent; unsure → Transient |
| gcs | `retry()` on upload session/chunk only (429 / ≥500); Stat/List/Get/Delete/Walk do not retry; Move formats non-404 with `%v` | Peel Detail; Missing for typed/narrow not-found; Permanent for 401/403 (typed or `"Error 401"`/`"Error 403"` text); Transient for timeout/429/5xx/connection; unsure → Transient |
| azure | azcore client retries; driver `maxRetries` for Move/writer, not Stat/Get/List/Walk/Delete reads; `is404` typed; Reader/PutContent often format with `%v` | Peel Detail; Missing / Permanent (`*azcore.ResponseError` 401/403, auth service codes, or service-code text after `%v`) / Transient maps (`isAzure*`); Permanent checked before Transient; unsure → Transient |
| local | No network; rare I/O via `formatErr` | Typed PathNotFound + raw `ENOENT` → Missing; retryable errno (`EINTR`/`EAGAIN`/`EBUSY`/`EIO`/`EMFILE`/`ENFILE`) → Transient; **any other OS/syscall** (`PathError`/`Errno`/permission/…) → Permanent; non-OS unknown → Transient |

---

## Zot wrapper differences

| Backend | Wrapper behavior |
|---------|------------------|
| s3 | `formatErr` on returns; Delete not idempotent (follow-up to match GCS/Azure); Walk peels `io.EOF`; WalkFn app errors unchanged; `NoSuchBucket` → Permanent |
| gcs | `formatErr` on most ops; typed + narrow string not-found; 401/403 → Permanent; Delete PathNotFound → nil; Walk peels `io.EOF`; WalkFn app errors unchanged |
| azure | Same `formatErr` / Delete-idempotent / Walk EOF peel / WalkFn app-error passthrough as GCS |
| local | Own driver; `IsNotExist` → PathNotFound (+ Missing); OS/syscall → Permanent by default (retryable errno whitelist → Transient); Walk peels `io.EOF` / `ErrFilledBuffer` → nil; WalkFn app errors unchanged; Delete not idempotent |

Cross-backend Walk empty-prefix divergence (important for enumeration policy):

| Backend | Walk(missing or empty non-root) |
|---------|----------------------------------|
| s3 | `nil` (silent empty) |
| gcs / azure (WalkFallback) | `PathNotFound` from List |
| local | `PathNotFound` from List if start missing; `nil` if start is real empty dir |

---

## Type set

| Type | Role |
|------|------|
| Missing | `PathNotFound` / not-found SDK maps (`NoSuchKey`, `ErrObjectNotExist`, BlobNotFound, …); object-storage empty non-root List |
| Transient | Timeout / 429 / 5xx / connection; **default when unsure** |
| Permanent | InvalidPath/Offset; `ErrUnsupportedMethod`; local **OS/syscall default** (permission, invalid path, `ENOSPC`, `EROFS`, … — not an errno allowlist); S3/Azure/GCS auth-style codes (GCS/Azure typed 401/403; Azure auth service-code text after `%v`); S3 `NoSuchBucket` |

### `formatErr` pipeline (all backends)

Match order:

1. Typed distribution errors: `PathNotFound` / `InvalidPath` / `InvalidOffset` / `ErrUnsupportedMethod`
2. Peel `storagedriver.Error.Detail` (`Error` does not Unwrap)
3. Known absence → Missing
   - Local: raw `os.IsNotExist` → Missing via `driver.Error{Detail}` (not an empty `PathNotFoundError`)
   - Remote: SDK not-found codes (`NoSuchKey`, `ErrObjectNotExist`, BlobNotFound, …)
4. Known non-retryable failure → Permanent
   - S3/Azure/GCS: auth (HTTP 401/403; S3 `NoSuchBucket`; …)
   - Local: OS/syscall → Permanent unless retryable errno (then Transient)
5. Known retryable failure → Transient (timeout / 429 / 5xx / …)
6. Unsure → Transient

Typed-arm rules:

- Stamp `DriverName` / `Path`, then `Mark*(stamped)` only.
- Do **not** `Wrap(stamped, err)` — distribution typed errors lack `Is`, so a stamp would stack two near-identical copies.
- Non-typed siblings (e.g. local Reader `InvalidOffset` + Close): classify the typed error alone, then `Wrap` the sibling onto the result.

After peeling `Detail`:

- If `detail` is not already reachable from `err`: `inner = Wrap(err, detail)`, then `Wrap(head, inner)` so both stay visible to `errors.Is` / `errors.As`.
- If `inner` already unwraps to `outer`, `Wrap` returns `inner` (keeps outer context).
- `Wrap` recovers if `errors.Is` panics on uncomparable targets (e.g. S3 partial Delete → `Error{Detail: Errors{…}}`).

---

## Gaps needing runtime / characterization tests

| Gap | Notes |
|-----|-------|
| 1. S3 HeadObject exact error code (`NotFound` vs `NoSuchKey`) on missing key vs missing-as-prefix; MinIO vs AWS | Needs multi-emulator compare; not locked by unit tests |
| 2. Whether S3 `parseError` ever sees Head’s NotFound (usually List failover happens first) | Distribution internal |
| 3. GCS Attrs error when object missing (`ErrObjectNotExist` vs wrapped googleapi 404) before folder probe | Needs GCSMOCK |
| 4. Injected 503/timeout on Stat during `CleanRepo` after ImageStore wrap | Depends on ImageStore preserving classification |

Characterization / mapping tests:

| Package | File | What it locks |
|---------|------|---------------|
| local | `upstream_driver_errors_test.go` | Real-FS Stat/List/Walk empty vs missing; List entries; permission → `driver.Error`; mid-walk vanish skip; WalkFn EOF → bare `io.EOF`; WalkFn `ErrFilledBuffer` → nil; WalkFn app error unchanged (not Transient); Delete not idempotent |
| local | `driver_internal_test.go` | `formatErr` → Missing / Transient / Permanent (OS→Permanent default; retryable errno → Transient; `ENOSPC`/`EROFS`/`EAGAIN`/`EIO`) |
| gcs | `upstream_driver_errors_test.go` | WalkFallback empty List abort / Stat-PNF skip / StartAfterHint swallow |
| gcs | `storage_error_mapping_test.go` | formatErr Missing vs Transient vs Permanent (401/403); InvalidPath/Offset; Delete idempotent; Walk EOF peel; WalkFn app error unchanged; transient List → Transient |
| azure | `upstream_driver_errors_test.go` + `azure_test.go` (Azurite) | WalkFallback empty List + Stat-PNF skip; Azurite List/Walk empty → PathNotFound; partial Stat → PathNotFound |
| azure | `storage_error_mapping_test.go` | formatErr table; InvalidPath/Offset; Delete idempotent; Walk EOF peel; WalkFn app error unchanged |
| s3 | `upstream_driver_errors_test.go` (S3MOCK) | Stat existing / virtual dir / missing; List `/` never PathNotFound vs non-root PathNotFound; Walk empty nil vs populated; Get/Delete missing; partial Stat IsDir quirk |
| s3 | `storage_error_mapping_test.go` | formatErr PathNotFound / awserr → Missing / Transient / Permanent (`NoSuchBucket`); Walk EOF peel; WalkFn app error unchanged |
| errclass | `errclass_test.go` | `Wrap` returns inner when it already unwraps to outer; no panic on `Error{Detail: Errors}` |
| gcs | `nextrepo_walk_abort_test.go` | (pre-existing) GetNextRepository soft-skip of reserved dirs despite empty-List `PathNotFound` |

---

## ImageStore / GC impact

ImageStore wrapping, soft-skip predicates, and GC/scrub/ValidateManifest caller policy live in [`../README.md`](../README.md) — not duplicated here.
