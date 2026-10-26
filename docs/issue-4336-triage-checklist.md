# Issue #4336 triage checklist

Tracking doc for https://github.com/project-zot/zot/issues/4336 ("S3 + namespaced repos:
`/v2/_catalog` empty while per-repo reads work; metaDB emptied on restart").

The issue bundles two distinct symptoms. Treat them separately — a fix for one does not imply
a fix for the other.

## Symptom A: `/v2/_catalog` empty while per-repo reads work

**Status: not fixed.** No PR currently addresses this.

`GET /v2/_catalog` is served by `ImageStore.GetNextRepositories()`
(`pkg/storage/imagestore/imagestore.go`), which walks storage directly with no metaDB
involvement. If this symptom is real and reproducible, the root cause is in the storage walk
itself (or in something upstream of it, e.g. IAM scoping), not in metaDB.

## Symptom B: metaDB emptied on restart

**Status: mitigated, not root-caused**, by `fix(meta): don't mass-delete metaDB repos on a
suspiciously empty storage walk` (#4338).

That PR guards the symptom downstream: `parseStorage()` no longer trusts an empty result from
`GetRepositories()` enough to mass-delete metaDB's repos when metaDB already has entries. It
does not explain *why* the walk came back empty in the first place, and does not fix Symptom A
at all (different code path, see above).

```
Driver/walk misbehaves → GetRepositories returns [] + nil
                              ↓
                    parseStorage trusts it
                              ↓
              #4338: don't delete metaDB (mitigation)
```

The preferred fix is upstream of this:

```
Driver/walk misbehaves → return real error (or distinguish empty vs failed)
                              ↓
                    GetRepositories propagates it
                              ↓
              _catalog → 500 / logs; parseStorage → err, no silent trust
```

### What upstream #4514 already covers (2026-10-05)

`fix(storage): fail closed on GC, dedupe, and incomplete listings` (#4514) moved part of the way
there for `GetRepositories()`:

- A walk that fails with an error other than "missing" now returns `nil, err` rather than a
  partial list, so `parseStorage()` gets the error instead of trusting what was listed.
- A walk that fails with "missing" (`errclass.IsStorageObjectMissing`) is accepted as an empty
  store only if `confirmEmptyStore()` finds the root absent or empty by listing it; a nested
  directory that vanished mid-walk (local, GCS/Azure fallback walks) is reported as an
  incomplete listing instead.

It does **not** cover the S3 case in the audit below: on an empty or wrongly scoped prefix, S3
`Walk` returns no error and no entries, so `confirmEmptyStore()` never runs and `[] + nil` is
still trusted. That is the case #4338's guard catches, and why Symptom B remains mitigated, not
root-caused. Symptom A is untouched: `GetNextRepositories()` still soft-skips by design.

## S3 Walk audit (2026-08-20)

Empirical results from calling the vendored `distribution/distribution` S3 driver directly
against LocalStack (`ghcr.io/project-zot/ci-images/localstack:community-archive`, the same
image zot's CI uses).

| Scenario | `Walk()` result | Notes |
|---|---|---|
| Empty prefix, bucket exists, nothing ever written | `nil` err, 0 entries | Not an error at all — no `PathNotFoundError` to swallow. The swallow branch in `GetRepositories()`/`GetNextRepositories()` is dead code for this case on S3. |
| Nonexistent `rootDirectory` (bucket exists) | `nil` err, 0 entries | S3 has no real directories, so "doesn't exist" and "exists but empty" are indistinguishable to `Walk`. |
| Namespaced repo (`myorg/myapp`) after push | Correctly enumerates all entries | No depth-related bug found — nested repo names aren't mishandled by zot's own walk/validation code. |
| Flat repo (`myapp`) after push | Correctly enumerates, properly isolated by `rootDirectory` | See test-infra note below. |
| Nonexistent **bucket** (not just empty prefix) | Real `driver.Error` wrapping `NoSuchBucket`, **not** `PathNotFoundError` | Already propagates as a genuine error today — not swallowed. |
| `Stat()` on an empty-but-existing prefix root | **`driver.PathNotFoundError`** | `Stat` *can* prove a root doesn't exist yet. `Walk`/`List` never surface this distinction. `GetRepositories()` only calls `Walk`, so it never gets this signal. |

**Key finding**: `GetRepositories()` has no way today to distinguish "genuinely empty registry"
from "walk silently found nothing" on S3, because `Walk` returns the identical `(nil, [])` for
both. `Stat(rootDir)` *does* carry that distinction. A root-cause fix could call `Stat` first to
decide whether an empty `Walk` result is trustworthy — reserving `PathNotFoundError` → empty
only for a provably uninitialized root, as suggested in review. (#4514's `confirmEmptyStore()`
only runs after a walk error, so it does not apply here; see above.)

**Not reproducible locally**: IAM-denied access. LocalStack community edition doesn't enforce
IAM policies. This needs either a real AWS bucket with a restrictive policy, or evidence from
the reporter (see checklist below).

**Separate pre-existing bug found during this audit**: `pkg/storage/s3/s3_test.go`'s
`createStoreDriver` test helper passes `"rootDir"` in the driver params map, but the S3 driver
reads `"rootdirectory"` (`FromParameters`, vendored `distribution/distribution` s3-aws driver).
The key has never matched, so `rootDir` scoping has silently been a no-op in every existing S3
test that uses this helper — all such tests actually share the bucket root regardless of the
`rootDir` argument passed in. Worth fixing before adding a new namespaced-repo S3 test, or the
new test will inherit the same blind spot and not test what it claims to.

## Proposed direction

**Layer 1 — Driver / imagestore (root cause).** Needs discussion before implementation:
- Audit what S3 `Walk`/`List` return for: empty prefix, IAM denied, wrong `rootDirectory`,
  nested repos. (Empty prefix, wrong rootDirectory, and nested repos are covered by the audit
  above; IAM denied is not yet covered — see checklist below.)
- Reserve `PathNotFoundError` → empty only for a provably uninitialized root (the `Stat`-based
  check above is a candidate mechanism); document the condition.
- Propagate other errors from `GetRepositories()`/`GetNextRepositories()`, and reconsider Debug
  as the log level for a swallowed `PathNotFoundError` (Warn at minimum). This needs agreement
  on what additional error types (if any) the storage driver interface should define and return
  before the error-handling code changes.
- Add an S3 test: push `myorg/myapp`, assert `GetRepositories()` and `_catalog` include it. Fix
  the `createStoreDriver` `rootDir` key bug first (see above), or this test won't actually
  verify prefix-scoped enumeration.

**Layer 2 — metaDB (defense in depth).** #4338's guard: don't mass-delete metaDB repos on a
suspicious empty walk. This is a mitigation, not a fix, and should ultimately depend on the
storage driver returning the correct/distinguishable error types from Layer 1 rather than
inferring "suspicious" purely from repo counts. Optionally extend later: heuristics for a
partial mismatch (metaDB repos absent from a non-empty but incomplete storage walk).

**Layer 3 — Triage.** Collect evidence from the reporter before declaring root cause on
Symptom A specifically (see checklist below).

## Evidence to collect from the reporter

- [ ] IAM policy attached to the credentials zot uses — specifically, does it grant
      `s3:ListBucket` (needed for `Walk`/`List`) separately from `s3:GetObject`
      (needed for per-repo reads)? A `ListBucket`-denied-but-`GetObject`-allowed policy would
      exactly explain "catalog empty, per-repo reads work."
- [ ] Whether `s3:ListBucket` is scoped with a `Condition` restricting it to a prefix (e.g.
      `s3:prefix` matching only some paths) — would explain why only *some* namespaced repos
      are affected rather than all.
- [ ] Exact `storage.rootDirectory` / `storage.storageDriver.rootdirectory` config value, and
      whether it matches the actual prefix under which `myorg/myapp` was pushed.
- [ ] Whether zot is configured with `subPaths`/substores, and if so, which store `myorg/**`
      falls under.
- [ ] S3 provider: real AWS S3, MinIO, Ceph, or something else — error semantics for
      access-denied vs empty-list are not guaranteed identical across S3-compatible backends.
- [ ] zot server logs at Debug level around a `GET /v2/_catalog` call and a startup/restart,
      to check whether the (currently Debug-level) "empty rootDir" line appears.
- [ ] Whether `storage.fastRestart` is enabled — relevant to how far the metaDB-wipe symptom
      (Symptom B) can propagate across restarts.
