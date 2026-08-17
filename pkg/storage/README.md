# Storage Subsystem Design

zot supports two classes of storage backends:

1. local filesystems
2. remote object stores (for example S3, GCS, Azure)

The storage backend stores repos, artifact blobs, and referrers. The cache database is configured independently of the storage backend.

Both new-write paths below are gated the same way, on the store's `dedupe` setting; what differs between local and remote is what the dedupe path actually does. Switching a store between dedupe enabled and disabled triggers a one-time migration or restore pass (see [Migration Behavior](#migration-behavior)) that reconciles existing content to the new mode - the lifecycles below describe new-write behavior under a fixed setting.

## Local Filesystem Blob Lifecycle

1. **Upload**: content is streamed to a temporary `.uploads/` location in the repository, then finalized.
   - Dedupe enabled: the content is promoted into `_blobstore/blobs/<algorithm>/<digest>` (first writer for that digest) or hardlinked to the already-promoted copy (subsequent writers). The repository's own `blobs/<algorithm>/<digest>` path is a real hardlink into that same inode, so it has real, independently readable content at all times and uses no extra disk space.
   - Dedupe disabled: content is moved directly into the repository's own path; `_blobstore` is never touched.
2. **Read**: reads resolve the repository's own path directly - a hardlink is indistinguishable from a normal file to any reader, so no indirection is needed.
3. **Delete**: removing a repository's blob removes only that repository's hardlink. The shared `_blobstore` copy is physically deleted only once its hardlink count reaches zero, checked via the filesystem's own link count where the platform reports it, falling back to a cache-based cross-repository reference scan otherwise.

## Remote Object Store Blob Lifecycle (S3/GCS/Azure)

1. **Upload**: content is streamed to a temporary `.uploads/` object, then finalized.
   - Dedupe enabled: the content is promoted into `_blobstore/blobs/<algorithm>/<digest>` (first writer for that digest). For subsequent writers, no bytes are copied at all - repository ownership is recorded purely as metadata (a logical reference) in the cache, and the repository's own blob path has no physical object.
   - Dedupe disabled: content is written directly to the repository's own path as a full, independent object; `_blobstore` is not used for new pushes.
2. **Read**: the global blobstore copy is preferred when it exists (the normal case for deduped content), falling back to the repository's own path only for blobs that predate the global blobstore or are mid-upload.
3. **Delete**: removing a repository's blob clears its logical reference from the cache. The shared `_blobstore` copy is physically deleted only once no other repository still holds a logical reference to that digest, determined via a cache-based cross-repository reference scan - there is no hardlink count on remote storage to consult.

## Dedupe Design

This repository uses a single global blob namespace named `_blobstore` for both local and remote dedupe flows.

1. Blob content is promoted to `_blobstore/blobs/<algorithm>/<digest>`.
2. Repository blob paths keep per-repo ownership semantics: each repository's ownership of a digest is tracked independently of every other repository's, so deleting or losing one repository's copy never affects another repository's ability to read the same shared content (see the Blob Lifecycle sections above for the exact mechanism per backend).
3. On remote backends with dedupe enabled, repository ownership is durable cache metadata; no per-repository blob object is created.
4. On local filesystems, dedupe still relies on hardlinks.
5. On remote backends with dedupe disabled, each repository stores a complete blob payload.

A genuine empty blob is represented by a zero-byte payload whose digest is the hash of empty content. Size alone is never used to identify ownership or deduplication state.

## Migration Behavior

Legacy layouts are upgraded automatically at startup when dedupe is enabled. The upgrade runs synchronously inside `Controller.Init()` (via `InitImageStore()`), before `InitMetaDB()`, `InitCVEInfo()`, and the health check is marked started - and `Init()` completes entirely before `Controller.Run()` sets up the HTTP router and starts accepting connections. So no request can reach a store before its migration for that startup has finished; if migration fails, `Init()` returns an error and the server never starts serving.

1. Migration is marker-guarded by `_global_blobstore_migrated` at the image store root.
2. If the marker exists, startup skips migration.
3. If migration is incomplete, startup retries on the next launch.
4. There is no user-facing migrate or rollback CLI for this flow.
5. Remote migration persists repository ownership before deleting legacy repository objects.
6. Disabling remote dedupe materializes full repository payloads and removes the migration marker; re-enabling dedupe migrates them back to `_blobstore`.

## Downgrade Policy

Downgrade across this dedupe migration is unsupported for both local and remote backends.

After migration to the `_blobstore` layout, running an older release against that same storage path is not a supported path, regardless of backend. There is no dedicated rollback flow, and behavior would depend on the older release's expectations and (for local filesystems) hardlink semantics. If you need to go from a new zot back to an older one, run a separate zot instance on the old layout and sync content into it from the new instance rather than downgrading in place.

## Migration Matrix

| Backend | Direction | Support | Notes |
| --- | --- | --- | --- |
| local filesystem | legacy per-repo blobs -> `_blobstore` layout | supported | Automatic at startup when dedupe is enabled; migration marker prevents repeated full scans. |
| local filesystem | `_blobstore` layout -> older local release | unsupported | No rollback CLI or dedicated rollback flow is provided; run a separate zot instance on the old layout and sync content into it instead. |
| remote object store (S3/GCS/Azure) | legacy per-repo blobs -> `_blobstore` + logical refs | supported | Automatic at startup when dedupe is enabled; checkpoint-guarded and resumable on next startup if incomplete. |
| remote object store (S3/GCS/Azure) | `_blobstore` + logical refs -> full per-repo blobs | supported | Automatic when dedupe is disabled; payloads are materialized before logical refs are removed. |
| remote object store (S3/GCS/Azure) | `_blobstore` + logical refs -> older remote release | unsupported | Remote downgrade is not a supported compatibility path. |

## Cache Backends

The cache is a digest -> path index that dedupe uses to look up content and repository ownership. For remote dedupe these references are durable metadata, so the cache backend must remain available and must be shared by every zot instance using the same object store.

zot currently supports:

1. BoltDB (local cache) - a single zot instance only; it cannot be shared across multiple instances.
2. Redis (remote cache) - required when multiple zot instances share a remote storage backend with dedupe enabled.
3. DynamoDB (remote cache) - also usable when multiple zot instances share a remote storage backend with dedupe enabled.
