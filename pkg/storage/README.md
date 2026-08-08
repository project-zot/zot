This document reflects the storage design decisions for proposal #3750.

zot supports two classes of storage backends:

1. local filesystems
2. remote object stores (for example S3, GCS, Azure)

The cache database is configured independently of the blob backend.

## Dedupe Design

This repository uses a single global blob namespace named `_blobstore` for both local and remote dedupe flows.

1. Blob content is promoted to `_blobstore/blobs/<algorithm>/<digest>`.
2. Repository blob paths keep per-repo ownership semantics.
3. On remote backends, per-repo paths are marker objects and reads resolve deterministically from `_blobstore`.
4. On local filesystems, dedupe still relies on hardlinks.

## Migration Behavior

Legacy layouts are upgraded automatically at startup when dedupe is enabled.

1. Migration is marker-guarded by `_global_blobstore_migrated` at the image store root.
2. If the marker exists, startup skips migration.
3. If migration is incomplete, startup retries on the next launch.
4. There is no user-facing migrate or rollback CLI for this flow.

## Downgrade Policy

Downgrade across this dedupe migration is unsupported for both local and remote backends.

After migration to the `_blobstore` layout, running an older release against that same storage path is not a supported path, regardless of backend. There is no dedicated rollback flow, and behavior would depend on the older release's expectations and (for local filesystems) hardlink semantics. If you need to go from a new zot back to an older one, run a separate zot instance on the old layout and sync content into it from the new instance rather than downgrading in place.

## Migration Matrix

| Backend | Direction | Support | Notes |
| --- | --- | --- | --- |
| local filesystem | legacy per-repo blobs -> `_blobstore` layout | supported | Automatic at startup when dedupe is enabled; migration marker prevents repeated full scans. |
| local filesystem | `_blobstore` layout -> older local release | unsupported | No rollback CLI or dedicated rollback flow is provided; run a separate zot instance on the old layout and sync content into it instead. |
| remote object store (S3/GCS/Azure) | legacy per-repo blobs -> `_blobstore` + marker layout | supported | Automatic at startup when dedupe is enabled; marker-guarded and resumable on next startup if incomplete. |
| remote object store (S3/GCS/Azure) | `_blobstore` + marker layout -> older remote release | unsupported | Remote downgrade is not a supported compatibility path. |

## Cache Backends

The cache is a digest -> path index that dedupe uses to look up whether a blob's content already exists and, if so, where. Every dedupe check and promotion into `_blobstore` goes through this index, so its backend must be reachable by every zot instance that shares the storage backend.

zot currently supports:

1. BoltDB (local cache) - a single zot instance only; it cannot be shared across multiple instances.
2. Redis (remote cache) - required when multiple zot instances share a remote storage backend with dedupe enabled.
3. DynamoDB (remote cache) - also usable when multiple zot instances share a remote storage backend with dedupe enabled.
