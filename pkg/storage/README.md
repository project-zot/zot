This document reflects the finalized storage design decisions for proposal #3750.

zot supports two classes of storage backends:

1. local filesystems
2. remote object stores (for example S3, GCS, Azure)

The cache database is configured independently of the blob backend.

## Dedupe Design (Final)

This repository uses a single global blob namespace named `_blobstore` for both local and remote dedupe flows.

1. Blob content is promoted to `_blobstore/blobs/<algorithm>/<digest>`.
2. Repository blob paths keep per-repo ownership semantics.
3. On remote backends, per-repo paths are marker objects and reads resolve deterministically from `_blobstore`.
4. On local filesystems, dedupe still relies on hardlinks.

## Migration Behavior (Final)

Legacy layouts are upgraded automatically at startup when dedupe is enabled.

1. Migration is marker-guarded by `_global_blobstore_migrated` at the image store root.
2. If the marker exists, startup skips migration.
3. If migration is incomplete, startup retries on the next launch.
4. There is no user-facing migrate or rollback CLI for this flow.

## Downgrade Policy

Remote downgrade across this dedupe migration is unsupported.

After migration to `_blobstore` marker-based remote layout, running an older remote dedupe layout is not a supported path.

## Migration Matrix

| Backend | Direction | Support | Notes |
| --- | --- | --- | --- |
| local filesystem | legacy per-repo blobs -> `_blobstore` layout | supported | Automatic at startup when dedupe is enabled; migration marker prevents repeated full scans. |
| local filesystem | `_blobstore` layout -> older local release | conditionally supported | No dedicated rollback flow; behavior depends on older release expectations and filesystem hardlink semantics. |
| remote object store (S3/GCS/Azure) | legacy per-repo blobs -> `_blobstore` + marker layout | supported | Automatic at startup when dedupe is enabled; marker-guarded and resumable on next startup if incomplete. |
| remote object store (S3/GCS/Azure) | `_blobstore` + marker layout -> older remote release | unsupported | No rollback CLI is provided; remote downgrade is not a supported compatibility path. |

## Cache Backends

zot currently supports:

1. BoltDB (local cache)
2. Redis (remote cache)
3. DynamoDB (remote cache)
