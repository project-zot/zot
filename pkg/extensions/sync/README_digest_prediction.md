# OCI digest prediction (removed)

Sync no longer converts Docker → OCI and no longer predicts post-conversion digests for
skip checks.

## Why it was removed

Sparse multi-arch sync cannot convert Docker lists (omitted children break conversion;
converting would change the list digest). Digest-addressed children cannot convert either.
Keeping conversion only for tagged single Docker images forced a mixed model and expensive
full-tree remote walks on every ensure — mostly wasted when conversion was skipped.

## Current behavior

| Concern | Behavior |
|---------|----------|
| Docker → OCI | Never on sync |
| Skip checks | Compare **upstream** digests |
| Docker media types | Need `http.compat` `docker2s2`, else reject during image sync |
| `preserveDigest` | Deprecated and ignored |

See `README_sparse_multiarch_sync.md` (Docker and `http.compat`).
