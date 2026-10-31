# Shared Blob Storage Proposal

## Executive Summary

This proposal redesigns zot's **remote storage** (S3, GCS, and any future cloud/remote drivers) to use shared blob storage, where all blobs are stored in a common location (`{rootDir}/storage/blobs/{algorithm}/{digest}`) across all repositories. This eliminates deduplication logic and reduces storage overhead for those backends.

**Scope:** All storage drivers **except local**. Shared blob storage applies to S3, GCS, and any other remote driver implemented in the future. **Local storage** is the only exception—it continues using per-repository blob structure with hard link deduplication.

## Current Architecture

### Blob Path Structure
```
{rootDir}/{repo}/blobs/{algorithm}/{digest}
```

### Current Issues
1. **Storage Overhead**: Duplicate blobs stored in multiple locations on remote storage (full copies, not hard links)
2. **Deduplication Complexity**: Requires cache database, periodic dedupe tasks, complex logic
3. **Remote Storage Limitations**: Hard links don't work on S3, GCS, or other remote backends, requiring full blob copies
4. **Cache Synchronization**: Cache can become out of sync with storage state

## Proposed Architecture

### Shared Blob Path (Remote Drivers: S3, GCS, etc.)
```
{rootDir}/storage/blobs/{algorithm}/{digest}  # Shared across all repos
{rootDir}/{repo}/index.json                   # Repository index (unchanged)
```

### Benefits
- ✅ Eliminates deduplication logic for remote storage (S3, GCS, future drivers)
- ✅ Single source of truth per blob on remote backends
- ✅ Reduces remote storage overhead significantly
- ✅ Simplifies cache (single path per digest vs multiple paths)
- ✅ Local storage unchanged (no migration needed)

### Trade-offs
- **GC Complexity**: For remote storage, must scan all repositories to build reference map before deleting blobs
- **Migration Required**: Existing remote storage (S3, GCS, etc.) needs migration to new structure

## Implementation

### Phase 1: Core Storage Changes

#### 1.1 Modify `BlobPath()` Function

Use an explicit check: **only the local driver** keeps per-repo blob paths; all other drivers (S3, GCS, and any future remote drivers) use shared blob storage. The codebase also treats a **nil** `storeDriver` as local:

```go
func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
    // Local: nil driver or driver name is local; use per-repo structure
    if is.storeDriver == nil || is.storeDriver.Name() == storageConstants.LocalStorageDriverName {
        return path.Join(is.rootDir, repo, ispec.ImageBlobsDir,
            digest.Algorithm().String(), digest.Encoded())
    }
    // S3, GCS, and any future remote driver: shared blob storage
    return path.Join(is.rootDir, "storage", ispec.ImageBlobsDir,
        digest.Algorithm().String(), digest.Encoded())
}
```

**Key Point:** Treat both `storeDriver == nil` and `storeDriver.Name() == LocalStorageDriverName` as local (per-repo path). All other drivers use shared blob storage.

#### 1.2 Remove Deduplication Logic (Remote Storage Only)

- Remove `DedupeBlob()` calls from blob upload paths when using S3, GCS, or other remote drivers
- Remove `GetAllDedupeReposCandidates()` usage for remote storage
- Simplify `CheckBlob()` for remote storage (no cache lookup for duplicates)
- Remove `RunDedupeBlobs()` scheduler task for remote storage
- **Local storage:** Keep existing deduplication logic (hard links)

#### 1.3 Update Cache Usage

**Cache Interface (unchanged):**
```go
type Cache interface {
    GetBlob(digest godigest.Digest) (string, error)
    GetAllBlobs(digest godigest.Digest) ([]string, error)
    PutBlob(digest godigest.Digest, path string) error
    HasBlob(digest godigest.Digest, path string) bool
    DeleteBlob(digest godigest.Digest, path string) error
}
```

**Behavior Changes:**
- **Local driver:** Cache tracks multiple paths per digest (for hard link deduplication)
- **Remote drivers (S3, GCS, etc.):** After migration, **all blobs are only under `/storage/`**. Cache stores **one path per digest** — the **shared path** `{rootDir}/storage/blobs/{algorithm}/{digest}`. New zot does not use or store original (per-repo) paths; read path is always the shared path. This keeps implementation simple and rollback is handled by a dedicated command (see §4.2).

**Implementation:**
Add `UseSinglePath` parameter to cache creation. Use single-path when storage is not local:

```go
// In pkg/storage/cache.go
useSinglePath := storageConfig.StorageDriver != nil

params := cache.BoltDBDriverParameters{
    RootDir:       storageConfig.RootDirectory,
    Name:          constants.BoltdbName,
    UseRelPaths:   getUseRelPaths(&storageConfig),
    UseSinglePath: useSinglePath, // true for S3, GCS, any remote driver
}
```

Cache semantics for remote:
- Store only one path per digest (the shared blob path).
- `UseSinglePath=false` (local): Track multiple paths per digest (existing behavior).

### Phase 2: Garbage Collection Changes

#### 2.1 Separate GC Implementations

- **Local Storage GC:** Per-repository (no changes)
- **Remote Storage GC (S3, GCS, etc.):** Global reference tracking (new implementation)

**GC Routing:** Treat “local” the same as in §1.1 (nil driver or `LocalStorageDriverName`). If the store exposes the driver, use the same condition; otherwise ensure `Name()` returns `LocalStorageDriverName` when the driver is nil so GC routes to per-repo.

```go
func (gc GarbageCollect) CleanRepo(ctx context.Context, repo string) error {
    // Local uses per-repo GC; all other drivers use global GC
    if gc.imgStore.Name() == storageConstants.LocalStorageDriverName {
        return gc.cleanRepoLocal(ctx, repo)
    }
    return gc.cleanRepoRemote(ctx, repo) // Global GC for S3, GCS, etc.
}
```

#### 2.2 Global Reference Tracking for Remote Storage

After migration, all blobs live only under **shared storage** `{rootDir}/storage/blobs/`. GC scans that directory and deletes any blob not referenced by any repository’s index/manifests.

```go
func (gc GarbageCollect) removeUnreferencedBlobsGlobal(delay time.Duration) error {
    // Step 1: Build global reference map by scanning all repositories
    refBlobs := map[string]bool{}
    repos, _ := gc.imgStore.GetRepositories()
    for _, repo := range repos {
        index, _ := common.GetIndex(gc.imgStore, repo, gc.log)
        gc.addIndexBlobsToReferences(repo, index, refBlobs)
    }
    
    // Step 2: Get all blobs in shared storage only
    allBlobs, _ := gc.imgStore.GetAllBlobs("") // see §2.3: scan {rootDir}/storage/blobs/
    
    // Step 3: Delete unreferenced blobs from shared storage
    for _, digest := range allBlobs {
        if _, ok := refBlobs[digest.String()]; !ok {
            // Check delay and delete if old enough
            gc.deleteBlobFromSharedStorage(digest)
        }
    }
    return nil
}
```

#### 2.3 Update `GetAllBlobs()` for Remote Storage

After migration, remote storage has blobs only under shared paths. When `repo == ""` (caller is GC), return all blobs in `{rootDir}/storage/blobs/`. When `repo != ""`, return blobs referenced by that repo (by walking its index/manifests).

```go
func (is *ImageStore) GetAllBlobs(repo string) ([]godigest.Digest, error) {
    if is.storeDriver != nil && is.storeDriver.Name() != storageConstants.LocalStorageDriverName {
        if repo == "" {
            // GC: all blobs in shared storage only
            return is.getAllBlobsFromSharedStorage()
        }
        return is.getBlobsReferencedByRepo(repo)
    }
    // Local: scan repo-specific directory (existing logic)
    // ...
}
```

### Phase 3: API Route Changes

#### 3.1 Blob Access Routes
No changes needed - storage layer abstraction handles path changes transparently.

#### 3.2 Mount/Copy Operations

Replace `GetAllDedupeReposCandidates()` with new method:

```go
// New storage method
func (is *ImageStore) GetReposReferencingBlob(digest godigest.Digest) ([]string, error) {
    repos := []string{}
    allRepos, _ := is.GetRepositories()
    for _, repo := range allRepos {
        index, _ := common.GetIndex(is, repo, is.log)
        if is.blobReferencedInIndex(repo, index, digest) {
            repos = append(repos, repo)
        }
    }
    return repos, nil
}

// Updated canMount() function
func canMount(userAc *reqCtx.UserAccessControl, imgStore storageTypes.ImageStore, 
    digest godigest.Digest) (bool, error) {
    if userAc == nil {
        return true, nil
    }
    repos, _ := imgStore.GetReposReferencingBlob(digest)
    for _, repo := range repos {
        if userAc.Can(constants.ReadPermission, repo) {
            return true, nil
        }
    }
    return false, nil
}
```

### Phase 4: Remote Storage Migration and Rollback (S3, GCS, etc.)

Migration applies to **all remote storage** from the start: S3 and GCS (and any future driver) use the same shared-blob layout and migration logic.

**Overall flow**

1. Run **`zot migrate-remote-storage`** so all original (per-repo) blobs are copied under **`/storage/`** paths; then per-repo blob copies are **deleted** (single copy under `/storage/`).
2. Run **new zot** — code expects **all blobs only under `/storage/`** (no per-repo blob paths).
3. To **rollback** to the pre-migration layout and run **older zot**: run **`zot rollback-remote-storage`** (see §4.2). The command repopulates per-repo blob paths by copying from `/storage/` according to each repo’s index and manifests (no dedupe), then **removes all blobs from `/storage/`** (cleanup). After it completes, run **older zot**.

Deduplication is not required for rollback: each repo gets full copies of the blobs it references.

#### 4.1 Migration Tool

**Command:** `zot migrate-remote-storage --config /path/to/config.json [--dry-run]`

The tool detects the configured storage driver (S3, GCS, etc.) and copies all blobs from per-repo paths to `{rootDir}/storage/blobs/{algorithm}/{digest}`. After a successful copy, **per-repo blob copies are deleted** so only one copy exists under `/storage/`. After migration, **only** the new zot (expecting blobs under `/storage/`) should be used.

**Key Features:**
- Works from any remote storage state (per-repo, partially migrated, or already shared)
- Idempotent (safe to run multiple times)
- Dry-run mode for preview
- Verifies blob integrity after copy

**Migration Process:**

1. Scan all `{repo}/blobs/` and build the set of blobs to migrate.
2. For each blob not already in `storage/blobs/`: copy to shared path, verify integrity.
3. **Delete** per-repo blob copies after successful migration (single copy under `/storage/`).

**Migration Steps:**
1. **Stop zot server** (prevents concurrent writes).
2. Run dry-run: `zot migrate-remote-storage --config config.json --dry-run`
3. Review results.
4. Run migration: `zot migrate-remote-storage --config config.json`
5. **Restart zot** with the **new** code (expects blobs only under `/storage/`).
6. Verify and monitor.

**Note:** No configuration changes needed. Shared blob storage is the default for all non-local drivers (S3, GCS, future).

#### 4.2 Rollback Command

**Command:** `zot rollback-remote-storage --config /path/to/config.json [--dry-run]`

To return to the previous layout and run **older zot**, the user runs this subcommand. The tool detects the configured storage driver (S3, GCS, etc.), copies blobs from `{rootDir}/storage/blobs/{algorithm}/{digest}` back into per-repo paths (no dedupe: every repo gets its own copy of the blobs it references), then **removes all blobs from `/storage/`** (cleanup) so only the per-repo layout remains.

**Key Features:**
- Works on storage that is already in shared-blob layout (post-migration state)
- Idempotent (safe to run multiple times; overwrites or skips as needed)
- Dry-run mode for preview
- Verifies blob integrity after copy (optional or configurable)

**Rollback Process:**

1. **Scan repositories:** List all repos under `{rootDir}/` (each has an `index.json`).
2. **Build blob→repo map:** For each repo, read `index.json` and follow manifest references recursively (image index, image manifest, config, layers). Collect the set of blob digests referenced by that repo and the paths where they must live: `{rootDir}/{repo}/blobs/{algorithm}/{digest}`.
3. **Copy blobs:** For each (repo, digest) pair, copy the blob from `{rootDir}/storage/blobs/{algorithm}/{digest}` to `{rootDir}/{repo}/blobs/{algorithm}/{digest}`. Create parent directories as needed. No dedupe: each repo gets a full copy of every blob it references.
4. **Verify:** Optionally verify integrity of copied blobs (e.g. digest check).
5. **Cleanup:** Remove all blobs (and empty algorithm dirs) under `{rootDir}/storage/blobs/` so only the per-repo layout remains.

**Rollback Steps:**
1. **Stop zot server** (prevents concurrent writes).
2. Run dry-run: `zot rollback-remote-storage --config config.json --dry-run`
3. Review results (which repos and how many blobs will be repopulated).
4. Run rollback: `zot rollback-remote-storage --config config.json`
5. **Start older zot** (pre–shared-blob-storage code) that expects blobs in per-repo paths.
6. Verify and monitor.

**Note:** After repopulating per-repo paths, the rollback command **removes blobs from `/storage/`** (cleanup) so that only the per-repo layout remains and no duplicate copies are left under shared storage.

## Performance Considerations

### GC Overhead
- **Current:** O(total_blobs), can run in parallel per repo
- **Proposed (remote storage):** O(total_repos + total_blobs), must scan all repos first
- **Mitigation:** Cache reference map, incremental GC, batch processing

### Storage Efficiency
- **Current remote (S3, GCS, etc.):** Full copies for duplicates (100% overhead)
- **Proposed:** Single copy in shared storage per remote backend
- **Savings:** Up to N-1 copies for N repositories sharing a blob

### Blob Access Performance
- **Current:** O(1) direct access + O(1) cache lookup
- **Proposed:** O(1) direct access to shared path only (single path per digest in cache)
- **Result:** Similar or slightly faster

## Implementation Plan

1. **Foundation**
   - Modify `BlobPath()` for non-local drivers (S3, GCS, etc.)
   - Update blob write operations
   - Add unit tests

2. **Remove Deduplication**
   - Remove `DedupeBlob()` calls for remote storage
   - Update cache with `UseSinglePath` parameter (true when not local)
   - Keep local deduplication logic

3. **GC Updates**
   - Implement global reference tracking for remote storage
   - Update `GetAllBlobs()` when driver is not local: for GC (`repo == ""`) return all blobs in shared storage only (§2.2, §2.3)
   - Keep per-repo GC for local

4. **API Updates**
   - Implement `GetReposReferencingBlob()`
   - Update `canMount()` function
   - Integration testing

5. **Migration & Testing**
   - Create `zot migrate-remote-storage` subcommand
   - Create `zot rollback-remote-storage` subcommand (scan index.json/manifests, copy blobs from `/storage/` to per-repo paths; no dedupe)
   - Test on sample data (S3, GCS)
   - Performance benchmarking
   - Documentation

## Risks and Mitigations

### Risk 1: GC Performance Degradation
**Mitigation:** Incremental GC, caching, batch processing, monitoring

### Risk 2: Remote Storage Migration Complexity
**Mitigation:** Comprehensive tool with dry-run, verification, error recovery, extensive testing (S3, GCS as applicable)

### Risk 3: Breaking Changes
**Mitigation:** Backward compatibility, comprehensive tests, clear migration path

### Risk 4: Remote-Storage-Specific Issues
**Mitigation:** Extensive testing per backend (S3, GCS), handle eventual consistency, monitor API costs

## Testing Strategy

### Go Unit Tests (pkg/storage/*_test.go)

Following existing zot test patterns using goconvey:

- **`pkg/storage/imagestore/imagestore_test.go`**: Test `BlobPath()`: local uses per-repo path; S3, GCS (and other non-local drivers) use shared path
- **`pkg/storage/gc/gc_test.go`**: Test global GC for remote storage using existing `testCases` pattern (local vs S3/GCS)
  - Use `tskip.SkipS3(t)` / `tskip.SkipGCS(t)` (or equivalent) for backend-specific tests
  - Test global reference tracking for non-local drivers
  - Verify per-repo GC still works for local storage
- **`pkg/storage/cache/*_test.go`**: Test cache behavior with `UseSinglePath` parameter
  - Verify single-path behavior for remote drivers, multi-path for local
- **`pkg/storage/storage_test.go`**: Test storage operations with shared blob paths for S3, GCS, etc.
  - Use existing `createObjectsStore()` helper; test blob upload/download with shared storage

### BATS Blackbox Tests (test/blackbox/*.bats)

Following existing BATS test patterns:

- **`test/blackbox/pushpull.bats`**: Verify push/pull operations work with shared blob storage
  - Test blob uploads go to shared storage location
  - Test blob downloads from shared storage only
  - Use existing S3/GCS test setup (e.g. `helpers_cloud.bash`) as applicable
- **`test/blackbox/garbage_collect.bats`**: Test GC with shared blob storage
  - Verify global GC scans shared storage only and correctly identifies unreferenced blobs
  - Verify GC does not delete referenced blobs
  - Use existing GC test patterns
- **`test/blackbox/restore_s3_blobs.bats`** (and GCS equivalents as needed): Test blob restoration after migration
  - Verify blob access after migration (all from `/storage/`)
  - Test error recovery scenarios
- **Rollback command:** Test `zot rollback-remote-storage` repopulates per-repo paths from `/storage/`, cleans up `/storage/`, and older zot can run
- **New test file: `test/blackbox/migrate_remote_storage.bats`**: Test migration tool for any remote storage (S3, GCS)
  - Test dry-run mode
  - Test actual migration
  - Test idempotency (running migration multiple times)
  - Test error recovery

### Upgrade Tests (test/blackbox/upgrade*.bats)

- **`test/blackbox/upgrade.bats`**: Test upgrade path from per-repo to shared blob storage
  - Verify existing remote storage (S3, GCS) can be migrated
  - Test backward compatibility during transition
  - Use existing upgrade test infrastructure

## Conclusion

Shared blob storage for **all remote drivers** (S3, GCS, and any future backend) eliminates deduplication complexity and significantly reduces storage overhead. The **local driver** is the only exception and keeps per-repository blob structure. The main trade-off is increased GC complexity for remote storage, which is manageable with proper implementation.
