# Shared Blob Storage Proposal

## Executive Summary

This proposal redesigns zot's S3 storage to use shared blob storage where all blobs are stored in a common location (`{rootDir}/storage/blobs/{algorithm}/{digest}`) across all repositories. This eliminates deduplication logic and reduces S3 storage overhead.

**Scope:** S3 storage only. Local storage continues using per-repository blob structure with hard link deduplication.

## Current Architecture

### Blob Path Structure
```
{rootDir}/{repo}/blobs/{algorithm}/{digest}
```

### Current Issues
1. **Storage Overhead**: Duplicate blobs stored in multiple S3 locations (full copies, not hard links)
2. **Deduplication Complexity**: Requires cache database, periodic dedupe tasks, complex logic
3. **S3 Limitations**: Hard links don't work on S3, requiring full blob copies
4. **Cache Synchronization**: Cache can become out of sync with storage state

## Proposed Architecture

### S3 Blob Path Structure
```
{rootDir}/storage/blobs/{algorithm}/{digest}  # Shared across all repos
{rootDir}/{repo}/index.json                   # Repository index (unchanged)
```

### Benefits
- ✅ Eliminates S3 deduplication logic
- ✅ Single source of truth per blob in S3
- ✅ Reduces S3 storage overhead significantly
- ✅ Simplifies cache (single path per digest vs multiple paths)
- ✅ Local storage unchanged (no migration needed)

### Trade-offs
- **GC Complexity**: Must scan all repositories to build reference map before deleting blobs
- **Migration Required**: Existing S3 storage needs migration to new structure

## Implementation

### Phase 1: Core Storage Changes

#### 1.1 Modify `BlobPath()` Function

```go
func (is *ImageStore) BlobPath(repo string, digest godigest.Digest) string {
    // S3 storage (storeDriver != nil) always uses shared blob storage
    if is.storageDriver != nil {
        return path.Join(is.rootDir, "storage", ispec.ImageBlobsDir, 
            digest.Algorithm().String(), digest.Encoded())
    }
    // Local storage (storeDriver == nil) uses per-repo structure
    return path.Join(is.rootDir, repo, ispec.ImageBlobsDir, 
        digest.Algorithm().String(), digest.Encoded())
}
```

**Key Point:** No configuration flag needed. S3 detection is automatic via `storeDriver != nil`.

#### 1.2 Remove Deduplication Logic (S3 Only)

- Remove `DedupeBlob()` calls from S3 blob upload paths
- Remove `GetAllDedupeReposCandidates()` usage for S3
- Simplify `CheckBlob()` for S3 (no cache lookup for duplicates)
- Remove `RunDedupeBlobs()` scheduler task for S3
- **Local storage:** Keep existing deduplication logic

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

**Behavior Changes for S3:**
- **Local:** Cache tracks multiple paths per digest (for hard link deduplication)
- **S3:** Cache tracks single shared path per digest (path parameter ignored or set to shared path)

**Implementation:**
Add `UseSinglePath` parameter to cache creation:

```go
// In pkg/storage/cache.go
useSinglePath := storageConfig.StorageDriver != nil // S3 uses shared storage

params := cache.BoltDBDriverParameters{
    RootDir:      storageConfig.RootDirectory,
    Name:         constants.BoltdbName,
    UseRelPaths:  getUseRelPaths(&storageConfig),
    UseSinglePath: useSinglePath, // New parameter
}
```

Cache implementations check this flag:
- `UseSinglePath=true` (S3): Store only one path per digest, ignore duplicates
- `UseSinglePath=false` (local): Track multiple paths per digest (existing behavior)

### Phase 2: Garbage Collection Changes

#### 2.1 Separate GC Implementations

- **Local Storage GC:** Per-repository (no changes)
- **S3 Storage GC:** Global reference tracking (new implementation)

**GC Routing:**
```go
func (gc GarbageCollect) CleanRepo(ctx context.Context, repo string) error {
    if gc.imgStore.StorageDriver() != nil {
        return gc.cleanRepoS3(ctx, repo) // Global GC for S3
    }
    return gc.cleanRepoLocal(ctx, repo)  // Per-repo GC for local
}
```

#### 2.2 Global Reference Tracking for S3

```go
func (gc GarbageCollect) removeUnreferencedBlobsGlobal(delay time.Duration) error {
    // Step 1: Build global reference map by scanning all repositories
    refBlobs := map[string]bool{}
    repos, _ := gc.imgStore.GetRepositories()
    for _, repo := range repos {
        index, _ := common.GetIndex(gc.imgStore, repo, gc.log)
        gc.addIndexBlobsToReferences(repo, index, refBlobs)
    }
    
    // Step 2: Get all blobs from shared storage
    allBlobs, _ := gc.getAllBlobsFromSharedStorage()
    
    // Step 3: Delete unreferenced blobs
    for _, digest := range allBlobs {
        if _, ok := refBlobs[digest.String()]; !ok {
            // Check delay and delete if old enough
            gc.deleteBlobFromSharedStorage(digest)
        }
    }
    return nil
}
```

#### 2.3 Update `GetAllBlobs()` for S3

```go
func (is *ImageStore) GetAllBlobs(repo string) ([]godigest.Digest, error) {
    if is.storageDriver != nil {
        if repo == "" {
            // GC needs all blobs from shared storage
            return is.getAllBlobsFromSharedStorage()
        }
        // Repo-specific: return blobs referenced by this repo
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

### Phase 4: S3 Migration Strategy

#### 4.1 Migration Tool

**Command:** `zot migrate-s3-storage --config /path/to/config.json [--dry-run]`

**Key Features:**
- Works from any S3 storage state (per-repo, partially migrated, or already shared)
- Idempotent (safe to run multiple times)
- Dry-run mode for preview
- Verifies blob integrity after copy

**Migration Process:**

1. **Phase 1: Scan Per-Repo Storage**
   - Scans all `{repo}/blobs/` directories
   - Builds map of blobs in per-repo locations

2. **Phase 2: Scan Shared Storage**
   - Scans `storage/blobs/` directory
   - Builds map of already-migrated blobs

3. **Phase 3: Determine Migration Needs**
   - **Needs migration:** Exists in per-repo but NOT in shared → Copy to shared
   - **Needs cleanup:** Exists in both → Delete per-repo copies
   - **Already migrated:** Only in shared → Skip

4. **Phase 4: Execute Migration**
   - Copy blobs to shared storage
   - Verify integrity
   - Delete per-repo copies

**Migration Steps:**
1. **Stop zot server** (prevents concurrent writes)
2. Run dry-run: `zot migrate-s3-storage --config config.json --dry-run`
3. Review results
4. Run migration: `zot migrate-s3-storage --config config.json`
5. **Restart zot** (automatically uses shared blob storage)
6. Verify and monitor

**Note:** No configuration changes needed - shared blob storage is default for S3.

## Performance Considerations

### GC Overhead
- **Current:** O(total_blobs), can run in parallel per repo
- **Proposed (S3):** O(total_repos + total_blobs), must scan all repos first
- **Mitigation:** Cache reference map, incremental GC, batch processing

### Storage Efficiency
- **Current S3:** Full copies for duplicates (100% overhead)
- **Proposed S3:** Single copy in shared storage
- **Savings:** Up to N-1 copies for N repositories sharing a blob

### Blob Access Performance
- **Current:** O(1) direct access + O(1) cache lookup
- **Proposed:** O(1) direct access (no cache lookup needed)
- **Result:** Slightly faster

## Implementation Plan

1. **Foundation**
   - Modify `BlobPath()` for S3
   - Update blob write operations
   - Add unit tests

2. **Remove Deduplication**
   - Remove `DedupeBlob()` calls for S3
   - Update cache with `UseSinglePath` parameter
   - Keep local deduplication logic

3. **GC Updates**
   - Implement global reference tracking for S3
   - Update `GetAllBlobs()` for shared storage
   - Keep per-repo GC for local

4. **API Updates**
   - Implement `GetReposReferencingBlob()`
   - Update `canMount()` function
   - Integration testing

5. **Migration & Testing**
   - Create migration tool
   - Test on sample data
   - Performance benchmarking
   - Documentation

## Risks and Mitigations

### Risk 1: GC Performance Degradation
**Mitigation:** Incremental GC, caching, batch processing, monitoring

### Risk 2: S3 Migration Complexity
**Mitigation:** Comprehensive tool with dry-run, verification, error recovery, extensive testing

### Risk 3: Breaking Changes
**Mitigation:** Backward compatibility, comprehensive tests, clear migration path

### Risk 4: S3-Specific Issues
**Mitigation:** Extensive S3 testing, handle eventual consistency, monitor API costs

## Testing Strategy

### Go Unit Tests (pkg/storage/*_test.go)

Following existing zot test patterns using goconvey:

- **`pkg/storage/imagestore/imagestore_test.go`**: Test `BlobPath()` with S3 vs local storage detection
- **`pkg/storage/gc/gc_test.go`**: Test global GC for S3 using existing `testCases` pattern (local vs S3)
  - Use `tskip.SkipS3(t)` for S3-specific tests
  - Test global reference tracking logic
  - Verify per-repo GC still works for local storage
- **`pkg/storage/cache/*_test.go`**: Test cache behavior with `UseSinglePath` parameter
  - Test BoltDB, Redis, DynamoDB cache implementations
  - Verify single-path behavior for S3, multi-path for local
- **`pkg/storage/storage_test.go`**: Test storage operations with shared blob paths
  - Use existing `createObjectsStore()` helper with S3/local test cases
  - Test blob upload/download with shared storage

### BATS Blackbox Tests (test/blackbox/*.bats)

Following existing BATS test patterns:

- **`test/blackbox/pushpull.bats`**: Verify push/pull operations work with shared blob storage
  - Test blob uploads go to shared storage location
  - Test blob downloads from shared storage
  - Use existing S3 test setup from `helpers_cloud.bash`
- **`test/blackbox/garbage_collect.bats`**: Test GC with shared blob storage
  - Verify global GC correctly identifies unreferenced blobs
  - Test GC doesn't delete blobs referenced by other repos
  - Use existing GC test patterns
- **`test/blackbox/restore_s3_blobs.bats`**: Test S3 blob restoration scenarios
  - Verify blob access after migration
  - Test error recovery scenarios
- **New test file: `test/blackbox/migrate_s3_storage.bats`**: Test migration tool
  - Test dry-run mode
  - Test actual migration
  - Test idempotency (running migration multiple times)
  - Test error recovery

### Upgrade Tests (test/blackbox/upgrade*.bats)

- **`test/blackbox/upgrade.bats`**: Test upgrade path from per-repo to shared blob storage
  - Verify existing S3 storage can be migrated
  - Test backward compatibility during transition
  - Use existing upgrade test infrastructure

## Conclusion

Shared blob storage for S3 eliminates deduplication complexity and significantly reduces storage overhead. The main trade-off is increased GC complexity, which is manageable with proper implementation. Local storage remains unchanged, providing a clean separation of concerns.
