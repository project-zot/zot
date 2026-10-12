package constants

import (
	"time"
)

const (
	// BlobUploadDir defines the upload directory for blob uploads.
	BlobUploadDir    = ".uploads"
	SchemaVersion    = 2
	DefaultFilePerms = 0o600
	DefaultDirPerms  = 0o700
	RLOCK            = "RLock"
	RWLOCK           = "RWLock"
	// RepoRLock and peers label lock-wait metrics separately for the per-repo lock vs.
	// the single global blobstore lock, now that they're no longer the same mutex.
	RepoRLock               = "RepoRLock"
	RepoRWLock              = "RepoRWLock"
	BlobstoreRLock          = "BlobstoreRLock"
	BlobstoreRWLock         = "BlobstoreRWLock"
	BlobsCache              = "blobs"
	BlobRefs                = "blob_refs"
	DuplicatesBucket        = "duplicates"
	OriginalBucket          = "original"
	DBExtensionName         = ".db"
	DBCacheLockCheckTimeout = 10 * time.Second
	BoltdbName              = "cache"
	DynamoDBDriverName      = "dynamodb"
	RedisDriverName         = "redis"
	RedisLocksBucket        = "locks"
	DefaultGCDelay          = 1 * time.Hour
	DefaultGCInterval       = 1 * time.Hour
	S3StorageDriverName     = "s3"
	GCSStorageDriverName    = "gcs"
	AzureStorageDriverName  = "azure"
	LocalStorageDriverName  = "local"
	// DedupeRestoreCompleteMarker is written at the image store root when a full dedupe-restore
	// pass has completed. Its presence means no deduped blobs remain, so subsequent startups
	// with dedupe=false can skip the expensive per-digest restore scan. The marker is deleted
	// whenever dedupe is re-enabled, so that the next dedupe→false transition reruns restore.
	DedupeRestoreCompleteMarker = "_restore_complete"
	// DedupeRestoreMarkerComplete is the content of DedupeRestoreCompleteMarker when a restore
	// pass has completed successfully.
	DedupeRestoreMarkerComplete = "1"
	// DedupeRestoreMarkerInvalid is the content written to DedupeRestoreCompleteMarker to
	// invalidate a previous completion, forcing the restore scan to run again.
	DedupeRestoreMarkerInvalid = "0"
	// GlobalBlobsRepo is the internal directory holding the master copy of deduped blobs.
	// The leading underscore ensures it can never collide with a valid OCI repository name.
	GlobalBlobsRepo = "_blobstore"
	// BlobstoreMigratedMarker is written at the image store root once the one-time upgrade
	// from per-repo blob layout to the global blobstore completes, so later startups skip
	// the upgrade scan even if the blobstore is empty (e.g. a fresh install).
	BlobstoreMigratedMarker = "_global_blobstore_migrated"
)
