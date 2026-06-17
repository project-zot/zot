package constants

import (
	"time"
)

const (
	// BlobUploadDir defines the upload directory for blob uploads.
	BlobUploadDir           = ".uploads"
	SchemaVersion           = 2
	DefaultFilePerms        = 0o600
	DefaultDirPerms         = 0o700
	RLOCK                   = "RLock"
	RWLOCK                  = "RWLock"
	BlobsCache              = "blobs"
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
)
