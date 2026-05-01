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
	LocalStorageDriverName  = "local"
	// GlobalBlobsRepo is the internal directory used as the master copy location for deduped blobs.
	// It uses a leading underscore to ensure it can never collide with a valid OCI repository name.
	GlobalBlobsRepo = "_blobstore"
)
