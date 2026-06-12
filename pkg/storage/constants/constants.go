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

	DynamoDBTableNamePrefix = "tablenamePrefix"
	DynamoDBCacheTableName  = "cachetablename"
	DynamoDBRepoMetaTable   = "repometatablename"
	DynamoDBRepoBlobsTable  = "repoblobsinfotablename"
	DynamoDBImageMetaTable  = "imagemetatablename"
	DynamoDBUserDataTable   = "userdatatablename"
	DynamoDBAPIKeyTable     = "apikeytablename"
	DynamoDBVersionTable    = "versiontablename"

	DynamoDBCacheTableSuffix = "BlobTable"
	DynamoDBRepoMetaSuffix   = "RepoMetadataTable"
	DynamoDBRepoBlobsSuffix  = "RepoBlobsInfoTable"
	DynamoDBImageMetaSuffix  = "ImageMetaTable"
	DynamoDBUserDataSuffix   = "UserDataTable"
	DynamoDBAPIKeySuffix     = "ApiKeyDataTable"
	DynamoDBVersionSuffix    = "VersionTable"
	RedisLocksBucket         = "locks"
	DefaultGCDelay           = 1 * time.Hour
	DefaultGCInterval        = 1 * time.Hour
	S3StorageDriverName      = "s3"
	GCSStorageDriverName     = "gcs"
	LocalStorageDriverName   = "local"
)
