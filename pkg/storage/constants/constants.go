package constants

import (
	"time"
)

const (
	// BlobUploadDir defines the upload directory for blob uploads.
	BlobUploadDir            = ".uploads"
	SchemaVersion            = 2
	DefaultFilePerms         = 0o600
	DefaultDirPerms          = 0o700
	RLOCK                    = "RLock"
	RWLOCK                   = "RWLock"
	BlobsCache               = "blobs"
	DuplicatesBucket         = "duplicates"
	OriginalBucket           = "original"
	DBExtensionName          = ".db"
	DBCacheLockCheckTimeout  = 10 * time.Second
	BoltdbName               = "cache"
	ReferrerFilterAnnotation = "org.opencontainers.references.filtersApplied"
	DynamoDBDriverName       = "dynamodb"
)
