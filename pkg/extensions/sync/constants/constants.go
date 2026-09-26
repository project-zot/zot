package constants

import "time"

// references type.
const (
	Cosign            = "CosignSignature"
	OCI               = "OCIReference"
	Tag               = "TagReference"
	SyncBlobUploadDir = ".sync"
)

// StreamTempDir, directly under each sync staging root, holds streaming blobs' temp files. A repo
// name can't start with "_", so it never collides with one. Removed at startup: nothing in it
// outlives its process.
const StreamTempDir = "_stream"

// Default timeout settings for sync operations.
const (
	DefaultSyncTimeout           = 3 * time.Hour    // default timeout for all sync operations (on-demand and periodic)
	DefaultResponseHeaderTimeout = 30 * time.Second // default timeout for reading response headers
)

// DefaultMaxConcurrentStreams is the stream cap when MaxConcurrentStreams is unset (shared with
// config validation).
const DefaultMaxConcurrentStreams = 32
