package constants

import "time"

// references type.
const (
	Cosign               = "CosignSignature"
	OCI                  = "OCIReference"
	Tag                  = "TagReference"
	SyncBlobUploadDir    = ".sync"
	StreamChunkSizeBytes = 500 // in stream mode, each chunk will be a max of 500 bytes in size
)

// Default timeout settings for sync operations.
const (
	DefaultSyncTimeout           = 3 * time.Hour    // default timeout for all sync operations (on-demand and periodic)
	DefaultResponseHeaderTimeout = 30 * time.Second // default timeout for reading response headers
)
