package constants

import "time"

// references type.
const (
	Cosign            = "CosignSignature"
	OCI               = "OCIReference"
	Tag               = "TagReference"
	SyncBlobUploadDir = ".sync"
)

// Default timeout settings for sync operations.
const (
	DefaultSyncTimeout           = 3 * time.Hour    // default timeout for all sync operations (on-demand and periodic)
	DefaultResponseHeaderTimeout = 30 * time.Second // default timeout for reading response headers
)

// DefaultMaxConcurrentStreams bounds how many distinct blobs a registry's stream manager streams
// to clients at once when a registry config does not set MaxConcurrentStreams explicitly.
// Exported (rather than a stream_manager.go-local const) so the cli/server config validator can
// compare against the same effective default the stream manager actually falls back to.
const DefaultMaxConcurrentStreams = 32
