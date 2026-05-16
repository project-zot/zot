package sync

import "errors"

var (
	ErrReaderNotInitialized           = errors.New("reader not initialized")
	ErrManifestNotFoundOnDemandDisabl = errors.New("manifest not found in ondemand disabled")
	ErrBlobNotFoundInActiveStreams    = errors.New("blob not found in active streams")
	ErrChunkingReaderNotInitialized   = errors.New("chunking blob reader not initialized for this blob!")
)
