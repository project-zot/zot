//go:build sync

package sync

import (
	"context"
	"errors"
	"os"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// This file contains the streaming-sync specific behavior of DestinationRegistry.

// tryCopyBlobFromStreamStore commits a blob to the image store directly from
// the stream temp store, avoiding a second read of the same bytes from the
// regclient temp ocidir that streaming sync already wrote to disk.
// It returns handled=false when streaming is not active or the blob is not
// (fully) available in the stream store, in which case the caller must fall
// back to the regular copy path.
func (registry *DestinationRegistry) tryCopyBlobFromStreamStore(ctx context.Context, repo string,
	blobDigest godigest.Digest, blobMediaType string, imageStore storageTypes.ImageStore,
) (bool, error) {
	if registry.streamManager == nil {
		return false, nil
	}

	streamPath := registry.streamManager.StreamBlobPath(blobDigest.String())
	if streamPath == "" {
		return false, nil
	}

	streamFile, err := os.Open(streamPath)
	if err != nil {
		return false, nil //nolint:nilerr // fall back to the regular copy path
	}

	defer streamFile.Close()

	registry.log.Debug().Str("blob", blobDigest.String()).
		Msg("using stream temp store blob for commit (avoiding double-read)")

	_, _, err = imageStore.FullBlobUpload(ctx, repo, streamFile, blobDigest)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't upload blob from stream store")

		// If the blob failed digest verification, the stream temp file is corrupt
		// (e.g. bad resume splice). Remove it so the next retry downloads from scratch.
		if errors.Is(err, zerr.ErrBadBlobDigest) {
			registry.streamManager.RemoveStreamBlob(blobDigest.String())
		}
	}

	return true, err
}
