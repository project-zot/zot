package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	godigest "github.com/opencontainers/go-digest"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/constants"
	events "zotregistry.dev/zot/v2/pkg/extensions/events"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// syncStreamer is the optional interface implemented by the sync on-demand
// implementation when streaming sync is compiled in (build tag "sync"). It is
// discovered via a type assertion on Controller.SyncOnDemand, so the API layer
// has no compile-time dependency on the sync extension or regclient types.
// When the assertion fails (sync not compiled in) or streaming is not enabled
// for a repo, every hook in this file is a no-op and the request flow is
// byte-for-byte identical to a zot without streaming sync.
type syncStreamer interface {
	// IsStreamingEnabledForRepo returns whether streaming sync is configured
	// for the given local repo.
	IsStreamingEnabledForRepo(repo string) bool
	// FetchManifestForStream fetches the manifest directly from upstream,
	// prepares the image for streaming and starts the sync in the background,
	// returning the raw manifest content, digest and media type.
	FetchManifestForStream(ctx context.Context, repo, reference string) ([]byte, godigest.Digest, string, error)
	// CachedBlobInfo returns size and media type of a blob belonging to an
	// active stream, or zerr.ErrBlobNotFound.
	CachedBlobInfo(blobDigest string) (int64, string, error)
	// ConnectBlobStream subscribes the writer to an in-flight blob download
	// and returns a function that copies the requested byte range to it, or
	// zerr.ErrBlobNotFoundInActiveStreams when the blob has no active stream.
	ConnectBlobStream(blobDigest string, writer io.Writer) (func(ctx context.Context, start, end int64) error, error)
}

// streamer returns the syncStreamer when streaming sync is available and
// enabled for the given repo.
func (rh *RouteHandler) streamer(repo string) (syncStreamer, bool) {
	if rh.c.SyncOnDemand == nil {
		return nil, false
	}

	streamer, ok := rh.c.SyncOnDemand.(syncStreamer)
	if !ok || !streamer.IsStreamingEnabledForRepo(repo) {
		return nil, false
	}

	return streamer, true
}

// wrapStreamingBlobWriter replaces the server's absolute WriteTimeout with a
// rolling per-write deadline for blob downloads of streaming-enabled repos.
// Multi-GB layers legitimately exceed an absolute WriteTimeout; with a rolling
// deadline, transfers that keep making progress are never cut off mid-stream,
// while stalled clients still time out after the configured duration of write
// inactivity. Repos not served by streaming sync keep the stock behavior.
func (rh *RouteHandler) wrapStreamingBlobWriter(response http.ResponseWriter, repo string) http.ResponseWriter {
	if _, ok := rh.streamer(repo); !ok {
		return response
	}

	writeTimeout := rh.c.Config.GetHTTPWriteTimeout()
	if writeTimeout <= 0 {
		return response
	}

	return newRollingDeadlineWriter(response, writeTimeout, rh.c.Log)
}

// tryStreamBlobInfo answers a HEAD blob request from the stream cache when the
// blob belongs to an active streaming download. Returns true if the response
// has been written.
func (rh *RouteHandler) tryStreamBlobInfo(repo, digest string, response http.ResponseWriter) bool {
	streamer, ok := rh.streamer(repo)
	if !ok {
		return false
	}

	rh.c.Log.Debug().Str("digest", digest).Msg("checking stream cache for blob existence")

	blobSize, blobMediaType, err := streamer.CachedBlobInfo(digest)
	if err != nil {
		if errors.Is(err, zerr.ErrBlobNotFound) {
			rh.c.Log.Debug().Str("digest", digest).Msg("blob not found in stream cache")
		} else {
			rh.c.Log.Error().Err(err).Str("digest", digest).Msg("failed to check stream cache for blob existence")
		}

		return false
	}

	response.Header().Set("Content-Length", strconv.FormatInt(blobSize, 10))
	response.Header().Set("Accept-Ranges", "bytes")
	response.Header().Set("Content-Type", blobMediaType)
	response.Header().Set(constants.DistContentDigestKey, digest)
	response.WriteHeader(http.StatusOK)

	return true
}

// tryServeStreamedBlob attempts to serve a blob that was not found in local
// storage from an active streaming download, or (if the stream just finished)
// from storage on a re-check. Returns true if a response has been written; on
// false the caller continues with its regular 404 handling.
func (rh *RouteHandler) tryServeStreamedBlob(response http.ResponseWriter, request *http.Request,
	imgStore storageTypes.ImageStore, name string, digest godigest.Digest,
	contentRange string, rangeHeaderPresent bool,
) bool {
	streamer, ok := rh.streamer(name)
	if !ok {
		return false
	}

	if rh.tryStreamBlob(streamer, response, request, name, digest, contentRange, rangeHeaderPresent) {
		return true
	}

	// The stream may have completed and committed the blob to storage between
	// the caller's original storage lookup and the stream lookup above.
	return rh.serveBlobFromStoreRetry(response, request, imgStore, name, digest, contentRange, rangeHeaderPresent)
}

// tryStreamBlob attempts to serve a blob (fully, or a single byte range) from
// an active streaming sync download. It returns true if a response has been
// written (successfully or not); false means the blob is not part of any
// active stream.
//
// Range support is essential here: when a streamed download is interrupted,
// docker reconnects with "Range: bytes=<received>-" to resume the layer pull.
// Without a 206 answer from the stream path, those resume attempts would fail
// and the pull would abort with the original error (e.g. unexpected EOF).
func (rh *RouteHandler) tryStreamBlob(streamer syncStreamer, response http.ResponseWriter, request *http.Request,
	name string, digest godigest.Digest, contentRange string, rangeHeaderPresent bool,
) bool {
	blobSize, mediaType, err := streamer.CachedBlobInfo(digest.String())
	if err != nil {
		rh.c.Log.Debug().Str("repo", name).Str("digest", digest.String()).
			Msg("blob not found in active streams")

		return false
	}

	start, end := int64(0), int64(-1)

	if rangeHeaderPresent {
		ranges, err := parseRangeHeader(contentRange, blobSize)
		if err != nil || len(ranges) != 1 {
			// Multi-range responses are not supported for in-flight blobs.
			response.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", blobSize))
			response.WriteHeader(http.StatusRequestedRangeNotSatisfiable)

			return true
		}

		start, end = ranges[0].start, ranges[0].end
	}

	rh.c.Log.Debug().Str("repo", name).Str("digest", digest.String()).
		Int64("start", start).Int64("end", end).Msg("connecting client to stream")

	copyRange, err := streamer.ConnectBlobStream(digest.String(), response)
	if err != nil {
		if errors.Is(err, zerr.ErrBlobNotFoundInActiveStreams) {
			// The stream may have been cleaned up between CachedBlobInfo and
			// here; let the caller fall back to storage / 404.
			rh.c.Log.Warn().Err(err).Str("digest", digest.String()).
				Msg("failed to connect client to stream")

			return false
		}

		rh.c.Log.Error().Err(err).Str("digest", digest.String()).
			Msg("unexpected error connecting client to stream")

		response.WriteHeader(http.StatusInternalServerError)

		return true
	}

	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.Header().Set("Content-Type", mediaType)
	response.Header().Set("Accept-Ranges", "bytes")

	if rangeHeaderPresent {
		response.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		response.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, blobSize))
		response.WriteHeader(http.StatusPartialContent)
	} else {
		response.Header().Set("Content-Length", strconv.FormatInt(blobSize, 10))
		response.WriteHeader(http.StatusOK)
	}

	// Flush headers immediately so the client knows the blob is available
	// and does not time out waiting for the first byte.
	if flusher, ok := response.(http.Flusher); ok {
		flusher.Flush()
	}

	if copyErr := copyRange(request.Context(), start, end); copyErr != nil {
		rh.c.Log.Error().Err(copyErr).Str("digest", digest.String()).
			Msg("unexpected error during stream copy")
	}

	return true
}

// serveBlobFromStoreRetry re-checks local storage for a blob after a stream
// lookup miss and serves it if present. It covers the window where a streaming
// sync commits the blob to storage and tears down the stream entry between the
// caller's original (failed) storage lookup and the stream lookup; without this
// re-check the client would get a spurious 404 for a blob that is available.
// Returns true if the response was written.
func (rh *RouteHandler) serveBlobFromStoreRetry(response http.ResponseWriter, request *http.Request,
	imgStore storageTypes.ImageStore, name string, digest godigest.Digest,
	contentRange string, rangeHeaderPresent bool,
) bool {
	mediaType := resolveBlobResponseMediaType(imgStore, name, digest, rh.c.Log)

	if !rangeHeaderPresent {
		reader, blen, err := imgStore.GetBlob(name, digest, mediaType)
		if err != nil {
			return false
		}

		defer reader.Close()

		response.Header().Set("Content-Length", strconv.FormatInt(blen, 10))
		response.Header().Set(constants.DistContentDigestKey, digest.String())

		WriteDataFromReader(response, http.StatusOK, blen, mediaType, reader, rh.c.Log)

		return true
	}

	ctx := events.WithEventContext(request.Context(), eventContextFromRequest(request))

	ok, bsize, err := imgStore.CheckBlob(ctx, name, digest)
	if err != nil || !ok {
		return false
	}

	ranges, err := parseRangeHeader(contentRange, bsize)
	if err != nil || len(ranges) != 1 {
		// Multi-range retries are not supported here; let the caller 404.
		return false
	}

	rng := ranges[0]

	reader, blen, _, err := imgStore.GetBlobPartial(name, digest, mediaType, rng.start, rng.end)
	if err != nil {
		return false
	}

	defer reader.Close()

	if blen != rng.length() {
		rh.c.Log.Error().Int64("expected", rng.length()).Int64("actual", blen).
			Msg("unexpected partial blob length on storage re-check")

		return false
	}

	response.Header().Set(constants.DistContentDigestKey, digest.String())
	response.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rng.start, rng.end, bsize))
	WriteDataFromReader(response, http.StatusPartialContent, rng.length(), mediaType, reader, rh.c.Log)

	return true
}

// streamedManifestFastPath serves a manifest GET for a streaming-enabled repo
// by fetching the manifest directly from upstream (starting the actual image
// sync in the background) instead of waiting for the full on-demand sync.
// handled=false means streaming does not apply and the caller must continue
// with the regular on-demand sync flow.
func (rh *RouteHandler) streamedManifestFastPath(ctx context.Context, imgStore storageTypes.ImageStore,
	name, reference string,
) (handled bool, content []byte, digest godigest.Digest, mediaType string, err error) {
	streamer, ok := rh.streamer(name)
	if !ok {
		return false, nil, "", "", nil
	}

	rh.c.Log.Debug().Str("repository", name).Str("reference", reference).
		Msg("streaming is enabled for repo. Direct fetching manifest.")

	content, digest, mediaType, err = streamer.FetchManifestForStream(ctx, name, reference)
	if err != nil {
		rh.c.Log.Err(err).Str("repository", name).Str("reference", reference).
			Msg("failed to fetch manifest for stream")

		content, digest, mediaType, err = imgStore.GetImageManifest(name, reference)

		return true, content, digest, mediaType, err
	}

	return true, content, digest, mediaType, nil
}
