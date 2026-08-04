package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/api/constants"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

func (rh *RouteHandler) handleBlobStream(response http.ResponseWriter, request *http.Request,
	repo string, digest godigest.Digest, mediaType string, imgStore storageTypes.ImageStore,
) bool {
	upstreamReader, size, isFirstClient, waitCh, err := rh.c.SyncOnDemand.SyncBlobOnDemand(
		request.Context(), repo, digest, imgStore)
	if err != nil {
		return false
	}

	if isFirstClient {
		// WithoutCancel: the cache upload must finish even if this client disconnects.
		rh.streamBlobFromUpstream(context.WithoutCancel(request.Context()),
			response, repo, digest, mediaType, upstreamReader, size, imgStore)

		return true
	}

	if waitCh != nil {
		select {
		case <-waitCh:
		case <-request.Context().Done():
			return true
		}

		blobReader, blobSize, err := imgStore.GetBlob(repo, digest, mediaType)
		if err != nil {
			rh.c.Log.Error().Err(err).Str("repo", repo).Str("digest", digest.String()).
				Msg("failed to get blob from cache after streaming completed")

			return false
		}

		defer blobReader.Close()

		response.Header().Set(constants.DistContentDigestKey, digest.String())
		WriteDataFromReader(response, http.StatusOK, blobSize, mediaType, blobReader, rh.c.Log)

		return true
	}

	defer upstreamReader.Close()

	response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	response.Header().Set(constants.DistContentDigestKey, digest.String())
	WriteDataFromReader(response, http.StatusOK, size, mediaType, upstreamReader, rh.c.Log)

	return true
}

func (rh *RouteHandler) streamBlobFromUpstream(
	ctx context.Context,
	response http.ResponseWriter,
	repo string, digest godigest.Digest, mediaType string,
	upstreamReader io.ReadCloser, size int64,
	imgStore storageTypes.ImageStore,
) {
	const blobStreamBufferSize = 32 * 1024

	storagePR, storagePW := io.Pipe()
	clientPR, clientPW := io.Pipe()
	storageErrCh := make(chan error, 1)

	// Closing the client pipe reader when this returns lets the producer's clientPW.Write
	// fail instead of blocking forever if the client disconnects mid-stream.
	defer clientPR.Close()

	go func() {
		_, _, err := imgStore.FullBlobUpload(ctx, repo, storagePR, digest)
		if err != nil {
			rh.c.Log.Error().Err(err).Str("repo", repo).Str("digest", digest.String()).
				Msg("failed to cache streamed blob to local storage")
		}

		// Unblock the producer's storagePW.Write with this error if FullBlobUpload
		// returned before draining the pipe.
		storagePR.CloseWithError(err)
		storageErrCh <- err
	}()

	go func() {
		defer upstreamReader.Close()

		clientAlive := true

		var copyErr error

		buf := make([]byte, blobStreamBufferSize)

		for {
			readN, readErr := upstreamReader.Read(buf)
			if readN > 0 {
				if _, err := storagePW.Write(buf[:readN]); err != nil {
					copyErr = err

					break
				}

				if clientAlive {
					if _, err := clientPW.Write(buf[:readN]); err != nil {
						clientAlive = false
						clientPW.CloseWithError(err)
					}
				}
			}

			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					copyErr = readErr
				}

				break
			}
		}

		storagePW.Close()
		storageErr := <-storageErrCh
		copyErr = errors.Join(copyErr, storageErr)

		if clientAlive {
			if copyErr != nil {
				clientPW.CloseWithError(copyErr)
			} else {
				clientPW.Close()
			}
		}

		rh.c.SyncOnDemand.BlobDownloadDone(repo, digest, copyErr)
	}()

	response.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	response.Header().Set(constants.DistContentDigestKey, digest.String())
	WriteDataFromReader(response, http.StatusOK, size, mediaType, clientPR, rh.c.Log)
}
