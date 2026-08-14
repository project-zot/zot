//go:build sync

package sync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
)

// RangedBlobFetcher issues HTTP GET requests with Range headers to resume
// partial blob downloads from an upstream registry. It bypasses regclient's
// BlobGet (which does not support Range) to achieve true bandwidth-saving resume.
type RangedBlobFetcher struct {
	httpClient *http.Client
	baseURL    string // e.g. "https://registry-1.docker.io"
	logger     log.Logger
}

// NewRangedBlobFetcher creates a fetcher that will issue ranged requests against
// the given registry base URL using the provided HTTP client (which should already
// have appropriate TLS and timeout settings from the sync config).
func NewRangedBlobFetcher(httpClient *http.Client, baseURL string, logger log.Logger) *RangedBlobFetcher {
	return &RangedBlobFetcher{
		httpClient: httpClient,
		baseURL:    strings.TrimRight(baseURL, "/"),
		logger:     logger,
	}
}

// FetchRanged issues a GET /v2/{repo}/blobs/{digest} with Range: bytes={offset}-
// and returns the response body (caller must close) and the total content length.
// If the server does not support Range (returns 200 instead of 206), the full body
// is returned and the caller should discard the first `offset` bytes.
//
// Returns:
//   - body: the response body reader (partial or full depending on server support)
//   - totalSize: the full blob size as reported by Content-Range or Content-Length
//   - isPartial: true if server responded with 206 (real range support)
//   - err: any error during the request
func (f *RangedBlobFetcher) FetchRanged(ctx context.Context, repo string, digest godigest.Digest,
	offset int64,
) (body io.ReadCloser, totalSize int64, isPartial bool, err error) {
	blobURL := fmt.Sprintf("%s/v2/%s/blobs/%s", f.baseURL, repo, digest.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
	if err != nil {
		return nil, 0, false, fmt.Errorf("failed to create ranged blob request: %w", err)
	}

	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, 0, false, fmt.Errorf("ranged blob fetch failed: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusPartialContent:
		// Server supports Range; parse Content-Range for total size.
		totalSize = parseContentRangeTotal(resp.Header.Get("Content-Range"))
		if totalSize <= 0 {
			// Fallback: use offset + Content-Length
			totalSize = offset + resp.ContentLength
		}

		f.logger.Debug().
			Str("digest", digest.String()).
			Int64("offset", offset).
			Int64("totalSize", totalSize).
			Msg("ranged blob fetch: server returned 206 Partial Content")

		return resp.Body, totalSize, true, nil

	case http.StatusOK:
		// Server does not support Range; returned full blob.
		totalSize = resp.ContentLength

		f.logger.Debug().
			Str("digest", digest.String()).
			Int64("offset", offset).
			Int64("totalSize", totalSize).
			Msg("ranged blob fetch: server returned 200 (no range support), caller must discard prefix")

		return resp.Body, totalSize, false, nil

	default:
		resp.Body.Close()

		return nil, 0, false, fmt.Errorf("ranged blob fetch: unexpected status %d for %s", resp.StatusCode, blobURL)
	}
}

// parseContentRangeTotal extracts the total size from a Content-Range header value
// of the form "bytes 0-499/1234". Returns 0 if the header is missing or unparseable.
func parseContentRangeTotal(header string) int64 {
	// Format: "bytes <start>-<end>/<total>" or "bytes <start>-<end>/*"
	if header == "" {
		return 0
	}

	slashIdx := strings.LastIndex(header, "/")
	if slashIdx < 0 || slashIdx == len(header)-1 {
		return 0
	}

	totalStr := header[slashIdx+1:]
	if totalStr == "*" {
		return 0
	}

	total, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil {
		return 0
	}

	return total
}
