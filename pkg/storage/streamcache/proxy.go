package streamcache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// StreamProxy proxy zwischen Remote-Registry und Client mit Caching
type StreamProxy struct {
	cache       *StreamCache
	log         log.Logger
	imageStore  storageTypes.ImageStore
	remoteURL   string
	credentials Credentials
}

type Credentials struct {
	Username string
	Password string
}

// NewStreamProxy erstellt einen neuen Stream-Proxy
func NewStreamProxy(
	cache *StreamCache,
	imageStore storageTypes.ImageStore,
	remoteURL string,
	credentials Credentials,
	log log.Logger,
) *StreamProxy {
	return &StreamProxy{
		cache:       cache,
		log:         log,
		imageStore:  imageStore,
		remoteURL:   remoteURL,
		credentials: credentials,
	}
}

// ProxyBlob proxied einen Blob von der Remote-Registry zum Client und cached ihn
func (sp *StreamProxy) ProxyBlob(
	ctx context.Context,
	repo string,
	digest godigest.Digest,
	mediaType string,
	responseWriter http.ResponseWriter,
) (int64, error) {
	// Prüfe zunächst im Cache
	if hasBlob, _ := sp.cache.HasBlob(digest); hasBlob {
		sp.log.Info().
			Str("digest", digest.String()).
			Str("repo", repo).
			Msg("serving blob from stream cache")

		reader, size, err := sp.cache.GetBlob(digest)
		if err != nil {
			sp.log.Error().Err(err).Msg("failed to get blob from cache")
		} else {
			defer reader.Close()

			responseWriter.Header().Set("Content-Type", mediaType)
			responseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", size))
			responseWriter.Header().Set("Docker-Content-Digest", digest.String())

			written, err := io.Copy(responseWriter, reader)
			if err == nil {
				// Starte asynchronen Import in persistenten Storage
				go sp.importBlobAsync(ctx, repo, digest)
				return written, nil
			}

			sp.log.Error().Err(err).Msg("failed to copy from cache to client")
		}
	}

	// Blob nicht im Cache, hole von Remote-Registry
	sp.log.Info().
		Str("digest", digest.String()).
		Str("repo", repo).
		Msg("fetching blob from remote registry")

	remoteReader, size, err := sp.fetchBlobFromRemote(ctx, repo, digest)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch blob from remote: %w", err)
	}
	defer remoteReader.Close()

	// Setze Response-Headers
	responseWriter.Header().Set("Content-Type", mediaType)
	responseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	responseWriter.Header().Set("Docker-Content-Digest", digest.String())

	// Streame zum Client und cache gleichzeitig
	written, err := sp.cache.StreamAndCache(ctx, digest, remoteReader, responseWriter)
	if err != nil {
		return written, fmt.Errorf("failed to stream and cache blob: %w", err)
	}

	// Starte asynchronen Import in persistenten Storage
	go sp.importBlobAsync(context.Background(), repo, digest)

	return written, nil
}

// fetchBlobFromRemote holt einen Blob von der Remote-Registry
func (sp *StreamProxy) fetchBlobFromRemote(
	ctx context.Context,
	repo string,
	digest godigest.Digest,
) (io.ReadCloser, int64, error) {
	// Erstelle HTTP-Request zur Remote-Registry
	url := fmt.Sprintf("%s/v2/%s/blobs/%s", sp.remoteURL, repo, digest.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Füge Authentifizierung hinzu, falls vorhanden
	if sp.credentials.Username != "" && sp.credentials.Password != "" {
		req.SetBasicAuth(sp.credentials.Username, sp.credentials.Password)
	}

	// Führe Request aus
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to fetch blob: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp.Body, resp.ContentLength, nil
}

// importBlobAsync importiert einen Blob asynchron vom Cache in den persistenten Storage
func (sp *StreamProxy) importBlobAsync(ctx context.Context, repo string, digest godigest.Digest) {
	sp.log.Info().
		Str("digest", digest.String()).
		Str("repo", repo).
		Msg("starting async import from cache to storage")

	// Warte kurz, damit der Client-Download abgeschlossen ist
	time.Sleep(1 * time.Second)

	err := sp.cache.ImportToStorage(ctx, digest, repo, sp.imageStore)
	if err != nil {
		sp.log.Error().
			Err(err).
			Str("digest", digest.String()).
			Str("repo", repo).
			Msg("failed to import blob from cache to storage")
		return
	}

	sp.log.Info().
		Str("digest", digest.String()).
		Str("repo", repo).
		Msg("blob imported from cache to storage successfully")
}

// CheckBlobInStorage prüft, ob ein Blob im persistenten Storage vorhanden ist
func (sp *StreamProxy) CheckBlobInStorage(repo string, digest godigest.Digest) (bool, int64, error) {
	return sp.imageStore.CheckBlob(repo, digest)
}

// FetchManifestFromRemote lädt ein Manifest direkt von der Remote-Registry
func (sp *StreamProxy) FetchManifestFromRemote(
	ctx context.Context,
	repo string,
	reference string,
) ([]byte, godigest.Digest, string, error) {
	// Erstelle HTTP-Request zur Remote-Registry
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", sp.remoteURL, repo, reference)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to create request: %w", err)
	}

	// Accept Header für OCI/Docker Manifests
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json")

	// Füge Authentifizierung hinzu, falls vorhanden
	if sp.credentials.Username != "" && sp.credentials.Password != "" {
		req.SetBasicAuth(sp.credentials.Username, sp.credentials.Password)
	}

	// Führe Request aus
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Lese Manifest
	manifestBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to read manifest: %w", err)
	}

	// Extrahiere Digest und MediaType
	digestStr := resp.Header.Get("Docker-Content-Digest")
	mediaType := resp.Header.Get("Content-Type")

	var digest godigest.Digest
	if digestStr != "" {
		digest = godigest.Digest(digestStr)
	} else {
		// Berechne Digest selbst
		digest = godigest.FromBytes(manifestBytes)
	}

	sp.log.Info().
		Str("repo", repo).
		Str("reference", reference).
		Str("digest", digest.String()).
		Msg("fetched manifest from remote")

	return manifestBytes, digest, mediaType, nil
}

// StoreManifest speichert ein Manifest im persistenten Storage
func (sp *StreamProxy) StoreManifest(
	ctx context.Context,
	repo string,
	reference string,
	mediaType string,
	manifestBytes []byte,
) error {
	// Initialisiere Repository falls nötig
	if err := sp.imageStore.InitRepo(repo); err != nil {
		sp.log.Warn().Err(err).Str("repo", repo).Msg("failed to init repo, continuing anyway")
	}

	// Speichere Manifest
	_, _, err := sp.imageStore.PutImageManifest(repo, reference, mediaType, manifestBytes)
	if err != nil {
		return fmt.Errorf("failed to store manifest: %w", err)
	}

	sp.log.Info().
		Str("repo", repo).
		Str("reference", reference).
		Msg("stored manifest in local storage")

	return nil
}
