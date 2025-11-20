package streamcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"

	"zotregistry.dev/zot/v2/pkg/log"
	storageTypes "zotregistry.dev/zot/v2/pkg/storage/types"
)

// StreamCache manages a temporary cache for streamed blobs
type StreamCache struct {
	cacheDir  string
	maxSize   int64
	log       log.Logger
	cacheLock sync.RWMutex
	// Map from digest to CacheEntry
	entries map[godigest.Digest]*CacheEntry
	// Map from digest to active downloads
	activeDownloads map[godigest.Digest]*ActiveDownload
	// Cleanup ticker
	cleanupTicker *time.Ticker
	cleanupStop   chan struct{}
}

// CacheEntry represents a cache entry
type CacheEntry struct {
	Digest      godigest.Digest
	FilePath    string
	Size        int64
	CreatedAt   time.Time
	Imported    bool // Has been imported to persistent storage
	ImportError error
	mu          sync.RWMutex
}

// ActiveDownload represents an ongoing download
type ActiveDownload struct {
	Digest   godigest.Digest
	Progress int64
	Error    error
	Done     chan struct{}
	mu       sync.RWMutex
}

// NewStreamCache creates a new stream cache
func NewStreamCache(cacheDir string, maxSize int64, log log.Logger) (*StreamCache, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	sc := &StreamCache{
		cacheDir:        cacheDir,
		maxSize:         maxSize,
		log:             log,
		entries:         make(map[godigest.Digest]*CacheEntry),
		activeDownloads: make(map[godigest.Digest]*ActiveDownload),
		cleanupStop:     make(chan struct{}),
	}

	// Load existing cache entries on startup
	if err := sc.loadExistingEntries(); err != nil {
		log.Warn().Err(err).Msg("failed to load existing cache entries")
	}

	// Start periodic cleanup (every 5 minutes)
	sc.cleanupTicker = time.NewTicker(5 * time.Minute)
	go sc.periodicCleanup()

	return sc, nil
}

// loadExistingEntries loads existing cache entries from the directory
func (sc *StreamCache) loadExistingEntries() error {
	entries, err := os.ReadDir(sc.cacheDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(sc.cacheDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			sc.log.Warn().Err(err).Str("file", filePath).Msg("failed to get file info")
			continue
		}

		// Try to extract digest from filename
		digest := godigest.Digest(entry.Name())
		if err := digest.Validate(); err != nil {
			sc.log.Warn().Str("file", entry.Name()).Msg("invalid digest in filename, skipping")
			continue
		}

		sc.entries[digest] = &CacheEntry{
			Digest:    digest,
			FilePath:  filePath,
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
			Imported:  false,
		}

		sc.log.Debug().Str("digest", digest.String()).Int64("size", info.Size()).
			Msg("loaded existing cache entry")
	}

	return nil
}

// HasBlob checks if a blob is already present in the cache
func (sc *StreamCache) HasBlob(digest godigest.Digest) (bool, int64) {
	sc.cacheLock.RLock()
	defer sc.cacheLock.RUnlock()

	if entry, exists := sc.entries[digest]; exists {
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		return true, entry.Size
	}

	return false, 0
}

// GetBlob returns a reader for a blob from the cache
func (sc *StreamCache) GetBlob(digest godigest.Digest) (io.ReadCloser, int64, error) {
	sc.cacheLock.RLock()
	entry, exists := sc.entries[digest]
	sc.cacheLock.RUnlock()

	if !exists {
		return nil, 0, fmt.Errorf("blob not found in cache: %s", digest)
	}

	entry.mu.RLock()
	filePath := entry.FilePath
	size := entry.Size
	entry.mu.RUnlock()

	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open cached blob: %w", err)
	}

	return file, size, nil
}

// TeeReader creates a multi-writer that streams to client and caches simultaneously
type TeeReader struct {
	source      io.ReadCloser
	destination *os.File
	client      io.Writer
	digest      godigest.Digest
	cache       *StreamCache
	written     int64
	hasher      godigest.Digester
	mu          sync.Mutex
}

// Read implements io.Reader and writes simultaneously to cache and client
func (tr *TeeReader) Read(p []byte) (n int, err error) {
	n, err = tr.source.Read(p)
	if n > 0 {
		// Write to client
		if _, writeErr := tr.client.Write(p[:n]); writeErr != nil {
			return n, writeErr
		}

		// Write to cache file
		if _, writeErr := tr.destination.Write(p[:n]); writeErr != nil {
			tr.cache.log.Error().Err(writeErr).Msg("failed to write to cache")
		}

		// Update hasher
		tr.hasher.Hash().Write(p[:n])

		tr.mu.Lock()
		tr.written += int64(n)
		tr.mu.Unlock()
	}

	return n, err
}

// Close closes the TeeReader and finalizes the cache entry
func (tr *TeeReader) Close() error {
	sourceErr := tr.source.Close()
	destErr := tr.destination.Close()

	// Verify digest
	calculatedDigest := tr.hasher.Digest()
	if calculatedDigest != tr.digest {
		// Digest mismatch, delete cache file
		tr.cache.log.Error().
			Str("expected", tr.digest.String()).
			Str("calculated", calculatedDigest.String()).
			Msg("digest mismatch, removing cache entry")
		os.Remove(tr.destination.Name())
		tr.cache.removeCacheEntry(tr.digest)
		return fmt.Errorf("digest mismatch: expected %s, got %s", tr.digest, calculatedDigest)
	}

	if sourceErr != nil {
		return sourceErr
	}

	return destErr
}

// StreamAndCache streams a blob to the client and caches it simultaneously
func (sc *StreamCache) StreamAndCache(
	_ context.Context,
	digest godigest.Digest,
	source io.ReadCloser,
	client io.Writer,
) (int64, error) {
	sc.cacheLock.Lock()

	// Check if a download is already in progress
	if activeDownload, exists := sc.activeDownloads[digest]; exists {
		sc.cacheLock.Unlock()
		// Wait for the ongoing download
		<-activeDownload.Done
		activeDownload.mu.RLock()
		err := activeDownload.Error
		activeDownload.mu.RUnlock()
		if err != nil {
			return 0, err
		}
		// Download completed, serve from cache
		return sc.serveFromCache(digest, client)
	}

	// Create new ActiveDownload
	activeDownload := &ActiveDownload{
		Digest: digest,
		Done:   make(chan struct{}),
	}
	sc.activeDownloads[digest] = activeDownload
	sc.cacheLock.Unlock()

	// Cleanup after completion
	defer func() {
		close(activeDownload.Done)
		sc.cacheLock.Lock()
		delete(sc.activeDownloads, digest)
		sc.cacheLock.Unlock()
	}()

	// Create cache file
	cacheFilePath := sc.getCacheFilePath(digest)
	cacheFile, err := os.Create(cacheFilePath)
	if err != nil {
		activeDownload.mu.Lock()
		activeDownload.Error = fmt.Errorf("failed to create cache file: %w", err)
		activeDownload.mu.Unlock()
		return 0, activeDownload.Error
	}

	// Create TeeReader for simultaneous streaming and caching
	teeReader := &TeeReader{
		source:      source,
		destination: cacheFile,
		client:      client,
		digest:      digest,
		cache:       sc,
		hasher:      digest.Algorithm().Digester(),
	}

	// Copy data
	written, err := io.Copy(io.Discard, teeReader)
	closeErr := teeReader.Close()

	if err != nil {
		activeDownload.mu.Lock()
		activeDownload.Error = err
		activeDownload.mu.Unlock()
		os.Remove(cacheFilePath)
		return written, err
	}

	if closeErr != nil {
		activeDownload.mu.Lock()
		activeDownload.Error = closeErr
		activeDownload.mu.Unlock()
		os.Remove(cacheFilePath)
		return written, closeErr
	}

	// Create cache entry
	entry := &CacheEntry{
		Digest:    digest,
		FilePath:  cacheFilePath,
		Size:      written,
		CreatedAt: time.Now(),
		Imported:  false,
	}

	sc.cacheLock.Lock()
	sc.entries[digest] = entry
	sc.cacheLock.Unlock()

	sc.log.Info().
		Str("digest", digest.String()).
		Int64("size", written).
		Msg("blob cached successfully")

	return written, nil
}

// serveFromCache serves a blob from the cache
func (sc *StreamCache) serveFromCache(digest godigest.Digest, client io.Writer) (int64, error) {
	reader, _, err := sc.GetBlob(digest)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	written, err := io.Copy(client, reader)
	return written, err
}

// getCacheFilePath generates the file path for a cache entry
func (sc *StreamCache) getCacheFilePath(digest godigest.Digest) string {
	return filepath.Join(sc.cacheDir, digest.String())
}

// removeCacheEntry removes a cache entry
func (sc *StreamCache) removeCacheEntry(digest godigest.Digest) {
	sc.cacheLock.Lock()
	defer sc.cacheLock.Unlock()

	if entry, exists := sc.entries[digest]; exists {
		os.Remove(entry.FilePath)
		delete(sc.entries, digest)
		sc.log.Debug().Str("digest", digest.String()).Msg("cache entry removed")
	}
}

// ImportToStorage imports a blob from cache to persistent storage
func (sc *StreamCache) ImportToStorage(
	_ context.Context,
	digest godigest.Digest,
	repo string,
	imageStore storageTypes.ImageStore,
) error {
	sc.cacheLock.RLock()
	entry, exists := sc.entries[digest]
	sc.cacheLock.RUnlock()

	if !exists {
		return fmt.Errorf("cache entry not found: %s", digest)
	}

	entry.mu.Lock()
	if entry.Imported {
		entry.mu.Unlock()
		sc.log.Debug().Str("digest", digest.String()).Msg("blob already imported")
		return nil
	}
	entry.mu.Unlock()

	// Open cache file
	file, err := os.Open(entry.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open cache file: %w", err)
	}
	defer file.Close()

	// Import to storage
	sc.log.Info().
		Str("digest", digest.String()).
		Str("repo", repo).
		Msg("importing blob from cache to storage")

	_, _, err = imageStore.FullBlobUpload(repo, file, digest)
	if err != nil {
		entry.mu.Lock()
		entry.ImportError = err
		entry.mu.Unlock()
		return fmt.Errorf("failed to import blob to storage: %w", err)
	}

	// Mark as imported
	entry.mu.Lock()
	entry.Imported = true
	entry.mu.Unlock()

	sc.log.Info().
		Str("digest", digest.String()).
		Str("repo", repo).
		Msg("blob imported successfully")

	// Cleanup: Remove cache file after successful import
	go func() {
		time.Sleep(5 * time.Second) // Wait briefly for potential parallel accesses
		sc.removeCacheEntry(digest)
		sc.log.Debug().Str("digest", digest.String()).Msg("cleaned up cache entry after import")
	}()

	return nil
}

// CleanupImportedEntries removes successfully imported cache entries
func (sc *StreamCache) CleanupImportedEntries() {
	sc.cacheLock.Lock()
	defer sc.cacheLock.Unlock()

	for digest, entry := range sc.entries {
		entry.mu.RLock()
		imported := entry.Imported
		filePath := entry.FilePath
		entry.mu.RUnlock()

		if imported {
			os.Remove(filePath)
			delete(sc.entries, digest)
			sc.log.Debug().Str("digest", digest.String()).Msg("cleaned up imported cache entry")
		}
	}
}

// GetPendingImports returns a list of blobs that still need to be imported
func (sc *StreamCache) GetPendingImports() []godigest.Digest {
	sc.cacheLock.RLock()
	defer sc.cacheLock.RUnlock()

	var pending []godigest.Digest
	for digest, entry := range sc.entries {
		entry.mu.RLock()
		imported := entry.Imported
		entry.mu.RUnlock()

		if !imported {
			pending = append(pending, digest)
		}
	}

	return pending
}

// generateCacheKey generates a unique cache key
func generateCacheKey(repo string, digest godigest.Digest) string {
	h := sha256.New()
	h.Write([]byte(repo))
	h.Write([]byte(digest.String()))
	return hex.EncodeToString(h.Sum(nil))
}

// periodicCleanup runs cleanup tasks regularly
func (sc *StreamCache) periodicCleanup() {
	for {
		select {
		case <-sc.cleanupTicker.C:
			sc.log.Debug().Msg("running periodic cache cleanup")

			// Remove imported entries
			sc.CleanupImportedEntries()

			// Remove old entries (older than 24h)
			sc.cleanupOldEntries(24 * time.Hour)

			// Check cache size
			sc.enforceSizeLimit()

		case <-sc.cleanupStop:
			sc.cleanupTicker.Stop()
			return
		}
	}
}

// Stop stops the cache and periodic cleanup
func (sc *StreamCache) Stop() {
	close(sc.cleanupStop)
}

// cleanupOldEntries removes cache entries older than the specified duration
func (sc *StreamCache) cleanupOldEntries(maxAge time.Duration) {
	sc.cacheLock.Lock()
	defer sc.cacheLock.Unlock()

	now := time.Now()
	for digest, entry := range sc.entries {
		entry.mu.RLock()
		age := now.Sub(entry.CreatedAt)
		imported := entry.Imported
		filePath := entry.FilePath
		entry.mu.RUnlock()

		if age > maxAge || imported {
			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				sc.log.Warn().Err(err).Str("digest", digest.String()).Msg("failed to remove old cache file")
			}
			delete(sc.entries, digest)
			sc.log.Debug().Str("digest", digest.String()).Dur("age", age).Msg("removed old cache entry")
		}
	}
}

// enforceSizeLimit ensures the cache does not exceed maxSize
func (sc *StreamCache) enforceSizeLimit() {
	if sc.maxSize <= 0 {
		return // No limit
	}

	sc.cacheLock.Lock()
	defer sc.cacheLock.Unlock()

	// Calculate current cache size
	var totalSize int64
	type entryWithAge struct {
		digest godigest.Digest
		age    time.Duration
		size   int64
	}
	var entriesWithAge []entryWithAge

	now := time.Now()
	for digest, entry := range sc.entries {
		entry.mu.RLock()
		size := entry.Size
		age := now.Sub(entry.CreatedAt)
		imported := entry.Imported
		entry.mu.RUnlock()

		if imported {
			continue // Skip already imported entries
		}

		totalSize += size
		entriesWithAge = append(entriesWithAge, entryWithAge{
			digest: digest,
			age:    age,
			size:   size,
		})
	}

	if totalSize <= sc.maxSize {
		return // Under limit
	}

	// Sort by age (oldest first)
	sort.Slice(entriesWithAge, func(i, j int) bool {
		return entriesWithAge[i].age > entriesWithAge[j].age
	})

	// Remove oldest entries until under limit
	for _, e := range entriesWithAge {
		if totalSize <= sc.maxSize {
			break
		}

		entry := sc.entries[e.digest]
		if entry != nil {
			entry.mu.RLock()
			filePath := entry.FilePath
			entry.mu.RUnlock()

			if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
				sc.log.Warn().Err(err).Str("digest", e.digest.String()).Msg("failed to remove cache file")
			}
			delete(sc.entries, e.digest)
			totalSize -= e.size
			sc.log.Info().
				Str("digest", e.digest.String()).
				Int64("size", e.size).
				Int64("totalSize", totalSize).
				Msg("removed cache entry to enforce size limit")
		}
	}
}

// GetCacheStats returns statistics about the cache
func (sc *StreamCache) GetCacheStats() map[string]interface{} {
	sc.cacheLock.RLock()
	defer sc.cacheLock.RUnlock()

	var totalSize int64
	var importedCount, pendingCount int

	for _, entry := range sc.entries {
		entry.mu.RLock()
		totalSize += entry.Size
		if entry.Imported {
			importedCount++
		} else {
			pendingCount++
		}
		entry.mu.RUnlock()
	}

	return map[string]interface{}{
		"totalEntries":   len(sc.entries),
		"totalSize":      totalSize,
		"importedCount":  importedCount,
		"pendingCount":   pendingCount,
		"maxSize":        sc.maxSize,
		"utilizationPct": float64(totalSize) / float64(sc.maxSize) * 100,
	}
}
