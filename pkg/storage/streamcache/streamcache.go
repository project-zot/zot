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

// StreamCache verwaltet einen temporären Cache für gestreamte Blobs
type StreamCache struct {
	cacheDir  string
	maxSize   int64
	log       log.Logger
	cacheLock sync.RWMutex
	// Map von Digest zu CacheEntry
	entries map[godigest.Digest]*CacheEntry
	// Map von Digest zu laufenden Downloads
	activeDownloads map[godigest.Digest]*ActiveDownload
	// Cleanup ticker
	cleanupTicker *time.Ticker
	cleanupStop   chan struct{}
}

// CacheEntry repräsentiert einen Cache-Eintrag
type CacheEntry struct {
	Digest      godigest.Digest
	FilePath    string
	Size        int64
	CreatedAt   time.Time
	Imported    bool // Wurde bereits in persistenten Storage importiert
	ImportError error
	mu          sync.RWMutex
}

// ActiveDownload repräsentiert einen laufenden Download
type ActiveDownload struct {
	Digest   godigest.Digest
	Progress int64
	Error    error
	Done     chan struct{}
	mu       sync.RWMutex
}

// NewStreamCache erstellt einen neuen Stream-Cache
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

	// Lade existierende Cache-Einträge beim Start
	if err := sc.loadExistingEntries(); err != nil {
		log.Warn().Err(err).Msg("failed to load existing cache entries")
	}

	// Starte periodisches Cleanup (alle 5 Minuten)
	sc.cleanupTicker = time.NewTicker(5 * time.Minute)
	go sc.periodicCleanup()

	return sc, nil
}

// loadExistingEntries lädt existierende Cache-Einträge aus dem Verzeichnis
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

		// Versuche Digest aus Dateinamen zu extrahieren
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

// HasBlob prüft, ob ein Blob bereits im Cache vorhanden ist
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

// GetBlob gibt einen Reader für einen Blob aus dem Cache zurück
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

// TeeReader erstellt einen Multi-Writer, der gleichzeitig an den Client streamt und cached
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

// Read implementiert io.Reader und schreibt gleichzeitig in Cache und zum Client
func (tr *TeeReader) Read(p []byte) (n int, err error) {
	n, err = tr.source.Read(p)
	if n > 0 {
		// Schreibe zum Client
		if _, writeErr := tr.client.Write(p[:n]); writeErr != nil {
			return n, writeErr
		}

		// Schreibe in Cache-Datei
		if _, writeErr := tr.destination.Write(p[:n]); writeErr != nil {
			tr.cache.log.Error().Err(writeErr).Msg("failed to write to cache")
		}

		// Update Hasher
		tr.hasher.Hash().Write(p[:n])

		tr.mu.Lock()
		tr.written += int64(n)
		tr.mu.Unlock()
	}

	return n, err
}

// Close schließt den TeeReader und finalisiert den Cache-Eintrag
func (tr *TeeReader) Close() error {
	sourceErr := tr.source.Close()
	destErr := tr.destination.Close()

	// Verifiziere Digest
	calculatedDigest := tr.hasher.Digest()
	if calculatedDigest != tr.digest {
		// Digest stimmt nicht überein, lösche Cache-Datei
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

// StreamAndCache streamt einen Blob zum Client und cached ihn gleichzeitig
func (sc *StreamCache) StreamAndCache(
	_ context.Context,
	digest godigest.Digest,
	source io.ReadCloser,
	client io.Writer,
) (int64, error) {
	sc.cacheLock.Lock()

	// Prüfe, ob bereits ein Download läuft
	if activeDownload, exists := sc.activeDownloads[digest]; exists {
		sc.cacheLock.Unlock()
		// Warte auf den laufenden Download
		<-activeDownload.Done
		activeDownload.mu.RLock()
		err := activeDownload.Error
		activeDownload.mu.RUnlock()
		if err != nil {
			return 0, err
		}
		// Download abgeschlossen, serviere aus Cache
		return sc.serveFromCache(digest, client)
	}

	// Erstelle neuen ActiveDownload
	activeDownload := &ActiveDownload{
		Digest: digest,
		Done:   make(chan struct{}),
	}
	sc.activeDownloads[digest] = activeDownload
	sc.cacheLock.Unlock()

	// Cleanup nach Abschluss
	defer func() {
		close(activeDownload.Done)
		sc.cacheLock.Lock()
		delete(sc.activeDownloads, digest)
		sc.cacheLock.Unlock()
	}()

	// Erstelle Cache-Datei
	cacheFilePath := sc.getCacheFilePath(digest)
	cacheFile, err := os.Create(cacheFilePath)
	if err != nil {
		activeDownload.mu.Lock()
		activeDownload.Error = fmt.Errorf("failed to create cache file: %w", err)
		activeDownload.mu.Unlock()
		return 0, activeDownload.Error
	}

	// Erstelle TeeReader für gleichzeitiges Streaming und Caching
	teeReader := &TeeReader{
		source:      source,
		destination: cacheFile,
		client:      client,
		digest:      digest,
		cache:       sc,
		hasher:      digest.Algorithm().Digester(),
	}

	// Kopiere Daten
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

	// Erstelle Cache-Entry
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

// serveFromCache serviert einen Blob aus dem Cache
func (sc *StreamCache) serveFromCache(digest godigest.Digest, client io.Writer) (int64, error) {
	reader, _, err := sc.GetBlob(digest)
	if err != nil {
		return 0, err
	}
	defer reader.Close()

	written, err := io.Copy(client, reader)
	return written, err
}

// getCacheFilePath generiert den Dateipfad für einen Cache-Eintrag
func (sc *StreamCache) getCacheFilePath(digest godigest.Digest) string {
	return filepath.Join(sc.cacheDir, digest.String())
}

// removeCacheEntry entfernt einen Cache-Eintrag
func (sc *StreamCache) removeCacheEntry(digest godigest.Digest) {
	sc.cacheLock.Lock()
	defer sc.cacheLock.Unlock()

	if entry, exists := sc.entries[digest]; exists {
		os.Remove(entry.FilePath)
		delete(sc.entries, digest)
		sc.log.Debug().Str("digest", digest.String()).Msg("cache entry removed")
	}
}

// ImportToStorage importiert einen Blob aus dem Cache in den persistenten Storage
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

	// Öffne Cache-Datei
	file, err := os.Open(entry.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open cache file: %w", err)
	}
	defer file.Close()

	// Importiere in Storage
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

	// Markiere als importiert
	entry.mu.Lock()
	entry.Imported = true
	entry.mu.Unlock()

	sc.log.Info().
		Str("digest", digest.String()).
		Str("repo", repo).
		Msg("blob imported successfully")

	// Cleanup: Entferne Cache-Datei nach erfolgreichem Import
	go func() {
		time.Sleep(5 * time.Second) // Warte kurz für mögliche parallele Zugriffe
		sc.removeCacheEntry(digest)
		sc.log.Debug().Str("digest", digest.String()).Msg("cleaned up cache entry after import")
	}()

	return nil
}

// CleanupImportedEntries entfernt erfolgreich importierte Cache-Einträge
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

// GetPendingImports gibt eine Liste von Blobs zurück, die noch importiert werden müssen
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

// generateCacheKey generiert einen eindeutigen Cache-Key
func generateCacheKey(repo string, digest godigest.Digest) string {
	h := sha256.New()
	h.Write([]byte(repo))
	h.Write([]byte(digest.String()))
	return hex.EncodeToString(h.Sum(nil))
}

// periodicCleanup führt regelmäßig Cleanup-Aufgaben aus
func (sc *StreamCache) periodicCleanup() {
	for {
		select {
		case <-sc.cleanupTicker.C:
			sc.log.Debug().Msg("running periodic cache cleanup")

			// Entferne importierte Einträge
			sc.CleanupImportedEntries()

			// Entferne alte Einträge (älter als 24h)
			sc.cleanupOldEntries(24 * time.Hour)

			// Prüfe Cache-Größe
			sc.enforceSizeLimit()

		case <-sc.cleanupStop:
			sc.cleanupTicker.Stop()
			return
		}
	}
}

// Stop stoppt den Cache und das periodische Cleanup
func (sc *StreamCache) Stop() {
	close(sc.cleanupStop)
}

// cleanupOldEntries entfernt Cache-Einträge älter als die angegebene Duration
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

// enforceSizeLimit stellt sicher, dass der Cache nicht größer als maxSize wird
func (sc *StreamCache) enforceSizeLimit() {
	if sc.maxSize <= 0 {
		return // Kein Limit
	}

	sc.cacheLock.Lock()
	defer sc.cacheLock.Unlock()

	// Berechne aktuelle Cache-Größe
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
			continue // Überspringe bereits importierte
		}

		totalSize += size
		entriesWithAge = append(entriesWithAge, entryWithAge{
			digest: digest,
			age:    age,
			size:   size,
		})
	}

	if totalSize <= sc.maxSize {
		return // Unter Limit
	}

	// Sortiere nach Alter (älteste zuerst)
	sort.Slice(entriesWithAge, func(i, j int) bool {
		return entriesWithAge[i].age > entriesWithAge[j].age
	})

	// Entferne älteste Einträge bis unter Limit
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

// GetCacheStats gibt Statistiken über den Cache zurück
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
