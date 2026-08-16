package imagestore

import (
	"path"
	"sync"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	common "zotregistry.dev/zot/v2/pkg/storage/common"
	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// repoGraphRefsTTL bounds how long a listing of repositories, and each repository's
// index.json, is trusted before being read again.
const repoGraphRefsTTL = time.Minute

// repoGraphRefs remembers, per repository, the set of digests reachable from its index.json
// manifest graph. It backs the global-blob reclaim decision, where the blob-ref index alone
// is not proof that nobody else owns a digest: a registry recovered from a lost or fresh
// local root (see resolveGlobalBlobFallback) has repositories whose ownership records are
// only restored lazily, one blob at a time as it is read, so until then their manifests are
// the only evidence that they still need the shared global object.
//
// Walking every repository's graph for every reclaimed blob would make GC quadratic, so a
// repository's set is kept and reused for as long as its index.json is byte-identical; the
// index is re-read (not re-walked) once per ttl. A stale entry can only err towards a
// repository still referencing a digest it has since dropped, which keeps a global blob that
// could have been reclaimed - never the reverse: a repository can only gain a reference
// through a push, and a push records its blob refs in the index that is consulted first.
type repoGraphRefs struct {
	mu       sync.Mutex
	ttl      time.Duration
	listedAt time.Time
	repos    []string
	entries  map[string]*repoGraphEntry
	// freshAfter, when set, makes anything read earlier count as expired whatever its age;
	// see refresh.
	freshAfter time.Time
}

// refresh makes the next lookup re-list repositories and re-read every index.json (walking
// only the graphs that changed). The reclaim sweep calls it once per pass: the ttl lets a
// manifest deleted a moment ago still count as a reference, which is harmless when deciding
// whether to mark a payload but would keep a sweep from reclaiming what GC just released.
func (graphs *repoGraphRefs) refresh() {
	graphs.mu.Lock()
	defer graphs.mu.Unlock()

	graphs.freshAfter = time.Now()
}

// expired reports whether something read at readAt has to be read again.
func (graphs *repoGraphRefs) expired(readAt, now time.Time) bool {
	return now.Sub(readAt) >= graphs.ttl || readAt.Before(graphs.freshAfter)
}

type repoGraphEntry struct {
	indexDigest godigest.Digest
	checkedAt   time.Time
	referenced  map[godigest.Digest]struct{}
}

// isDigestInOtherRepoGraphs reports whether any repository other than repo (and the global
// blobstore) reaches digest from its index.json. Any failure to list repositories or read a
// graph is returned as an error so the caller can fail closed.
func (is *ImageStore) isDigestInOtherRepoGraphs(repo string, digest godigest.Digest) (bool, error) {
	graphs := &is.repoGraphs

	graphs.mu.Lock()
	defer graphs.mu.Unlock()

	now := time.Now()

	if graphs.repos == nil || graphs.expired(graphs.listedAt, now) {
		repos, err := is.GetRepositories()
		if err != nil {
			return false, err
		}

		entries := make(map[string]*repoGraphEntry, len(repos))

		for _, name := range repos {
			if entry, ok := graphs.entries[name]; ok {
				entries[name] = entry
			}
		}

		graphs.repos, graphs.entries, graphs.listedAt = repos, entries, now
	}

	for _, other := range graphs.repos {
		if other == repo || other == storageConstants.GlobalBlobsRepo {
			continue
		}

		entry := graphs.entries[other]
		if entry == nil || graphs.expired(entry.checkedAt, now) {
			var err error

			entry, err = is.loadRepoGraphEntry(other, entry, now)
			if err != nil {
				return false, err
			}

			if entry == nil {
				delete(graphs.entries, other)

				continue
			}

			graphs.entries[other] = entry
		}

		if _, ok := entry.referenced[digest]; ok {
			return true, nil
		}
	}

	return false, nil
}

// loadRepoGraphEntry re-reads repo's index.json and walks its manifest graph only when the
// index differs from the one previous was built from. A repository whose index.json has gone
// (deleted since it was listed) yields a nil entry.
func (is *ImageStore) loadRepoGraphEntry(repo string, previous *repoGraphEntry, now time.Time,
) (*repoGraphEntry, error) {
	// Read through the driver rather than GetIndexContent: a repository removed since the
	// listing was taken is expected here and not worth an error log.
	buf, err := is.storeDriver.ReadFile(path.Join(is.rootDir, repo, ispec.ImageIndexFile))
	if err != nil {
		if errclass.IsStorageObjectMissing(err) {
			return nil, nil //nolint:nilnil // an absent repository references nothing
		}

		return nil, err
	}

	indexDigest := godigest.FromBytes(buf)
	if previous != nil && previous.indexDigest == indexDigest {
		previous.checkedAt = now

		return previous, nil
	}

	// The read view resolves manifests from the global blobstore too, which is where a
	// migrated repository's own manifests-as-blobs may live.
	referenced, err := common.GetReferencedBlobs(globalBlobstoreReadView{is}, repo, is.log)
	if err != nil {
		return nil, err
	}

	return &repoGraphEntry{indexDigest: indexDigest, checkedAt: now, referenced: referenced}, nil
}
