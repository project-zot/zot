package imagestore

// The one-time upgrade of a store from the per-repo blob layout of earlier releases to the
// global blobstore. Names follow the common blobstore refactor (#4137).

import (
	"path"

	godigest "github.com/opencontainers/go-digest"

	storageConstants "zotregistry.dev/zot/v2/pkg/storage/constants"
	"zotregistry.dev/zot/v2/pkg/storage/errclass"
)

// blobCandidate is the repo copy of a digest chosen to become its global blobstore copy.
type blobCandidate struct {
	repoName string
	blobPath string
	size     int64
}

// repoBlobRef is one repo's copy of a digest, recorded in the cache once the digest is promoted.
type repoBlobRef struct {
	digest   godigest.Digest
	repoName string
	blobPath string
}

/*
upgradeToGlobalBlobstore promotes every digest found in a repo into the global blobstore and
makes the blobstore copy its cache origin, unless BlobstoreMigratedMarker shows a previous pass
completed. It runs while the store is created, before anything is served, so it takes no lock.

The marker is written only after a complete pass: when some repo could not be listed, or repos
exist but none holds a blob, it is left out and the next start runs the pass again, which is
safe because every step repeats harmlessly. A storage or cache failure is returned, and the
store is not created. Repo copies on separate inodes, from a time dedupe was off, are linked to
the blobstore copy by the dedupe walk that runs at startup.
*/
func (is *ImageStore) upgradeToGlobalBlobstore() error {
	markerPath := path.Join(is.rootDir, storageConstants.BlobstoreMigratedMarker)

	if _, err := is.storeDriver.Stat(markerPath); err == nil {
		return nil
	} else if !errclass.IsStorageObjectMissing(err) {
		return err
	}

	// unlocked: the store is still being created, and nothing else can use it yet
	repos, err := is.getRepositories()
	if err != nil {
		return err
	}

	if len(repos) == 0 {
		is.writeBlobstoreMigrationMarker(markerPath)

		return nil
	}

	is.log.Info().Int("repoCount", len(repos)).Msg("upgrading storage: populating global blobstore from existing repos")

	candidates := map[godigest.Digest]blobCandidate{}
	repoBlobRefs := []repoBlobRef{}
	skippedRepoListFailures := 0

	for _, repoName := range repos {
		repoBlobs, err := is.GetAllBlobs(repoName)
		if err != nil {
			skippedRepoListFailures++

			is.log.Warn().Err(err).Str("repo", repoName).Msg("failed to list blobs during upgrade, skipping repo")

			continue
		}

		for _, digest := range repoBlobs {
			repoBlobPath := is.BlobPath(repoName, digest)

			// A copy that cannot be checked must not be taken for an empty one: a placeholder
			// could then be promoted, and the copy holding the content replaced by it.
			binfo, err := is.storeDriver.Stat(repoBlobPath)
			if err != nil {
				// listed, then deleted: nothing to promote or record
				if errclass.IsStorageObjectMissing(err) {
					continue
				}

				return err
			}

			candidate, found := candidates[digest]
			if !found {
				candidate = blobCandidate{repoName: repoName, blobPath: repoBlobPath}
			}

			// prefer a copy with content over an empty one
			if binfo.Size() > 0 && candidate.size == 0 {
				candidate = blobCandidate{repoName: repoName, blobPath: repoBlobPath, size: binfo.Size()}
			}

			candidates[digest] = candidate
			repoBlobRefs = append(repoBlobRefs, repoBlobRef{digest: digest, repoName: repoName, blobPath: repoBlobPath})
		}
	}

	markerOnlyDigests := 0

	for digest, candidate := range candidates {
		if lacksContent(digest, candidate.size) {
			markerOnlyDigests++

			is.log.Warn().Str("digest", digest.String()).Str("repo", candidate.repoName).
				Msg("upgrading digest with only empty copies found")
		}

		globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, digest)

		if err := is.promoteBlobCandidate(candidate, digest, globalBlobPath); err != nil {
			return err
		}
	}

	for _, ref := range repoBlobRefs {
		if err := is.cache.PutBlob(ref.digest, ref.blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", ref.digest.String()).Str("repo", ref.repoName).
				Msg("failed to record repo blob during upgrade")

			return err
		}

		globalBlobPath := is.BlobPath(storageConstants.GlobalBlobsRepo, ref.digest)

		if err := is.lifecycle.RemoveMigratedRepoBlob(globalBlobPath, ref.blobPath); err != nil {
			is.log.Error().Err(err).Str("digest", ref.digest.String()).Str("repo", ref.repoName).
				Str("repoBlobPath", ref.blobPath).Msg("failed to remove migrated repo blob")

			return err
		}
	}

	return is.completeBlobstoreUpgrade(markerPath, skippedRepoListFailures, len(candidates), markerOnlyDigests)
}

// promoteBlobCandidate makes the global blobstore copy of digest from candidate and records it
// as the digest's cache origin, replacing a repo copy recorded as origin by an earlier release.
func (is *ImageStore) promoteBlobCandidate(candidate blobCandidate, digest godigest.Digest,
	globalBlobPath string,
) error {
	if lacksContent(digest, candidate.size) {
		// Resume safety: a pass that stopped part way may have promoted a copy with content
		// already, which an empty copy must not replace.
		binfo, err := is.storeDriver.Stat(globalBlobPath)
		if err == nil && binfo.Size() > 0 {
			is.log.Info().Str("digest", digest.String()).Str("repo", candidate.repoName).
				Msg("keeping the global blobstore copy, its repo copies are empty")

			return is.cache.SetOrigin(digest, globalBlobPath)
		}

		if err != nil && !errclass.IsStorageObjectMissing(err) {
			return err
		}
	}

	if err := is.storeDriver.EnsureDir(path.Dir(globalBlobPath)); err != nil {
		is.log.Error().Err(err).Str("dir", path.Dir(globalBlobPath)).Msg("failed to create algorithm dir")

		return err
	}

	if err := is.lifecycle.PromoteCandidate(candidate.blobPath, globalBlobPath); err != nil {
		is.log.Error().Err(err).Str("src", candidate.blobPath).Str("dst", globalBlobPath).
			Msg("failed to promote blob to global blobstore")

		return err
	}

	// PutBlob never replaces an origin, and an earlier release recorded a repo copy as one
	if err := is.cache.SetOrigin(digest, globalBlobPath); err != nil {
		is.log.Error().Err(err).Str("digest", digest.String()).
			Msg("failed to record the global blobstore copy as origin during upgrade")

		return err
	}

	is.log.Info().Str("digest", digest.String()).Str("repo", candidate.repoName).
		Msg("promoted blob to global blobstore")

	return nil
}

// completeBlobstoreUpgrade writes the migration marker once a pass has covered every repo and
// promoted at least one digest; otherwise the next start runs the pass again.
func (is *ImageStore) completeBlobstoreUpgrade(markerPath string, skippedRepoListFailures int,
	promotedDigests int, markerOnlyDigests int,
) error {
	is.log.Info().Int("blobCount", promotedDigests).Int("markerOnlyDigestCount", markerOnlyDigests).
		Msg("global blobstore upgrade completed")

	if skippedRepoListFailures > 0 {
		is.log.Warn().Int("skippedRepoCount", skippedRepoListFailures).
			Msg("blobstore upgrade incomplete: migration marker not written because some repos were skipped")

		return nil
	}

	if promotedDigests == 0 {
		is.log.Warn().Msg("blobstore upgrade incomplete: migration marker not written because no digests were promoted")

		return nil
	}

	is.writeBlobstoreMigrationMarker(markerPath)

	return nil
}

// writeBlobstoreMigrationMarker records a completed upgrade at the store root, so later starts
// skip the scan. Failing to write it only means the next start scans again.
func (is *ImageStore) writeBlobstoreMigrationMarker(markerPath string) {
	if _, err := is.storeDriver.WriteFile(markerPath, []byte("1")); err != nil {
		is.log.Warn().Err(err).Msg("failed to write blobstore migration marker")
	}
}
