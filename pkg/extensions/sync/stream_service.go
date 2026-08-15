//go:build sync

package sync

import (
	"context"

	"github.com/regclient/regclient/types/manifest"

	zerr "zotregistry.dev/zot/v2/errors"
)

// This file contains the streaming-sync specific behavior of BaseService.

// IsStreamingForRepo returns whether streaming is enabled for the given local repo on this service.
// Streaming is enabled if the registry config has Stream set to true and the repo matches the content config.
func (service *BaseService) IsStreamingForRepo(repo string) bool {
	if !service.config.IsStreamEnabled() {
		return false
	}

	// If no content filter is configured, all repos match.
	if len(service.config.Content) == 0 {
		return true
	}

	return service.contentManager.GetContentByLocalRepo(repo) != nil
}

// FetchManifest on demand.
func (service *BaseService) FetchManifest(ctx context.Context, repo, reference string) (
	manifest.Manifest, []manifest.Manifest, error,
) {
	remoteRepo := repo

	remoteURL := service.remote.GetHostName()

	if len(service.config.Content) > 0 {
		remoteRepo = service.contentManager.GetRepoSource(repo)
		if remoteRepo == "" {
			service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
				Msg("will not sync image, filtered out by content")

			return nil, nil, zerr.ErrSyncImageFilteredOut
		}
	}

	service.log.Info().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
		Msg("sync: fetching manifest")

	if err := service.refreshRegistryTemporaryCredentials(); err != nil {
		service.log.Error().Err(err).Msg("failed to refresh credentials")
	}

	artifactRef, err := service.remote.GetImageReference(remoteRepo, reference)
	if err != nil {
		return nil, nil, err
	}

	fetchedManifest, err := service.rc.ManifestGet(ctx, artifactRef)
	if err != nil {
		return nil, nil, err
	}

	var childManifests []manifest.Manifest

	// For a manifest list, each individual manifest inside it also needs
	// to be downloaded.
	if fetchedManifest.IsList() {
		indexer, ok := fetchedManifest.(manifest.Indexer)
		if !ok {
			service.log.Error().Str("remote", remoteURL).Str("repo", repo).Str("reference", reference).
				Msg("failed to cast manifest to index")

			return nil, nil, zerr.ErrBadManifest
		}

		childDescriptors, err := indexer.GetManifestList()
		if err != nil {
			service.log.Error().Err(err).Str("remote", remoteURL).Str("repo", repo).
				Str("reference", reference).Msg("failed to get manifest list")

			return nil, nil, zerr.ErrBadManifest
		}

		for _, childDesc := range childDescriptors {
			childRef, err := service.remote.GetImageReference(remoteRepo, childDesc.Digest.String())
			if err != nil {
				service.log.Error().Err(err).Str("remote", remoteURL).Str("repo", repo).
					Str("reference", reference).Str("childDigest", childDesc.Digest.String()).
					Msg("failed to get image reference for child manifest")

				return nil, nil, err
			}

			childManifest, err := service.rc.ManifestGet(ctx, childRef)
			if err != nil {
				service.log.Error().Err(err).Str("remote", remoteURL).Str("repo", repo).
					Str("reference", reference).Str("childDigest", childDesc.Digest.String()).
					Msg("failed to fetch child manifest")

				return nil, nil, err
			}

			childManifests = append(childManifests, childManifest)
		}
	}

	return fetchedManifest, childManifests, nil
}
