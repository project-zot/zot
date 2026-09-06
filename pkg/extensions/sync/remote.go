//go:build sync

package sync

import (
	"context"
	"errors"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/scheme"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/log"
)

type RemoteRegistry struct {
	client      *regclient.RegClient
	hosts       []config.Host
	primaryHost string
	log         log.Logger
}

func NewRemoteRegistry(client *regclient.RegClient, hosts []config.Host, logger log.Logger) Remote {
	registry := &RemoteRegistry{}

	registry.log = logger
	registry.hosts = hosts
	registry.client = client
	//
	registry.primaryHost = hosts[0].Hostname

	return registry
}

func (registry *RemoteRegistry) GetHostName() string {
	return registry.primaryHost
}

func (registry *RemoteRegistry) GetRepositories(ctx context.Context) ([]string, error) {
	var err error

	var repoList []string

	for _, host := range registry.hosts {
		repoList, err = registry.getRepoList(ctx, host.Hostname)
		if err != nil {
			registry.log.Error().Err(err).Str("remote", host.Name).Msg("failed to list repositories in remote registry")

			continue
		}

		registry.log.Debug().Strs("repoList", repoList).Str("remote", host.Name).Msg("listed repositories in remote registry")

		return repoList, nil
	}

	return []string{}, err
}

func (registry *RemoteRegistry) getRepoList(ctx context.Context, hostname string) ([]string, error) {
	repositories := []string{}

	hostRef, err := ref.NewHost(hostname)
	if err != nil {
		return repositories, err
	}

	if _, err := registry.client.Ping(ctx, hostRef); err != nil {
		registry.log.Debug().Err(err).Str("remote", hostname).
			Msg("failed to ping remote registry before listing repositories")
	}

	last := ""

	for {
		repoOpts := []scheme.RepoOpts{}

		if last != "" {
			repoOpts = append(repoOpts, scheme.WithRepoLast(last))
		}

		clientRepoList, err := registry.client.RepoList(ctx, hostname, repoOpts...)
		if err != nil {
			return repositories, err
		}

		repoList, err := clientRepoList.GetRepos()
		if err != nil {
			return repositories, err
		}

		if len(repoList) == 0 || last == repoList[len(repoList)-1] {
			break
		}

		repositories = append(repositories, repoList...)

		last = repoList[len(repoList)-1]
	}

	return repositories, nil
}

func (registry *RemoteRegistry) GetImageReference(repo, reference string) (ref.Ref, error) {
	digest, ok := parseReference(reference)

	var imageRefPath string
	if ok {
		imageRefPath = fmt.Sprintf("%s/%s@%s", registry.primaryHost, repo, digest.String())
	} else {
		// is tag
		imageRefPath = fmt.Sprintf("%s/%s:%s", registry.primaryHost, repo, reference)
	}

	imageRef, err := ref.New(imageRefPath)
	if err != nil {
		return ref.Ref{}, err
	}

	if imageRef.Path != "" {
		return ref.Ref{}, zerr.ErrSyncParseRemoteRepo
	}

	// add check for imageref to be oci

	return imageRef, nil
}

// mapRegclientManifestErr maps regclient manifest fetch failures to zot errors so
// sync skippable/unresolved allowlists stay zot-only. All Remote manifest helpers
// (HeadManifest, HeadManifestRef, GetManifestList) must return errors through this
// path via translateManifestErr.
func mapRegclientManifestErr(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, errs.ErrHTTPUnauthorized) {
		return zerr.ErrUnauthorizedAccess
	}

	if errors.Is(err, errs.ErrNotFound) {
		return zerr.ErrManifestNotFound
	}

	return err
}

// translateManifestErr maps regclient manifest fetch errors to zot errors for sync/on-demand callers.
func (registry *RemoteRegistry) translateManifestErr(imageReference ref.Ref, err error) error {
	mapped := mapRegclientManifestErr(err)
	if errors.Is(mapped, err) {
		return err
	}

	registry.log.Info().Str("errorType", common.TypeOf(err)).
		Str("repository", imageReference.Repository).Str("reference", imageReference.Reference).
		Err(err).Msg("failed to get remote manifest")

	return mapped
}

// HeadManifest returns the remote digest and media type for repo:tag.
// Tries ManifestHead first; on not-found falls back to ManifestGet so registries that
// materialize tags on GET but not HEAD (e.g. some ECR pull-through caches) still work.
// Transport / dial failures are returned immediately — a second ManifestGet would only
// repeat the same backoff (see TestOnDemandMultipleImage).
func (registry *RemoteRegistry) HeadManifest(ctx context.Context, repo, tag string,
) (godigest.Digest, string, error) {
	imageReference, err := registry.GetImageReference(repo, tag)
	if err != nil {
		return "", "", err
	}

	return registry.HeadManifestRef(ctx, imageReference)
}

// HeadManifestRef is HeadManifest for an already-built remote ref.
func (registry *RemoteRegistry) HeadManifestRef(ctx context.Context, imageReference ref.Ref,
) (godigest.Digest, string, error) {
	man, err := registry.client.ManifestHead(ctx, imageReference)
	if err != nil {
		if !shouldFallbackManifestGet(err) {
			return "", "", registry.translateManifestErr(imageReference, err)
		}

		man, err = registry.client.ManifestGet(ctx, imageReference)
		if err != nil {
			return "", "", registry.translateManifestErr(imageReference, err)
		}
	}
	defer registry.client.Close(ctx, man.GetRef())

	desc := man.GetDescriptor()

	return desc.Digest, desc.MediaType, nil
}

// GetManifestList returns child descriptors when reference is an index/manifest list.
// Non-list images return nil, nil. Errors are mapped via translateManifestErr.
func (registry *RemoteRegistry) GetManifestList(ctx context.Context, repo, reference string,
) ([]descriptor.Descriptor, error) {
	imageReference, err := registry.GetImageReference(repo, reference)
	if err != nil {
		return nil, err
	}

	man, err := registry.client.ManifestGet(ctx, imageReference)
	if err != nil {
		return nil, registry.translateManifestErr(imageReference, err)
	}
	defer registry.client.Close(ctx, man.GetRef())

	if !man.IsList() {
		return nil, nil
	}

	indexer, ok := man.(manifest.Indexer)
	if !ok {
		return nil, nil
	}

	return indexer.GetManifestList()
}

// shouldFallbackManifestGet reports whether a ManifestHead failure is worth retrying
// with ManifestGet (not-found / not-materialized). Connection and other transport
// errors are not — GET would pay another full regclient backoff.
func shouldFallbackManifestGet(err error) bool {
	return errors.Is(err, errs.ErrNotFound)
}

func (registry *RemoteRegistry) GetTags(ctx context.Context, repo string) ([]string, error) {
	repoRefPath := fmt.Sprintf("%s/%s", registry.primaryHost, repo)

	repoReference, err := ref.New(repoRefPath)
	if err != nil {
		return []string{}, err
	}

	tl, err := registry.client.TagList(ctx, repoReference)
	if err != nil {
		return []string{}, err
	}

	return tl.GetTags()
}
