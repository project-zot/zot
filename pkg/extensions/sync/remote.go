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

// translateManifestErr maps regclient manifest fetch errors to zot errors for sync/on-demand callers.
func (registry *RemoteRegistry) translateManifestErr(imageReference ref.Ref, err error) error {
	if err == nil {
		return nil
	}

	/* public registries may return 401 for image not found
	they will try to check private registries as a fallback => 401 */
	if errors.Is(err, errs.ErrHTTPUnauthorized) {
		registry.log.Info().Str("errorType", common.TypeOf(err)).
			Str("repository", imageReference.Repository).Str("reference", imageReference.Reference).
			Err(err).Msg("failed to get manifest: unauthorized")

		return zerr.ErrUnauthorizedAccess
	}

	if errors.Is(err, errs.ErrNotFound) {
		registry.log.Info().Str("errorType", common.TypeOf(err)).
			Str("repository", imageReference.Repository).Str("reference", imageReference.Reference).
			Err(err).Msg("failed to find manifest")

		return zerr.ErrManifestNotFound
	}

	return err
}

func (registry *RemoteRegistry) headManifest(ctx context.Context, imageReference ref.Ref,
) (manifest.Manifest, error) {
	man, err := registry.client.ManifestHead(ctx, imageReference)
	if err != nil {
		return nil, registry.translateManifestErr(imageReference, err)
	}

	return man, nil
}

func (registry *RemoteRegistry) GetDigest(ctx context.Context, repo, tag string,
) (godigest.Digest, error) {
	imageReference, err := registry.GetImageReference(repo, tag)
	if err != nil {
		return "", err
	}

	man, err := registry.headManifest(ctx, imageReference)
	if err != nil {
		return "", err
	}
	defer registry.client.Close(ctx, man.GetRef())

	return man.GetDescriptor().Digest, nil
}

// GetOCIDigest returns the digest predictOCIDigest computes after regclient
// mod.WithManifestToOCI conversion, the original remote digest, and whether
// mod.Apply would modify the image.
func (registry *RemoteRegistry) GetOCIDigest(ctx context.Context, repo, tag string,
) (godigest.Digest, godigest.Digest, bool, error) {
	imageReference, err := registry.GetImageReference(repo, tag)
	if err != nil {
		return "", "", false, err
	}

	predicted, original, isConverted, err := predictOCIDigest(ctx, registry.client, imageReference)
	if err != nil {
		return "", "", false, registry.translateManifestErr(imageReference, err)
	}

	return predicted, original, isConverted, nil
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
