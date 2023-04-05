//go:build sync
// +build sync

package sync

import (
	"context"
	"fmt"

	"github.com/containers/image/v5/docker"
	dockerReference "github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"

	"zotregistry.io/zot/pkg/api/constants"
	"zotregistry.io/zot/pkg/common"
	client "zotregistry.io/zot/pkg/extensions/sync/httpclient"
	"zotregistry.io/zot/pkg/log"
)

type catalog struct {
	Repositories []string `json:"repositories"`
}

type RemoteRegistry struct {
	client  *client.Client
	context *types.SystemContext
	log     log.Logger
}

func NewRemoteRegistry(client *client.Client, logger log.Logger) Remote {
	registry := &RemoteRegistry{}

	registry.log = logger
	registry.client = client
	clientConfig := client.GetConfig()
	registry.context = getUpstreamContext(clientConfig.CertDir, clientConfig.Username,
		clientConfig.Password, clientConfig.TLSVerify)

	return registry
}

func (registry *RemoteRegistry) GetContext() *types.SystemContext {
	return registry.context
}

func (registry *RemoteRegistry) GetRepositories(ctx context.Context) ([]string, error) {
	var catalog catalog

	_, _, _, err := registry.client.MakeGetRequest(&catalog, "application/json", //nolint: dogsled
		constants.RoutePrefix, constants.ExtCatalogPrefix)
	if err != nil {
		return []string{}, err
	}

	return catalog.Repositories, nil
}

func (registry *RemoteRegistry) GetImageReference(repo, reference string) (types.ImageReference, error) {
	remoteHost := registry.client.GetHostname()

	repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", remoteHost, repo))
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
			Str("reference", reference).Str("remote", remoteHost).
			Err(err).Msg("couldn't parse repository reference")

		return nil, err
	}

	var namedRepoRef dockerReference.Named

	digest, ok := parseReference(reference)
	if ok {
		namedRepoRef, err = dockerReference.WithDigest(repoRef, digest)
		if err != nil {
			return nil, err
		}
	} else {
		namedRepoRef, err = dockerReference.WithTag(repoRef, reference)
		if err != nil {
			return nil, err
		}
	}

	imageRef, err := docker.NewReference(namedRepoRef)
	if err != nil {
		registry.log.Err(err).Str("transport", docker.Transport.Name()).Str("reference", namedRepoRef.String()).
			Msg("cannot obtain a valid image reference for given transport and reference")

		return nil, err
	}

	return imageRef, nil
}

func (registry *RemoteRegistry) GetManifestContent(imageReference types.ImageReference) (
	[]byte, string, digest.Digest, error,
) {
	imageSource, err := imageReference.NewImageSource(context.Background(), registry.GetContext())
	if err != nil {
		return []byte{}, "", "", err
	}

	defer imageSource.Close()

	manifestBuf, mediaType, err := imageSource.GetManifest(context.Background(), nil)
	if err != nil {
		return []byte{}, "", "", err
	}

	return manifestBuf, mediaType, digest.FromBytes(manifestBuf), nil
}

func (registry *RemoteRegistry) GetRepoTags(repo string) ([]string, error) {
	remoteHost := registry.client.GetHostname()

	tags, err := getRepoTags(context.Background(), registry.GetContext(), remoteHost, repo)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).
			Str("remote", remoteHost).Err(err).Msg("couldn't fetch tags for repo")

		return []string{}, err
	}

	return tags, nil
}
