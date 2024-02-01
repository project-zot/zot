//go:build sync
// +build sync

package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/containers/image/v5/docker"
	dockerReference "github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/common"
	client "zotregistry.dev/zot/pkg/extensions/sync/httpclient"
	"zotregistry.dev/zot/pkg/log"
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

	_, _, _, err := registry.client.MakeGetRequest(ctx, &catalog, "application/json", //nolint: dogsled
		constants.RoutePrefix, constants.ExtCatalogPrefix)
	if err != nil {
		return []string{}, err
	}

	return catalog.Repositories, nil
}

func (registry *RemoteRegistry) GetDockerRemoteRepo(repo string) string {
	dockerNamespace := "library"
	dockerRegistry := "docker.io"

	remoteHost := registry.client.GetHostname()

	repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", remoteHost, repo))
	if err != nil {
		return repo
	}

	if !strings.Contains(repo, dockerNamespace) &&
		strings.Contains(repoRef.String(), dockerNamespace) &&
		strings.Contains(repoRef.String(), dockerRegistry) {
		return fmt.Sprintf("%s/%s", dockerNamespace, repo)
	}

	return repo
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

	// if mediatype is docker then convert to OCI
	switch mediaType {
	case manifest.DockerV2Schema2MediaType:
		manifestBuf, err = convertDockerManifestToOCI(imageSource, manifestBuf)
		if err != nil {
			return []byte{}, "", "", err
		}
	case manifest.DockerV2ListMediaType:
		manifestBuf, err = convertDockerIndexToOCI(imageSource, manifestBuf)
		if err != nil {
			return []byte{}, "", "", err
		}
	}

	return manifestBuf, ispec.MediaTypeImageManifest, digest.FromBytes(manifestBuf), nil
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
