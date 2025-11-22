//go:build sync

package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/config"
	"github.com/regclient/regclient/scheme"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/mediatype"
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

func (registry *RemoteRegistry) headManifest(ctx context.Context, imageReference ref.Ref,
) (manifest.Manifest, error) {
	/// check what error it gives when not found
	man, err := registry.client.ManifestHead(ctx, imageReference)
	if err != nil {
		/* public registries may return 401 for image not found
		they will try to check private registries as a fallback => 401 */
		if errors.Is(err, errs.ErrHTTPUnauthorized) {
			registry.log.Info().Str("errorType", common.TypeOf(err)).
				Str("repository", imageReference.Repository).Str("reference", imageReference.Reference).
				Err(err).Msg("failed to get manifest: unauthorized")

			return nil, zerr.ErrUnauthorizedAccess
		} else if errors.Is(err, errs.ErrNotFound) {
			registry.log.Info().Str("errorType", common.TypeOf(err)).
				Str("repository", imageReference.Repository).Str("reference", imageReference.Reference).
				Err(err).Msg("failed to find manifest")

			return nil, zerr.ErrManifestNotFound
		}

		return nil, err
	}

	return man, nil
}

func (registry *RemoteRegistry) getManifest(ctx context.Context, imageReference ref.Ref,
) (manifest.Manifest, error) {
	/// check what error it gives when not found
	man, err := registry.client.ManifestGet(ctx, imageReference)
	if err != nil {
		/* public registries may return 401 for image not found
		they will try to check private registries as a fallback => 401 */
		if errors.Is(err, errs.ErrHTTPUnauthorized) {
			registry.log.Info().Str("errorType", common.TypeOf(err)).
				Str("repository", imageReference.Repository).Str("reference", imageReference.Reference).
				Err(err).Msg("failed to get manifest: unauthorized")

			return nil, zerr.ErrUnauthorizedAccess
		} else if errors.Is(err, errs.ErrNotFound) {
			registry.log.Info().Str("errorType", common.TypeOf(err)).
				Str("repository", imageReference.Repository).Str("reference", imageReference.Reference).
				Err(err).Msg("failed to find manifest")

			return nil, zerr.ErrManifestNotFound
		}

		return nil, err
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

	return man.GetDescriptor().Digest, err
}

// GetOCIDigest returns OCI remote digest, original remote digest (unconverted), if it was converted.
func (registry *RemoteRegistry) GetOCIDigest(ctx context.Context, repo, tag string,
) (godigest.Digest, godigest.Digest, bool, error) {
	var isConverted bool

	var desc ispec.Descriptor

	imageReference, err := registry.GetImageReference(repo, tag)
	if err != nil {
		return "", "", false, err
	}

	man, err := registry.getManifest(ctx, imageReference)
	if err != nil {
		return "", "", false, err
	}

	switch man.GetDescriptor().MediaType {
	case mediatype.Docker2Manifest:
		desc, err = convertDockerManifestToOCI(ctx, man, man.GetDescriptor(), imageReference, registry.client)
		isConverted = true
	case mediatype.Docker2ManifestList:
		desc, err = convertDockerListToOCI(ctx, man, imageReference, registry.client)
		isConverted = true
	case mediatype.OCI1Manifest, mediatype.OCI1ManifestList:
		desc = toOCIDescriptor(man.GetDescriptor())
	default:
		return "", "", false, zerr.ErrMediaTypeNotSupported
	}

	return desc.Digest, man.GetDescriptor().Digest, isConverted, err
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

func convertDockerListToOCI(ctx context.Context, man manifest.Manifest, imageReference ref.Ref,
	regclient *regclient.RegClient,
) (
	ispec.Descriptor, error,
) {
	var index ispec.Index

	index.SchemaVersion = 2
	index.Manifests = []ispec.Descriptor{}
	index.MediaType = ispec.MediaTypeImageIndex

	indexer, ok := man.(manifest.Indexer)
	if !ok {
		return ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	ociIndex, err := manifest.OCIIndexFromAny(man.GetOrig())
	if err != nil {
		return ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	manifests, err := indexer.GetManifestList()
	if err != nil {
		return ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	for _, manDesc := range manifests {
		ref := imageReference
		ref.Digest = manDesc.Digest.String()

		manEntry, err := regclient.ManifestGet(ctx, ref)
		if err != nil {
			return ispec.Descriptor{}, err
		}

		regclient.Close(ctx, manEntry.GetRef())

		var desc ispec.Descriptor

		switch manEntry.GetDescriptor().MediaType {
		case mediatype.Docker2Manifest:
			desc, err = convertDockerManifestToOCI(ctx, manEntry, manDesc, ref, regclient)
			if err != nil {
				return ispec.Descriptor{}, err
			}

		case mediatype.Docker2ManifestList:
			desc, err = convertDockerListToOCI(ctx, manEntry, ref, regclient)
			if err != nil {
				return ispec.Descriptor{}, err
			}
		default:
			return ispec.Descriptor{}, err
		}

		index.Manifests = append(index.Manifests, desc)
	}

	index.Annotations = ociIndex.Annotations

	indexBuf, err := json.Marshal(index)
	if err != nil {
		return ispec.Descriptor{}, err
	}

	indexDesc := toOCIDescriptor(man.GetDescriptor())

	indexDesc.MediaType = ispec.MediaTypeImageIndex
	indexDesc.Digest = godigest.FromBytes(indexBuf)
	indexDesc.Size = int64(len(indexBuf))

	return indexDesc, nil
}

func convertDockerManifestToOCI(ctx context.Context, man manifest.Manifest, desc descriptor.Descriptor,
	imageReference ref.Ref, regclient *regclient.RegClient,
) (
	ispec.Descriptor, error,
) {
	imager, ok := man.(manifest.Imager)
	if !ok {
		return ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	var ociManifest ispec.Manifest

	manifestBuf, err := man.RawBody()
	if err != nil {
		return ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	if err := json.Unmarshal(manifestBuf, &ociManifest); err != nil {
		return ispec.Descriptor{}, err
	}

	configDesc, err := imager.GetConfig()
	if err != nil {
		return ispec.Descriptor{}, err
	}

	// get config blob
	config, err := regclient.BlobGetOCIConfig(ctx, imageReference, configDesc)
	if err != nil {
		return ispec.Descriptor{}, err
	}

	configBuf, err := config.RawBody()
	if err != nil {
		return ispec.Descriptor{}, err
	}

	// convert config and manifest mediatype
	ociManifest.Config.Size = int64(len(configBuf))
	ociManifest.Config.Digest = godigest.FromBytes(configBuf)
	ociManifest.Config.MediaType = ispec.MediaTypeImageConfig
	ociManifest.MediaType = ispec.MediaTypeImageManifest

	layersDesc, err := imager.GetLayers()
	if err != nil {
		return ispec.Descriptor{}, err
	}

	ociManifest.Layers = []ispec.Descriptor{}

	for _, layerDesc := range layersDesc {
		ociManifest.Layers = append(ociManifest.Layers, toOCIDescriptor(layerDesc))
	}

	ociManifestBuf, err := json.Marshal(ociManifest)
	if err != nil {
		return ispec.Descriptor{}, err
	}

	manifestDesc := toOCIDescriptor(desc)

	manifestDesc.MediaType = ispec.MediaTypeImageManifest
	manifestDesc.Digest = godigest.FromBytes(ociManifestBuf)
	manifestDesc.Size = int64(len(ociManifestBuf))

	return manifestDesc, nil
}

func toOCIDescriptor(desc descriptor.Descriptor) ispec.Descriptor {
	ispecPlatform := &ispec.Platform{}

	platform := desc.Platform
	if platform != nil {
		ispecPlatform.Architecture = platform.Architecture
		ispecPlatform.OS = platform.OS
		ispecPlatform.OSFeatures = platform.OSFeatures
		ispecPlatform.OSVersion = platform.OSVersion
		ispecPlatform.Variant = platform.Variant
	} else {
		ispecPlatform = nil
	}

	var mediaType string

	switch desc.MediaType {
	case mediatype.Docker2Manifest:
		mediaType = ispec.MediaTypeImageManifest
	case mediatype.Docker2ManifestList:
		mediaType = ispec.MediaTypeImageIndex
	case mediatype.Docker2ImageConfig:
		mediaType = ispec.MediaTypeImageConfig
	case mediatype.Docker2ForeignLayer:
		mediaType = ispec.MediaTypeImageLayerNonDistributable //nolint: staticcheck
	case mediatype.Docker2LayerGzip:
		mediaType = ispec.MediaTypeImageLayerGzip
	default:
		mediaType = desc.MediaType
	}

	return ispec.Descriptor{
		MediaType:    mediaType,
		Digest:       desc.Digest,
		Size:         desc.Size,
		URLs:         desc.URLs,
		Annotations:  desc.Annotations,
		Platform:     ispecPlatform,
		ArtifactType: desc.ArtifactType,
	}
}
