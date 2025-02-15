//go:build sync
// +build sync

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
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/errs"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/ref"
	"github.com/regclient/regclient/types/repo"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/log"
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

	var repoList *repo.RepoList

	for _, host := range registry.hosts {
		repoList, err = registry.client.RepoList(ctx, host.Hostname)
		if err != nil {
			registry.log.Error().Err(err).Str("remote", host.Name).Msg("failed to list repositories in remote registry")

			continue
		}

		return repoList.Repositories, nil
	}

	return []string{}, err
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

	return imageRef, nil
}

func (registry *RemoteRegistry) GetOCIManifest(ctx context.Context, repo, reference string,
) ([]byte, ispec.Descriptor, bool, error) {
	var isConverted bool

	var buf []byte

	var desc ispec.Descriptor

	imageReference, err := registry.GetImageReference(repo, reference)
	if err != nil {
		return nil, ispec.Descriptor{}, false, err
	}

	/// check what error it gives when not found
	man, err := registry.client.ManifestGet(ctx, imageReference)
	if err != nil {
		/* public registries may return 401 for image not found
		they will try to check private registries as a fallback => 401 */
		if errors.Is(err, errs.ErrHTTPUnauthorized) {
			registry.log.Info().Str("errorType", common.TypeOf(err)).
				Str("repository", repo).Str("reference", reference).
				Err(err).Msg("failed to get manifest: unauthorized")

			return nil, ispec.Descriptor{}, false, zerr.ErrUnauthorizedAccess
		} else if errors.Is(err, errs.ErrNotFound) {
			registry.log.Info().Str("errorType", common.TypeOf(err)).
				Str("repository", repo).Str("reference", reference).
				Err(err).Msg("failed to find manifest")

			return nil, ispec.Descriptor{}, false, zerr.ErrManifestNotFound
		}

		return nil, ispec.Descriptor{}, false, err
	}

	switch man.GetDescriptor().MediaType {
	case mediatype.Docker2Manifest:
		buf, desc, err = convertDockerManifestToOCI(ctx, man, imageReference, registry.client)
		isConverted = true
	case mediatype.Docker2ManifestList:
		seen := []godigest.Digest{}

		buf, desc, err = convertDockerListToOCI(ctx, man, imageReference, seen, registry.client)
		isConverted = true
	case mediatype.OCI1Manifest, mediatype.OCI1ManifestList:
		buf, err = man.MarshalJSON()
		desc = toOCIDescriptor(man.GetDescriptor())
	default:
		return nil, desc, false, zerr.ErrMediaTypeNotSupported
	}

	return buf, desc, isConverted, err
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

func convertDockerListToOCI(ctx context.Context, man manifest.Manifest, imageReference ref.Ref, seen []godigest.Digest,
	regclient *regclient.RegClient,
) (
	[]byte, ispec.Descriptor, error,
) {
	var index ispec.Index

	// seen
	if common.Contains(seen, man.GetDescriptor().Digest) {
		return nil, ispec.Descriptor{}, nil
	}

	index.SchemaVersion = 2
	index.Manifests = []ispec.Descriptor{}
	index.MediaType = ispec.MediaTypeImageIndex

	indexer, ok := man.(manifest.Indexer)
	if !ok {
		return nil, ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	ociIndex, err := manifest.OCIIndexFromAny(man.GetOrig())
	if err != nil {
		return nil, ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	manifests, err := indexer.GetManifestList()
	if err != nil {
		return nil, ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	for _, manDesc := range manifests {
		ref := imageReference
		ref.Digest = manDesc.Digest.String()

		manEntry, err := regclient.ManifestGet(ctx, ref)
		if err != nil {
			return nil, ispec.Descriptor{}, err
		}

		regclient.Close(ctx, manEntry.GetRef())

		var desc ispec.Descriptor

		switch manEntry.GetDescriptor().MediaType {
		case mediatype.Docker2Manifest:
			_, desc, err = convertDockerManifestToOCI(ctx, manEntry, ref, regclient)
			if err != nil {
				return nil, ispec.Descriptor{}, err
			}

		case mediatype.Docker2ManifestList:
			_, desc, err = convertDockerListToOCI(ctx, manEntry, ref, seen, regclient)
			if err != nil {
				return nil, ispec.Descriptor{}, err
			}
		default:
			return nil, ispec.Descriptor{}, err
		}

		// copy desc platform from docker desc
		if manDesc.Platform != nil {
			desc.Platform = &ispec.Platform{
				Architecture: manDesc.Platform.Architecture,
				OS:           manDesc.Platform.OS,
				OSVersion:    manDesc.Platform.OSVersion,
				OSFeatures:   manDesc.Platform.OSFeatures,
				Variant:      manDesc.Platform.Variant,
			}
		}

		index.Manifests = append(index.Manifests, desc)
	}

	index.Annotations = ociIndex.Annotations
	index.ArtifactType = ociIndex.ArtifactType

	if ociIndex.Subject != nil {
		subject := toOCIDescriptor(*ociIndex.Subject)
		index.Subject = &subject
	}

	indexBuf, err := json.Marshal(index)
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	indexDesc := toOCIDescriptor(man.GetDescriptor())

	indexDesc.MediaType = ispec.MediaTypeImageIndex
	indexDesc.Digest = godigest.FromBytes(indexBuf)
	indexDesc.Size = int64(len(indexBuf))

	return indexBuf, indexDesc, nil
}

func convertDockerManifestToOCI(ctx context.Context, man manifest.Manifest, imageReference ref.Ref,
	regclient *regclient.RegClient,
) (
	[]byte, ispec.Descriptor, error,
) {
	imager, ok := man.(manifest.Imager)
	if !ok {
		return nil, ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	var ociManifest ispec.Manifest

	manifest, err := man.RawBody()
	if err != nil {
		return nil, ispec.Descriptor{}, zerr.ErrMediaTypeNotSupported
	}

	if err := json.Unmarshal(manifest, &ociManifest); err != nil {
		return nil, ispec.Descriptor{}, err
	}

	configDesc, err := imager.GetConfig()
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	// get config blob
	config, err := regclient.BlobGetOCIConfig(ctx, imageReference, configDesc)
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	configBuf, err := config.RawBody()
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	// var ociConfig ispec.Image

	// if err := json.Unmarshal(configBuf, &ociConfig); err != nil {
	// 	return nil, ispec.Descriptor{}, err
	// }

	// ociConfigContent, err := json.Marshal(ociConfig)
	// if err != nil {
	// 	return nil, ispec.Descriptor{}, err
	// }

	// convert config and manifest mediatype
	ociManifest.Config.Size = int64(len(configBuf))
	ociManifest.Config.Digest = godigest.FromBytes(configBuf)
	ociManifest.Config.MediaType = ispec.MediaTypeImageConfig
	ociManifest.MediaType = ispec.MediaTypeImageManifest

	layersDesc, err := imager.GetLayers()
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	ociManifest.Layers = []ispec.Descriptor{}

	for _, layerDesc := range layersDesc {
		ociManifest.Layers = append(ociManifest.Layers, toOCIDescriptor(layerDesc))
	}

	manifestBuf, err := json.Marshal(ociManifest)
	if err != nil {
		return nil, ispec.Descriptor{}, err
	}

	manifestDesc := toOCIDescriptor(man.GetDescriptor())

	manifestDesc.MediaType = ispec.MediaTypeImageManifest
	manifestDesc.Digest = godigest.FromBytes(manifestBuf)
	manifestDesc.Size = int64(len(manifestBuf))

	return manifestBuf, manifestDesc, nil
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
