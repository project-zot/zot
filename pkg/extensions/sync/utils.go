//go:build sync
// +build sync

package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/common"
	syncconf "zotregistry.dev/zot/pkg/extensions/config/sync"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/test/inject"
)

// Get sync.FileCredentials from file.
func getFileCredentials(filepath string) (syncconf.CredentialsFile, error) {
	credsFile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var creds syncconf.CredentialsFile

	err = json.Unmarshal(credsFile, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func getUpstreamContext(certDir, username, password string, tlsVerify bool) *types.SystemContext {
	upstreamCtx := &types.SystemContext{}
	upstreamCtx.DockerCertPath = certDir
	upstreamCtx.DockerDaemonCertPath = certDir

	if tlsVerify {
		upstreamCtx.DockerDaemonInsecureSkipTLSVerify = false
		upstreamCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(false)
	} else {
		upstreamCtx.DockerDaemonInsecureSkipTLSVerify = true
		upstreamCtx.DockerInsecureSkipTLSVerify = types.NewOptionalBool(true)
	}

	if username != "" && password != "" {
		upstreamCtx.DockerAuthConfig = &types.DockerAuthConfig{
			Username: username,
			Password: password,
		}
	}

	return upstreamCtx
}

// sync needs transport to be stripped to not be wrongly interpreted as an image reference
// at a non-fully qualified registry (hostname as image and port as tag).
func StripRegistryTransport(url string) string {
	return strings.Replace(strings.Replace(url, "http://", "", 1), "https://", "", 1)
}

// getRepoTags lists all tags in a repository.
// It returns a string slice of tags and any error encountered.
func getRepoTags(ctx context.Context, sysCtx *types.SystemContext, host, repo string) ([]string, error) {
	repoRef, err := parseRepositoryReference(fmt.Sprintf("%s/%s", host, repo))
	if err != nil {
		return []string{}, err
	}

	dockerRef, err := docker.NewReference(reference.TagNameOnly(repoRef))
	// hard to reach test case, injected error, see pkg/test/dev.go
	if err = inject.Error(err); err != nil {
		return nil, err // Should never happen for a reference with tag and no digest
	}

	tags, err := docker.GetRepositoryTags(ctx, sysCtx, dockerRef)
	if err != nil {
		return nil, err
	}

	return tags, nil
}

// parseRepositoryReference parses input into a reference.Named, and verifies that it names a repository, not an image.
func parseRepositoryReference(input string) (reference.Named, error) {
	ref, err := reference.ParseNormalizedNamed(input)
	if err != nil {
		return nil, err
	}

	if !reference.IsNameOnly(ref) {
		return nil, zerr.ErrInvalidRepositoryName
	}

	return ref, nil
}

// parse a reference, return its digest and if it's valid.
func parseReference(reference string) (digest.Digest, bool) {
	var ok bool

	d, err := digest.Parse(reference)
	if err == nil {
		ok = true
	}

	return d, ok
}

func getCopyOptions(upstreamCtx, localCtx *types.SystemContext) copy.Options {
	options := copy.Options{
		DestinationCtx:        localCtx,
		SourceCtx:             upstreamCtx,
		ReportWriter:          io.Discard,
		ForceManifestMIMEType: ispec.MediaTypeImageManifest, // force only oci manifest MIME type
		ImageListSelection:    copy.CopyAllImages,
	}

	return options
}

func getPolicyContext(log log.Logger) (*signature.PolicyContext, error) {
	policy := &signature.Policy{Default: []signature.PolicyRequirement{signature.NewPRInsecureAcceptAnything()}}

	policyContext, err := signature.NewPolicyContext(policy)
	if err := inject.Error(err); err != nil {
		log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Msg("couldn't create policy context")

		return nil, err
	}

	return policyContext, nil
}

func getSupportedMediaType() []string {
	return []string{
		ispec.MediaTypeImageIndex,
		ispec.MediaTypeImageManifest,
		manifest.DockerV2ListMediaType,
		manifest.DockerV2Schema2MediaType,
	}
}

func isSupportedMediaType(mediaType string) bool {
	mediaTypes := getSupportedMediaType()
	for _, m := range mediaTypes {
		if m == mediaType {
			return true
		}
	}

	return false
}

// given an imageSource and a docker manifest, convert it to OCI.
func convertDockerManifestToOCI(imageSource types.ImageSource, dockerManifestBuf []byte) ([]byte, error) {
	var ociManifest ispec.Manifest

	// unmarshal docker manifest into OCI manifest
	err := json.Unmarshal(dockerManifestBuf, &ociManifest)
	if err != nil {
		return []byte{}, err
	}

	configContent, err := getImageConfigContent(imageSource, ociManifest.Config.Digest)
	if err != nil {
		return []byte{}, err
	}

	// marshal config blob into OCI config, will remove keys specific to docker
	var ociConfig ispec.Image

	err = json.Unmarshal(configContent, &ociConfig)
	if err != nil {
		return []byte{}, err
	}

	ociConfigContent, err := json.Marshal(ociConfig)
	if err != nil {
		return []byte{}, err
	}

	// convert layers
	err = convertDockerLayersToOCI(ociManifest.Layers)
	if err != nil {
		return []byte{}, err
	}

	// convert config and manifest mediatype
	ociManifest.Config.Size = int64(len(ociConfigContent))
	ociManifest.Config.Digest = digest.FromBytes(ociConfigContent)
	ociManifest.Config.MediaType = ispec.MediaTypeImageConfig
	ociManifest.MediaType = ispec.MediaTypeImageManifest

	return json.Marshal(ociManifest)
}

// convert docker layers mediatypes to OCI mediatypes.
func convertDockerLayersToOCI(dockerLayers []ispec.Descriptor) error {
	for idx, layer := range dockerLayers {
		switch layer.MediaType {
		case manifest.DockerV2Schema2ForeignLayerMediaType:
			dockerLayers[idx].MediaType = ispec.MediaTypeImageLayerNonDistributable //nolint: staticcheck
		case manifest.DockerV2Schema2ForeignLayerMediaTypeGzip:
			dockerLayers[idx].MediaType = ispec.MediaTypeImageLayerNonDistributableGzip //nolint: staticcheck
		case manifest.DockerV2SchemaLayerMediaTypeUncompressed:
			dockerLayers[idx].MediaType = ispec.MediaTypeImageLayer
		case manifest.DockerV2Schema2LayerMediaType:
			dockerLayers[idx].MediaType = ispec.MediaTypeImageLayerGzip
		default:
			return zerr.ErrMediaTypeNotSupported
		}
	}

	return nil
}

// given an imageSource and a docker index manifest, convert it to OCI.
func convertDockerIndexToOCI(imageSource types.ImageSource, dockerManifestBuf []byte) ([]byte, error) {
	// get docker index
	originalIndex, err := manifest.ListFromBlob(dockerManifestBuf, manifest.DockerV2ListMediaType)
	if err != nil {
		return []byte{}, err
	}

	// get manifests digests
	manifestsDigests := originalIndex.Instances()

	manifestsUpdates := make([]manifest.ListUpdate, 0, len(manifestsDigests))

	// convert each manifests in index from docker to OCI
	for _, manifestDigest := range manifestsDigests {
		digestCopy := manifestDigest

		indexManifestBuf, _, err := imageSource.GetManifest(context.Background(), &digestCopy)
		if err != nil {
			return []byte{}, err
		}

		convertedIndexManifest, err := convertDockerManifestToOCI(imageSource, indexManifestBuf)
		if err != nil {
			return []byte{}, err
		}

		manifestsUpdates = append(manifestsUpdates, manifest.ListUpdate{
			Digest:    digest.FromBytes(convertedIndexManifest),
			Size:      int64(len(convertedIndexManifest)),
			MediaType: ispec.MediaTypeImageManifest,
		})
	}

	// update all manifests in index
	if err := originalIndex.UpdateInstances(manifestsUpdates); err != nil {
		return []byte{}, err
	}

	// convert index to OCI
	convertedList, err := originalIndex.ConvertToMIMEType(ispec.MediaTypeImageIndex)
	if err != nil {
		return []byte{}, err
	}

	return convertedList.Serialize()
}

// given an image source and a config blob digest, get blob config content.
func getImageConfigContent(imageSource types.ImageSource, configDigest digest.Digest,
) ([]byte, error) {
	configBlob, _, err := imageSource.GetBlob(context.Background(), types.BlobInfo{
		Digest: configDigest,
	}, none.NoCache)
	if err != nil {
		return nil, err
	}

	configBuf := new(bytes.Buffer)

	_, err = configBuf.ReadFrom(configBlob)

	return configBuf.Bytes(), err
}
