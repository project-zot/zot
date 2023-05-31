//go:build sync
// +build sync

package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"github.com/docker/distribution/reference"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/common"
	syncconf "zotregistry.io/zot/pkg/extensions/config/sync"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/test/inject"
)

const (
	SyncBlobUploadDir = ".sync"
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
