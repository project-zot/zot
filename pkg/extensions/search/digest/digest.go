package digestinfo

import (
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// DigestInfo implements searching by manifes/config/layer digest.
type DigestInfo struct {
	Log         log.Logger
	LayoutUtils *common.OciLayoutUtils
}

type ImageInfoByDigest struct {
	TagName       string
	TagDigest     digest.Digest
	ImageManifest v1.Manifest
}

// NewDigestInfo initializes a new DigestInfo object.
func NewDigestInfo(storeController storage.StoreController, log log.Logger) *DigestInfo {
	layoutUtils := common.NewOciLayoutUtils(storeController, log)

	return &DigestInfo{Log: log, LayoutUtils: layoutUtils}
}

// GetRepoInfoByDigest returns a list of manifests in a repository matching a specific digest.
func (digestInfo DigestInfo) GetRepoInfoByDigest(repo string, digest string) ([]ImageInfoByDigest, error) {
	repoManifests := []ImageInfoByDigest{}

	imagePath := common.GetImageRepoPath(digestInfo.LayoutUtils.StoreController, repo)
	if !digestInfo.LayoutUtils.DirExists(imagePath) {
		return nil, errors.ErrRepoNotFound
	}

	manifests, err := digestInfo.LayoutUtils.GetImageManifests(repo)
	if err != nil {
		digestInfo.Log.Error().Err(err).Msg("unable to read image manifests")

		return repoManifests, err
	}

	for _, manifest := range manifests {
		imageDigest := manifest.Digest
		found := false

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := digestInfo.LayoutUtils.GetImageBlobManifest(repo, imageDigest)
			if err != nil {
				digestInfo.Log.Error().Err(err).Msg("unable to read image blob manifest")

				return []ImageInfoByDigest{}, err
			}

			// Check the image manigest in index.json matches the search digest
			// This is a blob with mediaType application/vnd.oci.image.manifest.v1+json
			if strings.Contains(manifest.Digest.String(), digest) {
				found = true
			}

			// Check the image config matches the search digest
			// This is a blob with mediaType application/vnd.oci.image.config.v1+json
			if strings.Contains(imageBlobManifest.Config.Digest.Algorithm+":"+imageBlobManifest.Config.Digest.Hex, digest) &&
				!found {
				found = true
			}

			// Check to see if the individual layers in the oci image manifest match the digest
			// These are blobs with mediaType application/vnd.oci.image.layer.v1.tar+gzip
			for _, layer := range imageBlobManifest.Layers {
				if strings.Contains(layer.Digest.Algorithm+":"+layer.Digest.Hex, digest) && !found {
					found = true
				}
			}

			if found {
				repoManifests = append(
					repoManifests,
					ImageInfoByDigest{TagName: v, TagDigest: manifest.Digest, ImageManifest: imageBlobManifest},
				)
			}
		}
	}

	return repoManifests, nil
}
