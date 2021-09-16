package digestinfo

import (
	"strings"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/extensions/search/common"
	"github.com/anuvu/zot/pkg/log"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// DigestInfo implements searching by manifes/config/layer digest.
type DigestInfo struct {
	Log         log.Logger
	LayoutUtils *common.OciLayoutUtils
}

// NewDigestInfo initializes a new DigestInfo object.
func NewDigestInfo(log log.Logger) *DigestInfo {
	layoutUtils := common.NewOciLayoutUtils(log)

	return &DigestInfo{Log: log, LayoutUtils: layoutUtils}
}

// FilterImagesByDigest returns a list of image tags in a repository matching a specific divest.
func (digestinfo DigestInfo) GetImageTagsByDigest(repo string, digest string) ([]*string, error) {
	uniqueTags := []*string{}

	if !common.DirExists(repo) {
		return nil, errors.ErrRepoNotFound
	}

	manifests, err := digestinfo.LayoutUtils.GetImageManifests(repo)

	if err != nil {
		digestinfo.Log.Error().Err(err).Msg("unable to read image manifests")
		return uniqueTags, err
	}

	for _, manifest := range manifests {
		imageDigest := manifest.Digest

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			imageBlobManifest, err := digestinfo.LayoutUtils.GetImageBlobManifest(repo, imageDigest)

			if err != nil {
				digestinfo.Log.Error().Err(err).Msg("unable to read image blob manifest")
				return uniqueTags, err
			}

			tags := []*string{}

			// Check the image manigest in index.json matches the search digest
			// This is a blob with mediaType application/vnd.oci.image.manifest.v1+json
			if strings.Contains(manifest.Digest.String(), digest) {
				tags = append(tags, &v)
			}

			// Check the image config matches the search digest
			// This is a blob with mediaType application/vnd.oci.image.config.v1+json
			if strings.Contains(imageBlobManifest.Config.Digest.Algorithm+":"+imageBlobManifest.Config.Digest.Hex, digest) {
				tags = append(tags, &v)
			}

			// Check to see if the individual layers in the oci image manifest match the digest
			// These are blobs with mediaType application/vnd.oci.image.layer.v1.tar+gzip
			for _, layer := range imageBlobManifest.Layers {
				if strings.Contains(layer.Digest.Algorithm+":"+layer.Digest.Hex, digest) {
					tags = append(tags, &v)
				}
			}

			keys := make(map[string]bool)

			for _, entry := range tags {
				if _, value := keys[*entry]; !value {
					uniqueTags = append(uniqueTags, entry)
					keys[*entry] = true
				}
			}
		}
	}

	return uniqueTags, nil
}
