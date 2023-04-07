package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gobwas/glob"
	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
)

type StoreController struct {
	DefaultStore ImageStore
	SubStore     map[string]ImageStore
}

func (sc StoreController) GetImageStore(name string) ImageStore {
	if sc.SubStore != nil {
		// SubStore is being provided, now we need to find equivalent image store and this will be found by splitting name
		prefixName := getRoutePrefix(name)

		imgStore, ok := sc.SubStore[prefixName]
		if !ok {
			imgStore = sc.DefaultStore
		}

		return imgStore
	}

	return sc.DefaultStore
}

func getRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2) //nolint:gomnd

	if len(names) != 2 { //nolint:gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

// CheckIsImageSignature checks if the given image (repo:tag) represents a signature. The function
// returns:
//
// - bool: if the image is a signature or not
//
// - string: the type of signature
//
// - string: the digest of the image it signs
//
// - error: any errors that occur.
func CheckIsImageSignature(repoName string, manifestBlob []byte, reference string,
	storeController StoreController,
) (bool, string, godigest.Digest, error) {
	const cosign = "cosign"

	var manifestContent ispec.Artifact

	err := json.Unmarshal(manifestBlob, &manifestContent)
	if err != nil {
		return false, "", "", err
	}

	// check notation signature
	if _, ok := SignatureMediaTypes()[manifestContent.ArtifactType]; ok && manifestContent.Subject != nil {
		imgStore := storeController.GetImageStore(repoName)

		_, signedImageManifestDigest, _, err := imgStore.GetImageManifest(repoName,
			manifestContent.Subject.Digest.String())
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return true, "notation", signedImageManifestDigest, zerr.ErrOrphanSignature
			}

			return false, "", "", err
		}

		return true, "notation", signedImageManifestDigest, nil
	}

	// check cosign
	cosignTagRule := glob.MustCompile("sha256-*.sig")

	if tag := reference; cosignTagRule.Match(reference) {
		prefixLen := len("sha256-")
		digestLen := 64
		signedImageManifestDigestEncoded := tag[prefixLen : prefixLen+digestLen]

		signedImageManifestDigest := godigest.NewDigestFromEncoded(godigest.SHA256,
			signedImageManifestDigestEncoded)

		imgStore := storeController.GetImageStore(repoName)

		_, signedImageManifestDigest, _, err := imgStore.GetImageManifest(repoName,
			signedImageManifestDigest.String())
		if err != nil {
			if errors.Is(err, zerr.ErrManifestNotFound) {
				return true, cosign, signedImageManifestDigest, zerr.ErrOrphanSignature
			}

			return false, "", "", err
		}

		if signedImageManifestDigest.String() == "" {
			return true, cosign, signedImageManifestDigest, zerr.ErrOrphanSignature
		}

		return true, cosign, signedImageManifestDigest, nil
	}

	return false, "", "", nil
}

func SignatureMediaTypes() map[string]bool {
	return map[string]bool{
		notreg.ArtifactTypeNotation: true,
	}
}
