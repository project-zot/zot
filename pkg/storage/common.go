package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/docker/distribution/registry/storage/driver"
	"github.com/gobwas/glob"
	notation "github.com/notaryproject/notation-go"
	godigest "github.com/opencontainers/go-digest"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	"github.com/sigstore/cosign/pkg/oci/remote"

	zerr "zotregistry.io/zot/errors"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
)

func GetTagsByIndex(index ispec.Index) []string {
	tags := make([]string, 0)

	for _, manifest := range index.Manifests {
		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok {
			tags = append(tags, v)
		}
	}

	return tags
}

func GetManifestDescByReference(index ispec.Index, reference string) (ispec.Descriptor, bool) {
	var manifestDesc ispec.Descriptor

	for _, manifest := range index.Manifests {
		if reference == manifest.Digest.String() {
			return manifest, true
		}

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			return manifest, true
		}
	}

	return manifestDesc, false
}

func ValidateManifest(imgStore ImageStore, repo, reference, mediaType string, body []byte,
	log zerolog.Logger,
) (godigest.Digest, error) {
	// validate the manifest
	if !IsSupportedMediaType(mediaType) {
		log.Debug().Interface("actual", mediaType).
			Msg("bad manifest media type")

		return "", zerr.ErrBadManifest
	}

	if len(body) == 0 {
		log.Debug().Int("len", len(body)).Msg("invalid body length")

		return "", zerr.ErrBadManifest
	}

	switch mediaType {
	case ispec.MediaTypeImageManifest:
		var manifest ispec.Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}

		if manifest.Config.MediaType == ispec.MediaTypeImageConfig {
			digest, err := validateOCIManifest(imgStore, repo, reference, &manifest, log)
			if err != nil {
				log.Error().Err(err).Msg("invalid oci image manifest")

				return digest, err
			}
		}

		if manifest.Subject != nil {
			var m ispec.Descriptor
			if err := json.Unmarshal(body, &m); err != nil {
				log.Error().Err(err).Msg("unable to unmarshal JSON")

				return "", zerr.ErrBadManifest
			}
		}
	case oras.MediaTypeArtifactManifest:
		var m notation.Descriptor
		if err := json.Unmarshal(body, &m); err != nil {
			log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}
	case ispec.MediaTypeArtifactManifest:
		var artifact ispec.Artifact
		if err := json.Unmarshal(body, &artifact); err != nil {
			log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}

		if artifact.Subject != nil {
			var m ispec.Descriptor
			if err := json.Unmarshal(body, &m); err != nil {
				log.Error().Err(err).Msg("unable to unmarshal JSON")

				return "", zerr.ErrBadManifest
			}
		}
	}

	return "", nil
}

func validateOCIManifest(imgStore ImageStore, repo, reference string, manifest *ispec.Manifest, //nolint:unparam
	log zerolog.Logger,
) (godigest.Digest, error) {
	if manifest.SchemaVersion != storageConstants.SchemaVersion {
		log.Error().Int("SchemaVersion", manifest.SchemaVersion).Msg("invalid manifest")

		return "", zerr.ErrBadManifest
	}

	// validate image config
	config := manifest.Config

	blobBuf, err := imgStore.GetBlobContent(repo, config.Digest)
	if err != nil {
		return config.Digest, zerr.ErrBlobNotFound
	}

	var cspec ispec.Image

	err = json.Unmarshal(blobBuf, &cspec)
	if err != nil {
		return "", zerr.ErrBadManifest
	}

	// validate the layers
	for _, l := range manifest.Layers {
		_, err := imgStore.GetBlobContent(repo, l.Digest)
		if err != nil {
			return l.Digest, zerr.ErrBlobNotFound
		}
	}

	return "", nil
}

func GetAndValidateRequestDigest(body []byte, digestStr string, log zerolog.Logger) (godigest.Digest, error) {
	bodyDigest := godigest.FromBytes(body)

	d, err := godigest.Parse(digestStr)
	if err == nil {
		if d.String() != bodyDigest.String() {
			log.Error().Str("actual", bodyDigest.String()).Str("expected", d.String()).
				Msg("manifest digest is not valid")

			return "", zerr.ErrBadManifest
		}
	}

	return bodyDigest, err
}

/*
CheckIfIndexNeedsUpdate verifies if an index needs to be updated given a new manifest descriptor.

Returns whether or not index needs update, in the latter case it will also return the previous digest.
*/
func CheckIfIndexNeedsUpdate(index *ispec.Index, desc *ispec.Descriptor,
	log zerolog.Logger,
) (bool, godigest.Digest, error) {
	var oldDgst godigest.Digest

	var reference string

	tag, ok := desc.Annotations[ispec.AnnotationRefName]
	if ok {
		reference = tag
	} else {
		reference = desc.Digest.String()
	}

	updateIndex := true

	for midx, manifest := range index.Manifests {
		manifest := manifest
		if reference == manifest.Digest.String() {
			// nothing changed, so don't update
			desc = &manifest
			updateIndex = false

			break
		}

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			if manifest.Digest.String() == desc.Digest.String() {
				// nothing changed, so don't update
				desc = &manifest
				updateIndex = false

				break
			}

			// manifest contents have changed for the same tag,
			// so update index.json descriptor
			log.Info().
				Int64("old size", manifest.Size).
				Int64("new size", desc.Size).
				Str("old digest", manifest.Digest.String()).
				Str("new digest", desc.Digest.String()).
				Str("old mediaType", manifest.MediaType).
				Str("new mediaType", desc.MediaType).
				Msg("updating existing tag with new manifest contents")

			// changing media-type is disallowed!
			if manifest.MediaType != desc.MediaType {
				err := zerr.ErrBadManifest
				log.Error().Err(err).
					Str("old mediaType", manifest.MediaType).
					Str("new mediaType", desc.MediaType).Msg("cannot change media-type")

				return false, "", err
			}

			oldDesc := *desc

			desc = &manifest
			oldDgst = manifest.Digest
			desc.Size = oldDesc.Size
			desc.Digest = oldDesc.Digest

			index.Manifests = append(index.Manifests[:midx], index.Manifests[midx+1:]...)

			break
		}
	}

	return updateIndex, oldDgst, nil
}

// GetIndex returns the contents of index.json.
func GetIndex(imgStore ImageStore, repo string, log zerolog.Logger) (ispec.Index, error) {
	var index ispec.Index

	buf, err := imgStore.GetIndexContent(repo)
	if err != nil {
		return index, err
	}

	if err := json.Unmarshal(buf, &index); err != nil {
		log.Error().Err(err).Str("dir", path.Join(imgStore.RootDir(), repo)).Msg("invalid JSON")

		return index, zerr.ErrRepoBadVersion
	}

	return index, nil
}

// GetImageIndex returns a multiarch type image.
func GetImageIndex(imgStore ImageStore, repo string, digest godigest.Digest, log zerolog.Logger) (ispec.Index, error) {
	var imageIndex ispec.Index

	if err := digest.Validate(); err != nil {
		return imageIndex, err
	}

	buf, err := imgStore.GetBlobContent(repo, digest)
	if err != nil {
		return imageIndex, err
	}

	indexPath := path.Join(imgStore.RootDir(), repo, "blobs",
		digest.Algorithm().String(), digest.Encoded())

	if err := json.Unmarshal(buf, &imageIndex); err != nil {
		log.Error().Err(err).Str("path", indexPath).Msg("invalid JSON")

		return imageIndex, err
	}

	return imageIndex, nil
}

func RemoveManifestDescByReference(index *ispec.Index, reference string, detectCollisions bool,
) (ispec.Descriptor, error) {
	var removedManifest ispec.Descriptor

	var found bool

	foundCount := 0

	var outIndex ispec.Index

	for _, manifest := range index.Manifests {
		tag, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok && tag == reference {
			removedManifest = manifest
			found = true
			foundCount++

			continue
		} else if reference == manifest.Digest.String() {
			removedManifest = manifest
			found = true
			foundCount++

			continue
		}

		outIndex.Manifests = append(outIndex.Manifests, manifest)
	}

	if foundCount > 1 && detectCollisions {
		return ispec.Descriptor{}, zerr.ErrManifestConflict
	} else if !found {
		return ispec.Descriptor{}, zerr.ErrManifestNotFound
	}

	index.Manifests = outIndex.Manifests

	return removedManifest, nil
}

/*
Unmarshal an image index and for all manifests in that
index, ensure that they do not have a name or they are not in other
manifest indexes else GC can never clean them.
*/
func UpdateIndexWithPrunedImageManifests(imgStore ImageStore, index *ispec.Index, repo string,
	desc ispec.Descriptor, oldDgst godigest.Digest, log zerolog.Logger,
) error {
	if (desc.MediaType == ispec.MediaTypeImageIndex) && (oldDgst != "") {
		otherImgIndexes := []ispec.Descriptor{}

		for _, manifest := range index.Manifests {
			if manifest.MediaType == ispec.MediaTypeImageIndex {
				otherImgIndexes = append(otherImgIndexes, manifest)
			}
		}

		otherImgIndexes = append(otherImgIndexes, desc)

		prunedManifests, err := PruneImageManifestsFromIndex(imgStore, repo, oldDgst, *index, otherImgIndexes, log)
		if err != nil {
			return err
		}

		index.Manifests = prunedManifests
	}

	return nil
}

/*
Before an image index manifest is pushed to a repo, its constituent manifests
are pushed first, so when updating/removing this image index manifest, we also
need to determine if there are other image index manifests which refer to the
same constitutent manifests so that they can be garbage-collected correctly

PruneImageManifestsFromIndex is a helper routine to achieve this.
*/
func PruneImageManifestsFromIndex(imgStore ImageStore, repo string, digest godigest.Digest, //nolint:gocyclo
	outIndex ispec.Index, otherImgIndexes []ispec.Descriptor, log zerolog.Logger,
) ([]ispec.Descriptor, error) {
	dir := path.Join(imgStore.RootDir(), repo)

	indexPath := path.Join(dir, "blobs", digest.Algorithm().String(), digest.Encoded())

	buf, err := imgStore.GetBlobContent(repo, digest)
	if err != nil {
		return nil, err
	}

	var imgIndex ispec.Index
	if err := json.Unmarshal(buf, &imgIndex); err != nil {
		log.Error().Err(err).Str("path", indexPath).Msg("invalid JSON")

		return nil, err
	}

	inUse := map[string]uint{}

	for _, manifest := range imgIndex.Manifests {
		inUse[manifest.Digest.Encoded()]++
	}

	for _, otherIndex := range otherImgIndexes {
		oindex, err := GetImageIndex(imgStore, repo, otherIndex.Digest, log)
		if err != nil {
			return nil, err
		}

		for _, omanifest := range oindex.Manifests {
			_, ok := inUse[omanifest.Digest.Encoded()]
			if ok {
				inUse[omanifest.Digest.Encoded()]++
			}
		}
	}

	prunedManifests := []ispec.Descriptor{}

	// for all manifests in the index, skip those that either have a tag or
	// are used in other imgIndexes
	for _, outManifest := range outIndex.Manifests {
		if outManifest.MediaType != ispec.MediaTypeImageManifest {
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}

		_, ok := outManifest.Annotations[ispec.AnnotationRefName]
		if ok {
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}

		count, ok := inUse[outManifest.Digest.Encoded()]
		if !ok {
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}

		if count != 1 {
			// this manifest is in use in other image indexes
			prunedManifests = append(prunedManifests, outManifest)

			continue
		}
	}

	return prunedManifests, nil
}

func ApplyLinter(imgStore ImageStore, linter Lint, repo string, manifestDesc ispec.Descriptor) (bool, error) {
	pass := true

	if linter != nil {
		tag := manifestDesc.Annotations[ispec.AnnotationRefName]
		// apply linter only on images, not signatures
		if manifestDesc.MediaType == ispec.MediaTypeImageManifest &&
			// check that image manifest is not cosign signature
			!strings.HasPrefix(tag, "sha256-") &&
			!strings.HasSuffix(tag, remote.SignatureTagSuffix) {
			// lint new index with new manifest before writing to disk
			pass, err := linter.Lint(repo, manifestDesc.Digest, imgStore)
			if err != nil {
				return false, err
			}

			if !pass {
				return false, zerr.ErrImageLintAnnotations
			}
		}
	}

	return pass, nil
}

func GetOrasReferrers(imgStore ImageStore, repo string, gdigest godigest.Digest, artifactType string,
	log zerolog.Logger,
) ([]oras.Descriptor, error) {
	if err := gdigest.Validate(); err != nil {
		return nil, err
	}

	dir := path.Join(imgStore.RootDir(), repo)
	if !imgStore.DirExists(dir) {
		return nil, zerr.ErrRepoNotFound
	}

	index, err := GetIndex(imgStore, repo, log)
	if err != nil {
		return nil, err
	}

	found := false

	result := []oras.Descriptor{}

	for _, manifest := range index.Manifests {
		if manifest.MediaType != oras.MediaTypeArtifactManifest {
			continue
		}

		artManifest, err := GetOrasManifestByDigest(imgStore, repo, manifest.Digest, log)
		if err != nil {
			return nil, err
		}

		if artManifest.Subject.Digest != gdigest {
			continue
		}

		// filter by artifact type
		if artifactType != "" && artManifest.ArtifactType != artifactType {
			continue
		}

		result = append(result, oras.Descriptor{
			MediaType:    manifest.MediaType,
			ArtifactType: artManifest.ArtifactType,
			Digest:       manifest.Digest,
			Size:         manifest.Size,
			Annotations:  manifest.Annotations,
		})

		found = true
	}

	if !found {
		return nil, zerr.ErrManifestNotFound
	}

	return result, nil
}

func getReferrerFilterAnnotation(artifactTypes []string) string {
	// as per spec, return what filters were applied as an annotation if artifactTypes
	annotation := ""

	for _, artifactType := range artifactTypes {
		if artifactType == "" {
			// ignore empty artifactTypes
			continue
		}

		if annotation == "" {
			annotation = artifactType
		} else {
			annotation += "," + artifactType
		}
	}

	return annotation
}

func GetReferrers(imgStore ImageStore, repo string, gdigest godigest.Digest, artifactTypes []string,
	log zerolog.Logger,
) (ispec.Index, error) {
	nilIndex := ispec.Index{}

	if err := gdigest.Validate(); err != nil {
		return nilIndex, err
	}

	dir := path.Join(imgStore.RootDir(), repo)
	if !imgStore.DirExists(dir) {
		return nilIndex, zerr.ErrRepoNotFound
	}

	index, err := GetIndex(imgStore, repo, log)
	if err != nil {
		return nilIndex, err
	}

	result := []ispec.Descriptor{}

	for _, manifest := range index.Manifests {
		if manifest.Digest == gdigest {
			continue
		}

		buf, err := imgStore.GetBlobContent(repo, manifest.Digest)
		if err != nil {
			log.Error().Err(err).Str("blob", imgStore.BlobPath(repo, manifest.Digest)).Msg("failed to read manifest")

			if os.IsNotExist(err) || errors.Is(err, driver.PathNotFoundError{}) {
				return nilIndex, zerr.ErrManifestNotFound
			}

			return nilIndex, err
		}

		if manifest.MediaType == ispec.MediaTypeImageManifest {
			var mfst ispec.Manifest
			if err := json.Unmarshal(buf, &mfst); err != nil {
				log.Error().Err(err).Str("manifest digest", manifest.Digest.String()).Msg("invalid JSON")

				return nilIndex, err
			}

			if mfst.Subject == nil || mfst.Subject.Digest != gdigest {
				continue
			}

			// filter by artifact type
			if len(artifactTypes) > 0 {
				found := false

				for _, artifactType := range artifactTypes {
					if artifactType != "" && mfst.Config.MediaType != artifactType {
						continue
					}

					found = true

					break
				}

				if !found {
					continue
				}
			}

			result = append(result, ispec.Descriptor{
				MediaType:    manifest.MediaType,
				ArtifactType: mfst.Config.MediaType,
				Size:         manifest.Size,
				Digest:       manifest.Digest,
				Annotations:  mfst.Annotations,
			})
		} else if manifest.MediaType == ispec.MediaTypeArtifactManifest {
			var art ispec.Artifact
			if err := json.Unmarshal(buf, &art); err != nil {
				log.Error().Err(err).Str("manifest digest", manifest.Digest.String()).Msg("invalid JSON")

				return nilIndex, err
			}

			if art.Subject == nil || art.Subject.Digest != gdigest {
				continue
			}

			// filter by artifact type
			if len(artifactTypes) > 0 {
				found := false
				for _, artifactType := range artifactTypes {
					if artifactType != "" && art.ArtifactType != artifactType {
						continue
					}

					found = true

					break
				}

				if !found {
					continue
				}
			}

			result = append(result, ispec.Descriptor{
				MediaType:    manifest.MediaType,
				ArtifactType: art.ArtifactType,
				Size:         manifest.Size,
				Digest:       manifest.Digest,
				Annotations:  art.Annotations,
			})
		}
	}

	index = ispec.Index{
		Versioned:   imeta.Versioned{SchemaVersion: storageConstants.SchemaVersion},
		MediaType:   ispec.MediaTypeImageIndex,
		Manifests:   result,
		Annotations: map[string]string{},
	}

	// as per spec, return what filters were applied as an annotation if artifactTypes
	if annotation := getReferrerFilterAnnotation(artifactTypes); annotation != "" {
		index.Annotations[storageConstants.ReferrerFilterAnnotation] = annotation
		log.Info().Str("annotation", annotation).Msg("filters applied")
	}

	return index, nil
}

func GetOrasManifestByDigest(imgStore ImageStore, repo string, digest godigest.Digest, log zerolog.Logger,
) (oras.Manifest, error) {
	var artManifest oras.Manifest

	blobPath := imgStore.BlobPath(repo, digest)

	buf, err := imgStore.GetBlobContent(repo, digest)
	if err != nil {
		log.Error().Err(err).Str("blob", blobPath).Msg("failed to read manifest")

		if os.IsNotExist(err) || errors.Is(err, driver.PathNotFoundError{}) {
			return artManifest, zerr.ErrManifestNotFound
		}

		return artManifest, err
	}

	if err := json.Unmarshal(buf, &artManifest); err != nil {
		log.Error().Err(err).Str("blob", blobPath).Msg("invalid JSON")

		return artManifest, err
	}

	return artManifest, nil
}

func IsSupportedMediaType(mediaType string) bool {
	return mediaType == ispec.MediaTypeImageIndex ||
		mediaType == ispec.MediaTypeImageManifest ||
		mediaType == ispec.MediaTypeArtifactManifest ||
		mediaType == oras.MediaTypeArtifactManifest
}

// imageIsSignature checks if the given image (repo:tag) represents a signature. The function
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

	var manifestContent oras.Manifest

	err := json.Unmarshal(manifestBlob, &manifestContent)
	if err != nil {
		return false, "", "", err
	}

	// check notation signature
	if manifestContent.Subject != nil {
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
