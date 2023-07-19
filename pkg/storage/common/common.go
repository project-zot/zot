package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"path"
	"strings"
	"time"

	"github.com/docker/distribution/registry/storage/driver"
	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/schema"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	zlog "zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/scheduler"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
)

const (
	manifestWithEmptyLayersErrMsg = "layers: Array must have at least 1 items"
	cosignSignatureTagSuffix      = "sig"
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

func ValidateManifest(imgStore storageTypes.ImageStore, repo, reference, mediaType string, body []byte,
	log zlog.Logger,
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

		// validate manifest
		if err := ValidateManifestSchema(body); err != nil {
			log.Error().Err(err).Msg("OCIv1 image manifest schema validation failed")

			return "", zerr.NewError(zerr.ErrBadManifest).AddDetail("jsonSchemaValidation", err.Error())
		}

		if err := json.Unmarshal(body, &manifest); err != nil {
			log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}

		if manifest.Config.MediaType == ispec.MediaTypeImageConfig {
			// validate layers - a lightweight check if the blob is present
			for _, layer := range manifest.Layers {
				if IsNonDistributable(layer.MediaType) {
					log.Debug().Str("digest", layer.Digest.String()).Str("mediaType", layer.MediaType).
						Msg("skip checking non-distributable layer exists")

					continue
				}

				ok, _, _, err := imgStore.StatBlob(repo, layer.Digest)
				if !ok || err != nil {
					log.Error().Err(err).Str("digest", layer.Digest.String()).Msg("missing layer blob")

					return "", zerr.ErrBadManifest
				}
			}
		}
	case oras.MediaTypeArtifactManifest:
		var m oras.Descriptor
		if err := json.Unmarshal(body, &m); err != nil {
			log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}
	case ispec.MediaTypeImageIndex:
		// validate manifest
		if err := ValidateImageIndexSchema(body); err != nil {
			log.Error().Err(err).Msg("OCIv1 image index manifest schema validation failed")

			return "", zerr.NewError(zerr.ErrBadManifest).AddDetail("jsonSchemaValidation", err.Error())
		}

		var indexManifest ispec.Index
		if err := json.Unmarshal(body, &indexManifest); err != nil {
			log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}

		for _, manifest := range indexManifest.Manifests {
			if ok, _, _, err := imgStore.StatBlob(repo, manifest.Digest); !ok || err != nil {
				log.Error().Err(err).Str("digest", manifest.Digest.String()).Msg("missing manifest blob")

				return "", zerr.ErrBadManifest
			}
		}
	}

	return "", nil
}

func GetAndValidateRequestDigest(body []byte, digestStr string, log zlog.Logger) (godigest.Digest, error) {
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
	log zlog.Logger,
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
			updateIndex = false

			break
		}

		v, ok := manifest.Annotations[ispec.AnnotationRefName]
		if ok && v == reference {
			if manifest.Digest.String() == desc.Digest.String() {
				// nothing changed, so don't update
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
				reason := fmt.Sprintf("changing manifest media-type from \"%s\" to \"%s\" is disallowed",
					manifest.MediaType, desc.MediaType)

				return false, "", zerr.NewError(err).AddDetail("reason", reason)
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
func GetIndex(imgStore storageTypes.ImageStore, repo string, log zlog.Logger) (ispec.Index, error) {
	var index ispec.Index

	buf, err := imgStore.GetIndexContent(repo)
	if err != nil {
		if errors.As(err, &driver.PathNotFoundError{}) {
			return index, zerr.ErrRepoNotFound
		}

		return index, err
	}

	if err := json.Unmarshal(buf, &index); err != nil {
		log.Error().Err(err).Str("dir", path.Join(imgStore.RootDir(), repo)).Msg("invalid JSON")

		return index, zerr.ErrRepoBadVersion
	}

	return index, nil
}

// GetImageIndex returns a multiarch type image.
func GetImageIndex(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zlog.Logger,
) (ispec.Index, error) {
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

func GetImageManifest(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zlog.Logger,
) (ispec.Manifest, error) {
	var manifestContent ispec.Manifest

	manifestBlob, err := imgStore.GetBlobContent(repo, digest)
	if err != nil {
		return manifestContent, err
	}

	manifestPath := path.Join(imgStore.RootDir(), repo, "blobs",
		digest.Algorithm().String(), digest.Encoded())

	if err := json.Unmarshal(manifestBlob, &manifestContent); err != nil {
		log.Error().Err(err).Str("path", manifestPath).Msg("invalid JSON")

		return manifestContent, err
	}

	return manifestContent, nil
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
func UpdateIndexWithPrunedImageManifests(imgStore storageTypes.ImageStore, index *ispec.Index, repo string,
	desc ispec.Descriptor, oldDgst godigest.Digest, log zlog.Logger,
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
func PruneImageManifestsFromIndex(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, //nolint:gocyclo,lll
	outIndex ispec.Index, otherImgIndexes []ispec.Descriptor, log zlog.Logger,
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

func isBlobReferencedInImageManifest(imgStore storageTypes.ImageStore, repo string,
	bdigest, mdigest godigest.Digest, log zlog.Logger,
) (bool, error) {
	if bdigest == mdigest {
		return true, nil
	}

	manifestContent, err := GetImageManifest(imgStore, repo, mdigest, log)
	if err != nil {
		log.Error().Err(err).Str("repo", repo).Str("digest", mdigest.String()).
			Msg("gc: failed to read manifest image")

		return false, err
	}

	if bdigest == manifestContent.Config.Digest {
		return true, nil
	}

	for _, layer := range manifestContent.Layers {
		if bdigest == layer.Digest {
			return true, nil
		}
	}

	return false, nil
}

func IsBlobReferencedInImageIndex(imgStore storageTypes.ImageStore, repo string,
	digest godigest.Digest, index ispec.Index, log zlog.Logger,
) (bool, error) {
	for _, desc := range index.Manifests {
		var found bool

		switch desc.MediaType {
		case ispec.MediaTypeImageIndex:
			indexImage, err := GetImageIndex(imgStore, repo, desc.Digest, log)
			if err != nil {
				log.Error().Err(err).Str("repository", repo).Str("digest", desc.Digest.String()).
					Msg("failed to read multiarch(index) image")

				return false, err
			}

			found, _ = IsBlobReferencedInImageIndex(imgStore, repo, digest, indexImage, log)
		case ispec.MediaTypeImageManifest:
			found, _ = isBlobReferencedInImageManifest(imgStore, repo, digest, desc.Digest, log)
		}

		if found {
			return true, nil
		}
	}

	return false, nil
}

func IsBlobReferenced(imgStore storageTypes.ImageStore, repo string,
	digest godigest.Digest, log zlog.Logger,
) (bool, error) {
	dir := path.Join(imgStore.RootDir(), repo)
	if !imgStore.DirExists(dir) {
		return false, zerr.ErrRepoNotFound
	}

	index, err := GetIndex(imgStore, repo, log)
	if err != nil {
		return false, err
	}

	return IsBlobReferencedInImageIndex(imgStore, repo, digest, index, log)
}

/* Garbage Collection */

func AddImageManifestBlobsToReferences(imgStore storageTypes.ImageStore,
	repo string, mdigest godigest.Digest, refBlobs map[string]bool, log zlog.Logger,
) error {
	manifestContent, err := GetImageManifest(imgStore, repo, mdigest, log)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("digest", mdigest.String()).
			Msg("gc: failed to read manifest image")

		return err
	}

	refBlobs[mdigest.String()] = true
	refBlobs[manifestContent.Config.Digest.String()] = true

	// if there is a Subject, it may not exist yet and that is ok
	if manifestContent.Subject != nil {
		refBlobs[manifestContent.Subject.Digest.String()] = true
	}

	for _, layer := range manifestContent.Layers {
		refBlobs[layer.Digest.String()] = true
	}

	return nil
}

func AddORASImageManifestBlobsToReferences(imgStore storageTypes.ImageStore,
	repo string, mdigest godigest.Digest, refBlobs map[string]bool, log zlog.Logger,
) error {
	manifestContent, err := GetOrasManifestByDigest(imgStore, repo, mdigest, log)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("digest", mdigest.String()).
			Msg("gc: failed to read manifest image")

		return err
	}

	refBlobs[mdigest.String()] = true

	// if there is a Subject, it may not exist yet and that is ok
	if manifestContent.Subject != nil {
		refBlobs[manifestContent.Subject.Digest.String()] = true
	}

	for _, blob := range manifestContent.Blobs {
		refBlobs[blob.Digest.String()] = true
	}

	return nil
}

func AddImageIndexBlobsToReferences(imgStore storageTypes.ImageStore,
	repo string, mdigest godigest.Digest, refBlobs map[string]bool, log zlog.Logger,
) error {
	index, err := GetImageIndex(imgStore, repo, mdigest, log)
	if err != nil {
		log.Error().Err(err).Str("repository", repo).Str("digest", mdigest.String()).
			Msg("gc: failed to read manifest image")

		return err
	}

	refBlobs[mdigest.String()] = true

	// if there is a Subject, it may not exist yet and that is ok
	if index.Subject != nil {
		refBlobs[index.Subject.Digest.String()] = true
	}

	for _, manifest := range index.Manifests {
		refBlobs[manifest.Digest.String()] = true
	}

	return nil
}

func AddIndexBlobToReferences(imgStore storageTypes.ImageStore,
	repo string, index ispec.Index, refBlobs map[string]bool, log zlog.Logger,
) error {
	for _, desc := range index.Manifests {
		switch desc.MediaType {
		case ispec.MediaTypeImageIndex:
			if err := AddImageIndexBlobsToReferences(imgStore, repo, desc.Digest, refBlobs, log); err != nil {
				log.Error().Err(err).Str("repository", repo).Str("digest", desc.Digest.String()).
					Msg("failed to read blobs in multiarch(index) image")

				return err
			}
		case ispec.MediaTypeImageManifest:
			if err := AddImageManifestBlobsToReferences(imgStore, repo, desc.Digest, refBlobs, log); err != nil {
				log.Error().Err(err).Str("repository", repo).Str("digest", desc.Digest.String()).
					Msg("failed to read blobs in image manifest")

				return err
			}
		case oras.MediaTypeArtifactManifest:
			if err := AddORASImageManifestBlobsToReferences(imgStore, repo, desc.Digest, refBlobs, log); err != nil {
				log.Error().Err(err).Str("repository", repo).Str("digest", desc.Digest.String()).
					Msg("failed to read blobs in image manifest")

				return err
			}
		}
	}

	return nil
}

func AddRepoBlobsToReferences(imgStore storageTypes.ImageStore,
	repo string, refBlobs map[string]bool, log zlog.Logger,
) error {
	dir := path.Join(imgStore.RootDir(), repo)
	if !imgStore.DirExists(dir) {
		return zerr.ErrRepoNotFound
	}

	index, err := GetIndex(imgStore, repo, log)
	if err != nil {
		return err
	}

	return AddIndexBlobToReferences(imgStore, repo, index, refBlobs, log)
}

func ApplyLinter(imgStore storageTypes.ImageStore, linter Lint, repo string, descriptor ispec.Descriptor,
) (bool, error) {
	pass := true

	// we'll skip anything that's not a image manifest
	if descriptor.MediaType != ispec.MediaTypeImageManifest {
		return pass, nil
	}

	if linter != nil && !IsSignature(descriptor) {
		// lint new index with new manifest before writing to disk
		pass, err := linter.Lint(repo, descriptor.Digest, imgStore)
		if err != nil {
			return false, err
		}

		if !pass {
			return false, zerr.ErrImageLintAnnotations
		}
	}

	return pass, nil
}

func IsSignature(descriptor ispec.Descriptor) bool {
	tag := descriptor.Annotations[ispec.AnnotationRefName]

	switch descriptor.MediaType {
	case ispec.MediaTypeImageManifest:
		// is cosgin signature
		if strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, cosignSignatureTagSuffix) {
			return true
		}

		// is notation signature
		if descriptor.ArtifactType == notreg.ArtifactTypeNotation {
			return true
		}
	default:
		return false
	}

	return false
}

func GetOrasReferrers(imgStore storageTypes.ImageStore, repo string, gdigest godigest.Digest, artifactType string,
	log zlog.Logger,
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

func GetReferrers(imgStore storageTypes.ImageStore, repo string, gdigest godigest.Digest, artifactTypes []string,
	log zlog.Logger,
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

	for _, descriptor := range index.Manifests {
		if descriptor.Digest == gdigest {
			continue
		}

		buf, err := imgStore.GetBlobContent(repo, descriptor.Digest)
		if err != nil {
			log.Error().Err(err).Str("blob", imgStore.BlobPath(repo, descriptor.Digest)).Msg("failed to read manifest")

			if errors.Is(err, zerr.ErrBlobNotFound) {
				return nilIndex, zerr.ErrManifestNotFound
			}

			return nilIndex, err
		}

		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			var manifestContent ispec.Manifest

			if err := json.Unmarshal(buf, &manifestContent); err != nil {
				log.Error().Err(err).Str("manifest digest", descriptor.Digest.String()).Msg("invalid JSON")

				return nilIndex, err
			}

			if manifestContent.Subject == nil || manifestContent.Subject.Digest != gdigest {
				continue
			}

			// filter by artifact type
			manifestArtifactType := zcommon.GetManifestArtifactType(manifestContent)

			if len(artifactTypes) > 0 && !zcommon.Contains(artifactTypes, manifestArtifactType) {
				continue
			}

			result = append(result, ispec.Descriptor{
				MediaType:    descriptor.MediaType,
				ArtifactType: manifestArtifactType,
				Size:         descriptor.Size,
				Digest:       descriptor.Digest,
				Annotations:  manifestContent.Annotations,
			})
		case ispec.MediaTypeImageIndex:
			var indexContent ispec.Index

			if err := json.Unmarshal(buf, &indexContent); err != nil {
				log.Error().Err(err).Str("manifest digest", descriptor.Digest.String()).Msg("invalid JSON")

				return nilIndex, err
			}

			if indexContent.Subject == nil || indexContent.Subject.Digest != gdigest {
				continue
			}

			indexArtifactType := zcommon.GetIndexArtifactType(indexContent)

			if len(artifactTypes) > 0 && !zcommon.Contains(artifactTypes, indexArtifactType) {
				continue
			}

			result = append(result, ispec.Descriptor{
				MediaType:    descriptor.MediaType,
				ArtifactType: indexArtifactType,
				Size:         descriptor.Size,
				Digest:       descriptor.Digest,
				Annotations:  indexContent.Annotations,
			})
		}
	}

	index = ispec.Index{
		Versioned:   imeta.Versioned{SchemaVersion: storageConstants.SchemaVersion},
		MediaType:   ispec.MediaTypeImageIndex,
		Manifests:   result,
		Annotations: map[string]string{},
	}

	return index, nil
}

func GetOrasManifestByDigest(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zlog.Logger,
) (oras.Manifest, error) {
	var artManifest oras.Manifest

	blobPath := imgStore.BlobPath(repo, digest)

	buf, err := imgStore.GetBlobContent(repo, digest)
	if err != nil {
		log.Error().Err(err).Str("blob", blobPath).Msg("failed to read manifest")

		if errors.Is(err, zerr.ErrBlobNotFound) {
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
		mediaType == oras.MediaTypeArtifactManifest
}

func IsNonDistributable(mediaType string) bool {
	return mediaType == ispec.MediaTypeImageLayerNonDistributable || //nolint:staticcheck
		mediaType == ispec.MediaTypeImageLayerNonDistributableGzip || //nolint:staticcheck
		mediaType == ispec.MediaTypeImageLayerNonDistributableZstd //nolint:staticcheck
}

func ValidateManifestSchema(buf []byte) error {
	if err := schema.ValidatorMediaTypeManifest.Validate(bytes.NewBuffer(buf)); err != nil {
		if !IsEmptyLayersError(err) {
			return err
		}
	}

	return nil
}

func ValidateImageIndexSchema(buf []byte) error {
	if err := schema.ValidatorMediaTypeImageIndex.Validate(bytes.NewBuffer(buf)); err != nil {
		return err
	}

	return nil
}

func IsEmptyLayersError(err error) bool {
	var validationErr schema.ValidationError
	if errors.As(err, &validationErr) {
		if len(validationErr.Errs) == 1 && strings.Contains(err.Error(), manifestWithEmptyLayersErrMsg) {
			return true
		} else {
			return false
		}
	}

	return false
}

/*
	DedupeTaskGenerator takes all blobs paths found in the storage.imagestore and groups them by digest

for each digest and based on the dedupe value it will dedupe or restore deduped blobs to the original state(undeduped)\
by creating a task for each digest and pushing it to the task scheduler.
*/
type DedupeTaskGenerator struct {
	ImgStore storageTypes.ImageStore
	// storage dedupe value
	Dedupe bool
	// store blobs paths grouped by digest
	digest         godigest.Digest
	duplicateBlobs []string
	/* store processed digest, used for iterating duplicateBlobs one by one
	and generating a task for each unprocessed one*/
	lastDigests []godigest.Digest
	done        bool
	Log         zlog.Logger
}

func (gen *DedupeTaskGenerator) Next() (scheduler.Task, error) {
	var err error

	// get all blobs from storage.imageStore and group them by digest
	gen.digest, gen.duplicateBlobs, err = gen.ImgStore.GetNextDigestWithBlobPaths(gen.lastDigests)
	if err != nil {
		gen.Log.Error().Err(err).Msg("dedupe rebuild: failed to get next digest")

		return nil, err
	}

	// if no digests left, then mark the task generator as done
	if gen.digest == "" {
		gen.Log.Info().Msg("dedupe rebuild: finished")

		gen.done = true

		return nil, nil
	}

	// mark digest as processed before running its task
	gen.lastDigests = append(gen.lastDigests, gen.digest)

	// generate rebuild dedupe task for this digest
	return newDedupeTask(gen.ImgStore, gen.digest, gen.Dedupe, gen.duplicateBlobs, gen.Log), nil
}

func (gen *DedupeTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *DedupeTaskGenerator) IsReady() bool {
	return true
}

func (gen *DedupeTaskGenerator) Reset() {
	gen.lastDigests = []godigest.Digest{}
	gen.duplicateBlobs = []string{}
	gen.digest = ""
	gen.done = false
}

type dedupeTask struct {
	imgStore storageTypes.ImageStore
	// digest of duplicateBLobs
	digest godigest.Digest
	// blobs paths with the same digest ^
	duplicateBlobs []string
	dedupe         bool
	log            zlog.Logger
}

func newDedupeTask(imgStore storageTypes.ImageStore, digest godigest.Digest, dedupe bool,
	duplicateBlobs []string, log zlog.Logger,
) *dedupeTask {
	return &dedupeTask{imgStore, digest, duplicateBlobs, dedupe, log}
}

func (dt *dedupeTask) DoWork() error {
	// run task
	err := dt.imgStore.RunDedupeForDigest(dt.digest, dt.dedupe, dt.duplicateBlobs)
	if err != nil {
		// log it
		dt.log.Error().Err(err).Str("digest", dt.digest.String()).Msg("rebuild dedupe: failed to rebuild digest")
	}

	return err
}

/*
	GCTaskGenerator takes all repositories found in the storage.imagestore

and it will execute garbage collection for each repository by creating a task
for each repository and pushing it to the task scheduler.
*/
type GCTaskGenerator struct {
	ImgStore storageTypes.ImageStore
	lastRepo string
	nextRun  time.Time
	done     bool
	rand     *rand.Rand
}

func (gen *GCTaskGenerator) getRandomDelay() int {
	maxDelay := 30

	return gen.rand.Intn(maxDelay)
}

func (gen *GCTaskGenerator) Next() (scheduler.Task, error) {
	if gen.lastRepo == "" && gen.nextRun.IsZero() {
		gen.rand = rand.New(rand.NewSource(time.Now().UTC().UnixNano())) //nolint: gosec
	}

	delay := gen.getRandomDelay()

	gen.nextRun = time.Now().Add(time.Duration(delay) * time.Second)

	repo, err := gen.ImgStore.GetNextRepository(gen.lastRepo)
	if err != nil {
		return nil, err
	}

	if repo == "" {
		gen.done = true

		return nil, nil
	}

	gen.lastRepo = repo

	return NewGCTask(gen.ImgStore, repo), nil
}

func (gen *GCTaskGenerator) IsDone() bool {
	return gen.done
}

func (gen *GCTaskGenerator) IsReady() bool {
	return time.Now().After(gen.nextRun)
}

func (gen *GCTaskGenerator) Reset() {
	gen.lastRepo = ""
	gen.done = false
	gen.nextRun = time.Time{}
}

type gcTask struct {
	imgStore storageTypes.ImageStore
	repo     string
}

func NewGCTask(imgStore storageTypes.ImageStore, repo string,
) *gcTask {
	return &gcTask{imgStore, repo}
}

func (gct *gcTask) DoWork() error {
	// run task
	return gct.imgStore.RunGCRepo(gct.repo)
}
