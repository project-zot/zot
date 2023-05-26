package storage

import (
	"encoding/json"
	"errors"
	"path"
	"strings"

	notreg "github.com/notaryproject/notation-go/registry"
	godigest "github.com/opencontainers/go-digest"
	imeta "github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "github.com/oras-project/artifacts-spec/specs-go/v1"
	"github.com/rs/zerolog"
	"github.com/sigstore/cosign/v2/pkg/oci/remote"

	zerr "zotregistry.io/zot/errors"
	zcommon "zotregistry.io/zot/pkg/common"
	"zotregistry.io/zot/pkg/scheduler"
	storageConstants "zotregistry.io/zot/pkg/storage/constants"
	storageTypes "zotregistry.io/zot/pkg/storage/types"
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
		var m oras.Descriptor
		if err := json.Unmarshal(body, &m); err != nil {
			log.Error().Err(err).Msg("unable to unmarshal JSON")

			return "", zerr.ErrBadManifest
		}
	}

	return "", nil
}

func validateOCIManifest(imgStore storageTypes.ImageStore, repo, reference string, //nolint:unparam
	manifest *ispec.Manifest, log zerolog.Logger,
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
	for _, layer := range manifest.Layers {
		if IsNonDistributable(layer.MediaType) {
			log.Warn().Str("digest", layer.Digest.String()).Str("mediaType", layer.MediaType).Msg("not validating layer exists")

			continue
		}

		_, err := imgStore.GetBlobContent(repo, layer.Digest)
		if err != nil {
			return layer.Digest, zerr.ErrBlobNotFound
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
func GetIndex(imgStore storageTypes.ImageStore, repo string, log zerolog.Logger) (ispec.Index, error) {
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
func GetImageIndex(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zerolog.Logger,
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

func GetImageManifest(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zerolog.Logger,
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
func PruneImageManifestsFromIndex(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, //nolint:gocyclo,lll
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
		if strings.HasPrefix(tag, "sha256-") && strings.HasSuffix(tag, remote.SignatureTagSuffix) {
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

func GetReferrers(imgStore storageTypes.ImageStore, repo string, gdigest godigest.Digest, artifactTypes []string,
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

			if errors.Is(err, zerr.ErrBlobNotFound) {
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
			manifestArtifactType := zcommon.GetManifestArtifactType(mfst)

			if len(artifactTypes) > 0 && !zcommon.Contains(artifactTypes, manifestArtifactType) {
				continue
			}

			result = append(result, ispec.Descriptor{
				MediaType:    manifest.MediaType,
				ArtifactType: manifestArtifactType,
				Size:         manifest.Size,
				Digest:       manifest.Digest,
				Annotations:  mfst.Annotations,
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

func GetOrasManifestByDigest(imgStore storageTypes.ImageStore, repo string, digest godigest.Digest, log zerolog.Logger,
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
	Log         zerolog.Logger
}

func (gen *DedupeTaskGenerator) GenerateTask() (scheduler.Task, error) {
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
	log            zerolog.Logger
}

func newDedupeTask(imgStore storageTypes.ImageStore, digest godigest.Digest, dedupe bool,
	duplicateBlobs []string, log zerolog.Logger,
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
