package common

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.dev/zot/v2/errors"
	zcommon "zotregistry.dev/zot/v2/pkg/common"
	"zotregistry.dev/zot/v2/pkg/compat"
	mConvert "zotregistry.dev/zot/v2/pkg/meta/convert"
	proto_go "zotregistry.dev/zot/v2/pkg/meta/proto/gen"
	mTypes "zotregistry.dev/zot/v2/pkg/meta/types"
)

var (
	// ErrInvalidRepoSize indicates that stored repository size metadata cannot be safely projected.
	ErrInvalidRepoSize = errors.New("invalid repository size")
	// ErrInvalidRepoSizeCandidate indicates invalid size data supplied by a manifest candidate.
	ErrInvalidRepoSizeCandidate = errors.New("invalid repository size candidate")
)

func SignatureAlreadyExists(signatureSlice []mTypes.SignatureInfo, sm mTypes.SignatureMetadata) bool {
	return slices.ContainsFunc(signatureSlice, func(sigInfo mTypes.SignatureInfo) bool {
		return sm.SignatureDigest == sigInfo.SignatureManifestDigest
	})
}

func ProtoSignatureAlreadyExists(signatureSlice []*proto_go.SignatureInfo, sm mTypes.SignatureMetadata) bool {
	return slices.ContainsFunc(signatureSlice, func(sigInfo *proto_go.SignatureInfo) bool {
		return sm.SignatureDigest == sigInfo.SignatureManifestDigest
	})
}

func ReferenceIsDigest(reference string) bool {
	_, err := godigest.Parse(reference)

	return err == nil
}

func ReferenceIsTag(reference string) bool {
	return !ReferenceIsDigest(reference)
}

func ValidateRepoReferenceInput(repo, reference string, manifestDigest godigest.Digest) error {
	if repo == "" {
		return zerr.ErrEmptyRepoName
	}

	if reference == "" {
		return zerr.ErrEmptyTag
	}

	if manifestDigest == "" {
		return zerr.ErrEmptyDigest
	}

	return nil
}

// These constants are meant used to describe how high or low in rank a match is.
// Note that the "higher rank" relates to a lower number so ranks are sorted in a
// ascending order.
const (
	lowPriority          = 100
	mediumPriority       = 10
	highPriority         = 1
	perfectMatchPriority = 0
)

// RankRepoName associates a rank to a given repoName given a searchText.
// The importance of the value grows inversely proportional to the int value it has.
// For example: rank(1) > rank(10) > rank(100)...
func RankRepoName(searchText string, repoName string) int {
	searchText = strings.Trim(searchText, "/")
	searchTextSlice := strings.Split(searchText, "/")
	repoNameSlice := strings.Split(repoName, "/")

	if len(searchTextSlice) > len(repoNameSlice) {
		return -1
	}

	if searchText == repoName {
		return perfectMatchPriority
	}

	// searchText contains just 1 directory name
	if len(searchTextSlice) == 1 {
		lastNameInRepoPath := repoNameSlice[len(repoNameSlice)-1]

		// searchText: "bar" | repoName: "foo/bar" lastNameInRepoPath: "bar"
		if index := strings.Index(lastNameInRepoPath, searchText); index != -1 {
			return (index + 1) * highPriority
		}

		firstNameInRepoPath := repoNameSlice[0]

		// searchText: "foo" | repoName: "foo/bar" firstNameInRepoPath: "foo"
		if index := strings.Index(firstNameInRepoPath, searchText); index != -1 {
			return (index + 1) * mediumPriority
		}
	}

	foundPrefixInRepoName := true

	// searchText: "foo/bar/rep"  | repoName: "foo/bar/baz/repo" foundPrefixInRepoName: true
	// searchText: "foo/baz/rep"  | repoName: "foo/bar/baz/repo" foundPrefixInRepoName: false
	for i := 0; i < len(searchTextSlice)-1; i++ {
		if searchTextSlice[i] != repoNameSlice[i] {
			foundPrefixInRepoName = false

			break
		}
	}

	if foundPrefixInRepoName {
		lastNameInRepoPath := repoNameSlice[len(repoNameSlice)-1]
		lastNameInSearchText := searchTextSlice[len(searchTextSlice)-1]

		// searchText: "foo/bar/epo"  | repoName: "foo/bar/baz/repo" -> Index(repo, epo) = 1
		if index := strings.Index(lastNameInRepoPath, lastNameInSearchText); index != -1 {
			return (index + 1) * highPriority
		}
	}

	// searchText: "foo/bar/b"  | repoName: "foo/bar/baz/repo"
	if strings.HasPrefix(repoName, searchText) {
		return mediumPriority
	}

	// searchText: "bar/ba"  | repoName: "foo/bar/baz/repo"
	if index := strings.Index(repoName, searchText); index != -1 {
		return (index + 1) * lowPriority
	}

	// no match
	return -1
}

func GetRepoTag(searchText string) (string, string, error) {
	const repoTagCount = 2

	splitSlice := strings.Split(searchText, ":")

	if len(splitSlice) != repoTagCount {
		return "", "", zerr.ErrInvalidRepoRefFormat
	}

	repo := strings.TrimSpace(splitSlice[0])
	tag := strings.TrimSpace(splitSlice[1])

	return repo, tag, nil
}

func MatchesArtifactTypes(descriptorMediaType string, artifactTypes []string) bool {
	if len(artifactTypes) == 0 {
		return true
	}

	return slices.ContainsFunc(artifactTypes, func(artifactType string) bool {
		return artifactType == "" || descriptorMediaType == artifactType
	})
}

// CheckImageLastUpdated check if the given image is updated earlier than the current repoLastUpdated value
//
// It returns updated values for: repoLastUpdated, noImageChecked, isSigned.
func CheckImageLastUpdated(repoLastUpdated time.Time, isSigned bool, noImageChecked bool,
	manifestFilterData mTypes.FilterData,
) (time.Time, bool, bool) {
	if noImageChecked || repoLastUpdated.Before(manifestFilterData.LastUpdated) {
		repoLastUpdated = manifestFilterData.LastUpdated
		noImageChecked = false

		isSigned = manifestFilterData.IsSigned
	}

	return repoLastUpdated, noImageChecked, isSigned
}

func AddImageMetaToRepoMeta(repoMeta *proto_go.RepoMeta, repoBlobs *proto_go.RepoBlobs, reference string,
	imageMeta mTypes.ImageMeta,
) (*proto_go.RepoMeta, *proto_go.RepoBlobs) {
	switch {
	case compat.IsImageManifestMediaType(imageMeta.MediaType):
		if len(imageMeta.Manifests) == 0 {
			// Empty manifests is an invalid state for ImageManifest, but we still add basic blob info
			// to avoid skipping all metadata processing (e.g., LastUpdatedImage update)
			repoBlobs.Blobs[imageMeta.Digest.String()] = &proto_go.BlobInfo{
				Size: imageMeta.Size,
			}

			break
		}

		manifestData := imageMeta.Manifests[0]

		vendor := GetVendor(manifestData.Manifest.Annotations)
		if vendor == "" {
			vendor = GetVendor(manifestData.Manifest.Annotations)
		}

		vendors := []string{}
		if vendor != "" {
			vendors = append(vendors, vendor)
		}

		platforms := []*proto_go.Platform{GetProtoPlatform(&manifestData.Config.Platform)}
		if platforms[0].OS == "" && platforms[0].Architecture == "" {
			platforms = []*proto_go.Platform{}
		}

		subBlobs := []string{manifestData.Manifest.Config.Digest.String()}
		repoBlobs.Blobs[manifestData.Manifest.Config.Digest.String()] = &proto_go.BlobInfo{
			Size: manifestData.Manifest.Config.Size,
		}

		for _, layer := range manifestData.Manifest.Layers {
			subBlobs = append(subBlobs, layer.Digest.String())
			repoBlobs.Blobs[layer.Digest.String()] = &proto_go.BlobInfo{Size: layer.Size}
		}

		lastUpdated := zcommon.GetImageLastUpdated(manifestData.Config)

		repoBlobs.Blobs[imageMeta.Digest.String()] = &proto_go.BlobInfo{
			Size:        imageMeta.Size,
			Vendors:     vendors,
			Platforms:   platforms,
			SubBlobs:    subBlobs,
			LastUpdated: mConvert.GetProtoTime(&lastUpdated),
		}
	case compat.IsImageIndexMediaType(imageMeta.MediaType):
		subBlobs := []string{}
		lastUpdated := time.Time{}

		for _, manifest := range imageMeta.Index.Manifests {
			subBlobs = append(subBlobs, manifest.Digest.String())

			blobInfo := repoBlobs.Blobs[manifest.Digest.String()]

			if blobInfo != nil && blobInfo.LastUpdated != nil {
				if lastUpdated.Before(blobInfo.LastUpdated.AsTime()) {
					lastUpdated = blobInfo.LastUpdated.AsTime()
				}
			}
		}

		repoBlobs.Blobs[imageMeta.Digest.String()] = &proto_go.BlobInfo{
			Size:        imageMeta.Size,
			SubBlobs:    subBlobs,
			LastUpdated: mConvert.GetProtoTime(&lastUpdated),
		}
	}

	// a manifest added by digest changes the repo info only when it belongs to an index which was
	// added before it, e.g. sparse on-demand sync stores the index before its manifests
	if zcommon.IsDigest(reference) {
		updatedIndexes := updateParentIndexesLastUpdated(repoBlobs, imageMeta.Digest.String())
		if len(updatedIndexes) == 0 {
			return repoMeta, repoBlobs
		}

		size, platforms, vendors := recalculateAggregateFields(repoMeta, repoBlobs)
		repoMeta.Vendors = vendors
		repoMeta.Platforms = platforms
		repoMeta.Size = size

		for tag, descriptor := range repoMeta.Tags {
			if _, found := updatedIndexes[descriptor.Digest]; !found {
				continue
			}

			repoMeta.LastUpdatedImage = mConvert.GetProtoEarlierUpdatedImage(repoMeta.LastUpdatedImage,
				&proto_go.RepoLastUpdatedImage{
					LastUpdated: repoBlobs.Blobs[descriptor.Digest].LastUpdated,
					MediaType:   descriptor.MediaType,
					Digest:      descriptor.Digest,
					Tag:         tag,
				})
		}

		return repoMeta, repoBlobs
	}

	size, platforms, vendors := recalculateAggregateFields(repoMeta, repoBlobs)
	repoMeta.Vendors = vendors
	repoMeta.Platforms = platforms
	repoMeta.Size = size

	imageBlobInfo := repoBlobs.Blobs[imageMeta.Digest.String()]

	repoMeta.LastUpdatedImage = mConvert.GetProtoEarlierUpdatedImage(repoMeta.LastUpdatedImage,
		&proto_go.RepoLastUpdatedImage{
			LastUpdated: imageBlobInfo.LastUpdated,
			MediaType:   imageMeta.MediaType,
			Digest:      imageMeta.Digest.String(),
			Tag:         reference,
		})

	return repoMeta, repoBlobs
}

// ProjectRepoSize applies an image candidate to already-loaded repository metadata and returns
// the stored size and the projected size. The supplied metadata is intentionally mutated in
// memory; callers must provide data which is not shared with the database state.
func ProjectRepoSize(repoMeta *proto_go.RepoMeta, repoBlobs *proto_go.RepoBlobs, references []string,
	imageMeta mTypes.ImageMeta,
) (int64, int64, error) {
	currentSize := repoMeta.Size
	if currentSize < 0 {
		return currentSize, math.MaxInt64, fmt.Errorf("%w: stored size is negative", ErrInvalidRepoSize)
	}

	if err := validateCandidateRepoSize(repoBlobs, imageMeta); err != nil {
		return currentSize, math.MaxInt64, err
	}

	for _, reference := range references {
		repoMeta.Tags[reference] = &proto_go.TagDescriptor{
			Digest:    imageMeta.Digest.String(),
			MediaType: imageMeta.MediaType,
		}
	}

	reference := imageMeta.Digest.String()
	if len(references) > 0 {
		reference = references[0]
	}

	AddImageMetaToRepoMeta(repoMeta, repoBlobs, reference, imageMeta)

	projectedSize, err := recalculateAggregateSize(repoMeta, repoBlobs)
	if err != nil {
		return currentSize, math.MaxInt64, err
	}

	return currentSize, projectedSize, nil
}

func validateCandidateRepoSize(repoBlobs *proto_go.RepoBlobs, imageMeta mTypes.ImageMeta) error {
	if imageMeta.Size < 0 {
		return fmt.Errorf("%w: manifest size is negative", ErrInvalidRepoSizeCandidate)
	}

	candidateBlobSizes := map[string]int64{}

	validateBlobSize := func(digest godigest.Digest, size int64) error {
		if size < 0 {
			return fmt.Errorf("%w: blob %s size is negative", ErrInvalidRepoSizeCandidate, digest)
		}

		if candidateSize, ok := candidateBlobSizes[digest.String()]; ok && candidateSize != size {
			return fmt.Errorf("%w: candidate blob %s size changed", ErrInvalidRepoSizeCandidate, digest)
		}

		if blobInfo, ok := repoBlobs.Blobs[digest.String()]; ok && blobInfo != nil && blobInfo.Size != size {
			return fmt.Errorf("%w: blob %s size changed", ErrInvalidRepoSizeCandidate, digest)
		}

		candidateBlobSizes[digest.String()] = size

		return nil
	}

	switch {
	case compat.IsImageManifestMediaType(imageMeta.MediaType):
		if len(imageMeta.Manifests) == 0 {
			return validateBlobSize(imageMeta.Digest, imageMeta.Size)
		}

		manifestData := imageMeta.Manifests[0]
		if err := validateBlobSize(manifestData.Digest, manifestData.Size); err != nil {
			return err
		}
		if err := validateBlobSize(manifestData.Manifest.Config.Digest, manifestData.Manifest.Config.Size); err != nil {
			return err
		}

		for _, layer := range manifestData.Manifest.Layers {
			if err := validateBlobSize(layer.Digest, layer.Size); err != nil {
				return err
			}
		}
	case compat.IsImageIndexMediaType(imageMeta.MediaType):
		if imageMeta.Index == nil {
			return fmt.Errorf("%w: image index is missing", ErrInvalidRepoSizeCandidate)
		}

		if err := validateBlobSize(imageMeta.Digest, imageMeta.Size); err != nil {
			return err
		}

		for _, manifest := range imageMeta.Index.Manifests {
			if err := validateBlobSize(manifest.Digest, manifest.Size); err != nil {
				return err
			}
		}
	}

	return nil
}

func recalculateAggregateSize(repoMeta *proto_go.RepoMeta, repoBlobs *proto_go.RepoBlobs) (int64, error) {
	size := int64(0)
	seen := map[string]struct{}{}

	for _, descriptor := range repoMeta.Tags {
		if descriptor == nil || descriptor.Digest == "" {
			continue
		}

		queue := []string{descriptor.Digest}
		for len(queue) > 0 {
			currentBlob := queue[0]
			queue = queue[1:]

			if _, found := seen[currentBlob]; found {
				continue
			}

			blobInfo := repoBlobs.Blobs[currentBlob]
			if blobInfo == nil {
				continue
			}
			if blobInfo.Size < 0 || size > math.MaxInt64-blobInfo.Size {
				return 0, fmt.Errorf("%w: aggregate size overflow", ErrInvalidRepoSize)
			}

			seen[currentBlob] = struct{}{}
			size += blobInfo.Size
			queue = append(queue, blobInfo.SubBlobs...)
		}
	}

	return size, nil
}

func RemoveImageFromRepoMeta(repoMeta *proto_go.RepoMeta, repoBlobs *proto_go.RepoBlobs, ref string,
) (*proto_go.RepoMeta, *proto_go.RepoBlobs) {
	var updatedLastImage *proto_go.RepoLastUpdatedImage

	updatedBlobs := map[string]*proto_go.BlobInfo{}
	updatedSize := int64(0)
	updatedVendors := []string{}
	updatedPlatforms := []*proto_go.Platform{}

	for tag, descriptor := range repoMeta.Tags {
		if descriptor.Digest == "" {
			continue
		}

		queue := []string{descriptor.Digest}

		// Check if blob info exists before accessing it to prevent nil pointer dereference.
		// When a tag is skipped due to nil blob info, that tag remains in repoMeta.Tags but
		// won't have any associated blobs in the result, creating metadata inconsistency.
		// This is acceptable in GC/cleanup scenarios where data may already be inconsistent
		// due to partial deletions or corruption.
		descriptorBlobInfo := repoBlobs.Blobs[descriptor.Digest]
		if descriptorBlobInfo == nil {
			continue
		}

		updatedLastImage = mConvert.GetProtoEarlierUpdatedImage(updatedLastImage, &proto_go.RepoLastUpdatedImage{
			LastUpdated: descriptorBlobInfo.LastUpdated,
			MediaType:   descriptor.MediaType,
			Digest:      descriptor.Digest,
			Tag:         tag,
		})

		for len(queue) > 0 {
			currentBlob := queue[0]
			queue = queue[1:]

			if _, found := updatedBlobs[currentBlob]; !found {
				blobInfo := repoBlobs.Blobs[currentBlob]
				if blobInfo == nil {
					continue
				}

				updatedBlobs[currentBlob] = blobInfo
				updatedSize += blobInfo.Size
				updatedVendors = mConvert.AddVendors(updatedVendors, blobInfo.Vendors)
				updatedPlatforms = mConvert.AddProtoPlatforms(updatedPlatforms, blobInfo.Platforms)

				queue = append(queue, blobInfo.SubBlobs...)
			}
		}
	}

	repoMeta.Size = updatedSize
	repoMeta.Vendors = updatedVendors
	repoMeta.Platforms = updatedPlatforms
	repoMeta.LastUpdatedImage = updatedLastImage

	repoBlobs.Blobs = updatedBlobs

	return repoMeta, repoBlobs
}

// updateParentIndexesLastUpdated recalculates the last updated time of the indexes referencing
// the given digest, directly or through nested indexes, and returns the digests of those indexes.
func updateParentIndexesLastUpdated(repoBlobs *proto_go.RepoBlobs, digest string) map[string]struct{} {
	updatedIndexes := map[string]struct{}{}
	queue := []string{digest}

	for len(queue) > 0 {
		child := queue[0]
		queue = queue[1:]

		for parentDigest, parentInfo := range repoBlobs.Blobs {
			if _, found := updatedIndexes[parentDigest]; found || !slices.Contains(parentInfo.GetSubBlobs(), child) {
				continue
			}

			lastUpdated := time.Time{}

			for _, subBlob := range parentInfo.SubBlobs {
				blobInfo := repoBlobs.Blobs[subBlob]

				if blobInfo != nil && blobInfo.LastUpdated != nil && lastUpdated.Before(blobInfo.LastUpdated.AsTime()) {
					lastUpdated = blobInfo.LastUpdated.AsTime()
				}
			}

			parentInfo.LastUpdated = mConvert.GetProtoTime(&lastUpdated)
			updatedIndexes[parentDigest] = struct{}{}
			queue = append(queue, parentDigest)
		}
	}

	return updatedIndexes
}

func recalculateAggregateFields(repoMeta *proto_go.RepoMeta, repoBlobs *proto_go.RepoBlobs,
) (int64, []*proto_go.Platform, []string) {
	size := int64(0)
	platforms := []*proto_go.Platform{}
	vendors := []string{}
	blobsMap := map[string]struct{}{}

	for _, descriptor := range repoMeta.Tags {
		if descriptor.Digest == "" {
			continue
		}

		queue := []string{descriptor.Digest}

		for len(queue) > 0 {
			currentBlob := queue[0]
			queue = queue[1:]

			if _, found := blobsMap[currentBlob]; !found {
				blobInfo := repoBlobs.Blobs[currentBlob]
				if blobInfo == nil {
					continue
				}

				blobsMap[currentBlob] = struct{}{}
				size += blobInfo.Size
				vendors = mConvert.AddVendors(vendors, blobInfo.Vendors)
				platforms = mConvert.AddProtoPlatforms(platforms, blobInfo.Platforms)

				queue = append(queue, blobInfo.SubBlobs...)
			}
		}
	}

	return size, platforms, vendors
}

func GetProtoPlatform(platform *ispec.Platform) *proto_go.Platform {
	if platform == nil {
		return nil
	}

	return &proto_go.Platform{
		Architecture: getArch(platform.Architecture, platform.Variant),
		OS:           platform.OS,
	}
}

func getArch(arch string, variant string) string {
	if variant != "" {
		arch = arch + "/" + variant
	}

	return arch
}

func GetVendor(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationVendor, "org.label-schema.vendor")
}

func GetAnnotationValue(annotations map[string]string, annotationKey, labelKey string) string {
	value, ok := annotations[annotationKey]
	if !ok || value == "" {
		value, ok = annotations[labelKey]
		if !ok {
			value = ""
		}
	}

	return value
}

func GetPartialImageMeta(imageIndexMeta mTypes.ImageMeta, imageMeta mTypes.ImageMeta) mTypes.ImageMeta {
	partialImageMeta := imageIndexMeta
	partialImageMeta.Manifests = imageMeta.Manifests

	partialIndex := deref(imageIndexMeta.Index, ispec.Index{})
	partialIndex.Manifests = getPartialManifestList(partialIndex.Manifests, imageMeta.Digest.String())

	partialImageMeta.Index = &partialIndex

	return partialImageMeta
}

func getPartialManifestList(descriptors []ispec.Descriptor, manifestDigest string) []ispec.Descriptor {
	result := []ispec.Descriptor{}

	for i := range descriptors {
		if descriptors[i].Digest.String() == manifestDigest {
			result = append(result, descriptors[i])
		}
	}

	return result
}

func deref[T any](pointer *T, defaultVal T) T {
	if pointer != nil {
		return *pointer
	}

	return defaultVal
}
