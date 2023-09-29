package common

import (
	"fmt"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	mTypes "zotregistry.io/zot/pkg/meta/types"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary //nolint: gochecknoglobals // to replace standard lib

func UpdateManifestMeta(repoMeta mTypes.RepoMetadata, manifestDigest godigest.Digest,
	manifestMeta mTypes.ManifestMetadata,
) mTypes.RepoMetadata {
	updatedRepoMeta := repoMeta

	updatedStatistics := repoMeta.Statistics[manifestDigest.String()]
	updatedStatistics.DownloadCount = manifestMeta.DownloadCount
	updatedRepoMeta.Statistics[manifestDigest.String()] = updatedStatistics

	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = mTypes.ManifestSignatures{}
	}

	updatedRepoMeta.Signatures[manifestDigest.String()] = manifestMeta.Signatures

	return updatedRepoMeta
}

func SignatureAlreadyExists(signatureSlice []mTypes.SignatureInfo, sm mTypes.SignatureMetadata) bool {
	for _, sigInfo := range signatureSlice {
		if sm.SignatureDigest == sigInfo.SignatureManifestDigest {
			return true
		}
	}

	return false
}

func ReferenceIsDigest(reference string) bool {
	_, err := godigest.Parse(reference)

	return err == nil
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
// The imporance of the value grows inversly proportional to the int value it has.
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

	// searchText containst just 1 diretory name
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

func GetReferredSubject(descriptorBlob []byte) (godigest.Digest, bool) {
	var manifest ispec.Manifest

	err := json.Unmarshal(descriptorBlob, &manifest)
	if err != nil {
		return "", false
	}

	if manifest.Subject == nil || manifest.Subject.Digest.String() == "" {
		return "", false
	}

	return manifest.Subject.Digest, true
}

func MatchesArtifactTypes(descriptorMediaType string, artifactTypes []string) bool {
	if len(artifactTypes) == 0 {
		return true
	}

	found := false

	for _, artifactType := range artifactTypes {
		if artifactType != "" && descriptorMediaType != artifactType {
			continue
		}

		found = true

		break
	}

	return found
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

func FilterDataByRepo(foundRepos []mTypes.RepoMetadata, manifestMetadataMap map[string]mTypes.ManifestMetadata,
	indexDataMap map[string]mTypes.IndexData,
) (map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	var (
		foundManifestMetadataMap = make(map[string]mTypes.ManifestMetadata)
		foundindexDataMap        = make(map[string]mTypes.IndexData)
	)

	// keep just the manifestMeta we need
	for _, repoMeta := range foundRepos {
		for _, descriptor := range repoMeta.Tags {
			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				foundManifestMetadataMap[descriptor.Digest] = manifestMetadataMap[descriptor.Digest]
			case ispec.MediaTypeImageIndex:
				indexData := indexDataMap[descriptor.Digest]

				var indexContent ispec.Index

				err := json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{},
						fmt.Errorf("metadb: error while getting manifest data for digest %s %w", descriptor.Digest, err)
				}

				for _, manifestDescriptor := range indexContent.Manifests {
					manifestDigest := manifestDescriptor.Digest.String()

					foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
				}

				foundindexDataMap[descriptor.Digest] = indexData
			default:
				continue
			}
		}
	}

	return foundManifestMetadataMap, foundindexDataMap, nil
}

func FetchDataForRepos(metaDB mTypes.MetaDB, foundRepos []mTypes.RepoMetadata,
) (map[string]mTypes.ManifestMetadata, map[string]mTypes.IndexData, error) {
	foundManifestMetadataMap := map[string]mTypes.ManifestMetadata{}
	foundIndexDataMap := map[string]mTypes.IndexData{}

	for idx := range foundRepos {
		for _, descriptor := range foundRepos[idx].Tags {
			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestData, err := metaDB.GetManifestData(godigest.Digest(descriptor.Digest))
				if err != nil {
					return map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{}, err
				}

				foundManifestMetadataMap[descriptor.Digest] = mTypes.ManifestMetadata{
					ManifestBlob: manifestData.ManifestBlob,
					ConfigBlob:   manifestData.ConfigBlob,
				}
			case ispec.MediaTypeImageIndex:
				indexData, err := metaDB.GetIndexData(godigest.Digest(descriptor.Digest))
				if err != nil {
					return map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{}, err
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return map[string]mTypes.ManifestMetadata{},
						map[string]mTypes.IndexData{},
						fmt.Errorf("metadb: error while getting index data for digest %s %w", descriptor.Digest, err)
				}

				for _, manifestDescriptor := range indexContent.Manifests {
					manifestDigest := manifestDescriptor.Digest.String()

					manifestData, err := metaDB.GetManifestData(manifestDescriptor.Digest)
					if err != nil {
						return map[string]mTypes.ManifestMetadata{}, map[string]mTypes.IndexData{}, err
					}

					foundManifestMetadataMap[manifestDigest] = mTypes.ManifestMetadata{
						ManifestBlob: manifestData.ManifestBlob,
						ConfigBlob:   manifestData.ConfigBlob,
					}
				}

				foundIndexDataMap[descriptor.Digest] = indexData
			}
		}
	}

	return foundManifestMetadataMap, foundIndexDataMap, nil
}

// FindMediaTypeForDigest will look into the buckets for a certain digest. Depending on which bucket that
// digest is found the corresponding mediatype is returned.
func FindMediaTypeForDigest(metaDB mTypes.MetaDB, digest godigest.Digest) (bool, string) {
	_, err := metaDB.GetManifestData(digest)
	if err == nil {
		return true, ispec.MediaTypeImageManifest
	}

	_, err = metaDB.GetIndexData(digest)
	if err == nil {
		return true, ispec.MediaTypeImageIndex
	}

	return false, ""
}

func GetImageDescriptor(metaDB mTypes.MetaDB, repo, tag string) (mTypes.Descriptor, error) {
	repoMeta, err := metaDB.GetRepoMeta(repo)
	if err != nil {
		return mTypes.Descriptor{}, err
	}

	imageDescriptor, ok := repoMeta.Tags[tag]
	if !ok {
		return mTypes.Descriptor{}, zerr.ErrTagMetaNotFound
	}

	return imageDescriptor, nil
}

func InitializeImageConfig(blob []byte) ispec.Image {
	var configContent ispec.Image

	err := json.Unmarshal(blob, &configContent)
	if err != nil {
		return ispec.Image{}
	}

	return configContent
}
