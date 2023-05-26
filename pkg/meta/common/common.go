package common

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	metaTypes "zotregistry.io/zot/pkg/meta/types"
)

func UpdateManifestMeta(repoMeta metaTypes.RepoMetadata, manifestDigest godigest.Digest,
	manifestMeta metaTypes.ManifestMetadata,
) metaTypes.RepoMetadata {
	updatedRepoMeta := repoMeta

	updatedStatistics := repoMeta.Statistics[manifestDigest.String()]
	updatedStatistics.DownloadCount = manifestMeta.DownloadCount
	updatedRepoMeta.Statistics[manifestDigest.String()] = updatedStatistics

	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = metaTypes.ManifestSignatures{}
	}

	updatedRepoMeta.Signatures[manifestDigest.String()] = manifestMeta.Signatures

	return updatedRepoMeta
}

func SignatureAlreadyExists(signatureSlice []metaTypes.SignatureInfo, sm metaTypes.SignatureMetadata) bool {
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

func GetImageLastUpdatedTimestamp(configContent ispec.Image) time.Time {
	var timeStamp *time.Time

	if configContent.Created != nil && !configContent.Created.IsZero() {
		return *configContent.Created
	}

	if len(configContent.History) != 0 {
		timeStamp = configContent.History[len(configContent.History)-1].Created
	}

	if timeStamp == nil {
		timeStamp = &time.Time{}
	}

	return *timeStamp
}

func CheckIsSigned(signatures metaTypes.ManifestSignatures) bool {
	for _, signatures := range signatures {
		if len(signatures) > 0 {
			return true
		}
	}

	return false
}

func GetRepoTag(searchText string) (string, string, error) {
	const repoTagCount = 2

	splitSlice := strings.Split(searchText, ":")

	if len(splitSlice) != repoTagCount {
		return "", "", zerr.ErrInvalidRepoTagFormat
	}

	repo := strings.TrimSpace(splitSlice[0])
	tag := strings.TrimSpace(splitSlice[1])

	return repo, tag, nil
}

func GetMapKeys[K comparable, V any](genericMap map[K]V) []K {
	keys := make([]K, 0, len(genericMap))

	for k := range genericMap {
		keys = append(keys, k)
	}

	return keys
}

// acceptedByFilter checks that data contains at least 1 element of each filter
// criteria(os, arch) present in filter.
func AcceptedByFilter(filter metaTypes.Filter, data metaTypes.FilterData) bool {
	if filter.Arch != nil {
		foundArch := false
		for _, arch := range filter.Arch {
			foundArch = foundArch || containsString(data.ArchList, *arch)
		}

		if !foundArch {
			return false
		}
	}

	if filter.Os != nil {
		foundOs := false
		for _, os := range filter.Os {
			foundOs = foundOs || containsString(data.OsList, *os)
		}

		if !foundOs {
			return false
		}
	}

	if filter.HasToBeSigned != nil && *filter.HasToBeSigned != data.IsSigned {
		return false
	}

	if filter.IsBookmarked != nil && *filter.IsBookmarked != data.IsBookmarked {
		return false
	}

	if filter.IsStarred != nil && *filter.IsStarred != data.IsStarred {
		return false
	}

	return true
}

func containsString(strSlice []string, str string) bool {
	for _, val := range strSlice {
		if strings.EqualFold(val, str) {
			return true
		}
	}

	return false
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
	manifestFilterData metaTypes.FilterData,
) (time.Time, bool, bool) {
	if noImageChecked || repoLastUpdated.Before(manifestFilterData.LastUpdated) {
		repoLastUpdated = manifestFilterData.LastUpdated
		noImageChecked = false

		isSigned = manifestFilterData.IsSigned
	}

	return repoLastUpdated, noImageChecked, isSigned
}

func FilterDataByRepo(foundRepos []metaTypes.RepoMetadata, manifestMetadataMap map[string]metaTypes.ManifestMetadata,
	indexDataMap map[string]metaTypes.IndexData,
) (map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, error) {
	var (
		foundManifestMetadataMap = make(map[string]metaTypes.ManifestMetadata)
		foundindexDataMap        = make(map[string]metaTypes.IndexData)
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
					return map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{},
						fmt.Errorf("metadb: error while getting manifest data for digest %s %w", descriptor.Digest, err)
				}

				for _, manifestDescriptor := range indexContent.Manifests {
					manifestDigest := manifestDescriptor.Digest.String()

					foundManifestMetadataMap[manifestDigest] = manifestMetadataMap[manifestDigest]
				}

				foundindexDataMap[descriptor.Digest] = indexData
			default:
			}
		}
	}

	return foundManifestMetadataMap, foundindexDataMap, nil
}

func FetchDataForRepos(metaDB metaTypes.MetaDB, foundRepos []metaTypes.RepoMetadata,
) (map[string]metaTypes.ManifestMetadata, map[string]metaTypes.IndexData, error) {
	foundManifestMetadataMap := map[string]metaTypes.ManifestMetadata{}
	foundIndexDataMap := map[string]metaTypes.IndexData{}

	for idx := range foundRepos {
		for _, descriptor := range foundRepos[idx].Tags {
			switch descriptor.MediaType {
			case ispec.MediaTypeImageManifest:
				manifestData, err := metaDB.GetManifestData(godigest.Digest(descriptor.Digest))
				if err != nil {
					return map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{}, err
				}

				foundManifestMetadataMap[descriptor.Digest] = metaTypes.ManifestMetadata{
					ManifestBlob: manifestData.ManifestBlob,
					ConfigBlob:   manifestData.ConfigBlob,
				}
			case ispec.MediaTypeImageIndex:
				indexData, err := metaDB.GetIndexData(godigest.Digest(descriptor.Digest))
				if err != nil {
					return map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{}, err
				}

				var indexContent ispec.Index

				err = json.Unmarshal(indexData.IndexBlob, &indexContent)
				if err != nil {
					return map[string]metaTypes.ManifestMetadata{},
						map[string]metaTypes.IndexData{},
						fmt.Errorf("metadb: error while getting index data for digest %s %w", descriptor.Digest, err)
				}

				for _, manifestDescriptor := range indexContent.Manifests {
					manifestDigest := manifestDescriptor.Digest.String()

					manifestData, err := metaDB.GetManifestData(manifestDescriptor.Digest)
					if err != nil {
						return map[string]metaTypes.ManifestMetadata{}, map[string]metaTypes.IndexData{}, err
					}

					foundManifestMetadataMap[manifestDigest] = metaTypes.ManifestMetadata{
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
