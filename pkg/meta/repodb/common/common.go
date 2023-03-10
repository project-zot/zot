package common

import (
	"encoding/json"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zerr "zotregistry.io/zot/errors"
	"zotregistry.io/zot/pkg/meta/repodb"
)

func UpdateManifestMeta(repoMeta repodb.RepoMetadata, manifestDigest godigest.Digest,
	manifestMeta repodb.ManifestMetadata,
) repodb.RepoMetadata {
	updatedRepoMeta := repoMeta

	updatedStatistics := repoMeta.Statistics[manifestDigest.String()]
	updatedStatistics.DownloadCount = manifestMeta.DownloadCount
	updatedRepoMeta.Statistics[manifestDigest.String()] = updatedStatistics

	if manifestMeta.Signatures == nil {
		manifestMeta.Signatures = repodb.ManifestSignatures{}
	}

	updatedRepoMeta.Signatures[manifestDigest.String()] = manifestMeta.Signatures

	return updatedRepoMeta
}

func SignatureAlreadyExists(signatureSlice []repodb.SignatureInfo, sm repodb.SignatureMetadata) bool {
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

func ScoreRepoName(searchText string, repoName string) int {
	searchTextSlice := strings.Split(searchText, "/")
	repoNameSlice := strings.Split(repoName, "/")

	if len(searchTextSlice) > len(repoNameSlice) {
		return -1
	}

	if len(searchTextSlice) == 1 {
		// check if it maches first or last name in path
		if index := strings.Index(repoNameSlice[len(repoNameSlice)-1], searchTextSlice[0]); index != -1 {
			return index + 1
		}

		// we'll make repos that match the first name in path less important than matching the last name in path
		if index := strings.Index(repoNameSlice[0], searchTextSlice[0]); index != -1 {
			return (index + 1) * 10
		}

		return -1
	}

	if len(searchTextSlice) < len(repoNameSlice) &&
		strings.HasPrefix(repoName, searchText) {
		return 1
	}

	// searchText and repoName match perfectly up until the last name in path
	for i := 0; i < len(searchTextSlice)-1; i++ {
		if searchTextSlice[i] != repoNameSlice[i] {
			return -1
		}
	}

	// check the last
	if index := strings.Index(repoNameSlice[len(repoNameSlice)-1], searchTextSlice[len(searchTextSlice)-1]); index != -1 {
		return (index + 1)
	}

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

func CheckIsSigned(signatures repodb.ManifestSignatures) bool {
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
func AcceptedByFilter(filter repodb.Filter, data repodb.FilterData) bool {
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
