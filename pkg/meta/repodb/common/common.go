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

func ValidateRepoTagInput(repo, tag string, manifestDigest godigest.Digest) error {
	if repo == "" {
		return zerr.ErrEmptyRepoName
	}

	if tag == "" {
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

func GetImageLastUpdatedTimestamp(configBlob []byte) (time.Time, error) {
	var (
		configContent ispec.Image
		timeStamp     *time.Time
	)

	err := json.Unmarshal(configBlob, &configContent)
	if err != nil {
		return time.Time{}, err
	}

	if configContent.Created != nil && !configContent.Created.IsZero() {
		return *configContent.Created, nil
	}

	if len(configContent.History) != 0 {
		timeStamp = configContent.History[len(configContent.History)-1].Created
	}

	if timeStamp == nil {
		timeStamp = &time.Time{}
	}

	return *timeStamp, nil
}

func CheckIsSigned(signatures map[string][]string) bool {
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
