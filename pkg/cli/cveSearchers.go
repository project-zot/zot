package cli

import (
	"errors"
	"fmt"
)

func getSearchers() []searcher {
	searchers := []searcher{
		new(searchCveByID),
		new(searchByImageName),
		new(searchByImageNameAndTag),
		new(searchByPackageNameAndVersion),
		new(searchByPackageName),
		new(searchByPackageVendor),
	}

	return searchers
}

var allowedCombinations = `
Only these combinations of flags(or their shorthands) are allowed:
  --cve-id
  --image-name
  --image-name --tag
  --package-vendor
  --package-name
  --package-name --package-version
  --package-version
`

type searcher interface {
	search(params map[string]*string) (string, error)
}

func canSearch(params map[string]*string, requiredParams *set) bool {
	for key, value := range params {
		if requiredParams.contains(key) && *value == "" {
			return false
		} else if !requiredParams.contains(key) && *value != "" {
			return false
		}
	}
	return true
}

type searchCveByID struct{}

func (search searchCveByID) search(params map[string]*string) (string, error) {
	if !canSearch(params, newSet("cveID")) {
		return "", errors.New("searchByCveId: cannot search with given params. Only CVE ID is required")
	}
	return fmt.Sprintf("Searching with CVE ID: %s", *params["cveID"]), nil
}

type searchImageByCveID struct{}

func (search searchImageByCveID) search(params map[string]*string) (string, error) {
	if !canSearch(params, newSet("cveIDForImage")) {
		return "", errors.New("searchImageByCveID: cannot search image with given params. Only CVE ID is required")
	}
	return fmt.Sprintf("Searching image with CVE ID: %s", *params["cveID"]), nil
}

type searchByImageNameAndTag struct{}

func (search searchByImageNameAndTag) search(params map[string]*string) (string, error) {

	if !canSearch(params, newSet("imageName", "tag")) {
		return "", errors.New("searchByImageNameAndTag: cannot search with given params. Only image name and tag are required")
	}
	return fmt.Sprintf("Searching with image name and tag: %s and %s", *params["imageName"], *params["tag"]), nil
}

type searchByImageName struct{}

func (search searchByImageName) search(params map[string]*string) (string, error) {
	if !canSearch(params, newSet("imageName")) {
		return "", errors.New("searchByImageName: cannot search with given params. Only image name is required")
	}
	return fmt.Sprintf("Searching with image name: %s", *params["imageName"]), nil
}

type searchByPackageNameAndVersion struct{}

func (search searchByPackageNameAndVersion) search(params map[string]*string) (string, error) {
	if !canSearch(params, newSet("packageName", "packageVersion")) {
		return "", errors.New("searchByPackageNameAndVersion: cannot search with given params. Only package name and version are required")
	}
	return fmt.Sprintf("Searching with package name: %s and version %s", *params["packageName"], *params["packageVersion"]), nil
}

type searchByPackageName struct{}

func (search searchByPackageName) search(params map[string]*string) (string, error) {
	if !canSearch(params, newSet("packageName")) {
		return "", errors.New("searchByPackageName: cannot search with given params. Only package name is required")
	}
	return fmt.Sprintf("Searching with package name: %s", *params["packageName"]), nil
}

type searchByPackageVendor struct{}

func (search searchByPackageVendor) search(params map[string]*string) (string, error) {
	if !canSearch(params, newSet("packageVendor")) {
		return "", errors.New("searchByPackageVendor: cannot search with given params. Only package vendor is required")
	}
	return fmt.Sprintf("Searching with package vendor: %s", *params["packageVendor"]), nil
}

var exists = struct{}{}

type set struct {
	m map[string]struct{}
}

func newSet(initialValues ...string) *set {
	s := &set{}
	s.m = make(map[string]struct{})
	for _, val := range initialValues {
		s.m[val] = exists
	}
	return s
}

func (s *set) contains(value string) bool {
	_, c := s.m[value]
	return c
}
