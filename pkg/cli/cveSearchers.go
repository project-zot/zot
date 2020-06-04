package cli

import (
	"errors"
	"fmt"
)

func getSearchers() []searcher {
	searchers := []searcher{
		new(cveByIDSearcher),
		new(cveByImageNameSearcher),
		new(cveByImageNameAndTagSearcher),
		new(cveByPackageNameAndVersionSearcher),
		new(cveByPackageNameSearcher),
		new(cveByPackageVendorSearcher),
		new(imageByCveIDSearcher),
		new(cveByPackageVersionSearcher),
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

URL of the zot repository with --url is required
`

type searcher interface {
	search(params map[string]*string, searchService CveSearchService) (string, error)
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

type cveByIDSearcher struct{}

func (search cveByIDSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {
	if !canSearch(params, newSet("cveID")) {
		return "", cannotSearchError
	}
	return fmt.Sprintf("Searching with CVE ID: %s", *params["cveID"]), nil
}

type imageByCveIDSearcher struct{}

func (search imageByCveIDSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {
	if !canSearch(params, newSet("cveIDForImage")) {
		return "", cannotSearchError
	}
	if results, err := searchService.findImagesByCveId(*params["cveIDForImage"], servURL); err != nil {
		return "", err
	} else {
		return results.String(), nil
	}
}

type cveByImageNameAndTagSearcher struct{}

func (search cveByImageNameAndTagSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {

	if !canSearch(params, newSet("imageName", "tag")) {
		return "", cannotSearchError
	}
	return fmt.Sprintf("Searching with image name and tag: %s and %s", *params["imageName"], *params["tag"]), nil
}

type cveByImageNameSearcher struct{}

func (search cveByImageNameSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {
	if !canSearch(params, newSet("imageName")) {
		return "", cannotSearchError
	}
	if results, err := searchService.findCveByImageName(*params["imageName"], servURL); err != nil {
		return "", err
	} else {
		return results.String(), nil
	}
}

type cveByPackageNameAndVersionSearcher struct{}

func (search cveByPackageNameAndVersionSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {
	if !canSearch(params, newSet("packageName", "packageVersion")) {
		return "", cannotSearchError
	}
	return fmt.Sprintf("Searching with package name: %s and version %s", *params["packageName"], *params["packageVersion"]), nil
}

type cveByPackageNameSearcher struct{}

func (search cveByPackageNameSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {
	if !canSearch(params, newSet("packageName")) {
		return "", cannotSearchError
	}
	return fmt.Sprintf("Searching with package name: %s", *params["packageName"]), nil
}

type cveByPackageVersionSearcher struct{}

func (search cveByPackageVersionSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {
	if !canSearch(params, newSet("packageVersion")) {
		return "", cannotSearchError
	}
	return fmt.Sprintf("Searching with package version: %s", *params["packageVersion"]), nil
}

type cveByPackageVendorSearcher struct{}

func (search cveByPackageVendorSearcher) search(params map[string]*string, searchService CveSearchService) (string, error) {
	if !canSearch(params, newSet("packageVendor")) {
		return "", cannotSearchError
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

var cannotSearchError = errors.New("Cannot search with these parameters")
