package common

import (
	"errors"
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/resty.v1"
)

var ErrNoGoModFileFound = errors.New("test: no go.mod file found in parent directories")

func Location(baseURL string, resp *resty.Response) string {
	// For some API responses, the Location header is set and is supposed to
	// indicate an opaque value. However, it is not clear if this value is an
	// absolute URL (https://server:port/v2/...) or just a path (/v2/...)
	// zot implements the latter as per the spec, but some registries appear to
	// return the former - this needs to be clarified
	loc := resp.Header().Get("Location")

	uloc, err := url.Parse(loc)
	if err != nil {
		return ""
	}

	path := uloc.Path

	return baseURL + path
}

func GetProjectRootDir() (string, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		goModPath := filepath.Join(workDir, "go.mod")

		_, err := os.Stat(goModPath)
		if err == nil {
			return workDir, nil
		}

		if workDir == filepath.Dir(workDir) {
			return "", ErrNoGoModFileFound
		}

		workDir = filepath.Dir(workDir)
	}
}
