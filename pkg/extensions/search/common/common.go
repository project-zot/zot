package common

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/anuvu/zot/pkg/storage"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	AnnotationLabels           = "org.label-schema.labels"
	LabelAnnotationCreated     = "org.label-schema.build-date"
	LabelAnnotationVendor      = "org.label-schema.vendor"
	LabelAnnotationDescription = "org.label-schema.description"
	LabelAnnotationLicenses    = "org.label-schema.license"
)

type TagInfo struct {
	Name      string
	Digest    string
	Timestamp time.Time
}

func GetImageRepoPath(image string, storeController storage.StoreController) string {
	rootDir := GetRootDir(image, storeController)

	repo := GetRepo(image)

	return path.Join(rootDir, repo)
}

func GetRootDir(image string, storeController storage.StoreController) string {
	var rootDir string

	prefixName := GetRoutePrefix(image)

	subStore := storeController.SubStore

	if subStore != nil {
		imgStore, ok := storeController.SubStore[prefixName]
		if ok {
			rootDir = imgStore.RootDir()
		} else {
			rootDir = storeController.DefaultStore.RootDir()
		}
	} else {
		rootDir = storeController.DefaultStore.RootDir()
	}

	return rootDir
}

func GetRepo(image string) string {
	if strings.Contains(image, ":") {
		splitString := strings.SplitN(image, ":", 2)
		if len(splitString) != 2 { //nolint: gomnd
			return image
		}

		return splitString[0]
	}

	return image
}

func GetFixedTags(allTags []TagInfo, infectedTags []TagInfo) []TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(allTags[j].Timestamp)
	})

	latestInfected := TagInfo{}

	for _, tag := range infectedTags {
		if !tag.Timestamp.Before(latestInfected.Timestamp) {
			latestInfected = tag
		}
	}

	var fixedTags []TagInfo

	for _, tag := range allTags {
		if tag.Timestamp.After(latestInfected.Timestamp) {
			fixedTags = append(fixedTags, tag)
		}
	}

	return fixedTags
}

func GetLatestTag(allTags []TagInfo) TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(allTags[j].Timestamp)
	})

	return allTags[len(allTags)-1]
}

func GetRoutePrefix(name string) string {
	names := strings.SplitN(name, "/", 2)

	if len(names) != 2 { // nolint: gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

func GetDescription(labels map[string]string) string {
	desc, ok := labels[ispec.AnnotationDescription]
	if !ok {
		desc, ok = labels[LabelAnnotationDescription]
		if !ok {
			desc = ""
		}
	}

	return desc
}

func GetLicense(labels map[string]string) string {
	license, ok := labels[ispec.AnnotationLicenses]
	if !ok {
		license, ok = labels[LabelAnnotationLicenses]
		if !ok {
			license = ""
		}
	}

	return license
}

func GetVendor(labels map[string]string) string {
	vendor, ok := labels[ispec.AnnotationVendor]
	if !ok {
		vendor, ok = labels[LabelAnnotationVendor]
		if !ok {
			vendor = ""
		}
	}

	return vendor
}

func GetCategories(labels map[string]string) string {
	categories := labels[AnnotationLabels]

	return categories
}
