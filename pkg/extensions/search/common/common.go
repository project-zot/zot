package common

import (
	"fmt"
	"sort"
	"strings"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/pkg/storage"
)

const (
	// See https://github.com/opencontainers/image-spec/blob/main/annotations.md#back-compatibility-with-label-schema
	AnnotationLabels             = "org.label-schema.labels"
	LabelAnnotationCreated       = "org.label-schema.build-date"
	LabelAnnotationVendor        = "org.label-schema.vendor"
	LabelAnnotationDescription   = "org.label-schema.description"
	LabelAnnotationTitle         = "org.label-schema.name"
	LabelAnnotationDocumentation = "org.label-schema.usage"
	LabelAnnotationSource        = "org.label-schema.vcs-url"
)

type TagInfo struct {
	Name      string
	Digest    string
	Timestamp time.Time
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
		splitString := strings.SplitN(image, ":", 2) //nolint:gomnd
		if len(splitString) != 2 {                   //nolint:gomnd
			return image
		}

		return splitString[0]
	}

	return image
}

func GetImageDirAndTag(imageName string) (string, string) {
	var imageDir string

	var imageTag string

	if strings.Contains(imageName, ":") {
		imageDir, imageTag, _ = strings.Cut(imageName, ":")
	} else {
		imageDir = imageName
	}

	return imageDir, imageTag
}

func GetFixedTags(allTags, vulnerableTags []TagInfo) []TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(allTags[j].Timestamp)
	})

	earliestVulnerable := vulnerableTags[0]
	vulnerableTagMap := make(map[string]TagInfo, len(vulnerableTags))

	for _, tag := range vulnerableTags {
		vulnerableTagMap[tag.Name] = tag

		if tag.Timestamp.Before(earliestVulnerable.Timestamp) {
			earliestVulnerable = tag
		}
	}

	var fixedTags []TagInfo

	// There are some downsides to this logic
	// We assume there can't be multiple "branches" of the same
	// image built at different times containing different fixes
	// There may be older images which have a fix or
	// newer images which don't
	for _, tag := range allTags {
		if tag.Timestamp.Before(earliestVulnerable.Timestamp) {
			// The vulnerability did not exist at the time this
			// image was built
			continue
		}
		// If the image is old enough for the vulnerability to
		// exist, but it was not detected, it means it contains
		// the fix
		if _, ok := vulnerableTagMap[tag.Name]; !ok {
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
	names := strings.SplitN(name, "/", 2) //nolint:gomnd

	if len(names) != 2 { //nolint:gomnd
		// it means route is of global storage e.g "centos:latest"
		if len(names) == 1 {
			return "/"
		}
	}

	return fmt.Sprintf("/%s", names[0])
}

type ImageAnnotations struct {
	Description   string
	Licenses      string
	Title         string
	Documentation string
	Source        string
	Labels        string
	Vendor        string
}

/*
	OCI annotation/label with backwards compatibility

arg can be either lables or annotations
https://github.com/opencontainers/image-spec/blob/main/annotations.md.
*/
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

func GetDescription(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationDescription, LabelAnnotationDescription)
}

func GetVendor(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationVendor, LabelAnnotationVendor)
}

func GetTitle(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationTitle, LabelAnnotationTitle)
}

func GetDocumentation(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationDocumentation, LabelAnnotationDocumentation)
}

func GetSource(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationSource, LabelAnnotationSource)
}

func GetCategories(labels map[string]string) string {
	categories := labels[AnnotationLabels]

	return categories
}

func GetLicenses(annotations map[string]string) string {
	licenses := annotations[ispec.AnnotationLicenses]

	return licenses
}

func GetAnnotations(annotations, labels map[string]string) ImageAnnotations {
	description := GetDescription(annotations)
	if description == "" {
		description = GetDescription(labels)
	}

	title := GetTitle(annotations)
	if title == "" {
		title = GetTitle(labels)
	}

	documentation := GetDocumentation(annotations)
	if documentation == "" {
		documentation = GetDocumentation(annotations)
	}

	source := GetSource(annotations)
	if source == "" {
		source = GetSource(labels)
	}

	licenses := GetLicenses(annotations)
	if licenses == "" {
		licenses = GetLicenses(labels)
	}

	categories := GetCategories(annotations)
	if categories == "" {
		categories = GetCategories(labels)
	}

	vendor := GetVendor(annotations)
	if vendor == "" {
		vendor = GetVendor(labels)
	}

	return ImageAnnotations{
		Description:   description,
		Title:         title,
		Documentation: documentation,
		Source:        source,
		Licenses:      licenses,
		Labels:        categories,
		Vendor:        vendor,
	}
}
