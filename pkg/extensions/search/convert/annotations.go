package convert

import (
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// See https://github.com/opencontainers/image-spec/blob/main/annotations.md#back-compatibility-with-label-schema
	AnnotationLabels             = "org.label-schema.labels"
	LabelAnnotationCreated       = "org.label-schema.build-date"
	LabelAnnotationVendor        = "org.label-schema.vendor"
	LabelAnnotationDescription   = "org.label-schema.description"
	LabelAnnotationLicenses      = "org.label-schema.license"
	LabelAnnotationTitle         = "org.label-schema.name"
	LabelAnnotationDocumentation = "org.label-schema.usage"
	LabelAnnotationSource        = "org.label-schema.vcs-url"
)

type ImageAnnotations struct {
	Description   string
	Created       *time.Time
	Licenses      string
	Title         string
	Documentation string
	Source        string
	Labels        string
	Vendor        string
	Authors       string
}

/*
	OCI annotation/label with backwards compatibility

arg can be either labels or annotations
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

func GetCreated(annotations map[string]string) *time.Time {
	createdStr := GetAnnotationValue(annotations, ispec.AnnotationCreated, LabelAnnotationCreated)

	created, err := time.Parse(time.RFC3339, createdStr)
	if err != nil {
		return nil
	}

	return &created
}

func GetDescription(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationDescription, LabelAnnotationDescription)
}

func GetLicenses(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationLicenses, LabelAnnotationLicenses)
}

func GetVendor(annotations map[string]string) string {
	return GetAnnotationValue(annotations, ispec.AnnotationVendor, LabelAnnotationVendor)
}

func GetAuthors(annotations map[string]string) string {
	authors := annotations[ispec.AnnotationAuthors]

	return authors
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

func GetAnnotations(annotations, labels map[string]string) ImageAnnotations {
	created := GetCreated(annotations)
	if created == nil {
		created = GetCreated(labels)
	}

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
		documentation = GetDocumentation(labels)
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

	authors := GetAuthors(annotations)
	if authors == "" {
		authors = GetAuthors(labels)
	}

	return ImageAnnotations{
		Created:       created,
		Description:   description,
		Title:         title,
		Documentation: documentation,
		Source:        source,
		Licenses:      licenses,
		Labels:        categories,
		Vendor:        vendor,
		Authors:       authors,
	}
}

func GetIndexAnnotations(
	indexAnnotations map[string]string,
	annotationsFromManifest *ImageAnnotations,
) ImageAnnotations {
	created := GetCreated(indexAnnotations)
	if created == nil {
		created = annotationsFromManifest.Created
	}

	description := GetDescription(indexAnnotations)
	if description == "" {
		description = annotationsFromManifest.Description
	}

	title := GetTitle(indexAnnotations)
	if title == "" {
		title = annotationsFromManifest.Title
	}

	documentation := GetDocumentation(indexAnnotations)
	if documentation == "" {
		documentation = annotationsFromManifest.Documentation
	}

	source := GetSource(indexAnnotations)
	if source == "" {
		source = annotationsFromManifest.Source
	}

	licenses := GetLicenses(indexAnnotations)
	if licenses == "" {
		licenses = annotationsFromManifest.Licenses
	}

	categories := GetCategories(indexAnnotations)
	if categories == "" {
		categories = annotationsFromManifest.Labels
	}

	vendor := GetVendor(indexAnnotations)
	if vendor == "" {
		vendor = annotationsFromManifest.Vendor
	}

	authors := GetAuthors(indexAnnotations)
	if authors == "" {
		authors = annotationsFromManifest.Authors
	}

	return ImageAnnotations{
		Created:       created,
		Description:   description,
		Title:         title,
		Documentation: documentation,
		Source:        source,
		Licenses:      licenses,
		Labels:        categories,
		Vendor:        vendor,
		Authors:       authors,
	}
}
