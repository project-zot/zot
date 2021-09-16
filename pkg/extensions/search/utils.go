package search

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	AnnotationLabels           = "com.cisco.image.labels"
	LabelAnnotationCreated     = "org.label-schema.build-date"
	LabelAnnotationVendor      = "org.label-schema.vendor"
	LabelAnnotationDescription = "org.label-schema.description"
	LabelAnnotationLicenses    = "org.label-schema.license"
)

func getDescription(labels map[string]string) string {
	desc, ok := labels[ispec.AnnotationDescription]
	if !ok {
		desc, ok = labels[LabelAnnotationDescription]
		if !ok {
			desc = ""
		}
	}

	return desc
}

func getLicense(labels map[string]string) string {
	license, ok := labels[ispec.AnnotationLicenses]
	if !ok {
		license, ok = labels[LabelAnnotationLicenses]
		if !ok {
			license = ""
		}
	}

	return license
}

func getVendor(labels map[string]string) string {
	vendor, ok := labels[ispec.AnnotationVendor]
	if !ok {
		vendor, ok = labels[LabelAnnotationVendor]
		if !ok {
			vendor = ""
		}
	}

	return vendor
}

func getCategories(labels map[string]string) string {
	categories := labels[AnnotationLabels]

	return categories
}
