package model

import (
	"time"

	godigest "github.com/opencontainers/go-digest"
)

type ImageCVESummary struct {
	Count       int
	MaxSeverity string
}

//nolint:tagliatelle // graphQL schema
type CVE struct {
	ID          string    `json:"Id"`
	Description string    `json:"Description"`
	Severity    string    `json:"Severity"`
	Title       string    `json:"Title"`
	Reference   string    `json:"Reference"`
	PackageList []Package `json:"PackageList"`
}

//nolint:tagliatelle // graphQL schema
type Package struct {
	Name             string `json:"Name"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
}

const (
	unScanned = iota
	none
	unknown
	low
	medium
	high
	critical
)

// Values from https://www.first.org/cvss/v3.0/specification-document
const (
	SeverityNotScanned = ""         // scanning was not done or was not complete
	SeverityNone       = "NONE"     // no vulnerabilities were detected at all
	SeverityUnknown    = "UNKNOWN"  // coresponds to CVSS 3 score NONE
	SeverityLow        = "LOW"      // coresponds to CVSS 3 score LOW
	SeverityMedium     = "MEDIUM"   // coresponds to CVSS 3 score MEDIUM
	SeverityHigh       = "HIGH"     // coresponds to CVSS 3 score HIGH
	SeverityCritical   = "CRITICAL" // coresponds to CVSS 3 score CRITICAL
)

func severityInt(severity string) int {
	sevMap := map[string]int{
		SeverityNotScanned: unScanned,
		SeverityNone:       none,
		SeverityUnknown:    unknown,
		SeverityLow:        low,
		SeverityMedium:     medium,
		SeverityHigh:       high,
		SeverityCritical:   critical,
	}

	severityInt, ok := sevMap[severity]

	if !ok {
		// In the unlikely case the key is not in the map we
		// return the unknown severity level
		return unknown
	}

	return severityInt
}

func CompareSeverities(sev1, sev2 string) int {
	return severityInt(sev2) - severityInt(sev1)
}

type Descriptor struct {
	Digest    godigest.Digest
	MediaType string
}

type DescriptorInfo struct {
	Descriptor

	Timestamp time.Time
}

type TagInfo struct {
	Tag        string
	Descriptor Descriptor
	Manifests  []DescriptorInfo
	Timestamp  time.Time
}
