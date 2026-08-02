package model

import (
	"time"

	godigest "github.com/opencontainers/go-digest"

	zcommon "zotregistry.dev/zot/v2/pkg/common"
)

type ImageCVESummary struct {
	Count         int
	UnknownCount  int
	LowCount      int
	MediumCount   int
	HighCount     int
	CriticalCount int
	MaxSeverity   string
}

// NotSpecified is used in place of Package.FixedVersion/PackagePath when the
// scanner has no fix available or no path, so the field is never empty.
const NotSpecified = "Not Specified"

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

// ScanResult is the outcome of a Scanner.ScanImage call: the CVE map plus the digest and
// media type actually scanned and whether the result was served from cache. Scanners resolve
// this identity/cache info internally while scanning, so returning it here spares callers a
// second metaDB round trip to learn what was scanned.
type ScanResult struct {
	CVEMap    map[string]zcommon.CVE
	Digest    string
	MediaType string
	WasCached bool
}
