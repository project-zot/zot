// Code generated by github.com/99designs/gqlgen, DO NOT EDIT.

package search

import (
	"time"
)

type Cve struct {
	ID          *string        `json:"Id"`
	Title       *string        `json:"Title"`
	Description *string        `json:"Description"`
	Severity    *string        `json:"Severity"`
	PackageList []*PackageInfo `json:"PackageList"`
}

type CVEResultForImage struct {
	Tag     *string `json:"Tag"`
	CVEList []*Cve  `json:"CVEList"`
}

type ImageInfo struct {
	Name         *string      `json:"Name"`
	Tag          *string      `json:"Tag"`
	ConfigDigest *string      `json:"ConfigDigest"`
	Digest       *string      `json:"Digest"`
	Latest       *string      `json:"Latest"`
	Layers       []*LayerInfo `json:"Layers"`
	LastUpdated  *time.Time   `json:"LastUpdated"`
	Description  *string      `json:"Description"`
	Licenses     *string      `json:"Licenses"`
	Vendor       *string      `json:"Vendor"`
	Size         *string      `json:"Size"`
	Labels       *string      `json:"Labels"`
}

type ImgResultForCve struct {
	Name *string   `json:"Name"`
	Tags []*string `json:"Tags"`
}

type ImgResultForDigest struct {
	Name *string   `json:"Name"`
	Tags []*string `json:"Tags"`
}

type ImgResultForFixedCve struct {
	Tags []*TagInfo `json:"Tags"`
}

type Layer struct {
	Size   *string `json:"Size"`
	Digest *string `json:"Digest"`
}

type LayerInfo struct {
	Size   *string `json:"Size"`
	Digest *string `json:"Digest"`
}

type ManifestInfo struct {
	Digest   *string      `json:"Digest"`
	Tag      *string      `json:"Tag"`
	IsSigned *bool        `json:"IsSigned"`
	Layers   []*LayerInfo `json:"Layers"`
}

type PackageInfo struct {
	Name             *string `json:"Name"`
	InstalledVersion *string `json:"InstalledVersion"`
	FixedVersion     *string `json:"FixedVersion"`
}

type RepoInfo struct {
	Manifests []*ManifestInfo `json:"Manifests"`
}

type TagInfo struct {
	Name      *string    `json:"Name"`
	Digest    *string    `json:"Digest"`
	Timestamp *time.Time `json:"Timestamp"`
}
