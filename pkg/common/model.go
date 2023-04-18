package common

import (
	"time"
)

type RepoInfo struct {
	Summary        RepoSummary
	ImageSummaries []ImageSummary `json:"images"`
}

type RepoSummary struct {
	Name        string       `json:"name"`
	LastUpdated time.Time    `json:"lastUpdated"`
	Size        string       `json:"size"`
	Platforms   []Platform   `json:"platforms"`
	Vendors     []string     `json:"vendors"`
	NewestImage ImageSummary `json:"newestImage"`
}

type ImageSummary struct {
	RepoName        string                    `json:"repoName"`
	Tag             string                    `json:"tag"`
	Digest          string                    `json:"digest"`
	MediaType       string                    `json:"mediaType"`
	Manifests       []ManifestSummary         `json:"manifests"`
	Size            string                    `json:"size"`
	DownloadCount   int                       `json:"downloadCount"`
	LastUpdated     time.Time                 `json:"lastUpdated"`
	Description     string                    `json:"description"`
	IsSigned        bool                      `json:"isSigned"`
	Licenses        string                    `json:"licenses"`
	Labels          string                    `json:"labels"`
	Title           string                    `json:"title"`
	Source          string                    `json:"source"`
	Documentation   string                    `json:"documentation"`
	Authors         string                    `json:"authors"`
	Vendor          string                    `json:"vendor"`
	Vulnerabilities ImageVulnerabilitySummary `json:"vulnerabilities"`
	Referrers       []Referrer                `json:"referrers"`
}

type ManifestSummary struct {
	Digest          string                    `json:"digest"`
	ConfigDigest    string                    `json:"configDigest"`
	LastUpdated     time.Time                 `json:"lastUpdated"`
	Size            string                    `json:"size"`
	Platform        Platform                  `json:"platform"`
	DownloadCount   int                       `json:"downloadCount"`
	Layers          []LayerSummary            `json:"layers"`
	History         []LayerHistory            `json:"history"`
	Vulnerabilities ImageVulnerabilitySummary `json:"vulnerabilities"`
}

type Platform struct {
	Os   string `json:"os"`
	Arch string `json:"arch"`
}

type ErrorGraphQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type ImageVulnerabilitySummary struct {
	MaxSeverity string `json:"maxSeverity"`
	Count       int    `json:"count"`
}

type LayerSummary struct {
	Size   string `json:"size"`
	Digest string `json:"digest"`
	Score  int    `json:"score"`
}

type LayerHistory struct {
	Layer              LayerSummary       `json:"layer"`
	HistoryDescription HistoryDescription `json:"historyDescription"`
}

type HistoryDescription struct {
	Created    time.Time `json:"created"`
	CreatedBy  string    `json:"createdBy"`
	Author     string    `json:"author"`
	Comment    string    `json:"comment"`
	EmptyLayer bool      `json:"emptyLayer"`
}

type Referrer struct {
	MediaType    string       `json:"mediatype"`
	ArtifactType string       `json:"artifacttype"`
	Size         int          `json:"size"`
	Digest       string       `json:"digest"`
	Annotations  []Annotation `json:"annotations"`
}

type Annotation struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
