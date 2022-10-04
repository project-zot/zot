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
	Platforms   []OsArch     `json:"platforms"`
	Vendors     []string     `json:"vendors"`
	Score       int          `json:"score"`
	NewestImage ImageSummary `json:"newestImage"`
}

type ImageSummary struct {
	RepoName        string                    `json:"repoName"`
	Tag             string                    `json:"tag"`
	Digest          string                    `json:"digest"`
	ConfigDigest    string                    `json:"configDigest"`
	LastUpdated     time.Time                 `json:"lastUpdated"`
	IsSigned        bool                      `json:"isSigned"`
	Size            string                    `json:"size"`
	Platform        OsArch                    `json:"platform"`
	Vendor          string                    `json:"vendor"`
	Score           int                       `json:"score"`
	DownloadCount   int                       `json:"downloadCount"`
	Description     string                    `json:"description"`
	Licenses        string                    `json:"licenses"`
	Labels          string                    `json:"labels"`
	Title           string                    `json:"title"`
	Source          string                    `json:"source"`
	Documentation   string                    `json:"documentation"`
	History         []LayerHistory            `json:"history"`
	Layers          []LayerSummary            `json:"layers"`
	Vulnerabilities ImageVulnerabilitySummary `json:"vulnerabilities"`
	Authors         string                    `json:"authors"`
	Logo            string                    `json:"logo"`
}

type OsArch struct {
	Os   string `json:"os"`
	Arch string `json:"arch"`
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
