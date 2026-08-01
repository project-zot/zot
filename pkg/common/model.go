package common

import (
	"slices"
	"strings"
	"time"
)

type PageInfo struct {
	TotalCount int
	ItemCount  int
}

type RepoInfo struct {
	Summary        RepoSummary
	ImageSummaries []ImageSummary `json:"images"`
}

type RepoSummary struct {
	Name          string       `json:"name"`
	LastUpdated   time.Time    `json:"lastUpdated"`
	Size          string       `json:"size"`
	Platforms     []Platform   `json:"platforms"`
	Vendors       []string     `json:"vendors"`
	IsStarred     bool         `json:"isStarred"`
	IsBookmarked  bool         `json:"isBookmarked"`
	StarCount     int          `json:"starCount"`
	DownloadCount int          `json:"downloadCount"`
	NewestImage   ImageSummary `json:"newestImage"`
}

type PaginatedImagesResult struct {
	Results []ImageSummary `json:"results"`
	Page    PageInfo       `json:"page"`
}

type ImageSummary struct {
	RepoName          string                    `json:"repoName"`
	Tag               string                    `json:"tag"`
	Digest            string                    `json:"digest"`
	MediaType         string                    `json:"mediaType"`
	Manifests         []ManifestSummary         `json:"manifests"`
	Size              string                    `json:"size"`
	DownloadCount     int                       `json:"downloadCount"`
	LastUpdated       time.Time                 `json:"lastUpdated"`
	LastPullTimestamp time.Time                 `json:"lastPullTimestamp"`
	PushTimestamp     time.Time                 `json:"pushTimestamp"`
	TaggedTimestamp   time.Time                 `json:"taggedTimestamp"`
	Description       string                    `json:"description"`
	IsSigned          bool                      `json:"isSigned"`
	Licenses          string                    `json:"licenses"`
	Labels            string                    `json:"labels"`
	Title             string                    `json:"title"`
	Source            string                    `json:"source"`
	Documentation     string                    `json:"documentation"`
	Authors           string                    `json:"authors"`
	Vendor            string                    `json:"vendor"`
	Vulnerabilities   ImageVulnerabilitySummary `json:"vulnerabilities"`
	Referrers         []Referrer                `json:"referrers"`
	SignatureInfo     []SignatureSummary        `json:"signatureInfo"`
	ArtifactType      string                    `json:"artifactType"`
}

type ManifestSummary struct {
	Digest          string                    `json:"digest"`
	ConfigDigest    string                    `json:"configDigest"`
	LastUpdated     time.Time                 `json:"lastUpdated"`
	Size            string                    `json:"size"`
	Platform        Platform                  `json:"platform"`
	IsSigned        bool                      `json:"isSigned"`
	DownloadCount   int                       `json:"downloadCount"`
	Layers          []LayerSummary            `json:"layers"`
	History         []LayerHistory            `json:"history"`
	Vulnerabilities ImageVulnerabilitySummary `json:"vulnerabilities"`
	Referrers       []Referrer                `json:"referrers"`
	ArtifactType    string                    `json:"artifactType"`
	SignatureInfo   []SignatureSummary        `json:"signatureInfo"`
}

type SignatureSummary struct {
	Tool      string `json:"tool"`
	IsTrusted bool   `json:"isTrusted"`
	Author    string `json:"author"`
}

type Platform struct {
	Os      string `json:"os"`
	Arch    string `json:"arch"`
	Variant string `json:"variant"`
}

type ImageVulnerabilitySummary struct {
	MaxSeverity   string `json:"maxSeverity"`
	UnknownCount  int    `json:"unknownCount"`
	LowCount      int    `json:"lowCount"`
	MediumCount   int    `json:"mediumCount"`
	HighCount     int    `json:"highCount"`
	CriticalCount int    `json:"criticalCount"`
	Count         int    `json:"count"`
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

type OsArch struct {
	Os, Arch string
}

type ImageIdentifier struct {
	Repo     string
	Tag      string
	Digest   string
	Platform OsArch
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

type ImageListWithCVEFixedResponse struct {
	ImageListWithCVEFixed `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type ImageListWithCVEFixed struct {
	PaginatedImagesResult `json:"ImageListWithCVEFixed"` //nolint:tagliatelle // graphQL schema
}

type ImagesForCve struct {
	ImagesForCVEList `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type ImagesForCVEList struct {
	PaginatedImagesResult `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
}

type ImagesForDigest struct {
	ImagesForDigestList `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type ImagesForDigestList struct {
	PaginatedImagesResult `json:"ImageListForDigest"` //nolint:tagliatelle // graphQL schema
}

type RepoWithNewestImageResponse struct {
	RepoListWithNewestImage `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type DerivedImageListResponse struct {
	DerivedImageList `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type BaseImageListResponse struct {
	BaseImageList `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type DerivedImageList struct {
	PaginatedImagesResult `json:"derivedImageList"`
}

type BaseImageList struct {
	PaginatedImagesResult `json:"baseImageList"`
}

type ImageListResponse struct {
	ImageList `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type ImageList struct {
	PaginatedImagesResult `json:"imageList"`
}

type ExpandedRepoInfoResp struct {
	ExpandedRepoInfo `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type ReferrersResp struct {
	ReferrersResult `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type ReferrersResult struct {
	Referrers []Referrer `json:"referrers"`
}
type GlobalSearchResultResp struct {
	GlobalSearchResult `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type GlobalSearchResult struct {
	GlobalSearch `json:"globalSearch"`
}

type GlobalSearch struct {
	Images []ImageSummary `json:"images"`
	Repos  []RepoSummary  `json:"repos"`
	Layers []LayerSummary `json:"layers"`
	Page   PageInfo       `json:"page"`
}

type ExpandedRepoInfo struct {
	RepoInfo `json:"expandedRepoInfo"`
}

type PaginatedReposResult struct {
	Results []RepoSummary `json:"results"`
	Page    PageInfo      `json:"page"`
}

//nolint:tagliatelle // graphQL schema
type RepoListWithNewestImage struct {
	PaginatedReposResult `json:"RepoListWithNewestImage"`
}

type ErrorGQL struct {
	Message string   `json:"message"`
	Path    []string `json:"path"`
}

type SingleImageSummary struct {
	ImageSummary `json:"Image"` //nolint:tagliatelle
}
type ImageSummaryResult struct {
	SingleImageSummary `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

//nolint:tagliatelle // graphQL schema
type StarredRepos struct {
	PaginatedReposResult `json:"StarredRepos"`
}

//nolint:tagliatelle // graphQL schema
type BookmarkedRepos struct {
	PaginatedReposResult `json:"BookmarkedRepos"`
}

type StarredReposResponse struct {
	StarredRepos `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type BookmarkedReposResponse struct {
	BookmarkedRepos `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

type ImageTags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
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

func (cve *CVE) ContainsStr(str string) bool {
	str = strings.ToUpper(str)

	return strings.Contains(strings.ToUpper(cve.Title), str) ||
		strings.Contains(strings.ToUpper(cve.ID), str) ||
		strings.Contains(strings.ToUpper(cve.Severity), str) ||
		strings.Contains(strings.ToUpper(cve.Reference), str) ||
		strings.Contains(strings.ToUpper(cve.Description), str) ||
		slices.ContainsFunc(cve.PackageList, func(pack Package) bool {
			return strings.Contains(strings.ToUpper(pack.Name), str) ||
				strings.Contains(strings.ToUpper(pack.FixedVersion), str) ||
				strings.Contains(strings.ToUpper(pack.InstalledVersion), str) ||
				strings.Contains(strings.ToUpper(pack.PackagePath), str)
		})
}

//nolint:tagliatelle // graphQL schema
type Package struct {
	Name             string `json:"Name"`
	PackagePath      string `json:"PackagePath"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
}

type CVEListForImageResponse struct {
	CVEListForImageResult `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

//nolint:tagliatelle // graphQL schema
type CVEListForImageResult struct {
	CVEListForImage CVEResultForImage `json:"CVEListForImage"`
}

//nolint:tagliatelle // graphQL schema
type CVEResultForImage struct {
	Tag     string                    `json:"Tag"`
	CVEList []CVE                     `json:"CVEList"`
	Summary ImageVulnerabilitySummary `json:"Summary"`
}

type CVEDiffListForImagesResponse struct {
	CVEDiffListForImagesResult `json:"data"`

	Errors []ErrorGQL `json:"errors"`
}

//nolint:tagliatelle // graphQL schema
type CVEDiffListForImagesResult struct {
	CVEDiffListForImages CVEDiffListForImages `json:"CVEDiffListForImages"`
}

//nolint:tagliatelle // graphQL schema
type CVEDiffListForImages struct {
	Minuend    ImageIdentifier `json:"Minuend"`
	Subtrahend ImageIdentifier `json:"Subtrahend"`
	CVEList    []CVE           `json:"CVEList"`
}

type SortCriteria string

type PageInput struct {
	Limit  int
	Offset int
	SortBy SortCriteria
}
