package common

import (
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
	Name          string       `json:"Name"`          //nolint:tagliatelle // graphQL schema
	LastUpdated   time.Time    `json:"LastUpdated"`   //nolint:tagliatelle // graphQL schema
	Size          string       `json:"Size"`          //nolint:tagliatelle // graphQL schema
	Platforms     []Platform   `json:"Platforms"`     //nolint:tagliatelle // graphQL schema
	Vendors       []string     `json:"Vendors"`       //nolint:tagliatelle // graphQL schema
	IsStarred     bool         `json:"IsStarred"`     //nolint:tagliatelle // graphQL schema
	IsBookmarked  bool         `json:"IsBookmarked"`  //nolint:tagliatelle // graphQL schema
	StarCount     int          `json:"StarCount"`     //nolint:tagliatelle // graphQL schema
	DownloadCount int          `json:"DownloadCount"` //nolint:tagliatelle // graphQL schema
	NewestImage   ImageSummary `json:"NewestImage"`   //nolint:tagliatelle // graphQL schema
}

type PaginatedImagesResult struct {
	Results []ImageSummary `json:"results"`
	Page    PageInfo       `json:"page"`
}

type ImageSummary struct {
	RepoName        string                    `json:"RepoName"`        //nolint:tagliatelle // graphQL schema
	Tag             string                    `json:"Tag"`             //nolint:tagliatelle // graphQL schema
	Digest          string                    `json:"Digest"`          //nolint:tagliatelle // graphQL schema
	MediaType       string                    `json:"MediaType"`       //nolint:tagliatelle // graphQL schema
	Manifests       []ManifestSummary         `json:"Manifests"`       //nolint:tagliatelle // graphQL schema
	Size            string                    `json:"Size"`            //nolint:tagliatelle // graphQL schema
	DownloadCount   int                       `json:"DownloadCount"`   //nolint:tagliatelle // graphQL schema
	LastUpdated     time.Time                 `json:"LastUpdated"`     //nolint:tagliatelle // graphQL schema
	Description     string                    `json:"Description"`     //nolint:tagliatelle // graphQL schema
	IsSigned        bool                      `json:"IsSigned"`        //nolint:tagliatelle // graphQL schema
	Licenses        string                    `json:"Licenses"`        //nolint:tagliatelle // graphQL schema
	Labels          string                    `json:"Labels"`          //nolint:tagliatelle // graphQL schema
	Title           string                    `json:"Title"`           //nolint:tagliatelle // graphQL schema
	Source          string                    `json:"Source"`          //nolint:tagliatelle // graphQL schema
	Documentation   string                    `json:"Documentation"`   //nolint:tagliatelle // graphQL schema
	Authors         string                    `json:"Authors"`         //nolint:tagliatelle // graphQL schema
	Vendor          string                    `json:"Vendor"`          //nolint:tagliatelle // graphQL schema
	Vulnerabilities ImageVulnerabilitySummary `json:"Vulnerabilities"` //nolint:tagliatelle // graphQL schema
	Referrers       []Referrer                `json:"Referrers"`       //nolint:tagliatelle // graphQL schema
	SignatureInfo   []SignatureSummary        `json:"SignatureInfo"`   //nolint:tagliatelle // graphQL schema
}

type ManifestSummary struct {
	Digest          string                    `json:"Digest"`          //nolint:tagliatelle // graphQL schema
	ConfigDigest    string                    `json:"ConfigDigest"`    //nolint:tagliatelle // graphQL schema
	LastUpdated     time.Time                 `json:"LastUpdated"`     //nolint:tagliatelle // graphQL schema
	Size            string                    `json:"Size"`            //nolint:tagliatelle // graphQL schema
	Platform        Platform                  `json:"Platform"`        //nolint:tagliatelle // graphQL schema
	IsSigned        bool                      `json:"IsSigned"`        //nolint:tagliatelle // graphQL schema
	DownloadCount   int                       `json:"DownloadCount"`   //nolint:tagliatelle // graphQL schema
	Layers          []LayerSummary            `json:"Layers"`          //nolint:tagliatelle // graphQL schema
	History         []LayerHistory            `json:"History"`         //nolint:tagliatelle // graphQL schema
	Vulnerabilities ImageVulnerabilitySummary `json:"Vulnerabilities"` //nolint:tagliatelle // graphQL schema
	Referrers       []Referrer                `json:"Referrers"`       //nolint:tagliatelle // graphQL schema
	ArtifactType    string                    `json:"ArtifactType"`    //nolint:tagliatelle // graphQL schema
	SignatureInfo   []SignatureSummary        `json:"SignatureInfo"`   //nolint:tagliatelle // graphQL schema
}

type SignatureSummary struct {
	Tool      string `json:"Tool"`      //nolint:tagliatelle // graphQL schema
	IsTrusted bool   `json:"IsTrusted"` //nolint:tagliatelle // graphQL schema
	Author    string `json:"Author"`    //nolint:tagliatelle // graphQL schema
}

type Platform struct {
	Os      string `json:"Os"`      //nolint:tagliatelle // graphQL schema
	Arch    string `json:"Arch"`    //nolint:tagliatelle // graphQL schema
	Variant string `json:"Variant"` //nolint:tagliatelle // graphQL schema
}

type ImageVulnerabilitySummary struct {
	MaxSeverity   string `json:"MaxSeverity"`   //nolint:tagliatelle // graphQL schema
	UnknownCount  int    `json:"UnknownCount"`  //nolint:tagliatelle // graphQL schema
	LowCount      int    `json:"LowCount"`      //nolint:tagliatelle // graphQL schema
	MediumCount   int    `json:"MediumCount"`   //nolint:tagliatelle // graphQL schema
	HighCount     int    `json:"HighCount"`     //nolint:tagliatelle // graphQL schema
	CriticalCount int    `json:"CriticalCount"` //nolint:tagliatelle // graphQL schema
	Count         int    `json:"Count"`         //nolint:tagliatelle // graphQL schema
}

type LayerSummary struct {
	Size   string `json:"Size"`   //nolint:tagliatelle // graphQL schema
	Digest string `json:"Digest"` //nolint:tagliatelle // graphQL schema
	Score  int    `json:"Score"`  //nolint:tagliatelle // graphQL schema
}

type LayerHistory struct {
	Layer              LayerSummary       `json:"Layer"`              //nolint:tagliatelle // graphQL schema
	HistoryDescription HistoryDescription `json:"HistoryDescription"` //nolint:tagliatelle // graphQL schema
}

type HistoryDescription struct {
	Created    time.Time `json:"Created"`    //nolint:tagliatelle // graphQL schema
	CreatedBy  string    `json:"CreatedBy"`  //nolint:tagliatelle // graphQL schema
	Author     string    `json:"Author"`     //nolint:tagliatelle // graphQL schema
	Comment    string    `json:"Comment"`    //nolint:tagliatelle // graphQL schema
	EmptyLayer bool      `json:"EmptyLayer"` //nolint:tagliatelle // graphQL schema
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
	Errors                []ErrorGQL `json:"errors"`
	ImageListWithCVEFixed `json:"data"`
}

type ImageListWithCVEFixed struct {
	PaginatedImagesResult `json:"ImageListWithCVEFixed"` //nolint:tagliatelle // graphQL schema
}

type ImagesForCve struct {
	Errors           []ErrorGQL `json:"errors"`
	ImagesForCVEList `json:"data"`
}

type ImagesForCVEList struct {
	PaginatedImagesResult `json:"ImageListForCVE"` //nolint:tagliatelle // graphQL schema
}

type ImagesForDigest struct {
	Errors              []ErrorGQL `json:"errors"`
	ImagesForDigestList `json:"data"`
}

type ImagesForDigestList struct {
	PaginatedImagesResult `json:"ImageListForDigest"` //nolint:tagliatelle // graphQL schema
}

type RepoWithNewestImageResponse struct {
	RepoListWithNewestImage `json:"data"`
	Errors                  []ErrorGQL `json:"errors"`
}

type DerivedImageListResponse struct {
	DerivedImageList `json:"data"`
	Errors           []ErrorGQL `json:"errors"`
}

type BaseImageListResponse struct {
	BaseImageList `json:"data"`
	Errors        []ErrorGQL `json:"errors"`
}

type DerivedImageList struct {
	PaginatedImagesResult `json:"derivedImageList"`
}

type BaseImageList struct {
	PaginatedImagesResult `json:"baseImageList"`
}

type ImageListResponse struct {
	ImageList `json:"data"`
	Errors    []ErrorGQL `json:"errors"`
}

type ImageList struct {
	PaginatedImagesResult `json:"imageList"`
}

type ExpandedRepoInfoResp struct {
	ExpandedRepoInfo `json:"data"`
	Errors           []ErrorGQL `json:"errors"`
}

type ReferrersResp struct {
	ReferrersResult `json:"data"`
	Errors          []ErrorGQL `json:"errors"`
}

type ReferrersResult struct {
	Referrers []Referrer `json:"referrers"`
}
type GlobalSearchResultResp struct {
	GlobalSearchResult `json:"data"`
	Errors             []ErrorGQL `json:"errors"`
}

type GlobalSearchResult struct {
	GlobalSearch `json:"GlobalSearch"` //nolint:tagliatelle // graphQL schema
}

type GlobalSearch struct {
	Images []ImageSummary `json:"Images"` //nolint:tagliatelle // graphQL schema
	Repos  []RepoSummary  `json:"Repos"`  //nolint:tagliatelle // graphQL schema
	Layers []LayerSummary `json:"Layers"` //nolint:tagliatelle // graphQL schema
	Page   PageInfo       `json:"Page"`   //nolint:tagliatelle // graphQL schema
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
	Errors             []ErrorGQL `json:"errors"`
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
	Errors       []ErrorGQL `json:"errors"`
}

type BookmarkedReposResponse struct {
	BookmarkedRepos `json:"data"`
	Errors          []ErrorGQL `json:"errors"`
}

type ImageTags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}
