package cveinfo

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	zcommon "zotregistry.io/zot/pkg/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.io/zot/pkg/log"
	mTypes "zotregistry.io/zot/pkg/meta/types"
	"zotregistry.io/zot/pkg/storage"
)

type CveInfo interface {
	GetImageListForCVE(repo, cveID string) ([]cvemodel.TagInfo, error)
	GetImageListWithCVEFixed(repo, cveID string) ([]cvemodel.TagInfo, error)
	GetCVEListForImage(repo, tag string, searchedCVE string, pageinput cvemodel.PageInput,
	) ([]cvemodel.CVE, zcommon.PageInfo, error)
	GetCVESummaryForImageMedia(repo, digest, mediaType string) (cvemodel.ImageCVESummary, error)
}

type Scanner interface {
	ScanImage(image string) (map[string]cvemodel.CVE, error)
	IsImageFormatScannable(repo, ref string) (bool, error)
	IsImageMediaScannable(repo, digestStr, mediaType string) (bool, error)
	IsResultCached(digestStr string) bool
	GetCachedResult(digestStr string) map[string]cvemodel.CVE
	UpdateDB() error
}

type BaseCveInfo struct {
	Log     log.Logger
	Scanner Scanner
	MetaDB  mTypes.MetaDB
}

func NewScanner(storeController storage.StoreController, metaDB mTypes.MetaDB,
	dbRepository, javaDBRepository string, log log.Logger,
) Scanner {
	return trivy.NewScanner(storeController, metaDB, dbRepository, javaDBRepository, log)
}

func NewCVEInfo(scanner Scanner, metaDB mTypes.MetaDB, log log.Logger) *BaseCveInfo {
	return &BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		MetaDB:  metaDB,
	}
}

func (cveinfo BaseCveInfo) GetImageListForCVE(repo, cveID string) ([]cvemodel.TagInfo, error) {
	imgList := make([]cvemodel.TagInfo, 0)

	repoMeta, err := cveinfo.MetaDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repository", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return imgList, err
	}

	for tag, descriptor := range repoMeta.Tags {
		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest, ispec.MediaTypeImageIndex:
			manifestDigestStr := descriptor.Digest

			manifestDigest := godigest.Digest(manifestDigestStr)

			isScanableImage, err := cveinfo.Scanner.IsImageFormatScannable(repo, manifestDigestStr)
			if !isScanableImage || err != nil {
				cveinfo.Log.Debug().Str("image", repo+":"+tag).Err(err).Msg("image is not scanable")

				continue
			}

			cveMap, err := cveinfo.Scanner.ScanImage(zcommon.GetFullImageName(repo, tag))
			if err != nil {
				cveinfo.Log.Info().Str("image", repo+":"+tag).Err(err).Msg("image scan failed")

				continue
			}

			if _, hasCVE := cveMap[cveID]; hasCVE {
				imgList = append(imgList, cvemodel.TagInfo{
					Tag: tag,
					Descriptor: cvemodel.Descriptor{
						Digest:    manifestDigest,
						MediaType: descriptor.MediaType,
					},
				})
			}
		default:
			cveinfo.Log.Debug().Str("image", repo+":"+tag).Str("mediaType", descriptor.MediaType).
				Msg("image media type not supported for scanning")
		}
	}

	return imgList, nil
}

func (cveinfo BaseCveInfo) GetImageListWithCVEFixed(repo, cveID string) ([]cvemodel.TagInfo, error) {
	repoMeta, err := cveinfo.MetaDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repository", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return []cvemodel.TagInfo{}, err
	}

	vulnerableTags := make([]cvemodel.TagInfo, 0)
	allTags := make([]cvemodel.TagInfo, 0)

	for tag, descriptor := range repoMeta.Tags {
		switch descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			manifestDigestStr := descriptor.Digest

			tagInfo, err := getTagInfoForManifest(tag, manifestDigestStr, cveinfo.MetaDB)
			if err != nil {
				cveinfo.Log.Error().Err(err).Str("repository", repo).Str("tag", tag).
					Str("cve-id", cveID).Msg("unable to retrieve manifest and config")

				continue
			}

			allTags = append(allTags, tagInfo)

			if cveinfo.isManifestVulnerable(repo, tag, manifestDigestStr, cveID) {
				vulnerableTags = append(vulnerableTags, tagInfo)
			}
		case ispec.MediaTypeImageIndex:
			indexDigestStr := descriptor.Digest

			indexContent, err := getIndexContent(cveinfo.MetaDB, indexDigestStr)
			if err != nil {
				continue
			}

			vulnerableManifests := []cvemodel.DescriptorInfo{}
			allManifests := []cvemodel.DescriptorInfo{}

			for _, manifest := range indexContent.Manifests {
				tagInfo, err := getTagInfoForManifest(tag, manifest.Digest.String(), cveinfo.MetaDB)
				if err != nil {
					cveinfo.Log.Error().Err(err).Str("repository", repo).Str("tag", tag).
						Str("cve-id", cveID).Msg("unable to retrieve manifest and config")

					continue
				}

				manifestDescriptorInfo := cvemodel.DescriptorInfo{
					Descriptor: tagInfo.Descriptor,
					Timestamp:  tagInfo.Timestamp,
				}

				allManifests = append(allManifests, manifestDescriptorInfo)

				if cveinfo.isManifestVulnerable(repo, tag, manifest.Digest.String(), cveID) {
					vulnerableManifests = append(vulnerableManifests, manifestDescriptorInfo)
				}
			}

			if len(allManifests) > 0 {
				allTags = append(allTags, cvemodel.TagInfo{
					Tag: tag,
					Descriptor: cvemodel.Descriptor{
						Digest:    godigest.Digest(indexDigestStr),
						MediaType: ispec.MediaTypeImageIndex,
					},
					Manifests: allManifests,
					Timestamp: mostRecentUpdate(allManifests),
				})
			}

			if len(vulnerableManifests) > 0 {
				vulnerableTags = append(vulnerableTags, cvemodel.TagInfo{
					Tag: tag,
					Descriptor: cvemodel.Descriptor{
						Digest:    godigest.Digest(indexDigestStr),
						MediaType: ispec.MediaTypeImageIndex,
					},
					Manifests: vulnerableManifests,
					Timestamp: mostRecentUpdate(vulnerableManifests),
				})
			}
		default:
			cveinfo.Log.Debug().Str("mediaType", descriptor.MediaType).
				Msg("image media type not supported for scanning")
		}
	}

	var fixedTags []cvemodel.TagInfo

	if len(vulnerableTags) != 0 {
		cveinfo.Log.Info().Str("repository", repo).Str("cve-id", cveID).
			Interface("tags", vulnerableTags).Msg("vulnerable tags")
		fixedTags = GetFixedTags(allTags, vulnerableTags)
		cveinfo.Log.Info().Str("repository", repo).Str("cve-id", cveID).
			Interface("tags", fixedTags).Msg("fixed tags")
	} else {
		cveinfo.Log.Info().Str("repository", repo).Str("cve-id", cveID).
			Msg("image does not contain any tag that have given cve")
		fixedTags = allTags
	}

	return fixedTags, nil
}

func mostRecentUpdate(allManifests []cvemodel.DescriptorInfo) time.Time {
	if len(allManifests) == 0 {
		return time.Time{}
	}

	timeStamp := allManifests[0].Timestamp

	for i := range allManifests {
		if timeStamp.Before(allManifests[i].Timestamp) {
			timeStamp = allManifests[i].Timestamp
		}
	}

	return timeStamp
}

func getTagInfoForManifest(tag, manifestDigestStr string, metaDB mTypes.MetaDB) (cvemodel.TagInfo, error) {
	configContent, manifestDigest, err := getConfigAndDigest(metaDB, manifestDigestStr)
	if err != nil {
		return cvemodel.TagInfo{}, err
	}

	lastUpdated := zcommon.GetImageLastUpdated(configContent)

	return cvemodel.TagInfo{
		Tag:        tag,
		Descriptor: cvemodel.Descriptor{Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
		Manifests: []cvemodel.DescriptorInfo{
			{
				Descriptor: cvemodel.Descriptor{Digest: manifestDigest, MediaType: ispec.MediaTypeImageManifest},
				Timestamp:  lastUpdated,
			},
		},
		Timestamp: lastUpdated,
	}, nil
}

func (cveinfo *BaseCveInfo) isManifestVulnerable(repo, tag, manifestDigestStr, cveID string) bool {
	image := zcommon.GetFullImageName(repo, tag)

	isValidImage, err := cveinfo.Scanner.IsImageMediaScannable(repo, manifestDigestStr, ispec.MediaTypeImageManifest)
	if !isValidImage || err != nil {
		cveinfo.Log.Debug().Str("image", image).Str("cve-id", cveID).Err(err).
			Msg("image media type not supported for scanning, adding as a vulnerable image")

		return true
	}

	cveMap, err := cveinfo.Scanner.ScanImage(zcommon.GetFullImageName(repo, manifestDigestStr))
	if err != nil {
		cveinfo.Log.Debug().Str("image", image).Str("cve-id", cveID).
			Msg("scanning failed, adding as a vulnerable image")

		return true
	}

	hasCVE := false

	for id := range cveMap {
		if id == cveID {
			hasCVE = true

			break
		}
	}

	return hasCVE
}

func getIndexContent(metaDB mTypes.MetaDB, indexDigestStr string) (ispec.Index, error) {
	indexDigest, err := godigest.Parse(indexDigestStr)
	if err != nil {
		return ispec.Index{}, err
	}

	indexData, err := metaDB.GetIndexData(indexDigest)
	if err != nil {
		return ispec.Index{}, err
	}

	var indexContent ispec.Index

	err = json.Unmarshal(indexData.IndexBlob, &indexContent)
	if err != nil {
		return ispec.Index{}, err
	}

	return indexContent, nil
}

func getConfigAndDigest(metaDB mTypes.MetaDB, manifestDigestStr string) (ispec.Image, godigest.Digest, error) {
	manifestDigest, err := godigest.Parse(manifestDigestStr)
	if err != nil {
		return ispec.Image{}, "", err
	}

	manifestData, err := metaDB.GetManifestData(manifestDigest)
	if err != nil {
		return ispec.Image{}, "", err
	}

	var configContent ispec.Image

	// we'll fail the execution if the config is not compatibe with ispec.Image because we can't scan this type of images.
	err = json.Unmarshal(manifestData.ConfigBlob, &configContent)

	return configContent, manifestDigest, err
}

func filterCVEList(cveMap map[string]cvemodel.CVE, searchedCVE string, pageFinder *CvePageFinder) {
	searchedCVE = strings.ToUpper(searchedCVE)

	for _, cve := range cveMap {
		if strings.Contains(strings.ToUpper(cve.Title), searchedCVE) ||
			strings.Contains(strings.ToUpper(cve.ID), searchedCVE) {
			pageFinder.Add(cve)
		}
	}
}

func (cveinfo BaseCveInfo) GetCVEListForImage(repo, ref string, searchedCVE string, pageInput cvemodel.PageInput) (
	[]cvemodel.CVE,
	zcommon.PageInfo,
	error,
) {
	isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(repo, ref)
	if !isValidImage {
		cveinfo.Log.Debug().Str("image", repo+":"+ref).Err(err).Msg("image is not scanable")

		return []cvemodel.CVE{}, zcommon.PageInfo{}, err
	}

	image := zcommon.GetFullImageName(repo, ref)

	cveMap, err := cveinfo.Scanner.ScanImage(image)
	if err != nil {
		return []cvemodel.CVE{}, zcommon.PageInfo{}, err
	}

	pageFinder, err := NewCvePageFinder(pageInput.Limit, pageInput.Offset, pageInput.SortBy)
	if err != nil {
		return []cvemodel.CVE{}, zcommon.PageInfo{}, err
	}

	filterCVEList(cveMap, searchedCVE, pageFinder)

	cveList, pageInfo := pageFinder.Page()

	return cveList, pageInfo, nil
}

func (cveinfo BaseCveInfo) GetCVESummaryForImageMedia(repo, digest, mediaType string,
) (cvemodel.ImageCVESummary, error) {
	// There are several cases, expected returned values below:
	// not scanned yet                     - max severity ""            - cve count 0   - no Errors
	// not scannable                       - max severity ""            - cve count 0   - has Errors
	// scannable no issues found           - max severity "NONE"        - cve count 0   - no Errors
	// scannable issues found              - max severity from Scanner  - cve count >0  - no Errors
	imageCVESummary := cvemodel.ImageCVESummary{
		Count:       0,
		MaxSeverity: cvemodel.SeverityNotScanned,
	}

	// For this call we only look at the scanner cache, we skip the actual scanning to save time
	if !cveinfo.Scanner.IsResultCached(digest) {
		isValidImage, err := cveinfo.Scanner.IsImageMediaScannable(repo, digest, mediaType)
		if !isValidImage {
			cveinfo.Log.Debug().Str("digest", digest).Str("mediaType", mediaType).
				Err(err).Msg("image is not scannable")
		}

		return imageCVESummary, err
	}

	// We will make due with cached results
	cveMap := cveinfo.Scanner.GetCachedResult(digest)

	imageCVESummary.Count = len(cveMap)
	if imageCVESummary.Count == 0 {
		imageCVESummary.MaxSeverity = cvemodel.SeverityNone

		return imageCVESummary, nil
	}

	imageCVESummary.MaxSeverity = cvemodel.SeverityUnknown
	for _, cve := range cveMap {
		if cvemodel.CompareSeverities(imageCVESummary.MaxSeverity, cve.Severity) > 0 {
			imageCVESummary.MaxSeverity = cve.Severity
		}
	}

	return imageCVESummary, nil
}

func GetFixedTags(allTags, vulnerableTags []cvemodel.TagInfo) []cvemodel.TagInfo {
	sort.Slice(allTags, func(i, j int) bool {
		return allTags[i].Timestamp.Before(allTags[j].Timestamp)
	})

	earliestVulnerable := vulnerableTags[0]
	vulnerableTagMap := make(map[string]cvemodel.TagInfo, len(vulnerableTags))

	for _, tag := range vulnerableTags {
		vulnerableTagMap[tag.Tag] = tag

		switch tag.Descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			if tag.Timestamp.Before(earliestVulnerable.Timestamp) {
				earliestVulnerable = tag
			}
		case ispec.MediaTypeImageIndex:
			for _, manifestDesc := range tag.Manifests {
				if manifestDesc.Timestamp.Before(earliestVulnerable.Timestamp) {
					earliestVulnerable = tag
				}
			}
		default:
			continue
		}
	}

	var fixedTags []cvemodel.TagInfo

	// There are some downsides to this logic
	// We assume there can't be multiple "branches" of the same
	// image built at different times containing different fixes
	// There may be older images which have a fix or
	// newer images which don't
	for _, tag := range allTags {
		switch tag.Descriptor.MediaType {
		case ispec.MediaTypeImageManifest:
			if tag.Timestamp.Before(earliestVulnerable.Timestamp) {
				// The vulnerability did not exist at the time this
				// image was built
				continue
			}
			// If the image is old enough for the vulnerability to
			// exist, but it was not detected, it means it contains
			// the fix
			if _, ok := vulnerableTagMap[tag.Tag]; !ok {
				fixedTags = append(fixedTags, tag)
			}
		case ispec.MediaTypeImageIndex:
			fixedManifests := []cvemodel.DescriptorInfo{}

			// If the latest update inside the index is before the earliest vulnerability found then
			// the index can't contain a fix
			if tag.Timestamp.Before(earliestVulnerable.Timestamp) {
				continue
			}

			vulnTagInfo, indexHasVulnerableManifest := vulnerableTagMap[tag.Tag]

			for _, manifestDesc := range tag.Manifests {
				if manifestDesc.Timestamp.Before(earliestVulnerable.Timestamp) {
					// The vulnerability did not exist at the time this image was built
					continue
				}

				// check if the current manifest doesn't have the vulnerability
				if !indexHasVulnerableManifest || !containsDescriptorInfo(vulnTagInfo.Manifests, manifestDesc) {
					fixedManifests = append(fixedManifests, manifestDesc)
				}
			}

			if len(fixedManifests) > 0 {
				fixedTag := tag
				fixedTag.Manifests = fixedManifests

				fixedTags = append(fixedTags, fixedTag)
			}
		default:
			continue
		}
	}

	return fixedTags
}

func containsDescriptorInfo(slice []cvemodel.DescriptorInfo, descriptorInfo cvemodel.DescriptorInfo) bool {
	for _, di := range slice {
		if di.Digest == descriptorInfo.Digest {
			return true
		}
	}

	return false
}
