package cveinfo

import (
	"encoding/json"
	"fmt"

	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"zotregistry.io/zot/pkg/extensions/search/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
	"zotregistry.io/zot/pkg/storage/repodb"
)

type CveInfo interface {
	GetImageListForCVE(repo, cveID string) ([]ImageInfoByCVE, error)
	GetImageListWithCVEFixed(repo, cveID string) ([]common.TagInfo, error)
	GetCVEListForImage(image string) (map[string]cvemodel.CVE, error)
	GetCVESummaryForImage(image string) (ImageCVESummary, error)
	UpdateDB() error
}

type Scanner interface {
	ScanImage(image string) (map[string]cvemodel.CVE, error)
	IsImageFormatScannable(image string) (bool, error)
	CompareSeverities(severity1, severity2 string) int
	UpdateDB() error
}

type ImageInfoByCVE struct {
	Tag      string
	Digest   godigest.Digest
	Manifest ispec.Manifest
}

type ImageCVESummary struct {
	Count       int
	MaxSeverity string
}

type BaseCveInfo struct {
	Log     log.Logger
	Scanner Scanner
	RepoDB  repodb.RepoDB
}

func NewCVEInfo(storeController storage.StoreController, repoDB repodb.RepoDB,
	log log.Logger,
) *BaseCveInfo {
	scanner := trivy.NewScanner(storeController, repoDB, log)

	return &BaseCveInfo{
		Log:     log,
		Scanner: scanner,
		RepoDB:  repoDB,
	}
}

func (cveinfo BaseCveInfo) GetImageListForCVE(repo, cveID string) ([]ImageInfoByCVE, error) {
	imgList := make([]ImageInfoByCVE, 0)

	repoMeta, err := cveinfo.RepoDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repo", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return imgList, err
	}

	for tag, manifestDigestStr := range repoMeta.Tags {
		manifestDigest, err := godigest.Parse(manifestDigestStr)
		if err != nil {
			cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
				Str("cve-id", cveID).Str("digest", manifestDigestStr).Msg("unable to parse digest")

			return nil, err
		}

		manifestMeta, err := cveinfo.RepoDB.GetManifestMeta(manifestDigest)
		if err != nil {
			return nil, err
		}

		var manifestContent ispec.Manifest

		err = json.Unmarshal(manifestMeta.ManifestBlob, &manifestContent)
		if err != nil {
			cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
				Str("cve-id", cveID).Msg("unable to unmashal manifest blob")

			continue
		}

		image := fmt.Sprintf("%s:%s", repo, tag)

		isValidImage, _ := cveinfo.Scanner.IsImageFormatScannable(image)
		if !isValidImage {
			continue
		}

		cveMap, err := cveinfo.Scanner.ScanImage(image)
		if err != nil {
			continue
		}

		for id := range cveMap {
			if id == cveID {
				imgList = append(imgList, ImageInfoByCVE{
					Tag:      tag,
					Digest:   manifestDigest,
					Manifest: manifestContent,
				})

				break
			}
		}
	}

	return imgList, nil
}

func (cveinfo BaseCveInfo) GetImageListWithCVEFixed(repo, cveID string) ([]common.TagInfo, error) {
	repoMeta, err := cveinfo.RepoDB.GetRepoMeta(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repo", repo).Str("cve-id", cveID).
			Msg("unable to get list of tags from repo")

		return []common.TagInfo{}, err
	}

	vulnerableTags := make([]common.TagInfo, 0)
	allTags := make([]common.TagInfo, 0)

	var hasCVE bool

	for tag, manifestDigestStr := range repoMeta.Tags {
		manifestDigest, err := godigest.Parse(manifestDigestStr)
		if err != nil {
			cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
				Str("cve-id", cveID).Str("digest", manifestDigestStr).Msg("unable to parse digest")

			continue
		}

		manifestMeta, err := cveinfo.RepoDB.GetManifestMeta(manifestDigest)
		if err != nil {
			cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
				Str("cve-id", cveID).Msg("unable to obtain manifest meta")

			continue
		}

		var configContent ispec.Image

		err = json.Unmarshal(manifestMeta.ConfigBlob, &configContent)
		if err != nil {
			cveinfo.Log.Error().Err(err).Str("repo", repo).Str("tag", tag).
				Str("cve-id", cveID).Msg("unable to unmashal manifest blob")

			continue
		}

		tagInfo := common.TagInfo{
			Name:      tag,
			Timestamp: common.GetImageLastUpdated(configContent),
			Digest:    manifestDigest,
		}

		allTags = append(allTags, tagInfo)

		image := fmt.Sprintf("%s:%s", repo, tag)

		isValidImage, _ := cveinfo.Scanner.IsImageFormatScannable(image)
		if !isValidImage {
			cveinfo.Log.Debug().Str("image", image).Str("cve-id", cveID).
				Msg("image media type not supported for scanning, adding as a vulnerable image")

			vulnerableTags = append(vulnerableTags, tagInfo)

			continue
		}

		cveMap, err := cveinfo.Scanner.ScanImage(image)
		if err != nil {
			cveinfo.Log.Debug().Str("image", image).Str("cve-id", cveID).
				Msg("scanning failed, adding as a vulnerable image")

			vulnerableTags = append(vulnerableTags, tagInfo)

			continue
		}

		hasCVE = false

		for id := range cveMap {
			if id == cveID {
				hasCVE = true

				break
			}
		}

		if hasCVE {
			vulnerableTags = append(vulnerableTags, tagInfo)
		}
	}

	var fixedTags []common.TagInfo

	if len(vulnerableTags) != 0 {
		cveinfo.Log.Info().Str("repo", repo).Str("cve-id", cveID).Msgf("Vulnerable tags: %v", vulnerableTags)
		fixedTags = common.GetFixedTags(allTags, vulnerableTags)
		cveinfo.Log.Info().Str("repo", repo).Str("cve-id", cveID).Msgf("Fixed tags: %v", fixedTags)
	} else {
		cveinfo.Log.Info().Str("repo", repo).Str("cve-id", cveID).
			Msg("image does not contain any tag that have given cve")
		fixedTags = allTags
	}

	return fixedTags, nil
}

func (cveinfo BaseCveInfo) GetCVEListForImage(image string) (map[string]cvemodel.CVE, error) {
	cveMap := make(map[string]cvemodel.CVE)

	isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(image)
	if !isValidImage {
		return cveMap, err
	}

	return cveinfo.Scanner.ScanImage(image)
}

func (cveinfo BaseCveInfo) GetCVESummaryForImage(image string) (ImageCVESummary, error) {
	// There are several cases, expected returned values below:
	// not scannable / error during scan   - max severity ""            - cve count 0   - Errors
	// scannable no issues found           - max severity "NONE"        - cve count 0   - no Errors
	// scannable issues found              - max severity from Scanner  - cve count >0  - no Errors
	imageCVESummary := ImageCVESummary{
		Count:       0,
		MaxSeverity: "",
	}

	isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(image)
	if !isValidImage {
		return imageCVESummary, err
	}

	cveMap, err := cveinfo.Scanner.ScanImage(image)
	if err != nil {
		return imageCVESummary, err
	}

	imageCVESummary.Count = len(cveMap)

	if imageCVESummary.Count == 0 {
		imageCVESummary.MaxSeverity = "NONE"

		return imageCVESummary, nil
	}

	imageCVESummary.MaxSeverity = "UNKNOWN"
	for _, cve := range cveMap {
		if cveinfo.Scanner.CompareSeverities(imageCVESummary.MaxSeverity, cve.Severity) > 0 {
			imageCVESummary.MaxSeverity = cve.Severity
		}
	}

	return imageCVESummary, nil
}

func (cveinfo BaseCveInfo) UpdateDB() error {
	return cveinfo.Scanner.UpdateDB()
}
