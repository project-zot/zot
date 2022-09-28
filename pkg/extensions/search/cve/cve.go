package cveinfo

import (
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"zotregistry.io/zot/pkg/extensions/search/common"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
	"zotregistry.io/zot/pkg/extensions/search/cve/trivy"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
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
	Digest   digest.Digest
	Manifest v1.Manifest
}

type ImageCVESummary struct {
	Count       int
	MaxSeverity string
}

type BaseCveInfo struct {
	Log         log.Logger
	Scanner     Scanner
	LayoutUtils common.OciLayoutUtils
}

func NewCVEInfo(storeController storage.StoreController, log log.Logger) *BaseCveInfo {
	layoutUtils := common.NewBaseOciLayoutUtils(storeController, log)
	scanner := trivy.NewScanner(storeController, layoutUtils, log)

	return &BaseCveInfo{Log: log, Scanner: scanner, LayoutUtils: layoutUtils}
}

func (cveinfo BaseCveInfo) GetImageListForCVE(repo, cveID string) ([]ImageInfoByCVE, error) {
	imgList := make([]ImageInfoByCVE, 0)

	manifests, err := cveinfo.LayoutUtils.GetImageManifests(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repo", repo).Msg("unable to get list of tags from repo")

		return imgList, err
	}

	for _, manifest := range manifests {
		tag := manifest.Annotations[ispec.AnnotationRefName]

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
				digest := manifest.Digest

				imageBlobManifest, err := cveinfo.LayoutUtils.GetImageBlobManifest(repo, digest)
				if err != nil {
					cveinfo.Log.Error().Err(err).Msg("unable to read image blob manifest")

					return []ImageInfoByCVE{}, err
				}

				imgList = append(imgList, ImageInfoByCVE{
					Tag:      tag,
					Digest:   digest,
					Manifest: imageBlobManifest,
				})

				break
			}
		}
	}

	return imgList, nil
}

func (cveinfo BaseCveInfo) GetImageListWithCVEFixed(repo, cveID string) ([]common.TagInfo, error) {
	tagsInfo, err := cveinfo.LayoutUtils.GetImageTagsWithTimestamp(repo)
	if err != nil {
		cveinfo.Log.Error().Err(err).Str("repo", repo).Msg("unable to get list of tags from repo")

		return []common.TagInfo{}, err
	}

	vulnerableTags := make([]common.TagInfo, 0)

	var hasCVE bool

	for _, tag := range tagsInfo {
		image := fmt.Sprintf("%s:%s", repo, tag.Name)
		tagInfo := common.TagInfo{Name: tag.Name, Timestamp: tag.Timestamp, Digest: tag.Digest}

		isValidImage, _ := cveinfo.Scanner.IsImageFormatScannable(image)
		if !isValidImage {
			cveinfo.Log.Debug().Str("image", image).
				Msg("image media type not supported for scanning, adding as a vulnerable image")

			vulnerableTags = append(vulnerableTags, tagInfo)

			continue
		}

		cveMap, err := cveinfo.Scanner.ScanImage(image)
		if err != nil {
			cveinfo.Log.Debug().Str("image", image).
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

	if len(vulnerableTags) != 0 {
		cveinfo.Log.Info().Str("repo", repo).Msg("comparing fixed tags timestamp")

		tagsInfo = common.GetFixedTags(tagsInfo, vulnerableTags)
	} else {
		cveinfo.Log.Info().Str("repo", repo).Str("cve-id", cveID).
			Msg("image does not contain any tag that have given cve")
	}

	return tagsInfo, nil
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
	imageCVESummary := ImageCVESummary{
		Count:       0,
		MaxSeverity: "UNKNOWN",
	}

	isValidImage, err := cveinfo.Scanner.IsImageFormatScannable(image)
	if !isValidImage {
		return imageCVESummary, err
	}

	cveMap, err := cveinfo.Scanner.ScanImage(image)
	if err != nil {
		return imageCVESummary, err
	}

	for _, cve := range cveMap {
		if cveinfo.Scanner.CompareSeverities(imageCVESummary.MaxSeverity, cve.Severity) > 0 {
			imageCVESummary.MaxSeverity = cve.Severity
		}
	}
	imageCVESummary.Count = len(cveMap)

	return imageCVESummary, nil
}

func (cveinfo BaseCveInfo) UpdateDB() error {
	return cveinfo.Scanner.UpdateDB()
}
