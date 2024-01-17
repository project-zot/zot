package mocks

import (
	"context"

	"zotregistry.dev/zot/pkg/common"
	cvemodel "zotregistry.dev/zot/pkg/extensions/search/cve/model"
)

type CveInfoMock struct {
	GetImageListForCVEFn func(ctx context.Context, repo, cveID string) ([]cvemodel.TagInfo, error)

	GetImageListWithCVEFixedFn func(ctx context.Context, repo, cveID string) ([]cvemodel.TagInfo, error)

	GetCVEListForImageFn func(ctx context.Context, repo, reference, searchedCVE, excludedCVE, severity string,
		pageInput cvemodel.PageInput) ([]cvemodel.CVE, cvemodel.ImageCVESummary, common.PageInfo, error)

	GetCVESummaryForImageMediaFn func(ctx context.Context, repo string, digest, mediaType string,
	) (cvemodel.ImageCVESummary, error)

	GetCVEDiffListForImagesFn func(ctx context.Context, minuend, subtrahend, searchedCVE string,
		excludedCVE string, pageInput cvemodel.PageInput,
	) ([]cvemodel.CVE, cvemodel.ImageCVESummary, common.PageInfo, error)
}

func (cveInfo CveInfoMock) GetCVEDiffListForImages(ctx context.Context, minuend, subtrahend, searchedCVE string,
	excludedCVE string, pageInput cvemodel.PageInput,
) ([]cvemodel.CVE, cvemodel.ImageCVESummary, common.PageInfo, error) {
	if cveInfo.GetCVEDiffListForImagesFn != nil {
		return cveInfo.GetCVEDiffListForImagesFn(ctx, minuend, subtrahend, searchedCVE, excludedCVE, pageInput)
	}

	return []cvemodel.CVE{}, cvemodel.ImageCVESummary{}, common.PageInfo{}, nil
}

func (cveInfo CveInfoMock) GetImageListForCVE(ctx context.Context, repo, cveID string) ([]cvemodel.TagInfo, error) {
	if cveInfo.GetImageListForCVEFn != nil {
		return cveInfo.GetImageListForCVEFn(ctx, repo, cveID)
	}

	return []cvemodel.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetImageListWithCVEFixed(ctx context.Context, repo, cveID string,
) ([]cvemodel.TagInfo, error) {
	if cveInfo.GetImageListWithCVEFixedFn != nil {
		return cveInfo.GetImageListWithCVEFixedFn(ctx, repo, cveID)
	}

	return []cvemodel.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVEListForImage(ctx context.Context, repo string, reference string,
	searchedCVE string, excludedCVE string, severity string, pageInput cvemodel.PageInput,
) (
	[]cvemodel.CVE,
	cvemodel.ImageCVESummary,
	common.PageInfo,
	error,
) {
	if cveInfo.GetCVEListForImageFn != nil {
		return cveInfo.GetCVEListForImageFn(ctx, repo, reference, searchedCVE, excludedCVE, severity, pageInput)
	}

	return []cvemodel.CVE{}, cvemodel.ImageCVESummary{}, common.PageInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVESummaryForImageMedia(ctx context.Context, repo, digest, mediaType string,
) (cvemodel.ImageCVESummary, error) {
	if cveInfo.GetCVESummaryForImageMediaFn != nil {
		return cveInfo.GetCVESummaryForImageMediaFn(ctx, repo, digest, mediaType)
	}

	return cvemodel.ImageCVESummary{}, nil
}

type CveScannerMock struct {
	IsImageFormatScannableFn func(repo string, reference string) (bool, error)
	IsImageMediaScannableFn  func(repo string, digest, mediaType string) (bool, error)
	IsResultCachedFn         func(digest string) bool
	GetCachedResultFn        func(digest string) map[string]cvemodel.CVE
	ScanImageFn              func(ctx context.Context, image string) (map[string]cvemodel.CVE, error)
	UpdateDBFn               func(ctx context.Context) error
}

func (scanner CveScannerMock) IsImageFormatScannable(repo string, reference string) (bool, error) {
	if scanner.IsImageFormatScannableFn != nil {
		return scanner.IsImageFormatScannableFn(repo, reference)
	}

	return true, nil
}

func (scanner CveScannerMock) IsImageMediaScannable(repo string, digest, mediaType string) (bool, error) {
	if scanner.IsImageMediaScannableFn != nil {
		return scanner.IsImageMediaScannableFn(repo, digest, mediaType)
	}

	return true, nil
}

func (scanner CveScannerMock) IsResultCached(digest string) bool {
	if scanner.IsResultCachedFn != nil {
		return scanner.IsResultCachedFn(digest)
	}

	return false
}

func (scanner CveScannerMock) GetCachedResult(digest string) map[string]cvemodel.CVE {
	if scanner.GetCachedResultFn != nil {
		return scanner.GetCachedResultFn(digest)
	}

	return map[string]cvemodel.CVE{}
}

func (scanner CveScannerMock) ScanImage(ctx context.Context, image string) (map[string]cvemodel.CVE, error) {
	if scanner.ScanImageFn != nil {
		return scanner.ScanImageFn(ctx, image)
	}

	return map[string]cvemodel.CVE{}, nil
}

func (scanner CveScannerMock) UpdateDB(ctx context.Context) error {
	if scanner.UpdateDBFn != nil {
		return scanner.UpdateDBFn(ctx)
	}

	return nil
}
