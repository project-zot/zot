package mocks

import (
	"zotregistry.io/zot/pkg/extensions/search/common"
	cveinfo "zotregistry.io/zot/pkg/extensions/search/cve"
	cvemodel "zotregistry.io/zot/pkg/extensions/search/cve/model"
)

type CveInfoMock struct {
	GetImageListForCVEFn       func(repo, cveID string) ([]common.TagInfo, error)
	GetImageListWithCVEFixedFn func(repo, cveID string) ([]common.TagInfo, error)
	GetCVEListForImageFn       func(image string, pageInput cveinfo.PageInput) ([]cvemodel.CVE, cveinfo.PageInfo, error)
	GetCVESummaryForImageFn    func(image string) (cveinfo.ImageCVESummary, error)
	CompareSeveritiesFn        func(severity1, severity2 string) int
	UpdateDBFn                 func() error
}

func (cveInfo CveInfoMock) GetImageListForCVE(repo, cveID string) ([]common.TagInfo, error) {
	if cveInfo.GetImageListForCVEFn != nil {
		return cveInfo.GetImageListForCVEFn(repo, cveID)
	}

	return []common.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetImageListWithCVEFixed(repo, cveID string) ([]common.TagInfo, error) {
	if cveInfo.GetImageListWithCVEFixedFn != nil {
		return cveInfo.GetImageListWithCVEFixedFn(repo, cveID)
	}

	return []common.TagInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVEListForImage(image string, pageInput cveinfo.PageInput) (
	[]cvemodel.CVE,
	cveinfo.PageInfo,
	error,
) {
	if cveInfo.GetCVEListForImageFn != nil {
		return cveInfo.GetCVEListForImageFn(image, pageInput)
	}

	return []cvemodel.CVE{}, cveinfo.PageInfo{}, nil
}

func (cveInfo CveInfoMock) GetCVESummaryForImage(image string) (cveinfo.ImageCVESummary, error) {
	if cveInfo.GetCVESummaryForImageFn != nil {
		return cveInfo.GetCVESummaryForImageFn(image)
	}

	return cveinfo.ImageCVESummary{}, nil
}

func (cveInfo CveInfoMock) CompareSeverities(severity1, severity2 string) int {
	if cveInfo.CompareSeveritiesFn != nil {
		return cveInfo.CompareSeveritiesFn(severity1, severity2)
	}

	return 0
}

func (cveInfo CveInfoMock) UpdateDB() error {
	if cveInfo.UpdateDBFn != nil {
		return cveInfo.UpdateDBFn()
	}

	return nil
}

type CveScannerMock struct {
	IsImageFormatScannableFn func(image string) (bool, error)
	ScanImageFn              func(image string) (map[string]cvemodel.CVE, error)
	CompareSeveritiesFn      func(severity1, severity2 string) int
	UpdateDBFn               func() error
}

func (scanner CveScannerMock) IsImageFormatScannable(image string) (bool, error) {
	if scanner.IsImageFormatScannableFn != nil {
		return scanner.IsImageFormatScannableFn(image)
	}

	return true, nil
}

func (scanner CveScannerMock) ScanImage(image string) (map[string]cvemodel.CVE, error) {
	if scanner.ScanImageFn != nil {
		return scanner.ScanImageFn(image)
	}

	return map[string]cvemodel.CVE{}, nil
}

func (scanner CveScannerMock) CompareSeverities(severity1, severity2 string) int {
	if scanner.CompareSeveritiesFn != nil {
		return scanner.CompareSeveritiesFn(severity1, severity2)
	}

	return 0
}

func (scanner CveScannerMock) UpdateDB() error {
	if scanner.UpdateDBFn != nil {
		return scanner.UpdateDBFn()
	}

	return nil
}
