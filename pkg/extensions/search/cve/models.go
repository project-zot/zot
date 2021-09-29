// Package cveinfo ...
package cveinfo

import (
	"github.com/anuvu/zot/pkg/extensions/search/common"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/aquasecurity/trivy/integration/config"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
)

// CveInfo ...
type CveInfo struct {
	Log                log.Logger
	CveTrivyController CveTrivyController
	StoreController    storage.StoreController
	LayoutUtils        *common.OciLayoutUtils
}

type CveTrivyController struct {
	DefaultCveConfig *config.Config
	SubCveConfig     map[string]*config.Config
}

type ImageInfoByCVE struct {
	TagName       string
	TagDigest     digest.Digest
	ImageManifest v1.Manifest
}