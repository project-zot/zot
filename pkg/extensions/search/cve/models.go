// Package cveinfo ...
package cveinfo

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/opencontainers/go-digest"
	"github.com/urfave/cli/v2"
	"zotregistry.io/zot/pkg/extensions/search/common"
	"zotregistry.io/zot/pkg/log"
	"zotregistry.io/zot/pkg/storage"
)

// CveInfo ...
type CveInfo struct {
	Log                log.Logger
	CveTrivyController CveTrivyController
	StoreController    storage.StoreController
	LayoutUtils        *common.OciLayoutUtils
}

type CveTrivyController struct {
	DefaultCveConfig *TrivyCtx
	SubCveConfig     map[string]*TrivyCtx
}

type TrivyCtx struct {
	Input string
	Ctx   *cli.Context
}

type ImageInfoByCVE struct {
	TagName       string
	TagDigest     digest.Digest
	ImageManifest v1.Manifest
}
