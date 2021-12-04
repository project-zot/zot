// Package cveinfo ...
package cveinfo

import (
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
