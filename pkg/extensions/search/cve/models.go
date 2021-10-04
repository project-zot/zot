// Package cveinfo ...
package cveinfo

import (
	"github.com/anuvu/zot/pkg/extensions/search/common"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/urfave/cli/v2"
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
