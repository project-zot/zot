// Package cveinfo ...
package cveinfo

import (
	"time"

	"github.com/anuvu/zot/pkg/extensions/search/common"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	config "github.com/aquasecurity/trivy/integration/config"
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

type TagInfo struct {
	Name      string
	Timestamp time.Time
}
