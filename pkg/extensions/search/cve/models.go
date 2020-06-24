// Package cveinfo ...
package cveinfo

import (
	"github.com/anuvu/zot/pkg/log"
	config "github.com/aquasecurity/trivy/integration/config"
)

// CveInfo ...
type CveInfo struct {
	Log            log.Logger
	CveTrivyConfig *config.Config
}
