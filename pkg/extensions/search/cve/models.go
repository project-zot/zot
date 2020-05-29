// Package cveinfo ...
// Referred from https://github.com/kotakanbe/go-cve-dictionary/blob/master/models/models.go
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
